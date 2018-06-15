// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate gpu_buffer;
extern crate gpu_display;
extern crate gpu_renderer;

mod protocol;
mod backend;

use std::rc::Rc;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::mem::size_of;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::spawn;

use data_model::*;

use sys_util::{EventFd, PollContext, PollToken, GuestAddress, GuestMemory};

use self::gpu_buffer::Device;
use self::gpu_display::*;
use self::gpu_renderer::{Renderer, format_fourcc};

use super::{VirtioDevice, Queue, AvailIter, VIRTIO_F_VERSION_1, INTERRUPT_STATUS_USED_RING,
            TYPE_GPU};

use self::protocol::*;
use self::backend::Backend;

// First queue is for virtio gpu commands. Second queue is for cursor commands, which we expect
// there to be fewer of.
const QUEUE_SIZES: &'static [u16] = &[256, 16];

struct QueueDescriptor {
    index: u16,
    addr: GuestAddress,
    len: u32,
    data: Option<(GuestAddress, u32)>,
    ret: Option<(GuestAddress, u32)>,
}

struct ReturnDescriptor {
    index: u16,
    len: u32,
}

struct Frontend {
    ctrl_descriptors: VecDeque<QueueDescriptor>,
    cursor_descriptors: VecDeque<QueueDescriptor>,
    return_ctrl_descriptors: VecDeque<ReturnDescriptor>,
    return_cursor_descriptors: VecDeque<ReturnDescriptor>,
    backend: Backend,
}

impl Frontend {
    fn new(backend: Backend) -> Frontend {
        Frontend {
            ctrl_descriptors: Default::default(),
            cursor_descriptors: Default::default(),
            return_ctrl_descriptors: Default::default(),
            return_cursor_descriptors: Default::default(),
            backend,
        }
    }

    fn display(&self) -> &Rc<RefCell<GpuDisplay>> {
        self.backend.display()
    }

    fn process_display(&mut self) -> bool {
        self.backend.process_display()
    }

    fn process_gpu_command(&mut self,
                           mem: &GuestMemory,
                           cmd: GpuCommand,
                           data: Option<VolatileSlice>)
                           -> GpuResponse {
        match cmd {
            GpuCommand::GetDisplayInfo(_) => {
                GpuResponse::OkDisplayInfo(self.backend.display_info().to_vec())
            }
            GpuCommand::ResourceCreate2d(info) => {
                let format = info.format.to_native();
                match format_fourcc(format) {
                    Some(fourcc) => {
                        self.backend
                            .create_resource_2d(info.resource_id.to_native(),
                                                info.width.to_native(),
                                                info.height.to_native(),
                                                fourcc)
                    }
                    None => {
                        warn!("failed to create resource with unrecognized pipe format {}",
                              format);
                        GpuResponse::ErrInvalidParameter
                    }
                }

            }
            GpuCommand::ResourceUnref(info) => {
                self.backend.unref_resource(info.resource_id.to_native())
            }
            GpuCommand::SetScanout(info) => self.backend.set_scanout(info.resource_id.to_native()),
            GpuCommand::ResourceFlush(info) => {
                self.backend
                    .flush_resource(info.resource_id.to_native(),
                                    info.r.x.to_native(),
                                    info.r.y.to_native(),
                                    info.r.width.to_native(),
                                    info.r.height.to_native())
            }
            GpuCommand::TransferToHost2d(info) => {
                self.backend
                    .transfer_to_resource_2d(info.resource_id.to_native(),
                                             info.r.x.to_native(),
                                             info.r.y.to_native(),
                                             info.r.width.to_native(),
                                             info.r.height.to_native(),
                                             info.offset.to_native(),
                                             mem)
            }
            GpuCommand::ResourceAttachBacking(info) if data.is_some() => {
                let data = data.unwrap();
                let entry_count = info.nr_entries.to_native() as usize;
                let mut iovecs = Vec::with_capacity(entry_count);
                for i in 0..entry_count {
                    if let Ok(entry_ref) = data.get_ref((i * size_of::<virtio_gpu_mem_entry>()) as
                                                        u64) {
                        let entry: virtio_gpu_mem_entry = entry_ref.load();
                        let addr = GuestAddress(entry.addr.to_native());
                        let len = entry.length.to_native() as usize;
                        iovecs.push((addr, len))
                    } else {
                        return GpuResponse::ErrUnspec;
                    }
                }
                self.backend
                    .attach_backing(info.resource_id.to_native(), mem, iovecs)
            }
            GpuCommand::ResourceDetachBacking(info) => {
                self.backend.detach_backing(info.resource_id.to_native())
            }
            GpuCommand::UpdateCursor(info) => {
                self.backend
                    .update_cursor(info.resource_id.to_native(),
                                   info.pos.x.into(),
                                   info.pos.y.into())
            }
            GpuCommand::MoveCursor(info) => {
                self.backend
                    .move_cursor(info.pos.x.into(), info.pos.y.into())
            }
            GpuCommand::GetCapsetInfo(info) => {
                self.backend
                    .get_capset_info(info.capset_index.to_native())
            }
            GpuCommand::GetCapset(info) => {
                self.backend
                    .get_capset(info.capset_id.to_native(), info.capset_version.to_native())
            }
            GpuCommand::CtxCreate(info) => {
                self.backend
                    .create_renderer_context(info.hdr.ctx_id.to_native())
            }
            GpuCommand::CtxDestroy(info) => {
                self.backend
                    .destroy_renderer_context(info.hdr.ctx_id.to_native())
            }
            GpuCommand::CtxAttachResource(info) => {
                self.backend
                    .context_attach_resource(info.hdr.ctx_id.to_native(),
                                             info.resource_id.to_native())
            }
            GpuCommand::CtxDetachResource(info) => {
                self.backend
                    .context_detach_resource(info.hdr.ctx_id.to_native(),
                                             info.resource_id.to_native())
            }
            GpuCommand::ResourceCreate3d(info) => {
                let id = info.resource_id.to_native();
                let target = info.target.to_native();
                let format = info.format.to_native();
                let bind = info.bind.to_native();
                let width = info.width.to_native();
                let height = info.height.to_native();
                let depth = info.depth.to_native();
                let array_size = info.array_size.to_native();
                let last_level = info.last_level.to_native();
                let nr_samples = info.nr_samples.to_native();
                let flags = info.flags.to_native();
                self.backend
                    .resource_create_3d(id,
                                        target,
                                        format,
                                        bind,
                                        width,
                                        height,
                                        depth,
                                        array_size,
                                        last_level,
                                        nr_samples,
                                        flags)
            }
            GpuCommand::TransferToHost3d(info) => {
                let ctx_id = info.hdr.ctx_id.to_native();
                let res_id = info.resource_id.to_native();
                let x = info.box_.x.to_native();
                let y = info.box_.y.to_native();
                let z = info.box_.z.to_native();
                let width = info.box_.w.to_native();
                let height = info.box_.h.to_native();
                let depth = info.box_.d.to_native();
                let level = info.level.to_native();
                let stride = info.stride.to_native();
                let layer_stride = info.layer_stride.to_native();
                let offset = info.offset.to_native();
                self.backend
                    .transfer_to_resource_3d(ctx_id,
                                             res_id,
                                             x,
                                             y,
                                             z,
                                             width,
                                             height,
                                             depth,
                                             level,
                                             stride,
                                             layer_stride,
                                             offset)

            }
            GpuCommand::TransferFromHost3d(info) => {
                let ctx_id = info.hdr.ctx_id.to_native();
                let res_id = info.resource_id.to_native();
                let x = info.box_.x.to_native();
                let y = info.box_.y.to_native();
                let z = info.box_.z.to_native();
                let width = info.box_.w.to_native();
                let height = info.box_.h.to_native();
                let depth = info.box_.d.to_native();
                let level = info.level.to_native();
                let stride = info.stride.to_native();
                let layer_stride = info.layer_stride.to_native();
                let offset = info.offset.to_native();
                self.backend
                    .transfer_from_resource_3d(ctx_id,
                                               res_id,
                                               x,
                                               y,
                                               z,
                                               width,
                                               height,
                                               depth,
                                               level,
                                               stride,
                                               layer_stride,
                                               offset)
            }
            GpuCommand::CmdSubmit3d(info) if data.is_some() => {
                let data = data.unwrap(); // guarded by this match arm
                let cmd_size = info.size.to_native() as usize;
                match data.get_slice(0, cmd_size as u64) {
                    Ok(cmd_slice) => {
                        let mut cmd_buf = vec![0; cmd_size];
                        cmd_slice.copy_to(&mut cmd_buf[..]);
                        self.backend
                            .submit_command(info.hdr.ctx_id.to_native(), &mut cmd_buf[..])
                    }
                    Err(_) => GpuResponse::ErrInvalidParameter,
                }
            }
            _ => {
                error!("unhandled command {:?}", cmd);
                GpuResponse::ErrUnspec
            }
        }
    }

    fn take_descriptors(mem: &GuestMemory,
                        desc_iter: AvailIter,
                        descriptors: &mut VecDeque<QueueDescriptor>,
                        return_descriptors: &mut VecDeque<ReturnDescriptor>) {
        for desc in desc_iter {
            if desc.len as usize >= size_of::<virtio_gpu_ctrl_hdr>() && !desc.is_write_only() {
                let mut q_desc = QueueDescriptor {
                    index: desc.index,
                    addr: desc.addr,
                    len: desc.len,
                    data: None,
                    ret: None,
                };
                if let Some(extra_desc) = desc.next_descriptor() {
                    if extra_desc.is_write_only() {
                        q_desc.ret = Some((extra_desc.addr, extra_desc.len));
                    } else {
                        q_desc.data = Some((extra_desc.addr, extra_desc.len));
                    }
                }
                if let Some(extra_desc) = desc.next_descriptor() {
                    if extra_desc.is_write_only() && q_desc.ret.is_none() {
                        q_desc.ret = Some((extra_desc.addr, extra_desc.len));
                    }
                }
                descriptors.push_back(q_desc);
            } else {
                let likely_type = mem.read_obj_from_addr(desc.addr)
                    .unwrap_or(Le32::from(0));
                debug!("ctrl queue bad descriptor index = {} len = {} write = {} type = {}",
                       desc.index,
                       desc.len,
                       desc.is_write_only(),
                       virtio_gpu_cmd_str(likely_type.to_native()));
                return_descriptors.push_back(ReturnDescriptor {
                                                 index: desc.index,
                                                 len: 0,
                                             });
            }
        }
    }

    fn take_ctrl_descriptors(&mut self, mem: &GuestMemory, desc_iter: AvailIter) {
        Frontend::take_descriptors(mem,
                                   desc_iter,
                                   &mut self.ctrl_descriptors,
                                   &mut self.return_ctrl_descriptors);
    }

    fn take_cursor_descriptors(&mut self, mem: &GuestMemory, desc_iter: AvailIter) {
        Frontend::take_descriptors(mem,
                                   desc_iter,
                                   &mut self.cursor_descriptors,
                                   &mut self.return_cursor_descriptors);
    }

    fn process_descriptor(&mut self, mem: &GuestMemory, desc: QueueDescriptor) -> ReturnDescriptor {
        let mut resp = GpuResponse::ErrUnspec;
        let mut gpu_cmd = None;
        let mut len = 0;
        if let Ok(desc_mem) = mem.get_slice(desc.addr.offset(), desc.len as u64) {
            match GpuCommand::decode(desc_mem) {
                Ok(cmd) => {
                    match desc.data {
                        Some(data_desc) => {
                            match mem.get_slice(data_desc.0.offset(), data_desc.1 as u64) {
                                Ok(data_mem) => {
                                    resp = self.process_gpu_command(mem, cmd, Some(data_mem))
                                }
                                Err(e) => debug!("ctrl queue invalid data descriptor: {:?}", e),
                            }
                        }
                        None => resp = self.process_gpu_command(mem, cmd, None),
                    }
                    gpu_cmd = Some(cmd);
                }
                Err(e) => debug!("ctrl queue decode error: {:?}", e),
            }
        }
        if resp.is_err() {
            debug!("{:?} -> {:?}", gpu_cmd, resp);
        }
        if let Some(ret_desc) = desc.ret {
            if let Ok(ret_desc_mem) = mem.get_slice(ret_desc.0.offset(), ret_desc.1 as u64) {
                let mut fence_id = 0;
                let mut ctx_id = 0;
                let mut flags = 0;
                if let Some(cmd) = gpu_cmd {
                    let ctrl_hdr = cmd.ctrl_hdr();
                    // TODO: add proper fence support
                    if ctrl_hdr.flags.to_native() & VIRTIO_GPU_FLAG_FENCE != 0 {
                        fence_id = ctrl_hdr.fence_id.to_native();
                        ctx_id = ctrl_hdr.ctx_id.to_native();
                        flags = VIRTIO_GPU_FLAG_FENCE;
                    }
                }
                match resp.encode(flags, fence_id, ctx_id, ret_desc_mem) {
                    Ok(l) => len = l,
                    Err(e) => debug!("ctrl queue response encode error: {:?}", e),
                }
            }
        }
        ReturnDescriptor {
            index: desc.index,
            len,
        }
    }

    fn process_ctrl(&mut self, mem: &GuestMemory) -> Option<ReturnDescriptor> {
        self.return_ctrl_descriptors
            .pop_front()
            .or_else(|| {
                         self.ctrl_descriptors
                             .pop_front()
                             .map(|desc| self.process_descriptor(mem, desc))
                     })
    }

    fn process_cursor(&mut self, mem: &GuestMemory) -> Option<ReturnDescriptor> {
        self.return_cursor_descriptors
            .pop_front()
            .or_else(|| {
                         self.cursor_descriptors
                             .pop_front()
                             .map(|desc| self.process_descriptor(mem, desc))
                     })
    }
}

struct Worker {
    exit_evt: EventFd,
    mem: GuestMemory,
    interrupt_evt: EventFd,
    interrupt_status: Arc<AtomicUsize>,
    ctrl_queue: Queue,
    ctrl_evt: EventFd,
    cursor_queue: Queue,
    cursor_evt: EventFd,
    kill_evt: EventFd,
    state: Frontend,
}

impl Worker {
    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        let _ = self.interrupt_evt.write(1);
    }


    fn run(&mut self) {
        #[derive(PollToken)]
        enum Token {
            CtrlQueue,
            CursorQueue,
            Display,
            Kill,
        }

        let poll_ctx: PollContext<Token> =
            match PollContext::new()
                      .and_then(|pc| pc.add(&self.ctrl_evt, Token::CtrlQueue).and(Ok(pc)))
                      .and_then(|pc| {
                                    pc.add(&self.cursor_evt, Token::CursorQueue).and(Ok(pc))
                                })
                      .and_then(|pc| {
                                    pc.add(&*self.state.display().borrow(), Token::Display)
                                        .and(Ok(pc))
                                })
                      .and_then(|pc| pc.add(&self.kill_evt, Token::Kill).and(Ok(pc))) {
                Ok(pc) => pc,
                Err(e) => {
                    error!("failed creating PollContext: {:?}", e);
                    return;
                }
            };

        'poll: loop {
            let events = match poll_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed polling for events: {:?}", e);
                    break;
                }
            };
            let mut signal_used = false;
            for event in events.iter_readable() {
                match event.token() {
                    Token::CtrlQueue => {
                        let _ = self.ctrl_evt.read();
                        self.state
                            .take_ctrl_descriptors(&self.mem, self.ctrl_queue.iter(&self.mem));
                    }
                    Token::CursorQueue => {
                        let _ = self.cursor_evt.read();
                        self.state
                            .take_cursor_descriptors(&self.mem, self.cursor_queue.iter(&self.mem));
                    }
                    Token::Display => {
                        let close_requested = self.state.process_display();
                        if close_requested {
                            let _ = self.exit_evt.write(1);
                        }
                    }
                    Token::Kill => {
                        break 'poll;
                    }
                }
            }

            // All cursor commands go first because they have higher priority.
            loop {
                match self.state.process_cursor(&self.mem) {
                    Some(ReturnDescriptor { index, len }) => {
                        self.cursor_queue.add_used(&self.mem, index, len);
                        signal_used = true;
                    }
                    None => break,
                }
            }

            loop {
                match self.state.process_ctrl(&self.mem) {
                    Some(ReturnDescriptor { index, len }) => {
                        self.ctrl_queue.add_used(&self.mem, index, len);
                        signal_used = true;
                    }
                    None => break,
                }
            }

            if signal_used {
                self.signal_used_queue();
            }
        }
    }
}

pub struct Gpu {
    config_event: bool,
    exit_evt: EventFd,
    kill_evt: Option<EventFd>,
}

impl Gpu {
    pub fn new(exit_evt: EventFd) -> Gpu {
        Gpu {
            config_event: false,
            exit_evt,
            kill_evt: None,
        }
    }

    fn get_config(&self) -> virtio_gpu_config {
        let mut events_read = 0;
        if self.config_event {
            events_read |= VIRTIO_GPU_EVENT_DISPLAY;
        }
        virtio_gpu_config {
            events_read: Le32::from(events_read),
            events_clear: Le32::from(0),
            num_scanouts: Le32::from(1),
            num_capsets: Le32::from(1),
        }
    }
}

impl Drop for Gpu {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Gpu {
    fn keep_fds(&self) -> Vec<RawFd> {
        Vec::new()
    }

    fn device_type(&self) -> u32 {
        TYPE_GPU
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self, page: u32) -> u32 {
        match page {
            0 => (1 << VIRTIO_GPU_F_VIRGL),
            1 => VIRTIO_F_VERSION_1,
            _ => 0,
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        let _ = page;
        let _ = value;
    }


    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let offset = offset as usize;
        let len = data.len();
        let cfg = self.get_config();
        let cfg_slice = cfg.as_slice();
        if offset + len <= cfg_slice.len() {
            data.copy_from_slice(&cfg_slice[offset..offset + len]);
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let offset = offset as usize;
        let len = data.len();
        let mut cfg = self.get_config();
        {
            let cfg_slice = cfg.as_mut_slice();
            if offset + len <= cfg_slice.len() {
                cfg_slice[offset..offset + len].copy_from_slice(data);
            }
        }
        if (cfg.events_clear.to_native() & VIRTIO_GPU_EVENT_DISPLAY) != 0 {
            self.config_event = false;
        }
    }

    fn activate(&mut self,
                mem: GuestMemory,
                interrupt_evt: EventFd,
                interrupt_status: Arc<AtomicUsize>,
                mut queues: Vec<Queue>,
                mut queue_evts: Vec<EventFd>) {
        if queues.len() != QUEUE_SIZES.len() || queue_evts.len() != QUEUE_SIZES.len() {
            return;
        }

        let exit_evt = match self.exit_evt.try_clone() {
            Ok(e) => e,
            Err(e) => {
                error!("error cloning exit eventfd: {:?}", e);
                return;
            }
        };

        let (self_kill_evt, kill_evt) =
            match EventFd::new().and_then(|e| Ok((e.try_clone()?, e))) {
                Ok(v) => v,
                Err(e) => {
                    error!("error creating kill EventFd pair: {:?}", e);
                    return;
                }
            };
        self.kill_evt = Some(self_kill_evt);

        let ctrl_queue = queues.remove(0);
        let ctrl_evt = queue_evts.remove(0);
        let cursor_queue = queues.remove(0);
        let cursor_evt = queue_evts.remove(0);
        spawn(move || {
            const UNDESIRED_CARDS: &[&str] = &["vgem", "pvr"];
            let drm_card = match gpu_buffer::rendernode::open_device(UNDESIRED_CARDS) {
                Ok(f) => f,
                Err(e) => {
                    error!("failed to open card: {:?}", e);
                    return;
                }
            };

            let device = match Device::new(drm_card) {
                Ok(d) => d,
                Err(()) => {
                    error!("failed to open device");
                    return
                }
            };

            let display = match GpuDisplay::new() {
                Ok(c) => c,
                Err(e) => {
                    error!("{:?}", e);
                    return;
                }
            };

            let renderer = match Renderer::init() {
                Ok(r) => r,
                Err(e) => {
                    error!("failed to initialize gpu renderer: {}", e);
                    return;
                }
            };

            Worker {
                    exit_evt,
                    mem,
                    interrupt_evt,
                    interrupt_status,
                    ctrl_queue,
                    ctrl_evt,
                    cursor_queue,
                    cursor_evt,
                    kill_evt,
                    state: Frontend::new(Backend::new(device, display, renderer)),
                }
                .run()
        });
    }
}