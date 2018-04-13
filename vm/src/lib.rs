// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate arch;
extern crate devices;
extern crate device_manager;
extern crate kernel_cmdline;
extern crate kvm;
extern crate libc;
extern crate net_util;
extern crate nix;
extern crate sys_util;
extern crate vm_control;
extern crate x86_64;

use std::error;
use std::fmt;
use std::fs::{File, remove_file};
use std::io::{self, stdin};
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
use std::io::stdout;
use std::net;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Barrier};
use std::thread;
use std::thread::JoinHandle;
use std::time::Instant;

use nix::unistd::fork;
use nix::unistd::ForkResult::*;

use kvm::*;
use sys_util::*;
use vm_control::VmRequest;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use arch::LinuxArch;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86_64::X8664arch as Arch;

pub enum Error {
    BalloonDeviceNew(devices::virtio::BalloonError),
    CloneEventFd(sys_util::Error),
    CreateEventFd(sys_util::Error),
    CreateIrqChip(Box<error::Error>),
    CreateKvm(sys_util::Error),
    CreateSocket(io::Error),
    CreateVcpu(Box<error::Error>),
    CreateVm(Box<error::Error>),
    RegisterBalloon(device_manager::Error),
    RegisterRng(device_manager::Error),
    RegisterVsock(device_manager::Error),
    RngDeviceNew(devices::virtio::RngError),
    SignalFd(sys_util::SignalFdError),
    SpawnVcpu(io::Error),
    VhostVsockDeviceNew(devices::virtio::vhost::Error),

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    SetupIoBus(Box<error::Error>),

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    SetupMMIOBus(Box<error::Error>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::BalloonDeviceNew(ref e) => write!(f, "failed to create balloon: {:?}", e),
            &Error::CloneEventFd(ref e) => write!(f, "failed to clone eventfd: {:?}", e),
            &Error::CreateEventFd(ref e) => write!(f, "failed to create eventfd: {:?}", e),
            &Error::CreateIrqChip(ref e) => {
                write!(f, "failed to create in-kernel IRQ chip: {:?}", e)
            }
            &Error::CreateKvm(ref e) => write!(f, "failed to open /dev/kvm: {:?}", e),
            &Error::CreateSocket(ref e) => write!(f, "failed to create socket: {}", e),
            &Error::CreateVcpu(ref e) => write!(f, "failed to create vcpu: {:?}", e),
            &Error::CreateVm(ref e) => write!(f, "failed to create KVM VM object: {:?}", e),
            &Error::RegisterBalloon(ref e) => {
                write!(f, "error registering balloon device: {:?}", e)
            },
            &Error::RegisterRng(ref e) => write!(f, "error registering rng device: {:?}", e),
            &Error::RegisterVsock(ref e) => {
                write!(f, "error registering virtual socket device: {:?}", e)
            }
            &Error::RngDeviceNew(ref e) => write!(f, "failed to set up rng: {:?}", e),
            &Error::SignalFd(ref e) => write!(f, "failed to read signal fd: {:?}", e),
            &Error::SpawnVcpu(ref e) => write!(f, "failed to spawn VCPU thread: {:?}", e),
            &Error::VhostVsockDeviceNew(ref e) => {
                write!(f, "failed to set up virtual socket device: {:?}", e)
            }

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            &Error::SetupIoBus(ref e) => write!(f, "failed to setup iobus: {}", e),

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            &Error::SetupMMIOBus(ref e) => write!(f, "failed to setup mmio bus: {}", e),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

pub struct UnlinkUnixDatagram(pub UnixDatagram);
impl AsRef<UnixDatagram> for UnlinkUnixDatagram {
    fn as_ref(&self) -> &UnixDatagram{
        &self.0
    }
}

impl Drop for UnlinkUnixDatagram {
    fn drop(&mut self) {
        if let Ok(addr) = self.0.local_addr() {
            if let Some(path) = addr.as_pathname() {
                if let Err(e) = remove_file(path) {
                    warn!("failed to remove control socket file: {:?}", e);
                }
            }
        }
    }
}

static SECCOMP_POLICY_DIR: &'static str = "/usr/share/policy/crosvm";

pub enum DiskType {
    FlatFile,
    Qcow,
}

pub struct DiskOption {
    pub path: PathBuf,
    pub writable: bool,
    pub disk_type: DiskType,
}

pub struct Config {
    pub disks: Vec<DiskOption>,
    pub vcpu_count: Option<u32>,
    pub memory: Option<usize>,
    pub kernel_path: PathBuf,
    pub params: Vec<String>,
    pub host_ip: Option<net::Ipv4Addr>,
    pub netmask: Option<net::Ipv4Addr>,
    pub mac_address: Option<net_util::MacAddress>,
    pub vhost_net: bool,
    pub wayland_socket_path: Option<PathBuf>,
    pub socket_path: Option<PathBuf>,
    pub multiprocess: bool,
    pub seccomp_policy_dir: PathBuf,
    pub cid: Option<u64>,
    pub plugin: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            disks: Vec::new(),
            vcpu_count: None,
            memory: None,
            kernel_path: PathBuf::default(),
            params: Vec::new(),
            host_ip: None,
            netmask: None,
            mac_address: None,
            vhost_net: false,
            wayland_socket_path: None,
            socket_path: None,
            multiprocess: true,
            seccomp_policy_dir: PathBuf::from(SECCOMP_POLICY_DIR),
            cid: None,
            plugin: None,
        }
    }
}

pub fn run_vcpu(vcpu: Vcpu,
                cpu_id: u32,
                start_barrier: Arc<Barrier>,
                io_bus: devices::Bus,
                mmio_bus: devices::Bus,
                exit_evt: EventFd,
                kill_signaled: Arc<AtomicBool>) -> Result<JoinHandle<()>> {
    thread::Builder::new()
        .name(format!("crosvm_vcpu{}", cpu_id))
        .spawn(move || {
            unsafe {
                extern "C" fn handle_signal() {}
                // Our signal handler does nothing and is trivially async signal safe.
                register_signal_handler(SIGRTMIN() + 0, handle_signal)
                    .expect("failed to register vcpu signal handler");
            }

            start_barrier.wait();
            loop {
                let run_res = vcpu.run();
                match run_res {
                    Ok(run) => {
                        match run {
                            VcpuExit::IoIn(addr, data) => {
                                io_bus.read(addr as u64, data);
                            }
                            VcpuExit::IoOut(addr, data) => {
                                io_bus.write(addr as u64, data);
                            }
                            VcpuExit::MmioRead(addr, data) => {
                                mmio_bus.read(addr, data);
                            }
                            VcpuExit::MmioWrite(addr, data) => {
                                mmio_bus.write(addr, data);
                            }
                            VcpuExit::Hlt => break,
                            VcpuExit::Shutdown => break,
                            r => warn!("unexpected vcpu exit: {:?}", r),
                        }
                    }
                    Err(e) => {
                        match e.errno() {
                            libc::EAGAIN | libc::EINTR => {},
                            _ => {
                                error!("vcpu hit unknown error: {:?}", e);
                                break;
                            }
                        }
                    }
                }
                if kill_signaled.load(Ordering::SeqCst) {
                    break;
                }
            }
            exit_evt
                .write(1)
                .expect("failed to signal vcpu exit eventfd");
        })
        .map_err(Error::SpawnVcpu)
}


pub fn run_control(vm: &mut Vm,
                   control_sockets: Vec<UnlinkUnixDatagram>,
                   next_dev_pfn: &mut u64,
                   stdio_serial: Arc<Mutex<devices::Serial>>,
                   exit_evt: EventFd,
                   sigchld_fd: SignalFd,
                   kill_signaled: Arc<AtomicBool>,
                   vcpu_handles: Vec<JoinHandle<()>>,
                   balloon_host_socket: UnixDatagram,
                   _irqchip_fd: Option<File>)
                   -> Result<()> {
    const MAX_VM_FD_RECV: usize = 1;

    const EXIT: u32 = 0;
    const STDIN: u32 = 1;
    const CHILD_SIGNAL: u32 = 2;
    const VM_BASE: u32 = 3;

    let stdin_handle = stdin();
    let stdin_lock = stdin_handle.lock();
    stdin_lock
        .set_raw_mode()
        .expect("failed to set terminal raw mode");

    let mut pollables = Vec::new();
    pollables.push((EXIT, &exit_evt as &Pollable));
    pollables.push((STDIN, &stdin_lock as &Pollable));
    pollables.push((CHILD_SIGNAL, &sigchld_fd as &Pollable));
    for (i, socket) in control_sockets.iter().enumerate() {
        pollables.push((VM_BASE + i as u32, socket.as_ref() as &Pollable));
    }

    let mut poller = Poller::new(pollables.len());
    let mut scm = Scm::new(MAX_VM_FD_RECV);

    'poll: loop {
        let tokens = {
            match poller.poll(&pollables[..]) {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to poll: {:?}", e);
                    break;
                }
            }
        };
        for &token in tokens {
            match token {
                EXIT => {
                    info!("vcpu requested shutdown");
                    break 'poll;
                }
                STDIN => {
                    let mut out = [0u8; 64];
                    match stdin_lock.read_raw(&mut out[..]) {
                        Ok(0) => {
                            // Zero-length read indicates EOF. Remove from pollables.
                            pollables.retain(|&pollable| pollable.0 != STDIN);
                        },
                        Err(e) => {
                            warn!("error while reading stdin: {:?}", e);
                            pollables.retain(|&pollable| pollable.0 != STDIN);
                        },
                        Ok(count) => {
                            stdio_serial
                                .lock()
                                .unwrap()
                                .queue_input_bytes(&out[..count])
                                .expect("failed to queue bytes into serial port");
                        },
                    }
                }
                CHILD_SIGNAL => {
                    // Print all available siginfo structs, then exit the loop.
                    loop {
                        let result = sigchld_fd.read().map_err(Error::SignalFd)?;
                        if let Some(siginfo) = result {
                            error!("child {} died: signo {}, status {}, code {}",
                                   siginfo.ssi_pid,
                                   siginfo.ssi_signo,
                                   siginfo.ssi_status,
                                   siginfo.ssi_code);
                        }
                        break 'poll;
                    }
                }
                t if t >= VM_BASE && t < VM_BASE + (control_sockets.len() as u32) => {
                    let socket = &control_sockets[(t - VM_BASE) as usize];
                    match VmRequest::recv(&mut scm, socket.as_ref()) {
                        Ok(request) => {
                            let mut running = true;
                            match request {
                                VmRequest::Fork => {
                                    // We can not call fork_vm() from the vm_control execute
                                    // path, because it creates cyclic dependencies.
                                    // fork_vm is part of the vm crates that uses the x86_64
                                    // crate, which itself eventually uses the devices one. And
                                    // the devices crate uses the vm_control one through the
                                    // wayland virtio driver.
                                    // So by calling fork_vm() from vm_control, we'd create the
                                    // following cyclic dependency:
                                    // vm_control->vm->x86_64->arch->device_manager->devices->vm_control.
                                    fork_vm(vm)?;

                                    // The Fork execute branch is a NO-OP.
                                    let response =
                                        request.execute(vm, next_dev_pfn,
                                                        &mut running, &balloon_host_socket);
                                    if let Err(e) = response.send(&mut scm, socket.as_ref()) {
                                        error!("failed to send VmResponse: {:?}", e);
                                    }
                                },
                                _ => {
                                    let response =
                                        request.execute(vm, next_dev_pfn,
                                                        &mut running, &balloon_host_socket);
                                    if let Err(e) = response.send(&mut scm, socket.as_ref()) {
                                        error!("failed to send VmResponse: {:?}", e);
                                    }
                                    if !running {
                                        info!("control socket requested exit");
                                        break 'poll;
                                    }
                                },
                            }
                        }
                        Err(e) => error!("failed to recv VmRequest: {:?}", e),
                    }
                }
                _ => {}
            }
        }
    }

    // vcpu threads MUST see the kill signaled flag, otherwise they may
    // re-enter the VM.
    kill_signaled.store(true, Ordering::SeqCst);
    for handle in vcpu_handles {
        match handle.kill(SIGRTMIN() + 0) {
            Ok(_) => {
                if let Err(e) = handle.join() {
                    error!("failed to join vcpu thread: {:?}", e);
                }
            }
            Err(e) => error!("failed to kill vcpu thread: {:?}", e),
        }
    }

    stdin_lock
        .set_canon_mode()
        .expect("failed to restore canonical mode for terminal");

    Ok(())
}

fn setup_mmio_bus(cfg: &Config,
                  vm: &mut Vm,
                  mem: &GuestMemory,
                  balloon_device_socket: UnixDatagram)
                  -> Result<devices::Bus> {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let mut device_manager = Arch::get_device_manager(vm, mem.clone()).
        map_err(|e| Error::SetupMMIOBus(e))?;
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    let mut device_manager = device_manager::DeviceManager::new(vm,
                                                                mem.clone(),
                                                                0, 0, 0);
    let mut cmdline = kernel_cmdline::Cmdline::new(4096);

    let rng_box = Box::new(devices::virtio::Rng::new().map_err(Error::RngDeviceNew)?);
    let rng_jail = None;
    device_manager
        .register_mmio(rng_box, rng_jail, &mut cmdline)
        .map_err(Error::RegisterRng)?;

    let balloon_box = Box::new(devices::virtio::Balloon::new(balloon_device_socket)
                                   .map_err(Error::BalloonDeviceNew)?);
    let balloon_jail = None;
    device_manager.register_mmio(balloon_box, balloon_jail, &mut cmdline)
        .map_err(Error::RegisterBalloon)?;

    if let Some(cid) = cfg.cid {
        let vsock_box = Box::new(devices::virtio::vhost::Vsock::new(cid, &mem)
                                     .map_err(Error::VhostVsockDeviceNew)?);

        let jail = None;
        device_manager
            .register_mmio(vsock_box, jail, &mut cmdline)
            .map_err(Error::RegisterVsock)?;
    }

    Ok(device_manager.bus)
}

pub fn fork_vm(vm: &mut Vm) -> Result<()> {
    println!("Forking VM");

    /* Timestamp for the VM forking start */
    let now = Instant::now();

    /* Create a new KVM instance */
    let kvm = Kvm::new().map_err(Error::CreateKvm)?;

    vm.snapshot(&kvm).map_err(Error::CreateKvm)?;

    /* Fork the VMM process and run all new vCPU threads */
    match fork().expect("fork failed") {
        Parent {child} => {
            println!("Forked VMM - new VM {}", child);
        },

        Child => {
            let kvm = Kvm::new().map_err(Error::CreateKvm)?;

            /* Create a new VM, using the same memory space */
            let mut new_vm = Vm::new(&kvm, vm.get_memory().clone()).map_err(|e| Error::CreateVm(Box::new(e)))?;
            let tss_addr = GuestAddress(0xfffbd000);
            new_vm.set_tss_addr(tss_addr).map_err(Error::CreateKvm)?;
            new_vm.create_pit().map_err(Error::CreateKvm)?;
            new_vm.create_irq_chip().map_err(Error::CreateKvm)?;

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            let irq_chip = Arch::create_irq_chip(&new_vm).map_err(|e| Error::CreateIrqChip(e))?;
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            let irq_chip = None;

            let vcpu_states = vm.get_vcpu_states();
            let vcpu_count = vcpu_states.len();
            let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));
            let kill_signaled = Arc::new(AtomicBool::new(false));
            let exit_evt = EventFd::new().map_err(Error::CreateEventFd)?;

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            let (io_bus, stdio_serial) = Arch::setup_io_bus(&mut new_vm,
                                                            exit_evt.try_clone().
                                                            map_err(Error::CloneEventFd)?).
                map_err(|e| Error::SetupIoBus(e))?;


            let mut vcpu_handles = Vec::with_capacity(vcpu_count as usize);
            let mut cpu_id = 0;

            let mut cfg = Config::default();
            let (balloon_host_socket, balloon_device_socket) = UnixDatagram::pair()
                .map_err(Error::CreateSocket)?;
            let mmio_bus = setup_mmio_bus(&cfg,
                                          &mut new_vm,
                                          &vm.get_memory().clone(),
                                          balloon_device_socket)?;
            
            for state in vcpu_states {
                let state_regs = state.get_regs().map_err(Error::CreateKvm)?;
                let regs = match state_regs {
                    &None => {continue;},
                    &Some(ref r) => {r}
                };

                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                let new_vcpu = Arch::copy_vcpu(&kvm, &new_vm, regs, cpu_id, vcpu_count as u64).map_err(|e| Error::CreateVcpu(e))?;
                
                println!("Launching Child vCPU thread #{}", cpu_id);
                let handle = run_vcpu(new_vcpu,
                                      cpu_id as u32,
                                      vcpu_thread_barrier.clone(),
                                      io_bus.clone(),
                                      mmio_bus.clone(),
                                      exit_evt.try_clone().unwrap(),
                                      kill_signaled.clone())?;
                vcpu_handles.push(handle);
                cpu_id += 1;
            }

            /* Wake up all vCPU threads */
            vcpu_thread_barrier.wait();

            let elapsed = now.elapsed();
            println!("VM forking took [{}s:{}ms:{}µs]", elapsed.as_secs(), elapsed.subsec_nanos()/1000000, elapsed.subsec_nanos()/1000);
        }
    }
    Ok(())
}

