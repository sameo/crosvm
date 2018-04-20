// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate sys_util;
extern crate kernel_cmdline;
extern crate kvm;
extern crate libc;
extern crate device_manager;
extern crate devices;

use std::ffi::CStr;
use std::fs::File;
use std::result;
use std::sync::{Arc, Mutex};

use kvm::{Kvm, Vm, Vcpu, VcpuStateRegs};
use sys_util::{EventFd, GuestMemory};

pub type Result<T> = result::Result<T, Box<std::error::Error>>;

/// Trait which is implemented for each Linux Architecture in order to
/// set up the memory, cpus, and system devices and to boot the kernel.
pub trait LinuxArch {
    /// Loads the kernel from an open file.
    ///
    /// # Arguments
    ///
    /// * `mem` - The memory to be used by the guest.
    /// * `kernel_image` - the File object for the specified kernel.
    fn load_kernel(mem: &GuestMemory, kernel_image: &mut File) -> Result<()>;

    /// Configures the system memory space should be called once per vm before
    /// starting vcpu threads.
    ///
    /// # Arguments
    ///
    /// * `mem` - The memory to be used by the guest
    /// * `mem_size` - The size in bytes of system memory
    /// * `vcpu_count` - Number of virtual CPUs the guest will have
    /// * `cmdline` - the kernel commandline
    fn setup_system_memory(mem: &GuestMemory,
                           mem_size: u64,
                           vcpu_count: u32,
                           cmdline: &CStr) -> Result<()>;

    /// Creates a new VM object and initializes architecture specific devices
    ///
    /// # Arguments
    ///
    /// * `kvm` - The opened /dev/kvm object.
    /// * `mem` - The memory to be used by the guest.
    fn create_vm(kvm: &Kvm, mem: GuestMemory) -> Result<Vm>;

    /// This creates a GuestMemory object for this VM
    ///
    /// * `mem_size` - Desired physical memory size in bytes for this VM
    fn setup_memory(mem_size: u64) -> Result<GuestMemory>;

    /// The creates the interrupt controller device and optionally returns the fd for it.
    /// Some architectures may not have a separate descriptor for the interrupt
    /// controller, so they would return None even on success.
    ///
    /// # Arguments
    ///
    /// * `vm` - the vm object
    fn create_irq_chip(vm: &kvm::Vm) -> Result<Option<File>>;

    /// This returns the first page frame number for use by the balloon driver.
    ///
    /// # Arguments
    ///
    /// * `mem_size` - the size in bytes of physical ram for the guest
    fn get_base_dev_pfn(mem_size: u64) -> u64;

    /// This returns a minimal kernel command for this architecture.
    fn get_base_linux_cmdline() -> kernel_cmdline::Cmdline;

    /// This creates and returns a device_manager object for this vm.
    ///
    /// # Arguments
    ///
    /// * `vm` - the vm object
    /// * `mem` - A copy of the GuestMemory object for this VM.
    fn get_device_manager(vm: &mut Vm, mem: GuestMemory)
                          -> Result<device_manager::DeviceManager>;

    /// Sets up the IO bus for this platform
    ///
    /// # Arguments
    ///
    /// * - `vm` the vm object
    /// * - `exit_evt` - the event fd object which should receive exit events
    fn setup_io_bus(vm: &mut Vm, exit_evt: EventFd)
                    -> Result<(devices::Bus, Arc<Mutex<devices::Serial>>)>;

    /// Configures the vcpu and should be called once per vcpu from the vcpu's thread.
    ///
    /// # Arguments
    ///
    /// * `guest_mem` - The memory to be used by the guest.
    /// * `kernel_load_offset` - Offset in bytes from `guest_mem` at which the
    ///                          kernel starts.
    /// * `kvm` - The /dev/kvm object that created vcpu.
    /// * `vcpu` - The VCPU object to configure.
    /// * `cpu_id` - The id of the given `vcpu`.
    /// * `num_cpus` - Number of virtual CPUs the guest will have.
    fn configure_vcpu(guest_mem: &GuestMemory,
                      kvm: &Kvm,
                      vcpu: &Vcpu,
                      cpu_id: u64,
                      num_cpus: u64)
                      -> Result<()>;

    /// Copy a vcpu state into a new vcpu.
    fn copy_vcpu(kvm: &Kvm,
                 vm: &Vm,
                 regs: &VcpuStateRegs,
                 cpu_id: u64,
                 num_cpus: u64)
                 -> Result<(Vcpu)>;

    /// Configures a vcpu interrupt controller.
    fn configure_vcpu_pic(vcpu: &Vcpu) -> Result<()>;
}
