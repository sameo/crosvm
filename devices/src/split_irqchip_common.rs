// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Common constants and types used for Split IRQ chip devices (e.g. PIC, PIT, IOAPIC).

use bit_field::*;
use sys_util::EventFd;

#[bitfield]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DestinationMode {
    Physical = 0,
    Logical = 1,
}

#[bitfield]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TriggerMode {
    Edge = 0,
    Level = 1,
}

#[bitfield]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DeliveryMode {
    Fixed = 0b000,
    Lowest = 0b001,
    SMI = 0b010,        // System management interrupt
    RemoteRead = 0b011, // This is no longer supported by intel.
    NMI = 0b100,        // Non maskable interrupt
    Init = 0b101,
    Startup = 0b110,
    External = 0b111,
}

#[bitfield]
#[derive(Clone, Copy, PartialEq)]
pub struct MsiAddressMessage {
    reserved: BitField2,
    #[bits = 1]
    destination_mode: DestinationMode,
    redirection_hint: BitField1,
    reserved_2: BitField8,
    destination_id: BitField8,
    // According to Intel's implementation of MSI, these bits must always be 0xfee.
    always_0xfee: BitField12,
}

#[bitfield]
#[derive(Clone, Copy, PartialEq)]
pub struct MsiDataMessage {
    vector: BitField8,
    #[bits = 3]
    delivery_mode: DeliveryMode,
    reserved: BitField3,
    level: BitField1,
    #[bits = 1]
    trigger: TriggerMode,
    reserved2: BitField16,
}

/// Acts as a relay of interrupt signals between devices and IRQ chips.
#[derive(Default)]
pub struct GsiRelay {
    pub irqfd: [Option<EventFd>; kvm::NUM_IOAPIC_PINS],
    pub irqfd_resample: [Option<EventFd>; kvm::NUM_IOAPIC_PINS],
}

impl GsiRelay {
    pub fn new() -> GsiRelay {
        GsiRelay {
            irqfd: Default::default(),
            irqfd_resample: Default::default(),
        }
    }

    pub fn register_irqfd(&mut self, evt: EventFd, gsi: usize) {
        if gsi >= kvm::NUM_IOAPIC_PINS {
            // Invalid gsi; ignore.
            return;
        }
        self.irqfd[gsi] = Some(evt);
    }

    pub fn register_irqfd_resample(&mut self, evt: EventFd, resample_evt: EventFd, gsi: usize) {
        if gsi >= kvm::NUM_IOAPIC_PINS {
            // Invalid gsi; ignore.
            return;
        }
        self.irqfd[gsi] = Some(evt);
        self.irqfd_resample[gsi] = Some(resample_evt);
    }
}
