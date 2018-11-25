// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use pci::ac97_regs::*;

// AC97 Vendor ID
const AC97_VENDOR_ID1: u16 = 0x8086;
const AC97_VENDOR_ID2: u16 = 0x8086;

// Master volume register is specified in 1.5dB steps.
const MASTER_VOLUME_STEP_DB: f64 = 1.5;

/// `Ac97Mixer` holds the mixer state for the AC97 bus.
/// The mixer is used by calling the `readb`/`readw`/`readl` functions to read register values and
/// the `writeb`/`writew`/`writel` functions to set register values.
pub struct Ac97Mixer {
    // Mixer Registers
    master_volume_l: u8,
    master_volume_r: u8,
    master_mute: bool,
    mic_muted: bool,
    mic_20db: bool,
    mic_volume: u8,
    record_gain_l: u8,
    record_gain_r: u8,
    record_gain_mute: bool,
    pcm_out_vol_l: u16,
    pcm_out_vol_r: u16,
    pcm_out_mute: bool,
    power_down_control: u16,
}

impl Ac97Mixer {
    /// Creates an 'Ac97Mixer' with the standard default register values.
    pub fn new() -> Self {
        Ac97Mixer {
            master_volume_l: 0,
            master_volume_r: 0,
            master_mute: true,
            mic_muted: true,
            mic_20db: false,
            mic_volume: 0x8,
            record_gain_l: 0,
            record_gain_r: 0,
            record_gain_mute: true,
            pcm_out_vol_l: 0x8,
            pcm_out_vol_r: 0x8,
            pcm_out_mute: true,
            power_down_control: PD_REG_STATUS_MASK, // Report everything is ready.
        }
    }

    /// Reads a word from the register at `offset`.
    pub fn readw(&self, offset: u64) -> u16 {
        match offset {
            0x02 => self.get_master_reg(),
            0x0e => self.get_mic_volume(),
            0x1c => self.get_record_gain_reg(),
            0x18 => self.get_pcm_out_volume(),
            0x26 => self.power_down_control,
            0x7c => AC97_VENDOR_ID1,
            0x7e => AC97_VENDOR_ID2,
            _ => 0,
        }
    }

    /// Writes a word `val` to the register `offset`.
    pub fn writew(&mut self, offset: u64, val: u16) {
        match offset {
            0x02 => self.set_master_reg(val),
            0x0e => self.set_mic_volume(val),
            0x1c => self.set_record_gain_reg(val),
            0x18 => self.set_pcm_out_volume(val),
            0x26 => self.set_power_down_reg(val),
            _ => (),
        }
    }

    // Returns the master mute and l/r volumes (reg 0x02).
    fn get_master_reg(&self) -> u16 {
        let reg = (self.master_volume_l as u16) << 8 | self.master_volume_r as u16;
        if self.master_mute {
            reg | MUTE_REG_BIT
        } else {
            reg
        }
    }

    /// Returns the mute status and left and right attenuation from the master volume register.
    pub fn get_master_volume(&self) -> (bool, f64, f64) {
        (self.master_mute,
         f64::from(self.master_volume_l) * MASTER_VOLUME_STEP_DB,
         f64::from(self.master_volume_r) * MASTER_VOLUME_STEP_DB)
    }

    // Handles writes to the master register (0x02).
    fn set_master_reg(&mut self, val: u16) {
        self.master_mute = val & MUTE_REG_BIT != 0;
        self.master_volume_r = (val & VOL_REG_MASK) as u8;
        self.master_volume_l = (val >> 8 & VOL_REG_MASK) as u8;
    }

    // Returns the value read in the Mic volume register.
    fn get_mic_volume(&self) -> u16 {
        let mut reg = self.mic_volume as u16;
        if self.mic_muted {
            reg |= MUTE_REG_BIT;
        }
        if self.mic_20db {
            reg |= MIXER_MIC_20DB;
        }
        reg
    }

    // Sets the mic input mute, boost, and volume settings.
    fn set_mic_volume(&mut self, val: u16) {
        self.mic_volume = (val & MIXER_VOL_MASK) as u8;
        self.mic_muted = val & MUTE_REG_BIT != 0;
        self.mic_20db = val & MIXER_MIC_20DB != 0;
    }

    // Returns the value read in the Mic volume register.
    fn get_pcm_out_volume(&self) -> u16 {
        let reg = (self.pcm_out_vol_l as u16) << 8 | self.pcm_out_vol_r as u16;
        if self.pcm_out_mute {
            reg | MUTE_REG_BIT
        } else {
            reg
        }
    }

    // Sets the pcm output mute and volume states.
    fn set_pcm_out_volume(&mut self, val: u16) {
        self.pcm_out_vol_r = val & MIXER_VOL_MASK;
        self.pcm_out_vol_l = (val >> MIXER_VOL_LEFT_SHIFT) & MIXER_VOL_MASK;
        self.pcm_out_mute = val & MUTE_REG_BIT != 0;
    }

    // Returns the record gain register (0x01c).
    fn get_record_gain_reg(&self) -> u16 {
        let reg = (self.record_gain_l as u16) << 8 | self.record_gain_r as u16;
        if self.record_gain_mute {
            reg | MUTE_REG_BIT
        } else {
            reg
        }
    }

    // Handles writes to the record_gain register (0x1c).
    fn set_record_gain_reg(&mut self, val: u16) {
        self.record_gain_mute = val & MUTE_REG_BIT != 0;
        self.record_gain_r = (val & VOL_REG_MASK) as u8;
        self.record_gain_l = (val >> 8 & VOL_REG_MASK) as u8;
    }

    // Handles writes to the powerdown ctrl/status register (0x26).
    fn set_power_down_reg(&mut self, val: u16) {
        self.power_down_control =
            (val & !PD_REG_STATUS_MASK) | (self.power_down_control & PD_REG_STATUS_MASK);
    }
}
