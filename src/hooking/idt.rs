//! This module is responsible for hooking the IDT (Interrupt Descriptor Table) to redirect the
//! interrupt to a custom handler.
//!
//! The IDT is a table that is used to determine the correct response to interrupts and exceptions.
//! The IDT is an array of 256 entries, each of which is an 8-byte structure. Each entry in the IDT
//! is called a gate. The IDT is loaded into the processor using the `lidt` instruction.

#![allow(dead_code)]

use kernel::prelude::*;

#[repr(C, packed)]
struct Idtr {
    limit: u16,
    base: u64,
}

#[derive(Debug)]
#[repr(C, packed)]
struct Idtd {
    offset_lo: u16,
    segment: u16,
    ist: u16,
    zero0: u8,
    type_: u8,
    dpl: u8,
    p: u8,
    offset_md: u16,
    offset_hi: u32,
    zero1: u32,
}

impl Idtd {
    pub(crate) fn update_address(&mut self, new_full_address: u64) {
        self.offset_lo = (new_full_address & 0xFFFF) as u16;
        self.offset_md = ((new_full_address >> 16) & 0xFFFF) as u16;
        self.offset_hi = ((new_full_address >> 32) & 0xFFFFFFFF) as u32;
    }

    pub(crate) fn log_address(&self) -> u64 {
        pr_info!(
            "addr interrupt :: {:#x}",
            ((self.offset_hi as u64) << 32)
                | ((self.offset_md as u64) << 16)
                | (self.offset_lo as u64)
        );
        return ((self.offset_hi as u64) << 32)
            | ((self.offset_md as u64) << 16)
            | (self.offset_lo as u64);
    }

    pub(crate) fn new(value: u128) -> Self {
        Self {
            offset_lo: (value & 0xFFFF) as u16,
            segment: ((value >> 16) & 0xFFFF) as u16,
            ist: ((value >> 32) & 0x7) as u16,   // 3 bits
            zero0: ((value >> 35) & 0x1F) as u8, // 5 bits
            type_: ((value >> 40) & 0x1F) as u8, // 5 bits
            dpl: ((value >> 45) & 0x3) as u8,    // 2 bits
            p: ((value >> 47) & 0x1) as u8,      // 1 bit
            offset_md: ((value >> 48) & 0xFFFF) as u16,
            offset_hi: ((value >> 64) & 0xFFFFFFFF) as u32,
            zero1: ((value >> 96) & 0xFFFFFFFF) as u32,
        }
    }

    pub(crate) fn into_u128(&self) -> u128 {
        (self.offset_lo as u128)
            | ((self.segment as u128) << 16)
            | ((self.ist as u128 & 0x7) << 32)
            | ((self.zero0 as u128 & 0x1F) << 35)
            | ((self.type_ as u128 & 0x1F) << 40)
            | ((self.dpl as u128 & 0x3) << 45)
            | ((self.p as u128 & 0x1) << 47)
            | ((self.offset_md as u128) << 48)
            | ((self.offset_hi as u128) << 64)
            | ((self.zero1 as u128) << 96)
    }
}

pub(crate) fn hook_idt(new_handler: u128, interrupt_adr: usize) {
    unsafe {
        let origin_gate_addr = interrupt_adr;
        let origin_gate: u128 = *(origin_gate_addr as *const u128);

        pr_info!("origin_gate :: {:#x}", origin_gate as u128);

        let mut old_itd = Idtd::new(origin_gate);

        old_itd.log_address();
        old_itd.update_address(new_handler as u64);
        old_itd.log_address();

        *(origin_gate_addr as *mut u128) = old_itd.into_u128();

        let updated_gate: u128 = *(origin_gate_addr as *const u128);

        pr_info!("updated_gate :: {:#x}", updated_gate as u128);
    }
}
