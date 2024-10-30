use core::arch::asm;

pub(crate) fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let mut data = [0u32; 4];
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "mov [{0}], ebx",
            "mov [{0} + 4], edx",
            "mov [{0} + 8], ecx",
            "mov [{0} + 12], eax",
            "pop rbx",
            in(reg) &mut data,
            inout("eax") leaf => _,
            inout("ecx") subleaf => _,
            out("edx") _,
            options(nostack),
        );
    }

    (data[3], data[0], data[2], data[1])
}

pub(crate) fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;

    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
        );
    }

    ((high as u64) << 32) | (low as u64)
}

pub(crate) fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;

    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
        );
    }
}

pub(crate) mod irq {
    pub(crate) const DIVIDE_ERROR_VECTOR: u8 = 0;
    pub(crate) const DEBUG_VECTOR: u8 = 1;
    pub(crate) const NONMASKABLE_INTERRUPT_VECTOR: u8 = 2;
    pub(crate) const BREAKPOINT_VECTOR: u8 = 3;
    pub(crate) const OVERFLOW_VECTOR: u8 = 4;
    pub(crate) const BOUND_RANGE_EXCEEDED_VECTOR: u8 = 5;
    pub(crate) const INVALID_OPCODE_VECTOR: u8 = 6;
    pub(crate) const DEVICE_NOT_AVAILABLE_VECTOR: u8 = 7;
    pub(crate) const DOUBLE_FAULT_VECTOR: u8 = 8;
    pub(crate) const COPROCESSOR_SEGMENT_OVERRUN_VECTOR: u8 = 9;
    pub(crate) const INVALID_TSS_VECTOR: u8 = 10;
    pub(crate) const SEGMENT_NOT_PRESENT_VECTOR: u8 = 11;
    pub(crate) const STACK_SEGEMENT_FAULT_VECTOR: u8 = 12;
    pub(crate) const GENERAL_PROTECTION_FAULT_VECTOR: u8 = 13;
    pub(crate) const PAGE_FAULT_VECTOR: u8 = 14;
    pub(crate) const X87_FPU_VECTOR: u8 = 16;
    pub(crate) const ALIGNMENT_CHECK_VECTOR: u8 = 17;
    pub(crate) const MACHINE_CHECK_VECTOR: u8 = 18;
    pub(crate) const SIMD_FLOATING_POINT_VECTOR: u8 = 19;
    pub(crate) const VIRTUALIZATION_VECTOR: u8 = 20;
}

pub(crate) mod current {
    pub(crate) mod paging {
        pub(crate) const BASE_PAGE_SHIFT: usize = 12;

        #[cfg(target_arch = "x86")]
        pub(crate) const PAGE_SIZE_ENTRIES: usize = 1024;

        #[cfg(target_arch = "x86_64")]
        pub(crate) const PAGE_SIZE_ENTRIES: usize = 512;
    }
}

pub(crate) mod msr {
    pub(crate) const IA32_EFER: u32 = 0xc0000080;
}

#[repr(u8)]
pub(crate) enum Ring {
    Ring0,
    Ring1,
    Ring2,
    Ring3,
}

pub(crate) mod segmentation {
    use crate::utils::x86::Ring;
    use core::fmt;

    bitfield! {
        pub(crate) struct SegmentSelector(u16);
        impl Debug;
        u16;
        /// Index field (bits 3-15)
        index, set_index: 15, 3;
        /// Table Indicator (TI) (bit 2)
        ti, set_ti: 2;
        /// Requestor Privilege Level (bits 0-1)
        rpl, set_rpl: 1, 0;
    }

    impl SegmentSelector {
        pub(crate) const fn new(index: u16, rpl: Ring) -> Self {
            let mut selector = Self(index << 3);
            selector.0 |= rpl as u16;
            selector
        }

        pub(crate) const fn from_raw(bits: u16) -> Self {
            Self(bits)
        }

        pub(crate) fn is_ldt(&self) -> bool {
            self.ti()
        }

        pub(crate) fn ring_level(&self) -> Ring {
            match self.rpl() {
                0 => Ring::Ring0,
                1 => Ring::Ring1,
                2 => Ring::Ring2,
                3 => Ring::Ring3,
                _ => unreachable!(),
            }
        }
    }

    impl fmt::Display for SegmentSelector {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let ring = match self.ring_level() {
                Ring::Ring0 => "Ring 0",
                Ring::Ring1 => "Ring 1",
                Ring::Ring2 => "Ring 2",
                Ring::Ring3 => "Ring 3",
            };

            let tbl = if self.is_ldt() { "LDT" } else { "GDT" };

            write!(
                f,
                "Index {} in {} Table, {} segment selector",
                self.index(),
                tbl,
                ring
            )
        }
    }
}
