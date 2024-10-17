use core::arch::asm;

pub fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
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

pub fn rdmsr(msr: u32) -> u64 {
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

pub fn wrmsr(msr: u32, value: u64) {
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
//based on https://github.com/tandasat/Hypervisor-101-in-Rust/blob/00cdd3dcc6c46a96aff22e732bee5dc15cf681ed/hypervisor/src/hardware_vt/svm_run_vm.S#L47
//

pub mod irq {
    pub const DIVIDE_ERROR_VECTOR: u8 = 0;
    pub const DEBUG_VECTOR: u8 = 1;
    pub const NONMASKABLE_INTERRUPT_VECTOR: u8 = 2;
    pub const BREAKPOINT_VECTOR: u8 = 3;
    pub const OVERFLOW_VECTOR: u8 = 4;
    pub const BOUND_RANGE_EXCEEDED_VECTOR: u8 = 5;
    pub const INVALID_OPCODE_VECTOR: u8 = 6;
    pub const DEVICE_NOT_AVAILABLE_VECTOR: u8 = 7;
    pub const DOUBLE_FAULT_VECTOR: u8 = 8;
    pub const COPROCESSOR_SEGMENT_OVERRUN_VECTOR: u8 = 9;
    pub const INVALID_TSS_VECTOR: u8 = 10;
    pub const SEGMENT_NOT_PRESENT_VECTOR: u8 = 11;
    pub const STACK_SEGEMENT_FAULT_VECTOR: u8 = 12;
    pub const GENERAL_PROTECTION_FAULT_VECTOR: u8 = 13;
    pub const PAGE_FAULT_VECTOR: u8 = 14;
    pub const X87_FPU_VECTOR: u8 = 16;
    pub const ALIGNMENT_CHECK_VECTOR: u8 = 17;
    pub const MACHINE_CHECK_VECTOR: u8 = 18;
    pub const SIMD_FLOATING_POINT_VECTOR: u8 = 19;
    pub const VIRTUALIZATION_VECTOR: u8 = 20;
}

pub mod current {

    pub mod paging {
        pub const BASE_PAGE_SHIFT: usize = 12;

        #[cfg(target_arch = "x86")]
        pub const PAGE_SIZE_ENTRIES: usize = 1024;

        #[cfg(target_arch = "x86_64")]
        pub const PAGE_SIZE_ENTRIES: usize = 512;
    }
}
