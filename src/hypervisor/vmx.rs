use super::constants::*;
use core::arch::asm;
use kernel::prelude::*;

pub(crate) fn vmx_support() -> bool {
    let mut ecx: u32;
    unsafe {
        asm!(
            "mov eax, 1",
            "cpuid",
            "mov {0:e}, ecx",
            out(reg) ecx,
            options(nostack)
        );
    }
    (ecx >> 5) & 1 == 1
}

pub(crate) unsafe fn read_cr0() -> u64 {
    let cr0: u64;
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0);
    }
    cr0
}

pub(crate) unsafe fn read_cr3() -> u64 {
    let cr3: u64;
    unsafe {
        asm!(
            "mov {}, cr3",
            out(reg) cr3,
            options(nomem, nostack)
        );
    }
    cr3
}

pub(crate) unsafe fn read_cr4() -> u64 {
    let cr4: u64;
    unsafe {
        asm!(
            "mov {}, cr4",
            out(reg) cr4,
            options(nomem, nostack)
        );
    }
    cr4
}

pub(crate) unsafe fn write_cr4(val: u64) {
    unsafe {
        asm!(
            "mov cr4, {}",
            in(reg) val,
            options(nomem, nostack)
        );
    }
}

pub(crate) fn get_vmx_revision_id() -> u32 {
    let mut eax: u32;
    let mut edx: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") MSR_IA32_VMX_BASIC,
            out("eax") eax,
            out("edx") edx
        );
    }
    eax & 0x7FFFFFFF
}

pub(crate) fn vmxon(addr: u64) -> Result<()> {
    let mut success: u8;
    unsafe {
        asm!(
            "vmxon [{}]",
            "setna {}",
            in(reg) &addr,
            out(reg_byte) success,
            options(nostack)
        );
    }
    if success != 0 {
        Err(kernel::error::code::EINVAL)
    } else {
        Ok(())
    }
}

pub(crate) fn vmclear(addr: u64) -> Result<()> {
    let mut success: u8;
    unsafe {
        asm!(
            "vmclear [{}]",
            "setna {}",
            in(reg) &addr,
            out(reg_byte) success,
            options(nostack)
        );
    }
    if success != 0 {
        Err(kernel::error::code::EINVAL)
    } else {
        Ok(())
    }
}

pub(crate) fn vmptrld(addr: u64) -> Result<()> {
    let mut success: u8;
    unsafe {
        asm!(
            "vmptrld [{}]",
            "setna {}",
            in(reg) &addr,
            out(reg_byte) success,
            options(nostack)
        );
    }
    if success != 0 {
        Err(kernel::error::code::EINVAL)
    } else {
        Ok(())
    }
}

pub(crate) fn rdmsr(msr: u32) -> u64 {
    let mut low: u32;
    let mut high: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high
        );
    }
    ((high as u64) << 32) | (low as u64)
}

pub(crate) fn wrmsr(msr: u32, val: u64) {
    let low = val as u32;
    let high = (val >> 32) as u32;
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high
        );
    }
}
