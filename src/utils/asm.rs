#[allow(dead_code)]
#[allow(unused_unsafe)]
#[allow(unused_imports)]


use core::arch::asm;
#[allow(dead_code)]
pub(crate) fn rdmsr(msr: u32) -> u64 {
    let low: u32; 
    let high: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,       
            out("eax") low,      
            out("edx") high,     
            options(nostack, nomem) 
        );
    }
    ((high as u64) << 32) | (low as u64) 
}


#[allow(dead_code)]
pub(crate) fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;         
    let high = (value >> 32) as u32;
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,       
            in("eax") low,       
            in("edx") high,      
            options(nostack, nomem) 
        );
    }
}

