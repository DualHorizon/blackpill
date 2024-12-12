//! # Syscall hooking through LSTAR MSR

// use crate::utils::x86::{rdmsr, MSR_LSTAR};
use kernel::pr_info;

// pub(crate) fn get_syscall_table() -> Option<*mut *mut u64> {
//     let system_call: u64 = rdmsr(MSR_LSTAR);

//     pr_info!("System call address: {:#X}", system_call);

//     let ptr = system_call as *const u8;

//     unsafe {
//         // loop until first 3 bytes of instructions are found
//         for offset in 0..500 {
//             let current = ptr.add(offset);
//             pr_info!("Offset: {}", offset);
//             pr_info!("Current: {:#X}", current as u64);

//             // Check for the instruction pattern: 0xFF 0x14 0xC5
//             if *current == 0xFF && *current.add(1) == 0x14 && *current.add(2) == 0xC5 {
//                 pr_info!("Found syscall table");
//                 // Compute the address of the syscall table.
//                 let table_address = 0xFFFFFFFF00000000 | (*(current.add(3) as *const u32) as u64);
//                 return Some(table_address as *mut *mut u64);
//             }
//         }
//     }

//     None
// }

use crate::utils::x86::MSR_LSTAR;
use core::arch::asm;

#[allow(unused_assignments)]
#[allow(unused_mut)]
pub(crate) fn get_syscall_table() -> Option<*mut *mut u64> {
    let mut lo: u32 = 0;
    let mut hi: u32 = 0;
    let mut system_call: u64;

    unsafe {
        // Read the MSR_LSTAR register to get the system call entry point.
        asm!(
            "rdmsr",
            out("eax") lo,
            out("edx") hi,
            in("ecx") MSR_LSTAR,
        );

        system_call = ((hi as u64) << 32) | (lo as u64);
    }

    pr_info!("System call address: {:#X}", system_call);

    let ptr = system_call as *const u8;
    let mut found: Option<*mut *mut u64> = None;

    unsafe {
        for offset in 0..500 {
            let current = ptr.add(offset);

            pr_info!("Offset: {}", offset);
            pr_info!("Current: {:#X}", current as u64);

            // Check for the instruction pattern: 0xff 0x14 0xc5
            if *current == 0xff && *current.add(1) == 0x14 && *current.add(2) == 0xc5 {
                pr_info!("Found syscall table");
                // Compute the address of the syscall table.
                let table_address = 0xffffffff00000000 | (*(current.add(3) as *const u32) as u64);
                found = Some(table_address as *mut *mut u64);
                break;
            }
        }
    }

    found
}
