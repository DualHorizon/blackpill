use kernel::bindings::pt_regs;
use kernel::c_str;
use kernel::prelude::*;

use super::{hook, KProbe};

pub(crate) fn sys_hook() {
    let symbol = c_str!("__x64_sys_kill");

    hook(symbol.as_char_ptr(), pre_handler, post_handler).expect("Failed to hook sys_kill");
}

pub(crate) unsafe extern "C" fn pre_handler(_p: *mut KProbe, _regs: *mut pt_regs) -> i32 {
    pr_info!("sys_kill hooked\n");
    unsafe {
        // print all pt_regs registers in hexademical format
        // from r15 to ip
        pr_info!(
            "pre_handler:
            r15=0x{:X}, r14=0x{:X}, r13=0x{:X}, r12=0x{:X},
            r11=0x{:X}, r10=0x{:X}, r9=0x{:X}, r8=0x{:X},
            rdi=0x{:X}, rsi=0x{:X}, rdx=0x{:X}, rcx=0x{:X},
            rax=0x{:X}, orig_rax=0x{:X}, rip=0x{:X}, cs=0x{:X},
            eflags=0x{:X}, rsp=0x{:X}\n",
            (*_regs).r15,
            (*_regs).r14,
            (*_regs).r13,
            (*_regs).r12,
            (*_regs).r11,
            (*_regs).r10,
            (*_regs).r9,
            (*_regs).r8,
            (*_regs).di,
            (*_regs).si,
            (*_regs).dx,
            (*_regs).cx,
            (*_regs).ax,
            (*_regs).orig_ax,
            (*_regs).ip,
            (*_regs).__bindgen_anon_1.cs,
            (*_regs).flags,
            (*_regs).sp,
        );
    }
    1
}

pub(crate) unsafe extern "C" fn post_handler(
    _p: *mut KProbe,
    _regs: *mut pt_regs,
    _flags: u64,
) -> i32 {
    unsafe {
        // print all pt_regs registers in hexademical format
        // from r15 to ip
        pr_info!(
            "post_handler:
            r15=0x{:X}, r14=0x{:X}, r13=0x{:X}, r12=0x{:X},
            r11=0x{:X}, r10=0x{:X}, r9=0x{:X}, r8=0x{:X},
            rdi=0x{:X}, rsi=0x{:X}, rdx=0x{:X}, rcx=0x{:X},
            rax=0x{:X}, orig_rax=0x{:X}, rip=0x{:X}, cs=0x{:X},
            eflags=0x{:X}, rsp=0x{:X}\n",
            (*_regs).r15,
            (*_regs).r14,
            (*_regs).r13,
            (*_regs).r12,
            (*_regs).r11,
            (*_regs).r10,
            (*_regs).r9,
            (*_regs).r8,
            (*_regs).di,
            (*_regs).si,
            (*_regs).dx,
            (*_regs).cx,
            (*_regs).ax,
            (*_regs).orig_ax,
            (*_regs).ip,
            (*_regs).__bindgen_anon_1.cs,
            (*_regs).flags,
            (*_regs).sp,
        );
    }
    1
}
