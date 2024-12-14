use kernel::bindings::pt_regs;
use kernel::c_str;
use kernel::prelude::*;
use kernel::str::CStr;

use super::{hook, KProbe};

pub(crate) fn sys_hook() {
    let symbol = c_str!("__x64_sys_execve");

    hook(symbol.as_char_ptr(), pre_handler, post_handler).expect("Failed to hook sys_SYSCALL");
}

pub(crate) unsafe extern "C" fn pre_handler(_p: *mut KProbe, _regs: *mut pt_regs) -> i32 {
    pr_info!("execve pre_handler\n");

    unsafe {
        let p_filename = (*_regs).di;
        let _p_argv = (*_regs).si;
        let _p_envp = (*_regs).dx;

        let filename = CStr::from_char_ptr(p_filename as *const i8);
        pr_info!("filename: {}\n", filename);
    }

    0
}

pub(crate) unsafe extern "C" fn post_handler(
    _p: *mut KProbe,
    _regs: *mut pt_regs,
    _flags: u64,
) -> i32 {
    pr_info!("execve post_handler\n");
    unsafe {
        let reg = { (*_regs).di };
        if reg == 0 {
            pr_info!("execve pre_handler: NULL\n");
        } else {
            pr_info!("di: 0x{:X}\n", (*_regs).di);
        }
    }
    0
}
