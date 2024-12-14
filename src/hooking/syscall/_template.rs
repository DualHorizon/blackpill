use kernel::bindings::pt_regs;
use kernel::c_str;

use super::{hook, KProbe};

pub(crate) fn sys_hook() {
    let symbol = c_str!("__x64_sys_SYSCALL");

    hook(symbol.as_char_ptr(), pre_handler, post_handler).expect("Failed to hook sys_SYSCALL");
}

pub(crate) unsafe extern "C" fn pre_handler(_p: *mut KProbe, _regs: *mut pt_regs) -> i32 {
    1
}

pub(crate) unsafe extern "C" fn post_handler(
    _p: *mut KProbe,
    _regs: *mut pt_regs,
    _flags: u64,
) -> i32 {
    1
}
