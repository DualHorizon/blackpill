//! # Syscall hooking through LSTAR MSR

// use core::arch::asm;
use core::ffi::c_void;

use kernel::c_str;
use kernel::fmt;
use kernel::str::CString;
use kernel::{bindings, prelude::*, str::CStr};

#[repr(C)]
pub(crate) struct HListNode {
    next: *mut HListNode,
    pprev: *mut *mut HListNode,
}

#[repr(C)]
pub(crate) struct ListHead {
    next: *mut ListHead,
    prev: *mut ListHead,
}

#[repr(C)]
pub(crate) struct ArchSpecificInsn {
    dummy: i32,
}
pub(crate) type KProbeOpcode = i32;

#[repr(C)]
pub(crate) struct KProbe {
    hlist: HListNode,
    list: ListHead,
    nmissed: u64,
    addr: *mut KProbeOpcode,
    symbol_name: *const i8,
    offset: u32,
    pre_handler: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    post_handler: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    opcode: KProbeOpcode,
    ainsn: ArchSpecificInsn,
    flags: u32,
}

extern "C" {
    pub(crate) fn register_kprobe(kprobe: *const KProbe) -> core::ffi::c_int;
    // pub(crate) fn unregister_kprobe(kprobe:*const KProbe);
}

/// Hook a symbol with a handler.
/// Arguments:
/// - `symbol`: The symbol to hook.
/// - `handler`: The handler to call when the symbol is called.
/// Returns:
/// - `Ok(())` if the hook was successful.
/// - `Err(-1)` if the kmalloc failed.
/// - `Err(n)` if the register_kprobe failed.
pub(crate) fn hook(
    symbol: &CStr,
    handler: unsafe extern "C" fn(*mut c_void) -> i32,
) -> Result<(), i32> {
    unsafe {
        let kp = bindings::__kmalloc_noprof(core::mem::size_of::<KProbe>(), bindings::GFP_KERNEL)
            as *mut KProbe;

        if kp.is_null() {
            return Err(-1);
        }

        // Convert the syscall name to its symbol counterpart
        let symbol_name = CString::try_from_fmt(fmt!("__x64_sys_{}", symbol)).unwrap();

        (*kp).symbol_name = symbol_name.as_char_ptr();
        (*kp).post_handler = Some(handler);

        let res: i32 = register_kprobe(kp).into();

        if res != 0 {
            return Err(res);
        } else {
            pr_info!("Hooked\n");
        }
    }

    Ok(())
}

/// Hook syscalls with their respective handlers.
pub(crate) fn hook_syscalls() {
    pr_info!("Hooking syscalls...\n");
    let read_hook = hook(c_str!("read"), read_handler);

    if let Err(e) = read_hook {
        pr_err!("Failed to hook syscall: {}\n", e);
    }
}

pub(crate) unsafe extern "C" fn read_handler(_ptr: *mut c_void) -> i32 {
    pr_info!("Got hooked bro\n");
    1
}
