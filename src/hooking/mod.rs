//! Syscall hooking through kprobes. This module is responsible for hooking syscalls with their
//! respective handlers. A kprobe is a debugging facility that allows you to trap into a handler
//! function when a specified instruction is executed. This is used to hook syscalls and symbols.
//!
//! The `hook` function is used to hook a symbol with a handler. The `hook_syscalls` function is used
//! to hook syscalls with their respective handlers.

pub(crate) mod idt;

use core::ffi::c_void;
use kernel::c_str;
use kernel::{bindings, prelude::*};

extern "C" {
    pub(crate) fn register_kprobe(kprobe: *const KProbe) -> core::ffi::c_int;
    #[allow(dead_code)] // Needed because black kernel magic
    pub(crate) fn unregister_kprobe(kprobe: *const KProbe);
}

#[repr(C)]
pub(crate) struct HListNode {
    pub next: *mut HListNode,
    pub pprev: *mut *mut HListNode,
}

#[repr(C)]
pub(crate) struct ListHead {
    pub next: *mut ListHead,
    pub prev: *mut ListHead,
}

#[repr(C)]
pub(crate) struct ArchSpecificInsn {
    pub dummy: i32,
}

pub(crate) type KProbeOpcode = i32;
#[repr(C)]
pub(crate) struct KProbe {
    pub hlist: HListNode,
    pub list: ListHead,
    pub nmissed: u64,
    pub addr: *mut KProbeOpcode,
    pub symbol_name: *const i8,
    pub offset: u32,
    pub pre_handler: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    pub post_handler: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    pub opcode: KProbeOpcode,
    pub ainsn: ArchSpecificInsn,
    pub flags: u32,
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
    symbol: *const i8,
    handler: unsafe extern "C" fn(*mut c_void) -> i32,
) -> Result<(), i32> {
    unsafe {
        let kp = bindings::__kmalloc_noprof(core::mem::size_of::<KProbe>(), bindings::GFP_KERNEL)
            as *mut KProbe;

        if kp.is_null() {
            return Err(-1);
        }

        (*kp).symbol_name = symbol;
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
    let _read_hook = hook(c_str!("__x64_sys_read").as_char_ptr(), read_handler);
}

pub(crate) unsafe extern "C" fn read_handler(_ptr: *mut c_void) -> i32 {
    pr_info!("Got hooked bro");
    1
}
