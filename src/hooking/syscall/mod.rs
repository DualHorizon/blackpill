//! Syscall hooking through kprobes. This module is responsible for hooking syscalls with their
//! respective handlers. A kprobe is a debugging facility that allows you to trap into a handler
//! function when a specified instruction is executed. This is used to hook syscalls and symbols.
//!
//! The `hook` function is used to hook a symbol with a handler. The `hook_syscalls` function is used
//! to hook syscalls with their respective handlers.
//!
//! All handlers should be in their respective private submodules. For example, the `sys_kill` syscall handler should
//! be in the `sys_kill` module. This is to keep the code organized and maintainable.
//! Create a copy of the `_template.rs` file and add your syscall handler there.

mod sys_filldir64;
mod sys_mkdir;

use kernel::bindings::pt_regs;
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
    pub pre_handler: Option<unsafe extern "C" fn(*mut KProbe, *mut pt_regs) -> i32>,
    pub post_handler:
        Option<unsafe extern "C" fn(p: *mut KProbe, regs: *mut pt_regs, flags: u64) -> i32>,
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
    pre_handler: unsafe extern "C" fn(*mut KProbe, *mut pt_regs) -> i32,
    post_handler: unsafe extern "C" fn(p: *mut KProbe, regs: *mut pt_regs, flags: u64) -> i32,
) -> Result<(), i32> {
    unsafe {
        let kp = bindings::__kmalloc_noprof(core::mem::size_of::<KProbe>(), bindings::GFP_KERNEL)
            as *mut KProbe;

        if kp.is_null() {
            return Err(-1);
        }

        (*kp).symbol_name = symbol;
        (*kp).pre_handler = Some(pre_handler);
        (*kp).post_handler = Some(post_handler);

        let res: i32 = register_kprobe(kp).into();

        if res != 0 {
            return Err(res);
        } else {
            pr_info!("Hooked\n");
        }
    }

    Ok(())
}

#[allow(dead_code)]
pub(crate) fn print_all_regs(regs: *mut pt_regs) {
    unsafe {
        // print all pt_regs registers in hexademical format
        // from r15 to ip
        pr_info!(
            "r15=0x{:X}, r14=0x{:X}, r13=0x{:X}, r12=0x{:X},
            r11=0x{:X}, r10=0x{:X}, r9=0x{:X}, r8=0x{:X},
            rdi=0x{:X}, rsi=0x{:X}, rdx=0x{:X}, rcx=0x{:X},
            rax=0x{:X}, orig_rax=0x{:X}, rip=0x{:X}, cs=0x{:X},
            eflags=0x{:X}, rsp=0x{:X}\n",
            (*regs).r15,
            (*regs).r14,
            (*regs).r13,
            (*regs).r12,
            (*regs).r11,
            (*regs).r10,
            (*regs).r9,
            (*regs).r8,
            (*regs).di,
            (*regs).si,
            (*regs).dx,
            (*regs).cx,
            (*regs).ax,
            (*regs).orig_ax,
            (*regs).ip,
            (*regs).__bindgen_anon_1.cs,
            (*regs).flags,
            (*regs).sp,
        );
    }
}

/// Hook syscalls with their respective handlers.
pub(crate) fn hook_syscalls() {
    pr_info!("Hooking syscalls...\n");

    sys_mkdir::sys_hook();
    sys_filldir64::sys_hook();
}
