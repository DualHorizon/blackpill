//! This module contains utility functions that are used throughout the kernel module.
//! This includes getting the address of a function by its name and executing a userland program
//! in userspace as root user.

#![allow(dead_code)] // Needed because black kernel magic

#[macro_use]
pub(crate) mod bitfield;
pub(crate) mod x86;

use core::ffi::c_char;
use kernel::bindings;
use kernel::bindings::{call_usermodehelper, UMH_WAIT_EXEC};
use kernel::c_str;
use kernel::prelude::*;

use crate::hooking::syscall::{register_kprobe, unregister_kprobe, KProbe};

extern "C" {
    /// Look up the address of a function by its name.
    pub(crate) fn kallsyms_lookup_name(name: *const i8);
}

type KallsymsLookupNameFn = extern "C" fn(*const i8) -> *const ();

static mut KALLSYM_FOUND: i64 = 0;
static mut KALLSYM_ADDR: usize = 0;

/// Get the address of a function by its name.
/// Arguments:
/// - `function_name`: The name of the function to get the address of.
/// Returns:
/// - `Some(address)` if the function was found.
/// - `None` if the function was not found.
pub(crate) fn get_function_address(function_name: *const c_char) -> Option<usize> {
    unsafe {
        let mut address: usize = 0;

        if KALLSYM_FOUND == 0 {
            KALLSYM_FOUND = 1;
            let kallsyms_lookup_name_symbol = c_str!("kallsyms_lookup_name");

            match get_function_address(kallsyms_lookup_name_symbol.as_char_ptr()) {
                Some(address) => {
                    KALLSYM_ADDR = address;
                }
                None => {
                    pr_info!("kallsyms_lookup_name not found :(");
                }
            }
        }

        // Allocate memory for the kprobe
        let kp = bindings::__kmalloc_noprof(core::mem::size_of::<KProbe>(), bindings::GFP_KERNEL)
            as *mut KProbe;

        if kp.is_null() {
            return None;
        }

        // Initialize the kprobe
        (*kp).symbol_name = function_name;
        (*kp).addr = core::ptr::null_mut();

        // Register the kprobe
        let ret = register_kprobe(kp);
        if ret == 0 {
            // Get the address of the function
            address = (*kp).addr as usize;
            unregister_kprobe(kp);
        }

        bindings::kfree(kp as *mut core::ffi::c_void);

        if address != 0 {
            return Some(address);
        }

        // If kallsyms_lookup_name is found, use it to get the address of the function
        if KALLSYM_ADDR != 0 {
            let kallsyms_lookup_name_addr: usize = KALLSYM_ADDR;
            let kallsyms_lookup_name: KallsymsLookupNameFn =
                core::mem::transmute(kallsyms_lookup_name_addr);
            let ret = kallsyms_lookup_name(function_name);

            if ret as u64 > 0 {
                return Some(ret as usize);
            }
        }

        None
    }
}

/// Executes a userland program in userspace as root user.
/// Arguments:
/// - `program_path`: The path to the program to execute.
/// - `args`: The arguments to pass to the program.
/// Returns:
/// - The return code of the user-mode helper.
#[allow(dead_code)]
pub(crate) fn exec_as_root(program_path: &CStr, args: &CStr) -> Option<i32> {
    // Prepare argv and envp for the user-mode helper.
    let argv: [*mut c_char; 3] = [
        program_path.as_char_ptr() as *mut c_char,
        args.as_char_ptr() as *mut c_char,
        core::ptr::null_mut(),
    ];
    let envp: [*mut c_char; 5] = [
        c_str!("HOME=/").as_char_ptr() as *mut c_char,
        c_str!("USER=root").as_char_ptr() as *mut c_char,
        c_str!("TERM=linux").as_char_ptr() as *mut c_char,
        c_str!("PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin").as_char_ptr()
            as *mut c_char,
        core::ptr::null_mut(),
    ];

    let rc = unsafe {
        call_usermodehelper(
            argv[0] as *const c_char,
            argv.as_ptr() as *mut *mut c_char,
            envp.as_ptr() as *mut *mut c_char,
            UMH_WAIT_EXEC.try_into().unwrap(),
        )
    };

    Some(rc)
}
