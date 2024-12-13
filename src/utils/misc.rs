#![allow(dead_code)] // Needed because black kernel magic

use core::ffi::c_char;
use kernel::c_str;
use kernel::{bindings, prelude::*};

use crate::hooking::{register_kprobe, unregister_kprobe, KProbe};

extern "C" {
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
