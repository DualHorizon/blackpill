//!  To-do
use core::arch::global_asm;
use core::include;
use kernel::prelude::*;

include! {"hypervisor/mod.rs"}
include! {"utils/mod.rs"}
include! {"xdp/mod.rs"}

module! {
    type: Blackpill,
    name: "blackpill",
    author: "Unknown",
    description: "Do we really need to add a description ?",
    license: "GPL",
}

struct Blackpill {}

impl kernel::Module for Blackpill {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Rust minimal sample (init)\n");
        pr_info!("Am I built-in? {}\n", !cfg!(MODULE));

        Ok(Blackpill {})
    }
}

impl Drop for Blackpill {
    fn drop(&mut self) {
        pr_info!("Rust minimal sample (exit)\n");
    }
}
