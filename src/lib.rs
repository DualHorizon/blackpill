#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_assignments)]
#![allow(missing_docs)]
use kernel::prelude::*;

#[macro_use]
extern crate core;

pub(crate) mod hypervisor;

module! {
    type: Blackpill,
    name: "blackpill",
    author: "Unknown",
    description: "Blackpill hypervisor",
    license: "GPL",
}

struct Blackpill {
    vmx_context: Option<hypervisor::VmxContext>,
}

unsafe impl Sync for Blackpill {}
unsafe impl Send for Blackpill {}

impl kernel::Module for Blackpill {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Blackpill: initializing\n");

        match hypervisor::VmxContext::new() {
            Ok(mut vmx_context) => {
                vmx_context.init();
            }
            Err(e) => {
                pr_err!("Failed to create VMX context\n");
                Err(e)
            }
        }
    }
}

impl Drop for Blackpill {
    fn drop(&mut self) {
        pr_info!("Blackpill: cleanup\n");
        if let Some(ctx) = self.vmx_context.take() {
            drop(ctx);
        }
    }
}
