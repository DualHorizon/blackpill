extern "C" {
    /// Maps to the C function `hypervisor_init` from `src/hypervisor/hypervisor.c`.
    fn hypervisor_init() -> i32;
}

/// Initialize the hypervisor.
pub(crate) fn init() {
    unsafe {
        let _res = hypervisor_init();
    }
}
