use super::constants::*;
use super::vmcs::*;
use kernel::prelude::*;

#[repr(C)]
pub(crate) struct VmmStack {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rbp: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    rbx: u64,
    rax: u64,
}

#[no_mangle]
pub(crate) extern "C" fn vm_exit_handler(stack: &mut VmmStack) {
    let exit_reason = vmread(VM_EXIT_REASON).unwrap() & 0xffff;

    match exit_reason as u32 {
        EXIT_REASON_CPUID => {
            pr_info!("CPUID occurred\n");
            adjust_rip();
        }
        EXIT_REASON_VMCALL => {
            pr_info!("VMCALL occurred, RBX = {:#x}\n", stack.rbx);
            if stack.rbx == 0x1337 {
                pr_info!("Special VMCALL detected\n");
            }
            adjust_rip();
        }
        _ => {
            pr_info!("Unknown VM exit: {}\n", exit_reason);
            adjust_rip();
        }
    }
}

fn adjust_rip() {
    if let Ok(instruction_length) = vmread(VM_EXIT_INSTRUCTION_LENGTH) {
        if let Ok(rip) = vmread(GUEST_RIP) {
            let _ = vmwrite(GUEST_RIP, rip + instruction_length);
        }
    }
}
