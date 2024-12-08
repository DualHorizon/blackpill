use kernel::prelude::*;

mod constants;
mod exit_handler;
mod guest;
mod vmcs;
mod vmx;

use constants::*;
use core::alloc::Layout;
use core::arch::{asm, global_asm};
use core::ptr::NonNull;
use guest::{GuestStack, GuestState};
use kernel::alloc::{allocator::Kmalloc, Allocator};
use vmcs::*;
use vmx::*;

global_asm!(
    r#"
    .text
    .global guest_code
guest_code:
    mov ebx, 0x1337
    xor rax, rax
    cpuid
    mov rax, 0x1338
    vmcall
    ret

    .global vmm_entrypoint
vmm_entrypoint:
    ret

    .global vm_exit_handler_asm
vm_exit_handler_asm:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rdi, rsp
    call vm_exit_handler
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    vmresume
"#
);

extern "C" {
    fn guest_code();
    fn vm_exit_handler_asm();
}

pub(crate) struct VmxContext {
    vmxon_region: *mut u64,
    vmcs_region: *mut u64,
    guest_state: GuestState,
    guest_stack: GuestStack,
}

unsafe impl Send for VmxContext {}
unsafe impl Sync for VmxContext {}

impl VmxContext {
    pub(crate) fn new() -> Result<Self> {
        let layout = Layout::from_size_align(4096, 4096).unwrap();

        let vmxon_region = Kmalloc::alloc(layout, GFP_KERNEL)
            .map_err(|_| kernel::error::code::ENOMEM)?
            .as_ptr() as *mut u64;

        let vmcs_region = Kmalloc::alloc(layout, GFP_KERNEL)
            .map_err(|_| kernel::error::code::ENOMEM)?
            .as_ptr() as *mut u64;

        if vmcs_region.is_null() {
            unsafe {
                Kmalloc::free(NonNull::new(vmxon_region as *mut u8).unwrap(), layout);
            }
            return Err(kernel::error::code::ENOMEM);
        }

        let mut guest_state = GuestState::new();
        let guest_stack = GuestStack::new();
        guest_state.setup_initial_state(guest_code as u64, guest_stack.top());

        Ok(Self {
            vmxon_region,
            vmcs_region,
            guest_state,
            guest_stack,
        })
    }
    pub(crate) fn init(&mut self) -> ! {
        if !vmx_support() {
            panic!("VMX not supported");
        }

        self.enter_vmx_operation().expect("VMX operation failed");
        self.init_vmcs().expect("VMCS init failed");
        self.setup_vmcs_control_fields()
            .expect("VMCS control setup failed");

        unsafe {
            vmwrite(GUEST_RSP, self.guest_state.regs.rsp).unwrap();
            vmwrite(GUEST_RIP, self.guest_state.regs.rip).unwrap();
            vmwrite(GUEST_RFLAGS, self.guest_state.regs.rflags).unwrap();
            asm!("vmlaunch", options(noreturn));
        }
    }

    fn enter_vmx_operation(&mut self) -> Result<()> {
        unsafe {
            let cr4 = read_cr4();
            write_cr4(cr4 | X86_CR4_VMXE);

            let revision_id = get_vmx_revision_id();
            *(self.vmxon_region as *mut u32) = revision_id;
            *(self.vmcs_region as *mut u32) = revision_id;

            vmxon(self.vmxon_region as u64)?;
            vmclear(self.vmcs_region as u64)?;
            vmptrld(self.vmcs_region as u64)?;
        }
        Ok(())
    }
}

impl Drop for VmxContext {
    fn drop(&mut self) {
        unsafe {
            if !self.vmxon_region.is_null() {
                Kmalloc::free(
                    NonNull::new(self.vmxon_region as *mut u8).unwrap(),
                    Layout::from_size_align(4096, 4096).unwrap(),
                );
            }
            if !self.vmcs_region.is_null() {
                Kmalloc::free(
                    NonNull::new(self.vmcs_region as *mut u8).unwrap(),
                    Layout::from_size_align(4096, 4096).unwrap(),
                );
            }
            asm!("vmxoff");
        }
    }
}
