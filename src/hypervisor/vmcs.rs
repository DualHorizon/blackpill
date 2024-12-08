use super::constants::*;
use super::vmx::*;
use core::arch::asm;
use kernel::prelude::*;

pub(crate) fn vmwrite(field: u64, value: u64) -> Result<()> {
    let mut success: u8;
    unsafe {
        asm!(
            "vmwrite {1}, {2}",
            "setna {0}",
            out(reg_byte) success,
            in(reg) value,
            in(reg) field,
            options(nostack)
        );
    }
    if success != 0 {
        Err(kernel::error::code::EINVAL)
    } else {
        Ok(())
    }
}

pub(crate) fn vmread(field: u64) -> Result<u64> {
    let mut value: u64;
    let mut success: u8;
    unsafe {
        asm!(
            "vmread {2}, {1}",
            "setna {0}",
            out(reg_byte) success,
            out(reg) value,
            in(reg) field,
            options(nostack)
        );
    }
    if success != 0 {
        Err(kernel::error::code::EINVAL)
    } else {
        Ok(value)
    }
}

impl super::VmxContext {
    pub(crate) fn init_vmcs(&mut self) -> Result<()> {
        self.setup_host_state()?;
        self.setup_guest_state()?;
        Ok(())
    }

    fn setup_host_state(&self) -> Result<()> {
        unsafe {
            vmwrite(HOST_CR0, read_cr0())?;
            vmwrite(HOST_CR3, read_cr3())?;
            vmwrite(HOST_CR4, read_cr4())?;

            let mut es: u16;
            let mut cs: u16;
            let mut ss: u16;
            let mut ds: u16;
            let mut fs: u16;
            let mut gs: u16;
            let mut tr: u16;

            asm!(
                "mov {0:x}, es",
                "mov {1:x}, cs",
                "mov {2:x}, ss",
                "mov {3:x}, ds",
                "mov {4:x}, fs",
                "mov {5:x}, gs",
                "str {6:x}",
                out(reg) es,
                out(reg) cs,
                out(reg) ss,
                out(reg) ds,
                out(reg) fs,
                out(reg) gs,
                out(reg) tr,
            );

            vmwrite(HOST_ES_SELECTOR, es as u64)?;
            vmwrite(HOST_CS_SELECTOR, cs as u64)?;
            vmwrite(HOST_SS_SELECTOR, ss as u64)?;
            vmwrite(HOST_DS_SELECTOR, ds as u64)?;
            vmwrite(HOST_FS_SELECTOR, fs as u64)?;
            vmwrite(HOST_GS_SELECTOR, gs as u64)?;
            vmwrite(HOST_TR_SELECTOR, tr as u64)?;

            vmwrite(HOST_FS_BASE, rdmsr(MSR_FS_BASE))?;
            vmwrite(HOST_GS_BASE, rdmsr(MSR_GS_BASE))?;
            vmwrite(HOST_TR_BASE, 0)?;
            vmwrite(HOST_GDTR_BASE, 0)?;
            vmwrite(HOST_IDTR_BASE, 0)?;

            vmwrite(HOST_IA32_SYSENTER_CS, rdmsr(MSR_IA32_SYSENTER_CS))?;
            vmwrite(HOST_IA32_SYSENTER_ESP, rdmsr(MSR_IA32_SYSENTER_ESP))?;
            vmwrite(HOST_IA32_SYSENTER_EIP, rdmsr(MSR_IA32_SYSENTER_EIP))?;

            vmwrite(HOST_RIP, super::vm_exit_handler_asm as u64)?;
        }
        Ok(())
    }

    fn setup_guest_state(&self) -> Result<()> {
        unsafe {
            vmwrite(GUEST_CR0, read_cr0())?;
            vmwrite(GUEST_CR3, read_cr3())?;
            vmwrite(GUEST_CR4, read_cr4())?;

            vmwrite(GUEST_ES_SELECTOR, 0)?;
            vmwrite(GUEST_CS_SELECTOR, 0)?;
            vmwrite(GUEST_SS_SELECTOR, 0)?;
            vmwrite(GUEST_DS_SELECTOR, 0)?;
            vmwrite(GUEST_FS_SELECTOR, 0)?;
            vmwrite(GUEST_GS_SELECTOR, 0)?;
            vmwrite(GUEST_LDTR_SELECTOR, 0)?;
            vmwrite(GUEST_TR_SELECTOR, 0)?;

            vmwrite(GUEST_ES_BASE, 0)?;
            vmwrite(GUEST_CS_BASE, 0)?;
            vmwrite(GUEST_SS_BASE, 0)?;
            vmwrite(GUEST_DS_BASE, 0)?;
            vmwrite(GUEST_FS_BASE, 0)?;
            vmwrite(GUEST_GS_BASE, 0)?;
            vmwrite(GUEST_LDTR_BASE, 0)?;
            vmwrite(GUEST_TR_BASE, 0)?;

            vmwrite(GUEST_RFLAGS, 2)?;
            vmwrite(GUEST_RSP, 0)?;
            vmwrite(GUEST_RIP, super::guest_code as u64)?;

            vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0)?;
            vmwrite(GUEST_ACTIVITY_STATE, 0)?;
            vmwrite(VMCS_LINK_POINTER, u64::MAX)?;
        }
        Ok(())
    }

    pub(crate) fn setup_vmcs_control_fields(&self) -> Result<()> {
        let pin_based = rdmsr(MSR_IA32_VMX_PINBASED_CTLS);
        let proc_based = rdmsr(MSR_IA32_VMX_PROCBASED_CTLS);
        let exit_ctls = rdmsr(MSR_IA32_VMX_EXIT_CTLS);
        let entry_ctls = rdmsr(MSR_IA32_VMX_ENTRY_CTLS);

        vmwrite(PIN_BASED_VM_EXEC_CONTROL, pin_based & 0xffffffff)?;
        vmwrite(CPU_BASED_VM_EXEC_CONTROL, proc_based & 0xffffffff)?;
        vmwrite(VM_EXIT_CONTROLS, exit_ctls & 0xffffffff)?;
        vmwrite(VM_ENTRY_CONTROLS, entry_ctls & 0xffffffff)?;

        vmwrite(EXCEPTION_BITMAP, 0)?;
        vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0)?;
        vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0)?;
        vmwrite(CR3_TARGET_COUNT, 0)?;

        Ok(())
    }
}
