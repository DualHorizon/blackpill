//! The module containing the [`Vmx`] type, which implements the
//! [`hardware_vt::HardwareVt`] trait for Intel processors.
//!
//! The Intel Virtual Machine Extensions (VMX) technology enables hardware-assisted virtualization
//! on Intel processors.
//!
//! All references to external resources (denoted with "See:") refer to
//! "Intel® 64 and IA-32 Architectures Software Developer’s Manual Volume 3C:
//! System Programming Guide" Revision June 2023 at
//! <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html> unless
//! otherwise stated.
//! 
/// Control Area within VMCS for configuring VM operations and intercepts
use core::mem::size_of;

use super::{
    get_segment_descriptor_value, GuestRegisters, NestedPagingStructureEntryFlags,
    NestedPagingStructureEntryType, VmExitReason,
};
use crate::{
    hypervisor::hardware_vt::{self, ExceptionQualification, GuestException, NestedPageFaultQualification},
    utils::x86::{irq, msr, rdmsr, wrmsr},
    KBox, GFP_KERNEL,
};
use core::{
    arch::global_asm,
    ptr::{addr_of, addr_of_mut},
};

/// VMX-specific data to represent a guest.
#[derive(Debug)]
pub(crate) struct Vmx {
    vmcs: KBox<Vmcs>,
    host_state: KBox<HostStateArea>,
    registers: GuestRegisters,
}

impl Default for Vmx {
    fn default() -> Self {
        // Initialize default VMCS and host state structures
        let vmcs = Vmcs::default();
        let host_state = HostStateArea::default();

        // Then create KBoxes with GFP_KERNEL flags
        let vmcs = KBox::<Vmcs>::new(vmcs, GFP_KERNEL).unwrap();
        let host_state = KBox::<HostStateArea>::new(host_state, GFP_KERNEL).unwrap();

        Self {
            vmcs,
            host_state,
            registers: GuestRegisters::default(),
        }
    }
}

impl hardware_vt::HardwareVt for Vmx {
    /// Enables VMX on the current processor.
    fn enable(&mut self) {
        const VMX_ENABLE_FLAG: u64 = 1 << 13;

        // Enable VMX. We assume the processor supports VMX.
        // See: Section 23.7 Enabling and Entering VMX Operation
        wrmsr(msr::IA32_FEATURE_CONTROL, rdmsr(msr::IA32_FEATURE_CONTROL) | VMX_ENABLE_FLAG);
    }

    /// Configures VMX. Intercepts specified events and enables Extended Page Tables.
    fn initialize(&mut self, nested_pml4_addr: u64) {
        const VMX_EXIT_INTR: u32 = 1 << 0;
        const VMX_EXIT_PAUSE: u32 = 1 << 18;
        const VMX_EXIT_SHUTDOWN: u32 = 1 << 24;

        // Configure VMCS fields for VM exits on certain conditions
        self.vmcs.control_area.intercept_exit = VMX_EXIT_INTR | VMX_EXIT_PAUSE | VMX_EXIT_SHUTDOWN;
        self.vmcs.control_area.pause_threshold = u16::MAX;

        // Configure ASID for EPT
        self.vmcs.control_area.eptp_asid = 1;
        self.vmcs.control_area.eptp = nested_pml4_addr;

        // Set guest exceptions to intercept
        self.vmcs.control_area.intercept_exception = (1u32 << irq::BREAKPOINT_VECTOR)
            | (1u32 << irq::INVALID_OPCODE_VECTOR)
            | (1u32 << irq::PAGE_FAULT_VECTOR);
    }

    /// Updates the guest states to use input data.
    fn adjust_registers(&mut self, input_addr: u64, input_size: u64) {
        // For the snapshot being used for testing, we know RDI points to the
        // address of the buffer to be parsed, and RSI contains the size of it.
        self.registers.rdi = input_addr;
        self.registers.rsi = input_size;
    }

    /// Executes the guest until it triggers a VMEXIT.
    fn run(&mut self) -> VmExitReason {
        const VMEXIT_EXCP0: u64 = 0x00;
        const VMEXIT_INTR: u64 = 0x10;
        const VMEXIT_PAUSE: u64 = 0x20;
        const VMEXIT_SHUTDOWN: u64 = 0x30;
        const VMEXIT_EPT_VIOLATION: u64 = 0x40;

        unsafe { vmx_run(&mut self.registers, addr_of_mut!(*self.vmcs)) };

        // Update guest register state post-exit
        self.registers.rax = self.vmcs.guest_state_area.rax;
        self.registers.rip = self.vmcs.guest_state_area.rip;
        self.registers.rsp = self.vmcs.guest_state_area.rsp;
        self.registers.rflags = self.vmcs.guest_state_area.rflags;

        // Handle VMEXIT based on Intel VMX exit codes
        match self.vmcs.control_area.exit_reason {
            VMEXIT_EXCP0..=0x1f => VmExitReason::Exception(ExceptionQualification {
                rip: self.registers.rip,
                exception_code: GuestException::try_from(
                    (self.vmcs.control_area.exit_reason - VMEXIT_EXCP0) as u8,
                )
                .unwrap(),
            }),
            VMEXIT_EPT_VIOLATION => VmExitReason::NestedPageFault(NestedPageFaultQualification {
                rip: self.registers.rip,
                gpa: self.vmcs.control_area.exit_info2,
                missing_translation: (self.vmcs.control_area.exit_info1 & 0b1) == 0,
                write_access: (self.vmcs.control_area.exit_info1 & 0b10) != 0,
            }),
            VMEXIT_INTR | VMEXIT_PAUSE => VmExitReason::ExternalInterruptOrPause,
            VMEXIT_SHUTDOWN => VmExitReason::Shutdown(self.vmcs.control_area.exit_reason),
            _ => VmExitReason::Unexpected(self.vmcs.control_area.exit_reason),
        }
    }

    /// Invalidates caches for Extended Page Tables (EPT).
    fn invalidate_caches(&mut self) {
        // Invalidate EPT TLB entries for this guest
        self.vmcs.control_area.ept_invalidation = 0b1;
    }

    /// Gets entry flags for EPT entries based on the entry type.
    fn nps_entry_flags(
        &self,
        entry_type: NestedPagingStructureEntryType,
    ) -> NestedPagingStructureEntryFlags {
        match entry_type {
            NestedPagingStructureEntryType::Rwx | NestedPagingStructureEntryType::RwxWriteBack => {
                NestedPagingStructureEntryFlags {
                    permission: 0b111,
                    memory_type: 0,
                }
            }
            NestedPagingStructureEntryType::RxWriteBack => NestedPagingStructureEntryFlags {
                permission: 0b101,
                memory_type: 0,
            },
        }
    }
}

/// Virtual Machine Control Structure (VMCS), describing guest execution
#[derive(Debug, Default)]
#[repr(C, align(4096))]
struct Vmcs {
    control_area: ControlArea,
    guest_state_area: GuestStateArea,
}


/// The "metadata" area where we can specify what operations to intercept and
/// can read details of #VMEXIT.
///
/// See: Table B-1. VMCB Layout, Control Area
#[derive(Debug)]
#[repr(C)]
struct ControlArea {
    intercept_cr_read: u16,   // +0x000
    intercept_cr_write: u16,  // +0x002
    intercept_dr_read: u16,   // +0x004
    intercept_dr_write: u16,  // +0x006
    intercept_exception: u32, // +0x008
    intercept_misc1: u32,     // +0x00c
    intercept_misc2: u32,     // +0x010
    intercept_misc3: u32,     // +0x014
    _padding1: [u8; 0x03c - 0x018],      // +0x018
    pause_filter_threshold: u16,         // +0x03c
    pause_filter_count: u16,             // +0x03e
    iopm_base_pa: u64,                   // +0x040
    msrpm_base_pa: u64,                  // +0x048
    tsc_offset: u64,                     // +0x050
    guest_asid: u32,                     // +0x058
    tlb_control: u32,                    // +0x05c
    vintr: u64,                          // +0x060
    interrupt_shadow: u64,               // +0x068
    exit_code: u64,                      // +0x070
    exit_info1: u64,                     // +0x078
    exit_info2: u64,                     // +0x080
    exit_int_info: u64,                  // +0x088
    np_enable: u64,                      // +0x090
    avic_apic_bar: u64,                  // +0x098
    guest_pa_pf_ghcb: u64,               // +0x0a0
    event_inj: u64,                      // +0x0a8
    ncr3: u64,                           // +0x0b0
    lbr_virtualization_enable: u64,      // +0x0b8
    vmcb_clean: u64,                     // +0x0c0
    nrip: u64,                           // +0x0c8
    num_of_bytes_fetched: u8,            // +0x0d0
    guest_instruction_bytes: [u8; 15],   // +0x0d1
    avic_apic_backing_page_pointer: u64, // +0x0e0
    _padding2: u64,                      // +0x0e8
    avic_logical_table_pointer: u64,     // +0x0f0
    avic_physical_table_pointer: u64,    // +0x0f8
    _padding3: u64,                      // +0x100
    vmcb_save_state_pointer: u64,        // +0x108
    _padding4: [u8; 0x3e0 - 0x110],      // +0x110
    reserved_for_host: [u8; 0x20],       // +0x3e0
}

impl Default for ControlArea {
    fn default() -> Self {
        Self {
            intercept_cr_read: 0,
            intercept_cr_write: 0,
            intercept_dr_read: 0,
            intercept_dr_write: 0,
            intercept_exception: 0,
            intercept_misc1: 0,
            intercept_misc2: 0,
            intercept_misc3: 0,
            _padding1: [0; 0x03c - 0x018],
            pause_filter_threshold: 0,
            pause_filter_count: 0,
            iopm_base_pa: 0,
            msrpm_base_pa: 0,
            tsc_offset: 0,
            guest_asid: 0,
            tlb_control: 0,
            vintr: 0,
            interrupt_shadow: 0,
            exit_code: 0,
            exit_info1: 0,
            exit_info2: 0,
            exit_int_info: 0,
            np_enable: 0,
            avic_apic_bar: 0,
            guest_pa_pf_ghcb: 0,
            event_inj: 0,
            ncr3: 0,
            lbr_virtualization_enable: 0,
            vmcb_clean: 0,
            nrip: 0,
            num_of_bytes_fetched: 0,
            guest_instruction_bytes: [0; 15],
            avic_apic_backing_page_pointer: 0,
            _padding2: 0,
            avic_logical_table_pointer: 0,
            avic_physical_table_pointer: 0,
            _padding3: 0,
            vmcb_save_state_pointer: 0,
            _padding4: [0; 0x3e0 - 0x110],
            reserved_for_host: [0; 0x20],
        }
    }
}

const _: () = assert!(size_of::<ControlArea>() == 0x400);

/// The area to specify and read guest register values.
///
/// See: Table B-2. VMCB Layout, State Save Area
#[derive(Debug)]
#[repr(C)]
struct StateSaveArea {
    es_selector: u16,   // +0x000
    es_attrib: u16,     // +0x002
    es_limit: u32,      // +0x004
    es_base: u64,       // +0x008
    cs_selector: u16,   // +0x010
    cs_attrib: u16,     // +0x012
    cs_limit: u32,      // +0x014
    cs_base: u64,       // +0x018
    ss_selector: u16,   // +0x020
    ss_attrib: u16,     // +0x022
    ss_limit: u32,      // +0x024
    ss_base: u64,       // +0x028
    ds_selector: u16,   // +0x030
    ds_attrib: u16,     // +0x032
    ds_limit: u32,      // +0x034
    ds_base: u64,       // +0x038
    fs_selector: u16,   // +0x040
    fs_attrib: u16,     // +0x042
    fs_limit: u32,      // +0x044
    fs_base: u64,       // +0x048
    gs_selector: u16,   // +0x050
    gs_attrib: u16,     // +0x052
    gs_limit: u32,      // +0x054
    gs_base: u64,       // +0x058
    gdtr_selector: u16, // +0x060
    gdtr_attrib: u16,   // +0x062
    gdtr_limit: u32,    // +0x064
    gdtr_base: u64,     // +0x068
    ldtr_selector: u16, // +0x070
    ldtr_attrib: u16,   // +0x072
    ldtr_limit: u32,    // +0x074
    ldtr_base: u64,     // +0x078
    idtr_selector: u16, // +0x080
    idtr_attrib: u16,   // +0x082
    idtr_limit: u32,    // +0x084
    idtr_base: u64,     // +0x088
    tr_selector: u16,   // +0x090
    tr_attrib: u16,     // +0x092
    tr_limit: u32,      // +0x094
    tr_base: u64,       // +0x098
    _padding1: [u8; 0x0cb - 0x0a0], // +0x0a0
    cpl: u8,                        // +0x0cb
    _padding2: u32,                 // +0x0cc
    efer: u64,                      // +0x0d0
    _padding3: [u8; 0x148 - 0x0d8], // +0x0d8
    cr4: u64,                       // +0x148
    cr3: u64,                       // +0x150
    cr0: u64,                       // +0x158
    dr7: u64,                       // +0x160
    dr6: u64,                       // +0x168
    rflags: u64,                    // +0x170
    rip: u64,                       // +0x178
    _padding4: [u8; 0x1d8 - 0x180], // +0x180
    rsp: u64,                       // +0x1d8
}

impl Default for StateSaveArea {
    fn default() -> Self {
        Self {
            es_selector: 0,
            es_attrib: 0,
            es_limit: 0,
            es_base: 0,
            cs_selector: 0,
            cs_attrib: 0,
            cs_limit: 0,
            cs_base: 0,
            ss_selector: 0,
            ss_attrib: 0,
            ss_limit: 0,
            ss_base: 0,
            ds_selector: 0,
            ds_attrib: 0,
            ds_limit: 0,
            ds_base: 0,
            fs_selector: 0,
            fs_attrib: 0,
            fs_limit: 0,
            fs_base: 0,
            gs_selector: 0,
            gs_attrib: 0,
            gs_limit: 0,
            gs_base: 0,
            gdtr_selector: 0,
            gdtr_attrib: 0,
            gdtr_limit: 0,
            gdtr_base: 0,
            ldtr_selector: 0,
            ldtr_attrib: 0,
            ldtr_limit: 0,
            ldtr_base: 0,
            idtr_selector: 0,
            idtr_attrib: 0,
            idtr_limit: 0,
            idtr_base: 0,
            tr_selector: 0,
            tr_attrib: 0,
            tr_limit: 0,
            tr_base: 0,
            _padding1: [0; 0x0cb - 0x0a0],
            cpl: 0,
            _padding2: 0,
            efer: 0,
            _padding3: [0; 0x148 - 0x0d8],
            cr4: 0,
            cr3: 0,
            cr0: 0,
            dr7: 0,
            dr6: 0,
            rflags: 0,
            rip: 0,
            _padding4: [0; 0x1d8 - 0x180],
            rsp: 0,
        }
    }
}

const _: () = assert!(size_of::<StateSaveArea>() == 0x1e0);

impl Default for ControlArea {
    fn default() -> Self {
        Self {
            intercept_cr_read: 0,
            intercept_cr_write: 0,
            intercept_dr_read: 0,
            intercept_dr_write: 0,
            intercept_exception: 0,
            intercept_exit: 0,
            intercept_misc: 0,
            _padding: [0; 0x40],
            ept_invalidation: 0,
            eptp_asid: 0,
            eptp: 0,
            exit_reason: 0,
            exit_info1: 0,
            exit_info2: 0,
            _reserved: [0; 0x20],
        }
    }
}

struct VMXData {
    unsigned long vmxon_region;
    unsigned long vmcs_region;
    struct vmcs *vmcs;
};

struct ControlArea {
    u32 pin_based_vm_exec_control;
    u32 cpu_based_vm_exec_control;
    u32 secondary_vm_exec_control;
    u32 vm_exit_controls;
    u32 vm_entry_controls;
};

struct GuestStateArea {
    u64 cr0;
    u64 cr3;
    u64 cr4;
    u64 rsp;
    u64 rip;
    u64 rflags;
    u64 efer;
};


static int vmx_init(void) {
    u64 feature_control;
    u64 cr0, cr4;

    // Check if the processor supports VMX
    feature_control = __readmsr(MSR_IA32_FEATURE_CONTROL);
    if (!(feature_control & (1 << 2))) {
        pr_err("VMX not supported on this processor\n");
        return -EIO;
    }

    // Enable VMX by setting CR4.VMXE
    cr4 = __read_cr4();
    __write_cr4(cr4 | X86_CR4_VMXE);

    // Allocate memory for VMXON region
    vmx_data.vmxon_region = (unsigned long)__get_free_page(GFP_KERNEL);
    if (!vmx_data.vmxon_region) {
        pr_err("Failed to allocate VMXON region\n");
        return -ENOMEM;
    }
    memset((void *)vmx_data.vmxon_region, 0, PAGE_SIZE);

    // Allocate memory for VMCS region
    vmx_data.vmcs_region = (unsigned long)__get_free_page(GFP_KERNEL);
    if (!vmx_data.vmcs_region) {
        pr_err("Failed to allocate VMCS region\n");
        free_page(vmx_data.vmxon_region);
        return -ENOMEM;
    }
    memset((void *)vmx_data.vmcs_region, 0, PAGE_SIZE);

    // Set up VMXON region
    *(u32 *)vmx_data.vmxon_region = (u32)__readmsr(MSR_IA32_VMX_BASIC);
    if (vmxon((void *)vmx_data.vmxon_region)) {
        pr_err("VMXON failed\n");
        free_page(vmx_data.vmxon_region);
        free_page(vmx_data.vmcs_region);
        return -EIO;
    }

    // Set up VMCS region
    *(u32 *)vmx_data.vmcs_region = (u32)__readmsr(MSR_IA32_VMX_BASIC);
    if (vmclear((void *)vmx_data.vmcs_region)) {
        pr_err("VMCLEAR failed\n");
        vmxoff();
        free_page(vmx_data.vmxon_region);
        free_page(vmx_data.vmcs_region);
        return -EIO;
    }

    if (vmptrld((void *)vmx_data.vmcs_region)) {
        pr_err("VMPTRLD failed\n");
        vmxoff();
        free_page(vmx_data.vmxon_region);
        free_page(vmx_data.vmcs_region);
        return -EIO;
    }

    // Initialize Control Area
    control_area.pin_based_vm_exec_control = PIN_BASED_EXT_INTR_MASK;
    control_area.cpu_based_vm_exec_control = CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
    control_area.secondary_vm_exec_control = SECONDARY_EXEC_ENABLE_EPT;
    control_area.vm_exit_controls = VM_EXIT_HOST_ADDR_SPACE_SIZE;
    control_area.vm_entry_controls = VM_ENTRY_IA32E_MODE;

    // Initialize Guest State Area
    guest_state.cr0 = 0x20;
    guest_state.cr3 = 0;
    guest_state.cr4 = 0;
    guest_state.rsp = 0;
    guest_state.rip = 0;
    guest_state.rflags = 0x2;
    guest_state.efer = 0;

    // Set VMCS control fields
    vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, control_area.pin_based_vm_exec_control);
    vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, control_area.cpu_based_vm_exec_control);
    vmcs_write32(SECONDARY_VM_EXEC_CONTROL, control_area.secondary_vm_exec_control);
    vmcs_write32(VM_EXIT_CONTROLS, control_area.vm_exit_controls);
    vmcs_write32(VM_ENTRY_CONTROLS, control_area.vm_entry_controls);

    // Set VMCS guest state fields
    vmcs_writel(GUEST_CR0, guest_state.cr0);
    vmcs_writel(GUEST_CR3, guest_state.cr3);
    vmcs_writel(GUEST_CR4, guest_state.cr4);
    vmcs_writel(GUEST_RSP, guest_state.rsp);
    vmcs_writel(GUEST_RIP, guest_state.rip);
    vmcs_writel(GUEST_RFLAGS, guest_state.rflags);
    vmcs_write64(GUEST_IA32_EFER, guest_state.efer);

    pr_info("VMX module loaded successfully\n");
    return 0;
}

static void vmx_exit(void) {
    // Perform VMCLEAR on VMCS region
    if (vmclear((void *)vmx_data.vmcs_region)) {
        pr_err("VMCLEAR failed\n");
    }

    // Perform VMXOFF
    vmxoff();

    // Free allocated pages
    free_page(vmx_data.vmxon_region);
    free_page(vmx_data.vmcs_region);

    pr_info("VMX module unloaded\n");
}

module_init(vmx_init);
module_exit(vmx_exit);

