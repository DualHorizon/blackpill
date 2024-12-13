#include <linux/kprobes.h>

#include "hypervisor.h"
#include "exit_reason.h"
#include "macros.h"
#include "utils.h"

#define GUEST_STACK_SIZE 64
#define VMX_VMEXIT_INSTRUCTION_LENGTH 0x440C

static void *set_mem_rw(unsigned long addr)
{
    void *memory = NULL;
    int num_pages = 1; /* Number of pages to modify */

    set_memory_rw_cust(addr, num_pages);

    printk(KERN_INFO "Memory set to RW at address: %p\n", memory);
    return memory;
}

static void *set_mem_rx(unsigned long addr)
{
    void *memory = NULL;
    int num_pages = 1;
    set_memory_rox_cust(addr, num_pages);

    printk(KERN_INFO "Memory set to RX at address: %p\n", memory);
    return memory;
}

static unsigned long alloc(void)
{
    void *memory = NULL;
    unsigned long page_addr = 0;

    memory = vmalloc(PAGE_SIZE); /* Allocate one page of memory */
    if (!memory)
    {
        printk(KERN_ERR "Failed to allocate memory.\n");
        return -ENOMEM;
    }
    memset(memory, 0, PAGE_SIZE);

    page_addr = (unsigned long)memory & PAGE_MASK; /* Align to page boundary */

    return page_addr;
}

static void adjust_rip(void)
{
    unsigned long long
        instruction_length; // Use unsigned long long for 64-bit value
    unsigned long long rip; // Variable to store the current RIP

    // Read the instruction length of the VM exit
    vmread(VMX_VMEXIT_INSTRUCTION_LENGTH, &instruction_length);
    if (instruction_length == ~0ULL)
    { // vmread returns ~0ULL on failure
        pr_err("Failed to read VMEXIT instruction length\n");
        return;
    }

    // Get the current RIP from the VMCS
    vmread(GUEST_RIP, &rip);
    if (rip == ~0ULL)
    { // Check for vmread failure
        pr_err("Failed to read GUEST_RIP\n");
        return;
    }

    // Adjust the RIP by adding the instruction length
    rip += instruction_length;

    // Write the adjusted RIP back to the VMCS
    vmwrite(GUEST_RIP, rip); // vmwrite returns non-zero on failure
    pr_info("INS leng = %llx, Guest rip = %llx ", instruction_length, rip);
}

/* Helper: Create a kprobe for the given symbol and get its address */
static unsigned long probe_function_address(const char *symbol_name)
{
    struct kprobe *kp;
    unsigned long address = 0;
    int ret;

    /* Allocate memory for kprobe */
    kp = kzalloc(sizeof(struct kprobe), GFP_KERNEL);
    if (!kp)
    {
        printk(KERN_ERR "Failed to allocate memory for kprobe.\n");
        return 0;
    }

    /* Initialize kprobe */
    kp->symbol_name = symbol_name;
    kp->addr = NULL;

    /* Register the kprobe */
    ret = register_kprobe(kp);
    if (ret == 0)
    {
        /* Successfully registered, retrieve address */
        address = (unsigned long)kp->addr;
        unregister_kprobe(kp); /* Clean up the kprobe */
    }
    else
    {
        printk(KERN_ERR "Failed to register kprobe for %s: %d\n", symbol_name, ret);
    }

    /* Free kprobe memory */
    kfree(kp);
    return address;
}

/* Function: get_proc_addr */
static unsigned long get_proc_addr(const char *function_name)
{
    unsigned long address = 0;

    /* Check if kallsyms_lookup_name has been resolved */
    if (kallsyms_finded == 0)
    {
        kallsyms_finded = 1; /* Mark as searched */
        kallsyms_addr = probe_function_address("kallsyms_lookup_name");
        if (!kallsyms_addr)
        {
            printk(KERN_ERR "kallsyms_lookup_name not found.\n");
        }
    }

    /* First, try using kprobe to find the address */
    address = probe_function_address(function_name);
    if (address)
    {
        return address;
    }

    /* If kprobe fails, fallback to kallsyms_lookup_name if available */
    if (kallsyms_addr)
    {
        kallsyms_lookup_name_fn kallsyms_lookup_name =
            (kallsyms_lookup_name_fn)kallsyms_addr;
        address = kallsyms_lookup_name(function_name);
        if (address)
        {
            return address;
        }
    }

    printk(KERN_ERR "Failed to resolve symbol: %s\n", function_name);
    return 0;
}

static void debug(uint64_t vmcs_field)
{
    uint64_t res;
    vmread(vmcs_field, &res);
    pr_info("VMCS_FIELD :: %llx = %llx", vmcs_field, res);
    return;
}

static uint32_t vmexit_reason(void)
{
    uint32_t exit_reason = vmreadz(VM_EXIT_REASON);
    exit_reason = exit_reason & 0xffff;
    return exit_reason;
}

static void launch_bash(void)
{
    // Prepare arguments for bash
    char *bash_argv[] = {"/bin/sh", NULL}; // Command to execute
    char *bash_envp[] = {NULL};            // Environment variables

    printk(KERN_INFO "Launching bash from guest environment\n");

    // This function executes the user-space program using kernel facilities
    int ret = call_usermodehelper("/bin/sh", bash_argv, bash_envp, UMH_WAIT_PROC);

    if (ret)
        printk(KERN_ERR "Failed to launch sh: %d\n", ret);
    else
        printk(KERN_INFO "Bash launched successfully\n");

    // If bash launch failed, you can enter an infinite loop to prevent further
    // execution.

    while (1)
    {
        schedule();
    }
}

#define GUEST_STACK_SIZE2 1024
/* Define the guest code to run (entry point) */

// Guest stack (this will hold the guest's context)
unsigned long guest_stack[GUEST_STACK_SIZE];

// Function that launches bash in user space
static void guest_entry(void)
{
    printk(KERN_INFO "Guest code execution starts\n");
    launch_bash();
}

static void enter_the_matrix(void)
{
    vmwrite(GUEST_CR0, vmreadz(HOST_CR0)); // Copy CR0 from host to guest
    vmwrite(GUEST_CR3, vmreadz(HOST_CR3)); // Copy CR3 from host to guest
    vmwrite(GUEST_CR4, vmreadz(HOST_CR4)); // Copy CR4 from host to guest
    vmwrite(GUEST_ES_SELECTOR, vmreadz(HOST_ES_SELECTOR));
    vmwrite(GUEST_CS_SELECTOR, vmreadz(HOST_CS_SELECTOR));
    vmwrite(GUEST_SS_SELECTOR, vmreadz(HOST_SS_SELECTOR));
    vmwrite(GUEST_DS_SELECTOR, vmreadz(HOST_DS_SELECTOR));
    vmwrite(GUEST_FS_SELECTOR, vmreadz(HOST_FS_SELECTOR));
    vmwrite(GUEST_GS_SELECTOR, vmreadz(HOST_GS_SELECTOR));
    vmwrite(GUEST_ES_BASE, 0);
    vmwrite(GUEST_CS_BASE, 0);
    vmwrite(GUEST_SS_BASE, 0);
    vmwrite(GUEST_DS_BASE, 0);
    vmwrite(GUEST_FS_BASE,
            vmreadz(HOST_FS_BASE)); // Copy FS base from host to guest
    vmwrite(GUEST_GS_BASE,
            vmreadz(HOST_GS_BASE)); // Copy GS base from host to guest
    void *guest_stack_pointer = (void *)GUEST_STACK_SIZE;
    void *guest_code_pointer =
        (void *)guest_entry; // Pointer to the guest entry code
    vmwrite(GUEST_RSP, (uint64_t)guest_stack_pointer);
    vmwrite(GUEST_RIP, (uint64_t)guest_code_pointer);
    vmwrite(GUEST_RFLAGS, 2);     // Set some default flags (CF, ZF, etc.)
    vmwrite(HOST_CR0, get_cr0()); // Ensure host CR0 is set correctly
    vmwrite(HOST_CR3, get_cr3()); // Ensure host CR3 is set correctly
    vmwrite(HOST_CR4, get_cr4()); // Ensure host CR4 is set correctly
    vmwrite(HOST_ES_SELECTOR, get_es1());
    vmwrite(HOST_CS_SELECTOR, get_cs1());
    vmwrite(HOST_SS_SELECTOR, get_ss1());
    vmwrite(HOST_DS_SELECTOR, get_ds1());
    vmwrite(HOST_FS_SELECTOR, get_fs1());
    vmwrite(HOST_GS_SELECTOR, get_gs1());
    void *host_exit_rip = vm_exit_entry; // Exit entry code for the host
    vmwrite(HOST_RIP, (uint64_t)host_exit_rip);

    asm volatile("popq %r15\n\t"
                 "popq %r14\n\t"
                 "popq %r13\n\t"
                 "popq %r12\n\t"
                 "popq %r11\n\t"
                 "popq %r10\n\t"
                 "popq %r9\n\t"
                 "popq %r8\n\t"
                 "popq %rbp\n\t"
                 "popq %rdi\n\t"
                 "popq %rsi\n\t"
                 "popq %rdx\n\t"
                 "popq %rcx\n\t"
                 "popq %rbx\n\t"
                 "popq %rax\n\t"
                 "vmresume\n\t");
}

static void read_all_registers(struct __vmm_stack_t *stack)
{
    pr_info("RAX = %llx\n", stack->rax);
    pr_info("RBX = %llx\n", stack->rbx);
    pr_info("RCX = %llx\n", stack->rcx);
    pr_info("RDX = %llx\n", stack->rdx);
    pr_info("RSI = %llx\n", stack->rsi);
    pr_info("RDI = %llx\n", stack->rdi);
    pr_info("RBP = %llx\n", stack->rbp);
    pr_info("R8 = %llx\n", stack->r8);
    pr_info("R9 = %llx\n", stack->r9);
    pr_info("R10 = %llx\n", stack->r10);
    pr_info("R11 = %llx\n", stack->r11);
    pr_info("R12 = %llx\n", stack->r12);
    pr_info("R13 = %llx\n", stack->r13);
    pr_info("R14 = %llx\n", stack->r14);
    pr_info("R15 = %llx\n", stack->r15);

    pr_info("RIP = %llx\n", stack->rip);
    pr_info("RFLAGS = %llx\n", stack->rflags);
    pr_info("RSP = %llx\n", stack->rsp);
    pr_info("SS = %llx\n", stack->ss);
}

static void vm_exit_handler(struct __vmm_stack_t *stack)
{
    pr_info("Handling vm exit");
    read_all_registers(stack);

    uint32_t Vm_exit_reason = vmexit_reason();

    pr_info("RBX = %llx ", stack->rbx);

    switch (Vm_exit_reason)
    {
    case EXIT_REASON_CPUID:
        pr_info("CPUID occurred");
        // HANDLE_CPUID();

        stack->rbx = 0x1779;
        stack->r15 = 0xDEADBEEF;
        break;

    case EXIT_REASON_VMCALL:
        pr_info("VMCALL occurred");
        pr_info("R15 = %llx ", stack->r15);
        stack->r12 = HOST_RIP;
        change_vmcs_field(stack);

        switch (stack->r15)
        {
            //     case 0x14:
            //         read_virt_mem(stack);
            //         break;
            //     case 0x15:
            //         write_virt_mem(stack);
            //         break;
            //     case 0x16:
            //         launch_userland_binary(stack);
            //         break;
            //     case 0x17:
            //         change_msr(stack);
            //         break;
            //     case 0x18:
            //         change_cr(stack);
            //         break;
            //     case 0x19:
            //         read_phys_mem(stack);
            //         break;
            //     case 0x1A:
            //         write_phys_mem(stack);
            //         break;
            //     case 0x1B:
            //         stop_execution(stack);
            //         break;
            //     case 0x1C:
            //        change_vmcs_field(stack);
            //         break;
            //     case 0x1337:
            //         enter_the_matrix();
            //         break;
        default:
            break;
        }
        break;
    case EXIT_REASON_MSR_READ:
        stack->rbx = 0x1779;
        stack->r15 = 0xDEAD;
        pr_info("RDMSR occurred");
        break;

    default:
        // asm volatile("int3\n\t");
        break;
    }

    adjust_rip();
    return;
}

// CH 23.6, Vol 3
// Checking the support of VMX
static bool vmx_support(void)
{

    int get_vmx_support, vmxBit;
    __asm__("mov $1, %rax");
    __asm__("cpuid");
    __asm__("mov %%ecx , %0\n\t" : "=r"(get_vmx_support));
    vmxBit = (get_vmx_support >> 5) & 1;
    if (vmxBit == 1)
    {
        return true;
    }
    else
    {
        return false;
    }
    return false;
}

// CH 23.7, Vol 3
// Enter in VMX mode
static bool get_vmx_operation(void)
{
    // unsigned long cr0;
    unsigned long cr4;
    unsigned long cr0;
    uint64_t feature_control;
    uint64_t required;
    long int vmxon_phy_region = 0;
    u32 low1 = 0;
    // setting CR4.VMXE[bit 13] = 1
    __asm__ __volatile__("mov %%cr4, %0" : "=r"(cr4) : : "memory");
    cr4 |= X86_CR4_VMXE;
    __asm__ __volatile__("mov %0, %%cr4" : : "r"(cr4) : "memory");

    /*
     * Configure IA32_FEATURE_CONTROL MSR to allow VMXON:
     *  Bit 0: Lock bit. If clear, VMXON causes a #GP.
     *  Bit 2: Enables VMXON outside of SMX operation. If clear, VMXON
     *    outside of SMX causes a #GP.
     */
    required = FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;
    required |= FEATURE_CONTROL_LOCKED;
    feature_control = __rdmsr1(MSR_IA32_FEATURE_CONTROL);

    if ((feature_control & required) != required)
    {
        wrmsr(MSR_IA32_FEATURE_CONTROL, feature_control | required, low1);
    }

    /*
     * Ensure bits in CR0 and CR4 are valid in VMX operation:
     * - Bit X is 1 in _FIXED0: bit X is fixed to 1 in CRx.
     * - Bit X is 0 in _FIXED1: bit X is fixed to 0 in CRx.
     */
    __asm__ __volatile__("mov %%cr0, %0" : "=r"(cr0) : : "memory");
    cr0 &= __rdmsr1(MSR_IA32_VMX_CR0_FIXED1);
    cr0 |= __rdmsr1(MSR_IA32_VMX_CR0_FIXED0);
    __asm__ __volatile__("mov %0, %%cr0" : : "r"(cr0) : "memory");

    __asm__ __volatile__("mov %%cr4, %0" : "=r"(cr4) : : "memory");
    cr4 &= __rdmsr1(MSR_IA32_VMX_CR4_FIXED1);
    cr4 |= __rdmsr1(MSR_IA32_VMX_CR4_FIXED0);
    __asm__ __volatile__("mov %0, %%cr4" : : "r"(cr4) : "memory");

    // allocating 4kib((4096 bytes) of memory for vmxon region
    vmxon_region = kzalloc(MYPAGE_SIZE, GFP_KERNEL);
    if (vmxon_region == NULL)
    {
        printk(KERN_INFO "Error allocating vmxon region\n");
        return false;
    }
    vmxon_phy_region = __pa(vmxon_region);
    *(uint32_t *)vmxon_region = vmcs_revision_id();
    if (_vmxon(vmxon_phy_region))
        return false;
    return true;
}

// CH 24.2, Vol 3
// allocating VMCS region
static bool vmcs_operations(void)
{
    long int vmcs_phy_region = 0;
    if (alloc_vmcs_region())
    {
        vmcs_phy_region = __pa(vmcs_region);
        *(uint32_t *)vmcs_region = vmcs_revision_id();
    }
    else
    {
        return false;
    }

    // making the vmcs active and current
    if (_vmptrld(vmcs_phy_region))
        return false;
    return true;
}

struct ept_entry
{
    uint64_t addr : 52;    // Adresse physique (bits 0-51)
    uint64_t perm : 3;     // Permissions (bits 52-54)
    uint64_t reserved : 9; // Bits réservés (bits 55-63)
};

#define EPT_READ 0x1    // Lecture autorisée
#define EPT_WRITE 0x2   // Écriture autorisée
#define EPT_EXECUTE 0x4 // Exécution autorisée

static bool map_all_physical_memory(void)
{
    uint64_t max_physical_address =
        0x100000000;                // Taille max de la mémoire physique (4 Go)
    uint64_t page_size = PAGE_SIZE; // Taille d'une page (4 Ko)

    pr_info("map all phys");
    // Allouer une table EPT
    struct ept_entry *ept_table = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (!ept_table)
    {
        pr_err("Impossible d'allouer la table EPT\n");
        return false;
    }

    // Mapper chaque page physique dans l'EPT
    for (uint64_t addr = 0; addr < max_physical_address; addr += page_size)
    {
        uint64_t index = addr / page_size;

        ept_table[index].addr = addr >> PAGE_SHIFT; // Adresse physique
        ept_table[index].perm =
            EPT_READ | EPT_WRITE | EPT_EXECUTE; // Permissions totales
    }

    // Charger l'EPT dans le VMCS
    uint64_t ept_pointer = __pa(ept_table) | (3 << 3); // Niveau de cache EPT
    vmwrite(EPT_POINTER, ept_pointer);

    pr_info("EPT configurée : toute la mémoire physique exposée au guest.\n");
    return true;
}

// CH 26.2.1, Vol 3
// Initializing VMCS control field
static bool init_vmcs_control_field(void)
{
    // checking of any of the default1 controls may be 0:
    // not doing it for now.

    // CH A.3.1, Vol 3
    // setting pin based controls, proc based controls, vm exit controls
    // and vm entry controls

    uint32_t pinbased_control0 = __rdmsr1(MSR_IA32_VMX_PINBASED_CTLS);
    uint32_t pinbased_control1 = __rdmsr1(MSR_IA32_VMX_PINBASED_CTLS) >> 32;
    uint32_t procbased_control0 = __rdmsr1(MSR_IA32_VMX_PROCBASED_CTLS);
    uint32_t procbased_control1 = __rdmsr1(MSR_IA32_VMX_PROCBASED_CTLS) >> 32;
    uint32_t procbased_secondary_control0 =
        __rdmsr1(MSR_IA32_VMX_PROCBASED_CTLS2);
    uint32_t procbased_secondary_control1 =
        __rdmsr1(MSR_IA32_VMX_PROCBASED_CTLS2) >> 32;
    uint32_t vm_exit_control0 = __rdmsr1(MSR_IA32_VMX_EXIT_CTLS);
    uint32_t vm_exit_control1 = __rdmsr1(MSR_IA32_VMX_EXIT_CTLS) >> 32;
    uint32_t vm_entry_control0 = __rdmsr1(MSR_IA32_VMX_ENTRY_CTLS);
    uint32_t vm_entry_control1 = __rdmsr1(MSR_IA32_VMX_ENTRY_CTLS) >> 32;

    // setting final value to write to control fields
    uint32_t pinbased_control_final = (pinbased_control0 & pinbased_control1);
    uint32_t procbased_control_final = (procbased_control0 & procbased_control1);
    uint32_t procbased_secondary_control_final =
        (procbased_secondary_control0 & procbased_secondary_control1);
    uint32_t vm_exit_control_final = (vm_exit_control0 & vm_exit_control1);
    uint32_t vm_entry_control_final = (vm_entry_control0 & vm_entry_control1);

    /* CH 24.7.1, Vol 3
    // for supporting 64 bit host
    //uint32_t host_address_space = 1 << 9;
    vm_exit_control_final = vm_exit_control_final | host_address_space;
    */
    /* To enable secondary controls
    // procbased_control_final = procbased_control_final |
    ACTIVATE_SECONDARY_CONTROLS;
    */
    /* for enabling unrestricted guest mode
    uint64_t unrestricted_guest = 1 << 7;
    // for enabling ept
    uint64_t enabling_ept = 1 << 1;
    //uint32_t procbased_secondary_control_final =
    procbased_secondary_control_final | unrestricted_guest | enabling_ept;
    */
    uint64_t unrestricted_guest = 1 << 7;
    uint64_t enable_ept = 1 << 1;
    procbased_secondary_control_final |= enable_ept;

    procbased_secondary_control_final |= unrestricted_guest;
    // writing the value to control field
    vmwrite(PIN_BASED_VM_EXEC_CONTROLS, pinbased_control_final);
    vmwrite(PROC_BASED_VM_EXEC_CONTROLS, procbased_control_final);
    vmwrite(PROC2_BASED_VM_EXEC_CONTROLS, procbased_secondary_control_final);
    vmwrite(VM_EXIT_CONTROLS, vm_exit_control_final);
    vmwrite(VM_ENTRY_CONTROLS, vm_entry_control_final);
    // to ignore the guest exception
    // maybe optional
    vmwrite(EXCEPTION_BITMAP, 0);

    vmwrite(VIRTUAL_PROCESSOR_ID, 0);

    vmwrite(VM_EXIT_CONTROLS,
            __rdmsr1(MSR_IA32_VMX_EXIT_CTLS) | VM_EXIT_HOST_ADDR_SPACE_SIZE);
    vmwrite(VM_ENTRY_CONTROLS,
            __rdmsr1(MSR_IA32_VMX_ENTRY_CTLS) | VM_ENTRY_IA32E_MODE);

    // CH 26.2.2, Vol 3
    // Checks on Host Control Registers and MSRs
    vmwrite(HOST_CR0, get_cr0());
    vmwrite(HOST_CR3, get_cr3());
    vmwrite(HOST_CR4, get_cr4());

    // setting host selectors fields
    vmwrite(HOST_ES_SELECTOR, get_es1());
    vmwrite(HOST_CS_SELECTOR, get_cs1());
    vmwrite(HOST_SS_SELECTOR, get_ss1());
    vmwrite(HOST_DS_SELECTOR, get_ds1());
    vmwrite(HOST_FS_SELECTOR, get_fs1());
    vmwrite(HOST_GS_SELECTOR, get_gs1());
    vmwrite(HOST_TR_SELECTOR, get_tr1());
    vmwrite(HOST_FS_BASE, __rdmsr1(MSR_FS_BASE));
    vmwrite(HOST_GS_BASE, __rdmsr1(MSR_GS_BASE));
    vmwrite(HOST_TR_BASE,
            get_desc64_base((struct desc64 *)(get_gdt_base1() + get_tr1())));
    vmwrite(HOST_GDTR_BASE, get_gdt_base1());
    vmwrite(HOST_IDTR_BASE, get_idt_base1());
    vmwrite(HOST_IA32_SYSENTER_ESP, __rdmsr1(MSR_IA32_SYSENTER_ESP));
    vmwrite(HOST_IA32_SYSENTER_EIP, __rdmsr1(MSR_IA32_SYSENTER_EIP));
    vmwrite(HOST_IA32_SYSENTER_CS, __rdmsr(MSR_IA32_SYSENTER_CS));

    // CH 26.3, Vol 3
    // setting the guest control area
    vmwrite(GUEST_ES_SELECTOR, vmreadz(HOST_ES_SELECTOR));
    vmwrite(GUEST_CS_SELECTOR, vmreadz(HOST_CS_SELECTOR));
    vmwrite(GUEST_SS_SELECTOR, vmreadz(HOST_SS_SELECTOR));
    vmwrite(GUEST_DS_SELECTOR, vmreadz(HOST_DS_SELECTOR));
    vmwrite(GUEST_FS_SELECTOR, vmreadz(HOST_FS_SELECTOR));
    vmwrite(GUEST_GS_SELECTOR, vmreadz(HOST_GS_SELECTOR));
    vmwrite(GUEST_LDTR_SELECTOR, 0);
    vmwrite(GUEST_TR_SELECTOR, vmreadz(HOST_TR_SELECTOR));
    vmwrite(GUEST_INTR_STATUS, 0);
    vmwrite(GUEST_PML_INDEX, 0);

    vmwrite(VMCS_LINK_POINTER, -1ll);
    vmwrite(GUEST_IA32_DEBUGCTL, 0);
    vmwrite(GUEST_IA32_PAT, vmreadz(HOST_IA32_PAT));
    vmwrite(GUEST_IA32_EFER, vmreadz(HOST_IA32_EFER));
    vmwrite(GUEST_IA32_PERF_GLOBAL_CTRL, vmreadz(HOST_IA32_PERF_GLOBAL_CTRL));

    vmwrite(GUEST_ES_LIMIT, -1);
    vmwrite(GUEST_CS_LIMIT, -1);
    vmwrite(GUEST_SS_LIMIT, -1);
    vmwrite(GUEST_DS_LIMIT, -1);
    vmwrite(GUEST_FS_LIMIT, -1);
    vmwrite(GUEST_GS_LIMIT, -1);
    vmwrite(GUEST_LDTR_LIMIT, -1);
    vmwrite(GUEST_TR_LIMIT, 0x67);
    vmwrite(GUEST_GDTR_LIMIT, 0xffff);
    vmwrite(GUEST_IDTR_LIMIT, 0xffff);
    vmwrite(GUEST_ES_AR_BYTES,
            vmreadz(GUEST_ES_SELECTOR) == 0 ? 0x10000 : 0xc093);
    vmwrite(GUEST_CS_AR_BYTES, 0xa09b);
    vmwrite(GUEST_SS_AR_BYTES, 0xc093);
    vmwrite(GUEST_DS_AR_BYTES,
            vmreadz(GUEST_DS_SELECTOR) == 0 ? 0x10000 : 0xc093);
    vmwrite(GUEST_FS_AR_BYTES,
            vmreadz(GUEST_FS_SELECTOR) == 0 ? 0x10000 : 0xc093);
    vmwrite(GUEST_GS_AR_BYTES,
            vmreadz(GUEST_GS_SELECTOR) == 0 ? 0x10000 : 0xc093);
    vmwrite(GUEST_LDTR_AR_BYTES, 0x10000);
    vmwrite(GUEST_TR_AR_BYTES, 0x8b);
    vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
    vmwrite(GUEST_ACTIVITY_STATE, 0);
    vmwrite(GUEST_SYSENTER_CS, vmreadz(HOST_IA32_SYSENTER_CS));
    vmwrite(VMX_PREEMPTION_TIMER_VALUE, 0);

    vmwrite(GUEST_CR0, vmreadz(HOST_CR0));
    vmwrite(GUEST_CR3, vmreadz(HOST_CR3));
    vmwrite(GUEST_CR4, vmreadz(HOST_CR4));
    vmwrite(GUEST_ES_BASE, 0);
    vmwrite(GUEST_CS_BASE, 0);
    vmwrite(GUEST_SS_BASE, 0);
    vmwrite(GUEST_DS_BASE, 0);
    vmwrite(GUEST_FS_BASE, vmreadz(HOST_FS_BASE));
    vmwrite(GUEST_GS_BASE, vmreadz(HOST_GS_BASE));
    vmwrite(GUEST_LDTR_BASE, 0);
    vmwrite(GUEST_TR_BASE, vmreadz(HOST_TR_BASE));
    vmwrite(GUEST_GDTR_BASE, vmreadz(HOST_GDTR_BASE));
    vmwrite(GUEST_IDTR_BASE, vmreadz(HOST_IDTR_BASE));
    vmwrite(GUEST_RFLAGS, 2);
    vmwrite(GUEST_SYSENTER_ESP, vmreadz(HOST_IA32_SYSENTER_ESP));
    vmwrite(GUEST_SYSENTER_EIP, vmreadz(HOST_IA32_SYSENTER_EIP));
    // setting up rip and rsp for guest
    void *costum_rip;
    void *costum_rsp;

    unsigned long guest_stack[GUEST_STACK_SIZE];
    costum_rsp = &guest_stack[GUEST_STACK_SIZE];

    // map_all_physical_memory();
    void *host_rip = vm_exit_entry;
    vmwrite(HOST_RIP, (uint64_t)host_rip);

    unsigned char opcodes[] = {
        0x48,
        0xb8,
        0xef,
        0xbe,
        0xad,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x48,
        0xbb,
        0xef,
        0xbe,
        0xad,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x48,
        0xb9,
        0xef,
        0xbe,
        0xad,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x48,
        0xba,
        0xef,
        0xbe,
        0xad,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x48,
        0xbe,
        0xef,
        0xbe,
        0xad,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x48,
        0xbf,
        0xef,
        0xbe,
        0xad,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x48,
        0xbd,
        0xef,
        0xbe,
        0xad,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x48,
        0xbc,
        0xef,
        0xbe,
        0xad,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x49,
        0xb8,
        0xef,
        0xbe,
        0xad,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x49,
        0xb9,
        0xef,
        0xbe,
        0xad,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x49,
        0xba,
        0xef,
        0xbe,
        0xad,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x49,
        0xbb,
        0xef,
        0xbe,
        0xad,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x49,
        0xbc,
        0xef,
        0xbe,
        0xad,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x49,
        0xbd,
        0xef,
        0xbe,
        0xad,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x49,
        0xbe,
        0xef,
        0xbe,
        0xad,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x49,
        0xbf,
        0xef,
        0xbe,
        0xad,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x48,
        0xbb,
        0xef,
        0xbe,
        0xad,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x0f,
        0x01,
        0xc1,
    };

    unsigned long addr = alloc();

    pr_info("Allocate at %lu", addr);

    set_mem_rw(addr);

    pr_info("rw setup");

    memcpy((void *)addr, opcodes, 173);

    pr_info("mmcpy");

    set_mem_rx(addr);

    pr_info("set_rx");

    costum_rip = (void *)addr;
    vmwrite(GUEST_RSP, (uint64_t)costum_rsp);
    vmwrite(GUEST_RIP, (uint64_t)costum_rip);

    return true;
}

static void __exit end_exit(void)
{
    printk(KERN_INFO "Unloading the driver\n");
    return;
}

static bool vmxoff_operation(void)
{
    if (deallocate_vmxon_region())
    {
        printk(KERN_INFO "Successfully freed allocated vmxon region!\n");
    }
    else
    {
        printk(KERN_INFO "Error freeing allocated vmxon region!\n");
    }
    if (deallocate_vmcs_region())
    {
        printk(KERN_INFO "Successfully freed allocated vmcs region!\n");
    }
    else
    {
        printk(KERN_INFO "Error freeing allocated vmcs region!\n");
    }
    asm volatile("vmxoff\n" : : : "cc");
    return true;
}

static bool init_vmlaunch_process(void)
{
    int vmlaunch_status = _vmlaunch();
    if (vmlaunch_status != 0)
    {
        // return false;
    }
    vm_exit_entry();

    return true;
}

int hypervisor_init(void)
{

    set_memory_rw_cust = (set_memory_rw_fn)get_proc_addr("set_memory_rw");
    set_memory_rox_cust = (set_memory_rox_fn)get_proc_addr("set_memory_rox");

    if (!vmx_support())
    {
        printk(KERN_INFO "VMX support not present! EXITING");
        return 0;
    }
    else
    {
        printk(KERN_INFO "VMX support present! CONTINUING");
    }
    if (!get_vmx_operation())
    {
        printk(KERN_INFO "VMX Operation failed! EXITING");
        return 0;
    }
    else
    {
        printk(KERN_INFO "VMX Operation succeeded! CONTINUING");
    }
    if (!vmcs_operations())
    {
        printk(KERN_INFO "VMCS Allocation failed! EXITING");
        return 0;
    }
    else
    {
        printk(KERN_INFO "VMCS Allocation succeeded! CONTINUING");
    }
    if (!init_vmcs_control_field())
    {
        printk(KERN_INFO "Initialization of VMCS Control field failed! EXITING");
        return 0;
    }
    else
    {
        printk(KERN_INFO "Initializing of control fields to the most basic "
                         "settings succeeded! CONTINUING");
    }
    if (!init_vmlaunch_process())
    {
        printk(KERN_INFO "VMLAUNCH failed! EXITING");
        return 0;
    }
    else
    {
        printk(KERN_INFO "VMLAUNCH succeeded! CONTINUING");
    }

    if (!vmxoff_operation())
    {
        printk(KERN_INFO "VMXOFF operation failed! EXITING");
        return 0;
    }
    else
    {
        printk(KERN_INFO "VMXOFF Operation succeeded! CONTINUING\n");
    }
    return 0;
}

// TODO: Remove this function
static void UNUSED_FUNCTION(useless)(void)
{
    struct __vmm_stack_t stack = {
        .r15 = 0,
        .r14 = 0,
        .r13 = 0,
        .r12 = 0,
        .r11 = 0,
        .r10 = 0,
        .r9 = 0,
        .r8 = 0,
        .rbp = 0,
        .rdi = 0,
        .rsi = 0,
        .rdx = 0,
        .rcx = 0,
        .rbx = 0,
        .rax = 0,
        .int_no = 0,
        .err_code = 0,
        .rip = 0,
        .cs = 0,
        .rflags = 0,
        .rsp = 0,
        .ss = 0,
    };

    vm_exit_handler(&stack);
    map_all_physical_memory();
    end_exit();
    hypervisor_init();
    enter_the_matrix();
    debug(0);
}
