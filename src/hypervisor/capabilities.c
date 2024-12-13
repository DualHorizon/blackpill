/* All guest hypercalls capabilities */

#include <asm/asm.h>
#include <asm/errno.h>
#include <asm/io.h>
#include <asm/pgtable.h>
#include <asm/set_memory.h>
#include <linux/const.h>
#include <linux/cpu.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/fs.h> /* Needed for KERN_INFO */
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/major.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "capabilities.h"
#include "utils.h"

static void read_virt_mem(struct __vmm_stack_t *stack)
{
    pr_info("read_virt_mem called\n");
    unsigned long address = stack->r12;
    unsigned long value = 0;
    value = *((unsigned long *)address);
    pr_info("Read from address %lx: value = %lx\n", address, value);
}

static void write_virt_mem(struct __vmm_stack_t *stack)
{
    pr_info("write_virt_mem called\n");
    unsigned long address = stack->r12;
    unsigned long value = stack->rcx;
    *((unsigned long *)address) = value;
    pr_info("Wrote value %lx to address %lx\n", value, address);
}

static void launch_userland_binary(struct __vmm_stack_t *stack)
{
    pr_info("launch_userland_binary called\n");
    char *app_path = (char *)stack->r12;
    pr_info("Launching userland binary at: %s\n", app_path);
}

static void change_msr(struct __vmm_stack_t *stack)
{
    pr_info("change_msr called\n");

    unsigned long msr = stack->r12; // Dereference the stack directly
    unsigned long value = stack->rcx;
    pr_info("Changing MSR at %lx to value %lx\n", msr, value);

    u32 low = (u32)(value & 0xFFFFFFFF);          // Lower 32 bits
    u32 high = (u32)((value >> 32) & 0xFFFFFFFF); // Upper 32 bits

    wrmsr(msr, low, high);
}

static void change_cr(struct __vmm_stack_t *stack)
{
    pr_info("change_cr called\n");

    unsigned long cr_value = stack->r12;
    pr_info("Changing control register (CR3) to value %lx\n", cr_value);

    asm volatile("mov %0, %%cr3" ::"r"(cr_value));
}

static void read_phys_mem(struct __vmm_stack_t *stack)
{
    pr_info("read_phys_mem called\n");

    unsigned long phys_address = stack->r12;
    unsigned long value = 0;

    value = *((unsigned long *)phys_address);
    pr_info("Read physical memory at address %lx: value = %lx\n", phys_address,
            value);
}

static void write_phys_mem(struct __vmm_stack_t *stack)
{
    pr_info("write_phys_mem called\n");

    unsigned long phys_address = stack->r12;
    unsigned long value = stack->rcx;

    *((unsigned long *)phys_address) = value;
    pr_info("Wrote value %lx to physical address %lx\n", value, phys_address);
}

static void stop_execution(struct __vmm_stack_t *stack)
{
    pr_info("stop_execution called\n");

    pr_info("Stopping VM execution\n");

    while (1)
    {
        schedule();
    }
}

static void change_vmcs_field(struct __vmm_stack_t *stack)
{
    pr_info("change_vmcs_field called\n");

    unsigned long field = stack->r12;
    unsigned long value = stack->rcx;

    pr_info("Changing VMCS field %lx to value %lx\n", field, value);

    vmwrite(field, value);
}

static void enter_the_matrix(struct __vmm_stack_t *stack)
{
    pr_info("enter_the_matrix called\n");

    pr_info("Performing enter_the_matrix...\n");
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

    read_virt_mem(&stack);
    write_virt_mem(&stack);
    launch_userland_binary(&stack);
    change_msr(&stack);
    change_cr(&stack);
    read_phys_mem(&stack);
    write_phys_mem(&stack);
    stop_execution(&stack);
    change_vmcs_field(&stack);
    enter_the_matrix(&stack);
}
