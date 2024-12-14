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
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "utils.h"

struct __vmm_stack_t *stack;
extern void read_virt_mem(struct __vmm_stack_t *stack);
extern void write_virt_mem(struct __vmm_stack_t *stack);
extern void launch_userland_binary(struct __vmm_stack_t *stack);
extern void change_msr(struct __vmm_stack_t *stack);
extern void change_cr(struct __vmm_stack_t *stack);
extern void read_phys_mem(struct __vmm_stack_t *stack);
extern void write_phys_mem(struct __vmm_stack_t *stack);
extern void stop_execution(struct __vmm_stack_t *stack);
extern void change_vmcs_field(struct __vmm_stack_t *stack);
extern void enter_the_matrix(struct __vmm_stack_t *stack);

static inline int vmread(uint64_t encoding, uint64_t *value)
{
    uint64_t tmp;
    uint8_t ret;
    /*
    if (enable_evmcs)
            return evmcs_vmread(encoding, value);
    */
    __asm__ __volatile__("vmread %[encoding], %[value]; setna %[ret]"
                         : [value] "=rm"(tmp), [ret] "=rm"(ret)
                         : [encoding] "r"(encoding)
                         : "cc", "memory");

    *value = tmp;
    return ret;
}
/*
 * A wrapper around vmread (taken from kvm vmx.c) that ignores errors
 * and returns zero if the vmread instruction fails.
 */
static inline uint64_t vmreadz(uint64_t encoding)
{
    uint64_t value = 0;
    vmread(encoding, &value);
    return value;
}

static inline int vmwrite(uint64_t encoding, uint64_t value)
{
    uint8_t ret;
    __asm__ __volatile__("vmwrite %[value], %[encoding]; setna %[ret]"
                         : [ret] "=rm"(ret)
                         : [value] "rm"(value), [encoding] "r"(encoding)
                         : "cc", "memory");

    return ret;
}

struct __vmm_stack_t
{
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rbp;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rbx;
    uint64_t rax;
    uint64_t int_no;
    uint64_t err_code;
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
} __attribute__((packed));

extern void read_virt_mem(struct __vmm_stack_t *stack)
{
    pr_info("read_virt_mem called\n");
    unsigned long address = stack->r12;
    unsigned long value = 0;
    value = *((unsigned long *)address);
    pr_info("Read from address %lx: value = %lx\n", address, value);
}

extern void write_virt_mem(struct __vmm_stack_t *stack)
{
    pr_info("write_virt_mem called\n");
    unsigned long address = stack->r12;
    unsigned long value = stack->rcx;
    *((unsigned long *)address) = value;
    pr_info("Wrote value %lx to address %lx\n", value, address);
}

extern void launch_userland_binary(struct __vmm_stack_t *stack)
{
    pr_info("launch_userland_binary called\n");
    char *app_path = (char *)stack->r12;
    pr_info("Launching userland binary at: %s\n", app_path);
}

extern void change_msr(struct __vmm_stack_t *stack)
{
    pr_info("change_msr called\n");

    unsigned long msr = stack->r12; // Dereference the stack directly
    unsigned long value = stack->rcx;
    pr_info("Changing MSR at %lx to value %lx\n", msr, value);

    u32 low = (u32)(value & 0xFFFFFFFF);          // Lower 32 bits
    u32 high = (u32)((value >> 32) & 0xFFFFFFFF); // Upper 32 bits

    wrmsr(msr, low, high);
}

extern void change_cr(struct __vmm_stack_t *stack)
{
    pr_info("change_cr called\n");

    unsigned long cr_value = stack->r12;
    pr_info("Changing control register (CR3) to value %lx\n", cr_value);

    asm volatile("mov %0, %%cr3" ::"r"(cr_value));
}

extern void read_phys_mem(struct __vmm_stack_t *stack)
{
    pr_info("read_phys_mem called\n");

    unsigned long phys_address = stack->r12;
    unsigned long value = 0;

    value = *((unsigned long *)phys_address);
    pr_info("Read physical memory at address %lx: value = %lx\n", phys_address,
            value);
}

extern void write_phys_mem(struct __vmm_stack_t *stack)
{
    pr_info("write_phys_mem called\n");

    unsigned long phys_address = stack->r12;
    unsigned long value = stack->rcx;

    *((unsigned long *)phys_address) = value;
    pr_info("Wrote value %lx to physical address %lx\n", value, phys_address);
}

extern void stop_execution(struct __vmm_stack_t *stack)
{
    pr_info("stop_execution called\n");

    pr_info("Stopping VM execution\n");

    while (1)
    {
        schedule();
    }
}

extern void change_vmcs_field(struct __vmm_stack_t *stack)
{
    pr_info("change_vmcs_field called\n");

    unsigned long field = stack->r12;
    unsigned long value = stack->rcx;

    pr_info("Changing VMCS field %lx to value %lx\n", field, value);

    vmwrite(field, value);
}

extern void enter_the_matrix(struct __vmm_stack_t *stack)
{
    pr_info("enter_the_matrix called\n");

    pr_info("Performing enter_the_matrix...\n");
}
