#ifndef PROTOVIRT_H
#define PROTOVIRT_H

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

#include "macros.h"

#define VMM_STACK_SIZE 600016

// vmxon region
uint64_t *vmxon_region = NULL;
// vmcs region
uint64_t *vmcs_region = NULL;

struct desc64
{
    uint16_t limit0;
    uint16_t base0;
    unsigned base1 : 8, s : 1, type : 4, dpl : 2, p : 1;
    unsigned limit1 : 4, avl : 1, l : 1, db : 1, g : 1, base2 : 8;
    uint32_t base3;
    uint32_t zero1;
} __attribute__((packed));

static inline unsigned long long notrace __rdmsr1(unsigned int msr)
{
    DECLARE_ARGS(val, low, high);

    asm volatile("1: rdmsr\n"
                 "2:\n"
                 : EAX_EDX_RET(val, low, high)
                 : "c"(msr));

    return EAX_EDX_VAL(val, low, high);
}

// CH 30.3, Vol 3
// VMXON instruction - Enter VMX operation
static inline int _vmxon(uint64_t phys)
{
    uint8_t ret;

    __asm__ __volatile__("vmxon %[pa]; setna %[ret]"
                         : [ret] "=rm"(ret)
                         : [pa] "m"(phys)
                         : "cc", "memory");
    return ret;
}

// CH 24.11.2, Vol 3
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

// CH 24.2, Vol 3
// getting vmcs revision identifier
static inline uint32_t vmcs_revision_id(void)
{
    return __rdmsr1(MSR_IA32_VMX_BASIC);
}

// CH 23.7, Vol 3
// Enter in VMX mode
static bool alloc_vmcs_region(void)
{
    vmcs_region = kzalloc(MYPAGE_SIZE, GFP_KERNEL);
    if (vmcs_region == NULL)
    {
        printk(KERN_INFO "Error allocating vmcs region\n");
        return false;
    }
    return true;
}

static inline int _vmptrld(uint64_t vmcs_pa)
{
    uint8_t ret;

    __asm__ __volatile__("vmptrld %[pa]; setna %[ret]"
                         : [ret] "=rm"(ret)
                         : [pa] "m"(vmcs_pa)
                         : "cc", "memory");
    return ret;
}

// Ch A.2, Vol 3
// indicate whether any of the default1 controls may be 0
// if return 0, all the default1 controls are reserved and must be 1.
// if return 1,not all the default1 controls are reserved, and
// some (but not necessarily all) may be 0.
// static unsigned long long default1_controls(void){
//	unsigned long long check_default1_controls = (unsigned long
// long)((__rdmsr1(MSR_IA32_VMX_BASIC) << 55) & 1);
//	//printk(KERN_INFO "default1 controls value!---%llu\n",
// check_default1_controls); 	return check_default1_controls;
//}

static inline uint64_t get_desc64_base(const struct desc64 *desc)
{
    return ((uint64_t)desc->base3 << 32) |
           (desc->base0 | ((desc->base1) << 16) | ((desc->base2) << 24));
}

static inline int _vmlaunch(void)
{
    int ret;

    __asm__ __volatile__(
        "push %%rbp;"
        "push %%rcx;"
        "push %%rdx;"
        "push %%rsi;"
        "push %%rdi;"
        "push $0;"
        "vmwrite %%rsp, %[host_rsp];"
        "lea 1f(%%rip), %%rax;"
        "vmwrite %%rax, %[host_rip];"
        "vmlaunch;"
        "incq (%%rsp);"
        "1: pop %%rax;"
        "pop %%rdi;"
        "pop %%rsi;"
        "pop %%rdx;"
        "pop %%rcx;"
        "pop %%rbp;"
        : [ret] "=&a"(ret)
        : [host_rsp] "r"((uint64_t)HOST_RSP), [host_rip] "r"((uint64_t)HOST_RIP)
        : "memory", "cc", "rbx", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
          "r15");
    return ret;
}

static inline uint64_t get_cr0(void)
{
    uint64_t cr0;

    __asm__ __volatile__("mov %%cr0, %[cr0]" : /* output */[cr0] "=r"(cr0));
    return cr0;
}

static inline uint64_t get_cr3(void)
{
    uint64_t cr3;

    __asm__ __volatile__("mov %%cr3, %[cr3]" : /* output */[cr3] "=r"(cr3));
    return cr3;
}

static inline uint64_t get_cr4(void)
{
    uint64_t cr4;

    __asm__ __volatile__("mov %%cr4, %[cr4]" : /* output */[cr4] "=r"(cr4));
    return cr4;
}

static inline uint16_t get_es1(void)
{
    uint16_t es;

    __asm__ __volatile__("mov %%es, %[es]" : /* output */[es] "=rm"(es));
    return es;
}

static inline uint16_t get_cs1(void)
{
    uint16_t cs;

    __asm__ __volatile__("mov %%cs, %[cs]" : /* output */[cs] "=rm"(cs));
    return cs;
}

static inline uint16_t get_ss1(void)
{
    uint16_t ss;

    __asm__ __volatile__("mov %%ss, %[ss]" : /* output */[ss] "=rm"(ss));
    return ss;
}

static inline uint16_t get_ds1(void)
{
    uint16_t ds;

    __asm__ __volatile__("mov %%ds, %[ds]" : /* output */[ds] "=rm"(ds));
    return ds;
}

static inline uint16_t get_fs1(void)
{
    uint16_t fs;

    __asm__ __volatile__("mov %%fs, %[fs]" : /* output */[fs] "=rm"(fs));
    return fs;
}

static inline uint16_t get_gs1(void)
{
    uint16_t gs;

    __asm__ __volatile__("mov %%gs, %[gs]" : /* output */[gs] "=rm"(gs));
    return gs;
}

static inline uint16_t get_tr1(void)
{
    uint16_t tr;

    __asm__ __volatile__("str %[tr]" : /* output */[tr] "=rm"(tr));
    return tr;
}

static inline uint64_t get_gdt_base1(void)
{
    struct desc_ptr gdt;
    __asm__ __volatile__("sgdt %[gdt]" : /* output */[gdt] "=m"(gdt));
    return gdt.address;
}

static inline uint64_t get_idt_base1(void)
{
    struct desc_ptr idt;
    __asm__ __volatile__("sidt %[idt]" : /* output */[idt] "=m"(idt));
    return idt.address;
}

struct CPUID
{
    int eax;
    int ebx;
    int ecx;
    int edx;
};

struct __cpuid_params_t
{
    unsigned long long rax;
    unsigned long long rbx;
    unsigned long long rcx;
    unsigned long long rdx;
};

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

/// VMX OFF

// CH 27.2.1, Vol 3
// Basic VM exit reason

// Dealloc vmxon region
static bool deallocate_vmxon_region(void)
{
    if (vmxon_region)
    {
        kfree(vmxon_region);
        return true;
    }
    return false;
}

/* Dealloc vmcs guest region*/
static bool deallocate_vmcs_region(void)
{
    if (vmcs_region)
    {
        printk(KERN_INFO "Freeing allocated vmcs region!\n");
        kfree(vmcs_region);
        return true;
    }
    return false;
}

#endif
