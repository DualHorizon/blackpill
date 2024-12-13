#ifndef HYPERVISOR_CAPABILITIES_H
#define HYPERVISOR_CAPABILITIES_H

#include <linux/types.h>

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
}
__attribute__((packed));

static inline int vmread(uint64_t encoding, uint64_t *value)
{
    uint64_t tmp;
    uint8_t ret;

    __asm__ __volatile__(
        "vmread %[encoding], %[value]; setna %[ret]"
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
    __asm__ __volatile__(
        "vmwrite %[value], %[encoding]; setna %[ret]"
        : [ret] "=rm"(ret)
        : [value] "rm"(value), [encoding] "r"(encoding)
        : "cc", "memory");

    return ret;
}

#endif
