//! This module contains the hooking functionality for the kernel.
//! This includes hooking the IDT (Interrupt Descriptor Table) and hooking syscalls.

pub(crate) mod idt;
pub(crate) mod syscall;
