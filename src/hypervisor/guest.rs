#[repr(C)]
pub(crate) struct GuestState {
    pub regs: GuestRegisters,
    pub launched: bool,
}

#[repr(C)]
pub(crate) struct GuestRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
}

impl GuestState {
    pub(crate) fn new() -> Self {
        Self {
            regs: GuestRegisters {
                rax: 0,
                rbx: 0,
                rcx: 0,
                rdx: 0,
                rsi: 0,
                rdi: 0,
                rbp: 0,
                r8: 0,
                r9: 0,
                r10: 0,
                r11: 0,
                r12: 0,
                r13: 0,
                r14: 0,
                r15: 0,
                rip: 0,
                rsp: 0,
                rflags: 2,
            },
            launched: false,
        }
    }

    pub(crate) fn setup_initial_state(&mut self, entry_point: u64, stack_pointer: u64) {
        self.regs.rip = entry_point;
        self.regs.rsp = stack_pointer;
    }
}

pub(crate) const GUEST_STACK_SIZE: usize = 16384;

pub(crate) struct GuestStack {
    stack: [u8; GUEST_STACK_SIZE],
}

impl GuestStack {
    pub(crate) fn new() -> Self {
        Self {
            stack: [0; GUEST_STACK_SIZE],
        }
    }

    pub(crate) fn top(&self) -> u64 {
        (self.stack.as_ptr() as u64) + GUEST_STACK_SIZE as u64
    }
}
