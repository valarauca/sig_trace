//clone of sys/user.h user_regs_struct
//this is a clone of the user registers
#[repr(C)]
#[derive(Default,Clone,Debug)]
pub struct UserRegs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub fs: u64,
    pub gs: u64
}
impl UserRegs {

    //gets the number of the system call that was made
    pub fn get_syscall_num(&self) -> u64 {
        self.orig_rax
    }

    //gets the arguments of the system call
    pub fn get_args(&self) -> (u64,u64,u64,u64,u64,u64) {
        (self.rdi,self.rsi,self.rdx,self.r10,self.r8,self.r9)
    }

    //get the instruction pointer
    pub fn get_instruction(&self) -> u64 {
        self.rip
    }

    //get result
    pub fn get_result(&self) -> u64 {
        self.rax
    }
}
