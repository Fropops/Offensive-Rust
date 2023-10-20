
pub struct SyscallWrapper {
    resolver: SSNResolver,
}

impl SyscallWrapper {
    pub fn new() -> Self {
        let resolver : SSNResolver::new();
        resolver.load_syscalls();
        Self {
            resolver: resolver,
        }
    }

    pub fn NtOpenProcess(&self, ) -> i32 {
        let ssn = self.resolver.retrieve_ssn("NtOpenProcess").expect("No SSN found for NtOpenProcess!");
        let addr = self.resolver.get_random_syscall_addr().expect("No syscall address found");

        syscall!(
            ssn,
            addr,
            &mut process_handle,
            PROCESS_VM_WRITE | PROCESS_VM_READ,
            &mut oa,
            &mut ci
        )
    }
}

pub struct SSNResolver {
    functions: Vec<FunctionInfo>,
}

impl SSNResolver {
    pub fn new() -> Self {
        Self {
            functions: vec![]
        }
    }

    pub fn load_syscalls(&mut self) {
        functions = load_nt_syscall_info();
    }
}