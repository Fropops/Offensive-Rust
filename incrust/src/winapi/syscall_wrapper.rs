use std::ffi::c_void;
use std::ptr::null_mut;

use rand::seq::SliceRandom;

use super::helpers::FunctionInfo;
use super::helpers::load_nt_syscall_info;
use super::structs::CLIENT_ID;
// use crate::debug_info;
// use crate::debug_info_msg;
use crate::error::Result;
use crate::syscall;
use crate::winapi::structs::PROCESS_VM_READ;
use crate::winapi::structs::PROCESS_VM_WRITE;

use super::types::HANDLE;
use super::structs::OBJECT_ATTRIBUTES;

pub struct SyscallWrapper {
    resolver: SSNResolver,
}


impl SyscallWrapper {
    pub fn new() -> Self {
        let mut resolver = SSNResolver::new();
        resolver.load_syscalls();
        Self {
            resolver: resolver,
        }
    }

    // NTSTATUS NtAllocateVirtualMemory(
    //     IN HANDLE           ProcessHandle,    // Process handle in where to allocate memory
    //     IN OUT PVOID        *BaseAddress,     // The returned allocated memory's base address
    //     IN ULONG_PTR        ZeroBits,         // Always set to '0'
    //     IN OUT PSIZE_T      RegionSize,       // Size of memory to allocate
    //     IN ULONG            AllocationType,   // MEM_COMMIT | MEM_RESERVE
    //     IN ULONG            Protect           // Page protection 
    //   );
    pub fn NtAllocateVirtualMemory(&self, process_handle: HANDLE, base_address: &mut usize, region_size: &mut usize, allocation_type: u32, protect: u32) -> i32 {
        let func_name = "NtAllocateVirtualMemory";
        let ssn = self.resolver.retrieve_ssn(func_name).expect(format!("No SSN found for {} !", func_name).as_str());
        let addr = self.resolver.get_random_syscall_addr().expect("No syscall address available!");

        // debug_info_msg!(format!("call to {} SSN #{} addr {:#x} ", func_name, ssn, addr));
        // debug_info!(ssn);
        debug_info_hex!(addr);
        unsafe {
                syscall!(
                ssn,
                addr,
                process_handle,
                base_address,
                &mut 0u64,
                region_size,
                allocation_type,
                protect
            )
        }
    }


    
    pub fn NtOpenProcess(&self, process_handle: &mut HANDLE, desired_access :u32, process_id: isize) -> i32 {
        let func_name = "NtOpenProcess";
        let ssn = self.resolver.retrieve_ssn(func_name).expect(format!("No SSN found for {} !", func_name).as_str());
        let addr = self.resolver.get_random_syscall_addr().expect("No syscall address available!");
        debug_info_hex!(addr);

        let mut oa = OBJECT_ATTRIBUTES::default();

        let mut ci = CLIENT_ID {
            UniqueProcess: process_id as HANDLE,
            UniqueThread: 0,
        };

        unsafe {
            syscall!(
                ssn,
                addr,
                process_handle,
                desired_access,
                &mut oa,
                &mut ci
            )
        }
    }
}


struct SSNResolver {
    functions: Vec<FunctionInfo>,
    syscall_addresses: Vec<u64>,
}

impl SSNResolver {
    pub fn new() -> Self {
        Self {
            functions: vec![],
            syscall_addresses: vec![]
        }
    }

    pub fn load_syscalls(&mut self) {
        self.functions = load_nt_syscall_info().expect("Cannot load nt infos!");
        for func in &self.functions {
            if func.syscall_address.is_some() {
                self.syscall_addresses.push(func.syscall_address.unwrap())
            }
        }
    }

    pub fn retrieve_ssn(&self, func_name: &str) -> Result<u16> {
        for func in &self.functions {
            if func.name.to_lowercase() == func_name.to_lowercase() {
                if func.syscall_number.is_none() {
                    return Err(Box::from(format!("Function {} has no ssn !", func_name)));
                }
                return Ok(func.syscall_number.unwrap());
            }
        }
        return Err(Box::from(format!("Function {} cannot be found !", func_name)));
    }

    pub fn get_random_syscall_addr(&self) -> Result<u64> {
        if self.syscall_addresses.len() == 0 {
            return Err(Box::from("No syscall address available !"));
        }
        Ok(self.syscall_addresses.choose(&mut rand::thread_rng()).unwrap().clone())
    }
}