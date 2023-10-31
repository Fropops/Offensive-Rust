#[cfg(all(feature = "syscall_indirect", not(feature = "syscall_direct")))]
use rand::seq::SliceRandom;

use super::helpers::FunctionInfo;
use super::helpers::load_nt_syscall_info;
use super::structs::CLIENT_ID;

// use crate::debug_info_hex;
// use crate::debug_base_hex;

// use crate::debug_info;
// use crate::debug_info_msg;
use crate::error::Result;
use crate::syscall;

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
    #[allow(dead_code)]
    pub fn nt_allocate_virtual_memory(&self, process_handle: HANDLE, base_address: &mut usize, region_size: &mut usize, allocation_type: u32, protect: u32) -> i32 {
        let func_name = lc!("NtAllocateVirtualMemory");
        
        unsafe {
                syscall!(
                self,
                func_name,
                process_handle,
                base_address,
                0usize,
                region_size,
                allocation_type,
                protect
            )
        }
    }

    // NTSTATUS NtProtectVirtualMemory(
    //     IN HANDLE               ProcessHandle,
    //     IN OUT PVOID            *BaseAddress,
    //     IN OUT PULONG           NumberOfBytesToProtect,
    //     IN ULONG                NewAccessProtection,
    //     OUT PULONG              OldAccessProtection );
    #[allow(dead_code)]
    pub fn nt_protect_virtual_memory(&self, process_handle: HANDLE, base_address: &mut usize, number_of_bytes_to_protect: &mut usize, new_access_portection: u32, old_access_protection: &mut u32) -> i32 {
        let func_name = lc!("NtProtectVirtualMemory");
        unsafe {
                syscall!(
                self,
                func_name,
                process_handle,
                base_address,
                number_of_bytes_to_protect,
                new_access_portection,
                old_access_protection
            )
        }
    }

    // NTSTATUS NtWriteVirtualMemory(
    //     IN HANDLE               ProcessHandle,          // Process handle whose memory is to be written to          
    //     IN PVOID                BaseAddress,            // Base address in the specified process to which data is written
    //     IN PVOID                Buffer,                 // Data to be written
    //     IN ULONG                NumberOfBytesToWrite,   // Number of bytes to be written
    //     OUT PULONG              NumberOfBytesWritten    // Pointer to a variable that receives the number of bytes actually written 
    //   );
    #[allow(dead_code)]
    pub fn nt_write_virtual_memory(&self, process_handle: HANDLE, base_address: usize, buffer: usize, number_of_bytes_to_write: usize, number_of_bytes_written: &mut usize) -> i32 {
        let func_name = lc!("NtWriteVirtualMemory");
        unsafe {
                syscall!(
                self,
                func_name,
                process_handle,
                base_address,
                buffer,
                number_of_bytes_to_write,
                number_of_bytes_written
            )
        }
    }

    // NTSTATUS NtCreateThreadEx(
    //     OUT PHANDLE                 ThreadHandle,         // Pointer to a HANDLE variable that recieves the created thread's handle
    //     IN 	ACCESS_MASK             DesiredAccess,        // Thread's access rights (set to THREAD_ALL_ACCESS - 0x1FFFFF)  
    //     IN 	POBJECT_ATTRIBUTES      ObjectAttributes,     // Pointer to OBJECT_ATTRIBUTES structure (set to NULL)
    //     IN 	HANDLE                  ProcessHandle,        // Handle to the process in which the thread is to be created.
    //     IN 	PVOID                   StartRoutine,         // Base address of the application-defined function to be executed
    //     IN 	PVOID                   Argument,             // Pointer to a variable to be passed to the thread function (set to NULL)
    //     IN 	ULONG                   CreateFlags,          // The flags that control the creation of the thread (set to NULL)
    //     IN 	SIZE_T                  ZeroBits,             // Set to NULL
    //     IN 	SIZE_T                  StackSize,            // Set to NULL
    //     IN 	SIZE_T                  MaximumStackSize,     // Set to NULL
    //     IN 	PPS_ATTRIBUTE_LIST      AttributeList         // Pointer to PS_ATTRIBUTE_LIST structure (set to NULL)
    // );
    #[allow(dead_code)]
    pub fn nt_create_thread_ex(&self, thread_handle: &mut HANDLE, desired_access: u32, process_handle: HANDLE, start_routine: usize) -> i32 {
        let func_name = lc!("NtCreateThreadEx");
        unsafe {
                syscall!(
                self,
                func_name,
                thread_handle,
                desired_access,
                0usize,
                process_handle,
                start_routine,
                0usize,
                0u32,
                0usize,
                0usize,
                0usize,
                0usize
            )
        }
    }

    //NTSTATUS NtOpenProcess(
    //     [out]          PHANDLE            ProcessHandle,
    //     [in]           ACCESS_MASK        DesiredAccess,
    //     [in]           POBJECT_ATTRIBUTES ObjectAttributes,
    //     [in, optional] PCLIENT_ID         ClientId
    //);
    #[allow(dead_code)]
    pub fn nt_open_process(&self, process_handle: &mut HANDLE, desired_access :u32, process_id: isize) -> i32 {
        let func_name = lc!("NtOpenProcess");
        
        let oa = OBJECT_ATTRIBUTES::default();

        let ci = CLIENT_ID {
            UniqueProcess: process_id as HANDLE,
            UniqueThread: 0,
        };

        unsafe {
            syscall!(
                self,
                func_name,
                process_handle,
                desired_access,
                &oa,
                &ci
            )
        }
    }

    // NTSTATUS NtWaitForSingleObject(
    //     [in] HANDLE         Handle,
    //     [in] BOOLEAN        Alertable,
    //     [in] PLARGE_INTEGER Timeout
    //   );
    #[allow(dead_code)]
    pub fn nt_wait_for_single_object(&self, handle: HANDLE) -> i32 {
        let func_name = lc!("NtWaitForSingleObject");
        unsafe {
            syscall!(
                self,
                func_name,
                handle,
                0usize,
                0usize
            )
        }
    }

    // NTSTATUS NtClose(
    //     [in] HANDLE Handle
    //   );
    #[allow(dead_code)]
    pub fn nt_close(&self, handle: HANDLE) -> i32 {
        let func_name = lc!("NtClose");
        unsafe {
            syscall!(
                self,
                func_name,
                handle
            )
        }
    }

    // NTSTATUS NtQuerySystemInformation(
    //     [in]            SYSTEM_INFORMATION_CLASS SystemInformationClass,
    //     [in, out]       PVOID                    SystemInformation,
    //     [in]            ULONG                    SystemInformationLength,
    //     [out, optional] PULONG                   ReturnLength
    //   );
    #[allow(dead_code)]
    pub fn nt_query_system_information(&self, system_information_class: i32, system_information: *mut u8, system_information_length: u32, return_length: *mut u32) -> i32 {
        let func_name = lc!("NtQuerySystemInformation");
        unsafe {
            syscall!(
                self,
                func_name,
                system_information_class,
                system_information,
                system_information_length,
                return_length
            )
        }
    }
}




struct SSNResolver {
    functions: Vec<FunctionInfo>,
    syscall_addresses: Vec<usize>,
}

impl SSNResolver {
    pub fn new() -> Self {
        Self {
            functions: vec![],
            syscall_addresses: vec![]
        }
    }

    pub fn load_syscalls(&mut self) {
        self.functions = load_nt_syscall_info().unwrap();
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
                    let mut error_msg = lc!("Function ");
                    error_msg.push_str(func_name);
                    error_msg.push_str(" has no ssn !");
                    return Err(Box::from(error_msg));
                }
                return Ok(func.syscall_number.unwrap());
            }
        }

        let mut error_msg = lc!("Function ");
        error_msg.push_str(func_name);
        error_msg.push_str(" cannot be found !");
        return Err(Box::from(error_msg));
    }

    #[cfg(all(feature = "syscall_indirect", not(feature = "syscall_direct")))]
    pub fn get_random_syscall_addr(&self) -> Result<usize> {
        if self.syscall_addresses.len() == 0 {
            let error_msg = lc!("No syscall address available !");
            return Err(Box::from(error_msg));
        }
        Ok(self.syscall_addresses.choose(&mut rand::thread_rng()).unwrap().clone())
        //Ok(0x77882e0a)
    }
}