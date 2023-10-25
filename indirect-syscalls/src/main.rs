#[macro_use]
mod debug;
mod winapi;
mod error;

use winapi::types::HANDLE;

use winapi::syscall_wrapper::SyscallWrapper;

use crate::winapi::structs::{PROCESS_ALL_ACCESS, STATUS_SUCCESS};
pub const PAGE_READWRITE: u32 = 4u32;
pub const MEM_COMMIT: u32 = 4096u32;
pub const MEM_RESERVE: u32 = 8192u32;

fn main() {
        let mut size: usize = 100;
        let mut address: usize = 0;

        let process_id: isize = 10596;
        let mut process_handle: HANDLE = 0;

        let ntdll = SyscallWrapper::new();
 
        let nt_open_process_res = ntdll.NtOpenProcess(&mut process_handle, PROCESS_ALL_ACCESS, process_id);
        debug_info_hex!(nt_open_process_res);
        debug_info!(process_handle);
        
        if nt_open_process_res != STATUS_SUCCESS {
            debug_error_msg!(format!("Failed to retrieve handle to process #{}", process_id));
            return;
        }

        let nt_allocate_virtual_memory_res = ntdll.NtAllocateVirtualMemory(process_handle, &mut address,  &mut size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        debug_info_hex!(nt_allocate_virtual_memory_res);
        debug_info!(size);
        debug_info_hex!(address);
        if nt_allocate_virtual_memory_res != STATUS_SUCCESS {
            debug_error_msg!(format!("Failed to allocate memory (size = {})", size));
            return;
        }
}
