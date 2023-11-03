mod common;
mod winapi;

use std::mem::size_of;

use winapi::types::{HINSTANCE, HANDLE};
use winapi::dll_functions::get_dll_base_address;
use crate::winapi::constants::{NULL, TRUE, INVALID_HANDLE_VALUE};
use crate::winapi::dll_functions::get_proc_address;
use crate::winapi::kernel32::{FILE_DISPOSITION_INFO, SYNCHRONIZE, DELETE, FILE_SHARE_READ, OPEN_EXISTING, SECURITY_ATTRIBUTES, FileDispositionInfo, FILE_RENAME_INFO, FileRenameInfo, MAX_PATH16, GetLastError, CloseHandle, CreateFileW, GetModuleFileNameW, SetFileInformationByHandle};
use crate::winapi::types::PWSTR;



fn main() {
        let kernel32_base_address: HINSTANCE = get_dll_base_address("kernel32.dll");
        debug_success_msg!(format!("kernel32.dll found at address {:?}", kernel32_base_address as *const u64));

        let fn_set_file_information_by_handle: SetFileInformationByHandle = unsafe { std::mem::transmute(get_proc_address(kernel32_base_address, "SetFileInformationByHandle")) };
         debug_success_msg!(format!("kernel32.dll.fn_set_file_information_by_handle found at address {:?}", fn_set_file_information_by_handle as *const u64));

        let fn_get_module_filename: GetModuleFileNameW = unsafe { std::mem::transmute(get_proc_address(kernel32_base_address, "GetModuleFileNameW")) };
        debug_success_msg!(format!("kernel32.dll.fn_get_module_filename found at address {:?}", fn_get_module_filename as *const u64));

        let fn_create_file: CreateFileW = unsafe { std::mem::transmute(get_proc_address(kernel32_base_address, "CreateFileW")) };
        debug_success_msg!(format!("kernel32.dll.CreateFileW found at address {:?}", fn_create_file as *const u64));

        let fn_close_handle: CloseHandle = unsafe { std::mem::transmute(get_proc_address(kernel32_base_address, "CloseHandle")) };
        debug_success_msg!(format!("kernel32.dll.CloseHandle found at address {:?}", fn_close_handle as *const u64));

        let fn_get_last_error: GetLastError = unsafe { std::mem::transmute(get_proc_address(kernel32_base_address, "GetLastError")) };
        debug_success_msg!(format!("kernel32.dll.GetLastErrorHandle found at address {:?}", fn_get_last_error as *const u64));


        //Get the path of the executable
        let filename_ptr = PWSTR::from_raw([0u16;MAX_PATH16 as usize].as_mut_ptr());
        if unsafe { fn_get_module_filename(NULL as HANDLE, filename_ptr, MAX_PATH16 * 2) } == 0 {
                debug_error_msg!("Failed to get the current module path");
                return
        }
        let module_filename = unsafe {filename_ptr.to_string().unwrap()};
        debug_info!(&module_filename);
        

        //Rename the Stream
        let new_stream = ":TestDelete";
        debug_info_msg!(format!("Renaming :$DATA to {}  ...", new_stream));

        let mut file_handle = unsafe { fn_create_file(filename_ptr, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL as *mut SECURITY_ATTRIBUTES, OPEN_EXISTING, 0u32, NULL as HANDLE) };
        if file_handle == INVALID_HANDLE_VALUE {
                debug_error_msg!("Failed to get a file handle on the current module file");
                return
        }
        //debug_info!(file_handle);

        let mut rename_info = FILE_RENAME_INFO::default();
        rename_info.FileNameLength = (new_stream.len() * 2) as u32;

        //copy the actual stream name to the struc FILE_RENAME_INFO
        let v : Vec<u16> = new_stream.encode_utf16().collect();
        for (place, data) in rename_info.FileName.iter_mut().zip(v.iter()) {
                *place = *data
            }

        //debug_info!(rename_info.FileNameLength);

        if unsafe { fn_set_file_information_by_handle(file_handle, FileRenameInfo, (&rename_info as *const FILE_RENAME_INFO) as usize , size_of::<FILE_RENAME_INFO>() as u32) != TRUE }  {
                debug_error_msg!(format!("Failed to rename the module file: Error {:?}",unsafe { fn_get_last_error() as *const usize } ));
                return
        }

        debug_ok_msg!("done !");

        let _ = unsafe { fn_close_handle(file_handle) };


        //Delete the file
        debug_info_msg!(format!("Deleting {}  ...", &module_filename));
        file_handle = unsafe { fn_create_file(filename_ptr, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL as *mut SECURITY_ATTRIBUTES, OPEN_EXISTING, 0u32, NULL as HANDLE) };
        if file_handle == INVALID_HANDLE_VALUE {
                debug_error_msg!("Failed to get a file handle on the current module file");
                return
        }
        //debug_info!(file_handle);


        let delete_info = FILE_DISPOSITION_INFO  {
                DeleteFile: 1,
        };

        if unsafe { fn_set_file_information_by_handle(file_handle, FileDispositionInfo, (&delete_info as *const FILE_DISPOSITION_INFO) as usize , size_of::<FILE_DISPOSITION_INFO>() as u32) != TRUE }  {
                debug_error_msg!(format!("Failed to delete the module file: Error {:?}",unsafe { fn_get_last_error() as *const usize } ));
                return
        }

        debug_ok_msg!("done !");

        let _ = unsafe { fn_close_handle(file_handle) };
}
