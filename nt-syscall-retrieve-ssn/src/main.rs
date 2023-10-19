mod debug;
mod winapi;

use std::error::Error;

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;


use winapi::helpers::load_nt_syscall_info;


pub type HWND = isize;
pub type MessageBoxA = unsafe extern "system" fn (HWND, winapi::types::PCSTR, winapi::types::PCSTR, u32) -> i32;
pub type LoadLibraryA = unsafe extern "system" fn (winapi::types::PCSTR) -> i32;

fn main() {
    let _ = load_nt_syscall_info();


    //Example 1 : List all dlls and all functions of the current process
    // let dlls = get_loaded_dlls();

    // debug_info_msg!("List of loaded dlls in current Process : ");
    // for dll_name in dlls {
    //     let base_address = get_dll_base_address(&dll_name);
    //     debug_ok_msg!(format!("Found dll {} at address {:?}", dll_name.to_lowercase().as_str(), base_address as *const u64));

    //     let func_res = get_dll_functions(base_address);
    //     if func_res.is_err() {
    //         let error = func_res.err().unwrap();
    //         debug_error!("Error ", &error);
    //         continue;
    //     }
        
    //     let functions = func_res.unwrap();
    //     for fun_info in functions {
    //         debug_ok_msg!(format!("Found function {} #{} at {:?}", fun_info.name, fun_info.ordinal, fun_info.address as *const u64));
    //     }
    // }

    //Example 2 : List all functions of the current process's ntdll
    // let dll_name = "ntdll.dll";
    // let base_address = get_dll_base_address(dll_name.to_lowercase().as_str());
    // debug_ok_msg!(format!("Found dll {} at address {:?}", dll_name.to_lowercase().as_str(), base_address as *const u64));

    // let func_res = get_dll_functions(base_address);
    // if func_res.is_err() {
    //     let error = func_res.err().unwrap();
    //     debug_error!("Error ", &error);
    //     return;
    // }
    
    // let functions = func_res.unwrap();
    // for fun_info in functions {
    //     debug_ok_msg!(format!("Found function {} #{} at {:?}", fun_info.name, fun_info.ordinal, fun_info.address as *const u64));
    // }

    //Example 3 : Find the address of a the NtMapViewOfSection
    // let dll_name = "ntdll.dll";
    // let function_name = "NtMapViewOfSection";
    // let dll_base_address = get_dll_base_address(dll_name);
    // let function_address = get_proc_address(dll_base_address, function_name);
    // debug_success_msg!(format!("Found function {} on dll {} at address {:?}", function_name, dll_name, function_address as *const u64));

    //Example 4 loading and displaying MessageBox
    // unsafe {
    //     let kernel32_base_address: HINSTANCE = get_dll_base_address("kernel32.dll");
    //     debug_success_msg!(format!("kernel32.dll found at address {:?}", kernel32_base_address as *const u64));

    //     let fn_load_library: LoadLibraryA = std::mem::transmute(get_proc_address(kernel32_base_address, "LoadLibraryA"));
    //     debug_success_msg!(format!("kernel32.dll.LoadLibraryA found at address {:?}", fn_load_library as *const u64));

    //     fn_load_library(winapi::types::PCSTR::from_raw("user32.dll\0".as_ptr()));
    //     debug_success_msg!("user32.dll loaded!");

    //     let user32_base_address: HINSTANCE = get_dll_base_address("user32.dll");
    //     debug_success_msg!(format!("user32.dll found at address {:?}", user32_base_address as *const u64));

    //     let fn_message_box: MessageBoxA = std::mem::transmute(get_proc_address(user32_base_address, "MessageBoxA"));
    //     debug_success_msg!(format!("user32.dll.MessageBoxA found at address {:?}", fn_load_library as *const u64));

    //     fn_message_box(0, winapi::types::PCSTR::from_raw("This Message box was loaded manually !\0".as_ptr()), winapi::types::PCSTR::from_raw("Test Message Box\0".as_ptr()), 0);
    //     debug_success_msg!("MessageBox displayed!");
    // }

}
