mod common;
mod winapi;


use winapi::types::HINSTANCE;
use winapi::dll_functions::get_dll_base_address;
// pub type HWND = isize;
// pub type MessageBoxA = unsafe extern "system" fn (HWND, winapi::types::PCSTR, winapi::types::PCSTR, u32) -> i32;
// pub type LoadLibraryA = unsafe extern "system" fn (winapi::types::PCSTR) -> i32;

fn main() {
        let kernel32_base_address: HINSTANCE = get_dll_base_address("kernel32.dll");
        debug_success_msg!(format!("kernel32.dll found at address {:?}", kernel32_base_address as *const u64));

        // let fn_load_library: LoadLibraryA = std::mem::transmute(get_proc_address(kernel32_base_address, "LoadLibraryA"));
        // debug_success_msg!(format!("kernel32.dll.LoadLibraryA found at address {:?}", fn_load_library as *const u64));

        // fn_load_library(winapi::types::PCSTR::from_raw("user32.dll\0".as_ptr()));
        // debug_success_msg!("user32.dll loaded!");

        // let user32_base_address: HINSTANCE = get_dll_base_address("user32.dll");
        // debug_success_msg!(format!("user32.dll found at address {:?}", user32_base_address as *const u64));

        // let fn_message_box: MessageBoxA = std::mem::transmute(get_proc_address(user32_base_address, "MessageBoxA"));
        // debug_success_msg!(format!("user32.dll.MessageBoxA found at address {:?}", fn_load_library as *const u64));

        // fn_message_box(0, winapi::types::PCSTR::from_raw("This Message box was loaded manually !\0".as_ptr()), winapi::types::PCSTR::from_raw("Test Message Box\0".as_ptr()), 0);
        // debug_success_msg!("MessageBox displayed!");
}
