mod debug;
mod winapi;
mod syscall;

use std::error::Error;

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

use winapi::helpers::load_nt_syscall_info;

fn main() {
    let nt_functions = load_nt_syscall_info();

    for func in nt_functions.unwrap() {
        debug_info_msg!(format!("[{:?} => {:?}] Size = {} bytes : {} | Syscall #{:?} jump at {:?}", 
            func.address as *const u64, 
            func.next_func_address as *const u64, 
            func.size(), 
            func.name,
            func.syscall_number,
            func.syscall_address));
        }
}
