use crate::winapi::dll_functions::{get_dll_base_address, get_dll_functions};
use crate::common::error::Result;


#[cfg(target_arch = "x86_64")]
pub fn get_syscall_function_size() -> isize {
    32
}

#[cfg(target_arch = "x86")]
pub fn get_syscall_function_size() -> isize {
    16
}

pub struct FunctionInfo {
    pub name: String,
    pub address: usize,
    pub ordinal: u16,
    pub hooked: bool,
    pub next_func_address: usize,
    pub syscall_number: Option<u16>,
    pub syscall_address: Option<usize>,
}

impl FunctionInfo {
    pub fn new(name: String, address: usize, ordinal: u16) -> Self {
        Self { name: name, address: address, ordinal: ordinal, next_func_address: 0, syscall_address: None, syscall_number: None, hooked: false }
    }

    pub fn size(&self) -> isize{
        if self.next_func_address == 0 {
            return -1;
        }
        (self.next_func_address - self.address) as isize
    }
}


impl Clone for FunctionInfo {
    fn clone(&self) -> Self {
        Self { name: String::from(self.name.to_string()), address: self.address, ordinal: self.ordinal, next_func_address: self.next_func_address, syscall_address: self.syscall_address, syscall_number: self.syscall_number, hooked: self.hooked }
    }
}


#[allow(dead_code)]
pub fn load_nt_syscall_info() -> Result<Vec<FunctionInfo>> {
    let syscall_function_size = get_syscall_function_size();
    

    let nt_dll_name = lc!("ntdll.dll");
    let nt_base_address = get_dll_base_address(nt_dll_name.to_lowercase().as_str());

    let mut all_functions = get_dll_functions(nt_base_address.unwrap())?;
    all_functions.sort_by(|a, b| a.address.cmp(&b.address));

    let mut nt_functions: Vec<FunctionInfo> = vec![];
    
    //filter on Nt functions and populate address of the next function
    for func_index in 0..all_functions.len()-1 {
        let func = &all_functions[func_index];
        let current_address = func.address;

        let mut new_fun = func.clone();

        if func.name.to_lowercase().starts_with("nt") { 
            for next_index in func_index+1..all_functions.len()-1 {
                let next_func = &all_functions[next_index];
                if next_func.address > current_address {
                    new_fun.next_func_address = next_func.address;
                    break;
                }
            }

            // debug_info!(&new_fun.name);
            // debug_info!(&new_fun.size());

            if new_fun.size() == syscall_function_size {
                nt_functions.push(new_fun)
            }
        }
    }

    //Look for syscalls address
    unsafe {
        for func in & mut nt_functions {
            // if &func.name == "NtAllocateVirtualMemory" {
            //     debug_info!(&func.name);
            //     debug_info_msg!(format!("{:#x}", func.address));
            // }
            //debug_info!(&func.name);
            //debug_info_msg!(format!("{:#x}", func.address));
            func.hooked = true;

            for byte_index in 0..func.size()-1 {
                let look_start_address = func.address + (byte_index as usize);

                //look for ssn
                #[cfg(target_arch = "x86_64")]
                if *(look_start_address as  *const u8) == 0x4C 
                    && *((look_start_address + 1) as  *const u8) == 0x8B 
                    && *((look_start_address + 2) as  *const u8) == 0xD1 
                    && *((look_start_address + 3) as  *const u8) == 0xB8 
                    {
                        let low =  *((look_start_address + 4) as  *const u8);
                        let high =  *((look_start_address + 5) as  *const u8);

                        func.syscall_number = Some((high as u16) << 8 | (low as u16));
                        //debug_info!(func.syscall_number);
                        func.hooked = false;
                    }

                #[cfg(target_arch = "x86")]
                if *(look_start_address as  *const u8) == 0xB8  
                    && *((look_start_address + 3) as  *const u8) == 0x00 
                    && *((look_start_address + 4) as  *const u8) == 0x00 
                    {
                        let low =  *((look_start_address + 1) as  *const u8);
                        let high =  *((look_start_address + 2) as  *const u8);

                        func.syscall_number = Some((high as u16) << 8 | (low as u16));
                        //debug_info!(func.syscall_number);
                        func.hooked = false;
                    }
                
                
                //look for syscall address
                #[cfg(target_arch = "x86_64")]
                if *(look_start_address as  *const u8) == 0x0F 
                    && *((look_start_address + 1) as  *const u8) == 0x05
                    && *((look_start_address + 2) as  *const u8) == 0xC3
                    {
                        func.syscall_address = Some(look_start_address);
                    }


                
                #[cfg(target_arch = "x86")]
                {
                    //debug_info_msg!(format!("{:#x} {:#x}", *(look_start_address as  *const u8), *((look_start_address + 1) as  *const u8)));
                    if *(look_start_address as  *const u8) == 0xFF 
                    && (*((look_start_address + 1) as  *const u8) == 0x12 || *((look_start_address + 1) as  *const u8) == 0xD2)
                    && (*((look_start_address + 2) as  *const u8) == 0xC3) //looking for ret alone if it's 0xC2, it changes the stack frame and then crashes the app
                    {
                        func.syscall_address = Some(look_start_address);
                        //debug_info_msg!(format!("jump {:#x}", look_start_address));
                    }
                }   

            }
        }
    }

    //find incremental syscall number for hooked syscalls
    let mut next_syscall_number = 0u16;
    for func in & mut nt_functions {
        if func.hooked {
            func.syscall_number = Some(next_syscall_number);
            next_syscall_number += 1;
        }
        else {
            next_syscall_number = func.syscall_number.unwrap() + 1;
        }
    }

    Ok(nt_functions)
}
