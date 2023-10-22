use crate::*;

use super::functions::__readgsqword;
use super::structs::PEB;
use super::structs::LDR_DATA_TABLE_ENTRY;
use super::structs::LIST_ENTRY;
use super::structs::IMAGE_DOS_HEADER;
use super::structs::IMAGE_NT_HEADERS64;
use super::structs::IMAGE_OPTIONAL_HEADER64;
use super::structs::IMAGE_DATA_DIRECTORY;
use super::structs::IMAGE_EXPORT_DIRECTORY;
use super::structs::IMAGE_DOS_SIGNATURE;
use super::structs::IMAGE_NT_SIGNATURE;
use super::structs::IMAGE_NT_OPTIONAL_HDR64_MAGIC;
use super::types::HINSTANCE;
use super::types::UINT_PTR;

use crate::error::Result;

pub struct FunctionInfo {
    pub name: String,
    pub address: u64,
    pub ordinal: u16,
    pub next_func_address: u64,
    pub syscall_number: Option<u16>,
    pub syscall_address: Option<u64>,
}

impl FunctionInfo {
    pub fn new(name: String, address: u64, ordinal: u16) -> Self {
        Self { name: name, address: address, ordinal: ordinal, next_func_address: 0, syscall_address: None, syscall_number: None }
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
        Self { name: String::from(self.name.to_string()), address: self.address, ordinal: self.ordinal, next_func_address: self.next_func_address, syscall_address: self.syscall_address, syscall_number: self.syscall_number }
    }
}

pub fn load_nt_syscall_info() -> Result<Vec<FunctionInfo>> {
    let nt_dll_name = "ntdll.dll";
    let nt_base_address = get_dll_base_address(nt_dll_name.to_lowercase().as_str());

    let mut all_functions = get_dll_functions(nt_base_address)?;
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

            nt_functions.push(new_fun)
        }
    }

    //Look for syscalls address
    unsafe {
        for func in & mut nt_functions {
            for byte_index in 0..func.size()-1 {
                let look_start_address = func.address + (byte_index as u64);

                //look for ssn
                if *(look_start_address as  *const u8) == 0x4C 
                    && *((look_start_address + 1) as  *const u8) == 0x8B 
                    && *((look_start_address + 2) as  *const u8) == 0xD1 
                    && *((look_start_address + 3) as  *const u8) == 0xB8 
                    {
                        let low =  *((look_start_address + 4) as  *const u8);
                        let high =  *((look_start_address + 5) as  *const u8);

                        func.syscall_number = Some((high as u16) << 8 | (low as u16));
                    }
                
                //look for syscall address
                if *(look_start_address as  *const u8) == 0x0F 
                    && *((look_start_address + 1) as  *const u8) == 0x05
                    && *((look_start_address + 2) as  *const u8) == 0xC3
                    {
                        func.syscall_address = Some(look_start_address);
                    }
            }
        }
    }

    Ok(nt_functions)
}

pub fn get_dll_base_address(module_name: &str) -> HINSTANCE {
    unsafe {

        let peb_offset: *const u64 = __readgsqword(0x60)  as *const u64;
        //debug_info!(peb_offset);
        let rf_peb: *const PEB = peb_offset as * const PEB;
        let peb = *rf_peb;
        let mut p_ldr_data_table_entry: *const LDR_DATA_TABLE_ENTRY = (*peb.Ldr).InMemoryOrderModuleList.Flink as *const LDR_DATA_TABLE_ENTRY;
        let mut p_list_entry = &(*peb.Ldr).InMemoryOrderModuleList as *const LIST_ENTRY;

        loop {
            let dll_name = (*p_ldr_data_table_entry).FullDllName.to_string().unwrap();
            
            //last element of the list => shoudl stop the loop
            if p_list_entry == (*peb.Ldr).InMemoryOrderModuleList.Blink {
                return 0
            }

            if module_name.to_lowercase() == dll_name.to_lowercase() {
                let module_base: HINSTANCE = (*p_ldr_data_table_entry).Reserved2[0] as HINSTANCE;
                return module_base;
            }

            //go to next element of the list
            p_list_entry = (*p_list_entry).Flink;
            p_ldr_data_table_entry = (*p_list_entry).Flink as *const LDR_DATA_TABLE_ENTRY;
        }
    }
}

pub fn get_proc_address(module_handle: HINSTANCE, function_name: &str) -> u64 {
    let dos_headers: *const IMAGE_DOS_HEADER;
    let nt_headers: *const IMAGE_NT_HEADERS64;
    let optional_header: * const IMAGE_OPTIONAL_HEADER64;
    let data_directory: *const IMAGE_DATA_DIRECTORY;
    let export_directory: *const IMAGE_EXPORT_DIRECTORY;
    let mut function_address_array: UINT_PTR;
    let mut function_name_array: UINT_PTR;
    let mut function_ordinals_array: UINT_PTR;
    
    unsafe {
        dos_headers = module_handle as *const IMAGE_DOS_HEADER;
        if (*dos_headers).e_magic != IMAGE_DOS_SIGNATURE {
            debug_error!("Invalid dos signature!");
        }

        nt_headers = (module_handle as u64 + (*dos_headers).e_lfanew as u64) as *const IMAGE_NT_HEADERS64;
        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            debug_error!("Invalid NT signature!");
        }

        optional_header	= &(*nt_headers).OptionalHeader;
        if (*optional_header).Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            debug_error!("Invalid Optional Header signature!");
        }

        data_directory = (&(*optional_header).DataDirectory[0]) as *const IMAGE_DATA_DIRECTORY;
        export_directory = (module_handle as u64 + (*data_directory).VirtualAddress as u64) as *const IMAGE_EXPORT_DIRECTORY;
        function_address_array = (module_handle as u64 + (*export_directory).AddressOfFunctions as u64) as UINT_PTR;
        function_name_array = (module_handle as u64 + (*export_directory).AddressOfNames as u64) as UINT_PTR;
        function_ordinals_array = (module_handle as u64 + (*export_directory).AddressOfNameOrdinals as u64) as UINT_PTR;
        
        //debug_info!((*export_directory).NumberOfFunctions);
        for _ in 1..(*export_directory).NumberOfFunctions {
            let name_offest: u32 = *(function_name_array as *const u32);

            let fun_name = std::ffi::CStr::from_ptr(
                (module_handle as u64 + name_offest as u64) as *const i8
            ).to_str().unwrap();
            
            let fun_ord = *(function_ordinals_array as *const u16);
            let address_ptr = function_address_array + fun_ord as u64 * (std::mem::size_of::<u32>() as u64);
            let fun_addr = module_handle as u64 + *(address_ptr as *const u32) as u64;
            //debug_info!(fun_name);
            //debug_info!(fun_ord);
            //debug_info!(fun_addr); 

            if fun_name.to_lowercase() == function_name.to_lowercase() {
                return fun_addr;
            }

            function_name_array = function_name_array + std::mem::size_of::<u32>() as u64;
            function_ordinals_array = function_ordinals_array + std::mem::size_of::<u16>() as u64;
        }
        return 0;
    }
}

pub fn get_loaded_dlls() -> Vec<String> {
    unsafe {
        let mut dlls: Vec<String> = vec!();

        let peb_offset: *const u64 = __readgsqword(0x60)  as *const u64;
        debug_info!(peb_offset);
        let rf_peb: *const PEB = peb_offset as * const PEB;
        let peb = *rf_peb;
        let mut p_ldr_data_table_entry: *const LDR_DATA_TABLE_ENTRY = (*peb.Ldr).InMemoryOrderModuleList.Flink as *const LDR_DATA_TABLE_ENTRY;
        let mut p_list_entry = &(*peb.Ldr).InMemoryOrderModuleList as *const LIST_ENTRY;

        loop {
            let dll_name = (*p_ldr_data_table_entry).FullDllName.to_string().unwrap();
            
            //last element of the list => shoudl stop the loop
            if p_list_entry == (*peb.Ldr).InMemoryOrderModuleList.Blink {
                return dlls
            }

            dlls.push(dll_name);

            //go to next element of the list
            p_list_entry = (*p_list_entry).Flink;
            p_ldr_data_table_entry = (*p_list_entry).Flink as *const LDR_DATA_TABLE_ENTRY;
        }
    }
}

pub fn get_dll_functions(module_handle: HINSTANCE) -> Result<Vec<FunctionInfo>> {
    let mut functions: Vec<FunctionInfo> = vec!();
 
    let dos_headers: *const IMAGE_DOS_HEADER;
    let nt_headers: *const IMAGE_NT_HEADERS64;
    let optional_header: * const IMAGE_OPTIONAL_HEADER64;
    let data_directory: *const IMAGE_DATA_DIRECTORY;
    let export_directory: *const IMAGE_EXPORT_DIRECTORY;
    let mut function_address_array: UINT_PTR;
    let mut function_name_array: UINT_PTR;
    let mut function_ordinals_array: UINT_PTR;
    
    unsafe {
        dos_headers = module_handle as *const IMAGE_DOS_HEADER;
        if (*dos_headers).e_magic != IMAGE_DOS_SIGNATURE {
            return Err(Box::from("Invalid dos signature!"));
        }

        nt_headers = (module_handle as u64 + (*dos_headers).e_lfanew as u64) as *const IMAGE_NT_HEADERS64;
        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            return Err(Box::from("Invalid NT signature!"));
        }

        optional_header	= &(*nt_headers).OptionalHeader;
        if (*optional_header).Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            return Err(Box::from("Invalid Optional Header signature!"));
        }

        data_directory = (&(*optional_header).DataDirectory[0]) as *const IMAGE_DATA_DIRECTORY;
        export_directory = (module_handle as u64 + (*data_directory).VirtualAddress as u64) as *const IMAGE_EXPORT_DIRECTORY;
        function_address_array = (module_handle as u64 + (*export_directory).AddressOfFunctions as u64) as UINT_PTR;
        function_name_array = (module_handle as u64 + (*export_directory).AddressOfNames as u64) as UINT_PTR;
        function_ordinals_array = (module_handle as u64 + (*export_directory).AddressOfNameOrdinals as u64) as UINT_PTR;
        
        //debug_info!((*export_directory).NumberOfFunctions);
        for _ in 1..(*export_directory).NumberOfFunctions {
            let name_offest: u32 = *(function_name_array as *const u32);

            let fun_name = std::ffi::CStr::from_ptr(
                (module_handle as u64 + name_offest as u64) as *const i8
            ).to_str().unwrap();
            
            let fun_ord = *(function_ordinals_array as *const u16);
            let address_ptr = function_address_array + fun_ord as u64 * (std::mem::size_of::<u32>() as u64);
            let fun_addr = module_handle as u64 + *(address_ptr as *const u32) as u64;
            //debug_info!(fun_name);
            //debug_info!(fun_ord);
            //debug_info!(fun_addr); 

            function_name_array = function_name_array + std::mem::size_of::<u32>() as u64;
            function_ordinals_array = function_ordinals_array + std::mem::size_of::<u16>() as u64;

            functions.push(FunctionInfo::new(String::from(fun_name), fun_addr, fun_ord));
        }
 
    }

    Ok(functions)
}

