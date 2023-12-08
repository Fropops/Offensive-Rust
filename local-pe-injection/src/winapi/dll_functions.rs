use crate::*;
use crate::winapi::kernel32::LoadLibraryA;
use crate::winapi::types::PCSTR;

use super::nt::syscall_functions::FunctionInfo;
use super::structs::LDR_DATA_TABLE_ENTRY;
use super::structs::LIST_ENTRY;
use super::structs::IMAGE_DOS_HEADER;
use super::types::IMAGE_NT_HEADERS;
use super::types::IMAGE_OPTIONAL_HEADER;
use super::structs::IMAGE_DATA_DIRECTORY;
use super::structs::IMAGE_EXPORT_DIRECTORY;
use super::constants::IMAGE_DOS_SIGNATURE;
use super::constants::IMAGE_NT_SIGNATURE;
use super::constants::IMAGE_NT_OPTIONAL_HDR_MAGIC;
use super::types::HINSTANCE;

use crate::common::error::Result;
pub struct FunctionLoadInfo {
    pub dll_name: Option<String>,
    pub func_name: Option<String>,
    pub func_ord: Option<u16>,
    pub address: Option<usize>,
    pub module_handle: Option<HINSTANCE>,
    pub loaded_in_memory: bool,
}

impl Default for FunctionLoadInfo {
    fn default() -> Self {
        Self { dll_name: Default::default(), func_ord: Default::default(), func_name: Default::default(), address: Default::default(), module_handle: Default::default(), loaded_in_memory: Default::default() }
    }
}


use core::arch::asm;
use super::{types::DWORD, structs::PEB};

#[cfg(target_arch = "x86_64")]
use super::types::DWORD64;

#[inline]
#[cfg(target_arch = "x86_64")]
pub unsafe fn __readgsqword(offset: DWORD) -> DWORD64 {
    let out: u64;
    asm!(
        "mov {}, gs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
    out
}

#[inline]
#[cfg(target_arch = "x86")]
pub unsafe fn __readfsdword(offset: DWORD) -> DWORD {
    let out: u32;
    asm!(
        "mov {}, fs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
    out
}


#[cfg(target_arch = "x86_64")]
pub fn get_peb() -> PEB {
    unsafe 
    {
        let peb_offset: *const usize = __readgsqword(0x60)  as *const usize;
        let rf_peb: *const PEB = peb_offset as * const PEB;
        *rf_peb
    }
}

#[cfg(target_arch = "x86")]
pub fn get_peb() -> PEB {
    unsafe 
    {
        let peb_offset: *const usize = __readfsdword(0x30)  as *const usize;
        let rf_peb: *const PEB = peb_offset as * const PEB;
        *rf_peb
    }
}

#[allow(dead_code)]
pub fn get_dll_base_address(module_name: &str) -> Option<HINSTANCE> {
    unsafe {
        let peb = get_peb();
        let mut p_ldr_data_table_entry: *const LDR_DATA_TABLE_ENTRY = (*peb.Ldr).InMemoryOrderModuleList.Flink as *const LDR_DATA_TABLE_ENTRY;
        let mut p_list_entry = &(*peb.Ldr).InMemoryOrderModuleList as *const LIST_ENTRY;

        loop {
            let dll_name = (*p_ldr_data_table_entry).FullDllName.to_string().unwrap();
            
            //last element of the list => shoudl stop the loop
            if p_list_entry == (*peb.Ldr).InMemoryOrderModuleList.Blink {
                return None
            }

            if module_name.to_lowercase() == dll_name.to_lowercase() {
                let module_base: HINSTANCE = (*p_ldr_data_table_entry).Reserved2[0] as HINSTANCE;
                return Some(module_base);
            }

            //go to next element of the list
            p_list_entry = (*p_list_entry).Flink;
            p_ldr_data_table_entry = (*p_list_entry).Flink as *const LDR_DATA_TABLE_ENTRY;
        }
    }
}

pub fn get_dll_proc_address_forwarded(dll_and_func_name: &str) -> FunctionLoadInfo {
    let parts: Vec<&str> = dll_and_func_name.split(".").collect();
    let dll_name = parts[0];
    let dll_func = parts[1];

    get_dll_proc_address(dll_name, dll_func)
}

#[allow(dead_code)]
pub fn get_dll_proc_address(dll_name: &str, function_name: &str) -> FunctionLoadInfo {
    unsafe {
        let mut fn_load_info = FunctionLoadInfo::default();
        fn_load_info.dll_name = Some(String::from(dll_name));
        fn_load_info.func_name = Some(String::from(function_name));

        let mut dll_name_str = String::from(dll_name);
        dll_name_str.push('\0');

        let local_handle = get_dll_base_address(dll_name);
        match local_handle {
            None => {
                let loaded_handle = LoadLibraryA(PCSTR::from_raw(dll_name_str.as_bytes().as_ptr()));
                if loaded_handle == 0 {
                    return fn_load_info;
                }
                fn_load_info.loaded_in_memory = true;
                fn_load_info.module_handle = Some(loaded_handle);
            },
            Some(handle) => fn_load_info.module_handle = Some(handle)
        }

        let mut info = get_proc_address(fn_load_info.module_handle.unwrap(), function_name);
        if info.dll_name.is_none() {
            info.dll_name = fn_load_info.dll_name.clone();
            if fn_load_info.loaded_in_memory {
                info.loaded_in_memory = true;
            }
        }
        return info;
    }
}


#[allow(dead_code)]
pub fn get_proc_address(module_handle: HINSTANCE, function_name: &str) -> FunctionLoadInfo {
    let mut fn_load_info = FunctionLoadInfo::default();
    fn_load_info.func_name = Some(String::from(function_name));
    fn_load_info.module_handle = Some(module_handle);

    let dos_headers: *const IMAGE_DOS_HEADER;
    let nt_headers: *const IMAGE_NT_HEADERS;
    let optional_header: * const IMAGE_OPTIONAL_HEADER;
    let data_directory: *const IMAGE_DATA_DIRECTORY;
    let export_directory: *const IMAGE_EXPORT_DIRECTORY;
    let function_address_array: usize;
    let mut function_name_array: usize;
    let mut function_ordinals_array: usize;
    
    unsafe {
        dos_headers = module_handle as *const IMAGE_DOS_HEADER;
        if (*dos_headers).e_magic != IMAGE_DOS_SIGNATURE {
            debug_error!("Invalid dos signature!");
            return fn_load_info;
        }

        nt_headers = (module_handle as usize + (*dos_headers).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            debug_error!("Invalid NT signature!");
            return fn_load_info;
        }

        optional_header	= &(*nt_headers).OptionalHeader;
        if (*optional_header).Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC {
            debug_error!("Invalid Optional Header signature!");
            return fn_load_info;
        }

        data_directory = (&(*optional_header).DataDirectory[0]) as *const IMAGE_DATA_DIRECTORY;
        export_directory = (module_handle as usize + (*data_directory).VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;
        function_address_array = (module_handle as usize + (*export_directory).AddressOfFunctions as usize) as usize;
        function_name_array = (module_handle as usize + (*export_directory).AddressOfNames as usize) as usize;
        function_ordinals_array = (module_handle as usize + (*export_directory).AddressOfNameOrdinals as usize) as usize;
        
        //debug_info!((*export_directory).NumberOfFunctions);
        for _index in 0..(*export_directory).NumberOfNames { 
            let name_offest: u32 = *(function_name_array as *const u32);

            let fun_name = std::ffi::CStr::from_ptr(
                (module_handle as usize + name_offest as usize) as *const i8
            ).to_str().unwrap();

            let fun_ord = *(function_ordinals_array as *const u16);
            let address_ptr = function_address_array + fun_ord as usize * (std::mem::size_of::<u32>() as usize);
            let fun_rva = *(address_ptr as *const u32) as usize;
  
            if fun_name.to_lowercase() == function_name.to_lowercase() {
                //it's a forward
                if fun_rva > (*data_directory).VirtualAddress as usize && fun_rva < (*data_directory).VirtualAddress as usize + (*data_directory).Size as usize {
                    
                    let forward_name_pcstr = PCSTR::from_raw((module_handle as usize + fun_rva) as *const u8);
                    let forward_name = forward_name_pcstr.to_string().unwrap();
                    let inf = get_dll_proc_address_forwarded(forward_name.as_str());
                    //debug_info_msg!(format!("forwarded from {} to {}, found at {:#x}", fun_name, forward_name, fn_adr));
                    return inf;
                }

                fn_load_info.address = Some(module_handle as usize + *(address_ptr as *const u32) as usize);
                return fn_load_info;
            }

            function_name_array = function_name_array + std::mem::size_of::<u32>() as usize;
            function_ordinals_array = function_ordinals_array + std::mem::size_of::<u16>() as usize;
        }
        return fn_load_info;
    }
}


pub fn get_dll_proc_address_by_ordinal_index(dll_name: &str, ordinal_index: u16) -> FunctionLoadInfo {
    let mut fn_load_info = FunctionLoadInfo::default();
    fn_load_info.dll_name = Some(String::from(dll_name));
    fn_load_info.func_ord = Some(ordinal_index);


    unsafe {
        let mut dll_name_str = String::from(dll_name);
        dll_name_str.push('\0');

        let local_handle = get_dll_base_address(dll_name);
        match local_handle {
            None => {
                let loaded_handle = LoadLibraryA(PCSTR::from_raw(dll_name_str.as_bytes().as_ptr()));
                if loaded_handle == 0 {
                    return fn_load_info;
                }
                fn_load_info.loaded_in_memory = true;
                fn_load_info.module_handle = Some(loaded_handle);
            },
            Some(handle) => fn_load_info.module_handle = Some(handle)
        }

        let mut info = get_proc_address_by_ordinal_index(fn_load_info.module_handle.unwrap(), ordinal_index);
        if info.dll_name.is_none() {
            info.dll_name = fn_load_info.dll_name.clone();
            if fn_load_info.loaded_in_memory {
                info.loaded_in_memory = true;
            }
        }
        return info;
    }
}

#[allow(dead_code)]
pub fn get_proc_address_by_ordinal_index(module_handle: HINSTANCE, ordinal_index: u16) -> FunctionLoadInfo {
    let mut fn_load_info = FunctionLoadInfo::default();
    fn_load_info.module_handle = Some(module_handle);
    fn_load_info.func_ord = Some(ordinal_index);

    let dos_headers: *const IMAGE_DOS_HEADER;
    let nt_headers: *const IMAGE_NT_HEADERS;
    let optional_header: * const IMAGE_OPTIONAL_HEADER;
    let data_directory: *const IMAGE_DATA_DIRECTORY;
    let export_directory: *const IMAGE_EXPORT_DIRECTORY;
    let function_address_array: usize;
    
    unsafe {
        dos_headers = module_handle as *const IMAGE_DOS_HEADER;
        if (*dos_headers).e_magic != IMAGE_DOS_SIGNATURE {
            debug_error!("Invalid dos signature!");
            return fn_load_info;
        }

        nt_headers = (module_handle as usize + (*dos_headers).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            debug_error!("Invalid NT signature!");
            return fn_load_info;
        }

        optional_header	= &(*nt_headers).OptionalHeader;
        if (*optional_header).Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC {
            debug_error!("Invalid Optional Header signature!");
            return fn_load_info;
        }

        data_directory = (&(*optional_header).DataDirectory[0]) as *const IMAGE_DATA_DIRECTORY;
        export_directory = (module_handle as usize + (*data_directory).VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;
        function_address_array = (module_handle as usize + (*export_directory).AddressOfFunctions as usize) as usize;
        
        for index in 1..(*export_directory).NumberOfFunctions as u16 { 
            if index == ordinal_index {

                let address_ptr = function_address_array + (index - 1) as usize * (std::mem::size_of::<u32>() as usize);
                let fun_rva = *(address_ptr as *const u32) as usize;

                if fun_rva > (*data_directory).VirtualAddress as usize && fun_rva < (*data_directory).VirtualAddress as usize + (*data_directory).Size as usize {
                    let forward_name_pcstr = PCSTR::from_raw((module_handle as usize + fun_rva) as *const u8);
                    let forward_name = forward_name_pcstr.to_string().unwrap();
                    let info = get_dll_proc_address_forwarded(forward_name.as_str());
                    //debug_info_msg!(format!("forwarded from #{} to {}, found at {:#x}", ordinal_index, forward_name, fn_adr));
                    return info;
                }
                //debug_info_hex!(*(address_ptr as *const u32) as usize);
                fn_load_info.address = Some(module_handle as usize + *(address_ptr as *const u32) as usize);
                return fn_load_info;
            }
        }
        return fn_load_info;
    }
}

#[allow(dead_code)]
pub fn get_loaded_dlls() -> Vec<String> {
    unsafe {
        let mut dlls: Vec<String> = vec!();

        let peb = get_peb();
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

#[allow(dead_code)]
pub fn get_dll_functions(module_handle: HINSTANCE) -> Result<Vec<FunctionInfo>> {
    let mut functions: Vec<FunctionInfo> = vec!();
 
    let dos_headers: *const IMAGE_DOS_HEADER;
    let nt_headers: *const IMAGE_NT_HEADERS;
    let optional_header: * const IMAGE_OPTIONAL_HEADER;
    let data_directory: *const IMAGE_DATA_DIRECTORY;
    let export_directory: *const IMAGE_EXPORT_DIRECTORY;
    let function_address_array: usize;
    let mut function_name_array: usize;
    let mut function_ordinals_array: usize;
    
    unsafe {
        dos_headers = module_handle as *const IMAGE_DOS_HEADER;
        if (*dos_headers).e_magic != IMAGE_DOS_SIGNATURE {
            return Err(Box::from("Invalid dos signature!"));
        }

        nt_headers = (module_handle as u64 + (*dos_headers).e_lfanew as u64) as *const IMAGE_NT_HEADERS;
        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            return Err(Box::from("Invalid NT signature!"));
        }

        optional_header	= &(*nt_headers).OptionalHeader;
        if (*optional_header).Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC {
            return Err(Box::from("Invalid Optional Header signature!"));
        }

        data_directory = (&(*optional_header).DataDirectory[0]) as *const IMAGE_DATA_DIRECTORY;
        export_directory = (module_handle as usize + (*data_directory).VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;
        function_address_array = (module_handle as usize + (*export_directory).AddressOfFunctions as usize) as usize;
        function_name_array = (module_handle as usize + (*export_directory).AddressOfNames as usize) as usize;
        function_ordinals_array = (module_handle as usize + (*export_directory).AddressOfNameOrdinals as usize) as usize;


        let first_ord = *(function_ordinals_array as *const u16) as u32;
        for _index in first_ord..(*export_directory).NumberOfFunctions { 
            //debug_info_msg!(format!("{} of {}",_index,(*export_directory).NumberOfFunctions));
            let name_offest: u32 = *(function_name_array as *const u32);

            let fun_name = std::ffi::CStr::from_ptr(
                (module_handle as usize + name_offest as usize) as *const i8
            ).to_str().unwrap();
            
            let fun_ord = *(function_ordinals_array as *const u16);
            let address_ptr = function_address_array + fun_ord as usize * (std::mem::size_of::<u32>() as usize);
            let fun_addr = module_handle as usize + *(address_ptr as *const u32) as usize;

            function_name_array = function_name_array + std::mem::size_of::<u32>() as usize;
            function_ordinals_array = function_ordinals_array + std::mem::size_of::<u16>() as usize;

            functions.push(FunctionInfo::new(String::from(fun_name), fun_addr, fun_ord));
        }
 
    }

    Ok(functions)
}
