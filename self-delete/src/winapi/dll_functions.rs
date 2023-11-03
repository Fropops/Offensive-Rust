use crate::{debug_error, debug_base };

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
pub fn get_dll_base_address(module_name: &str) -> HINSTANCE {
    unsafe {
        let peb = get_peb();
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

#[allow(dead_code)]
pub fn get_proc_address(module_handle: HINSTANCE, function_name: &str) -> usize {
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
        }

        nt_headers = (module_handle as usize + (*dos_headers).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            debug_error!("Invalid NT signature!");
        }

        optional_header	= &(*nt_headers).OptionalHeader;
        if (*optional_header).Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC {
            debug_error!("Invalid Optional Header signature!");
        }

        data_directory = (&(*optional_header).DataDirectory[0]) as *const IMAGE_DATA_DIRECTORY;
        export_directory = (module_handle as usize + (*data_directory).VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;
        function_address_array = (module_handle as usize + (*export_directory).AddressOfFunctions as usize) as usize;
        function_name_array = (module_handle as usize + (*export_directory).AddressOfNames as usize) as usize;
        function_ordinals_array = (module_handle as usize + (*export_directory).AddressOfNameOrdinals as usize) as usize;
        
        //debug_info!((*export_directory).NumberOfFunctions);
        let first_ord = *(function_ordinals_array as *const u16) as u32;
        for _index in first_ord..(*export_directory).NumberOfFunctions { 
            let name_offest: u32 = *(function_name_array as *const u32);

            let fun_name = std::ffi::CStr::from_ptr(
                (module_handle as usize + name_offest as usize) as *const i8
            ).to_str().unwrap();
            
            let fun_ord = *(function_ordinals_array as *const u16);
            let address_ptr = function_address_array + fun_ord as usize * (std::mem::size_of::<u32>() as usize);
            let fun_addr = module_handle as usize + *(address_ptr as *const u32) as usize;
            //debug_info!(fun_name);
            //debug_info!(fun_ord);
            //debug_info!(fun_addr); 

            if fun_name.to_lowercase() == function_name.to_lowercase() {
                return fun_addr;
            }

            function_name_array = function_name_array + std::mem::size_of::<u32>() as usize;
            function_ordinals_array = function_ordinals_array + std::mem::size_of::<u16>() as usize;
        }
        return 0;
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