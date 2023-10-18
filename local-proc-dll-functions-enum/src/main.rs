mod debug;
mod winapi;


use winapi::functions::__readgsqword;
use winapi::structs::PEB;
use winapi::structs::LDR_DATA_TABLE_ENTRY;
use winapi::structs::LIST_ENTRY;
use winapi::structs::IMAGE_DOS_HEADER;
use winapi::structs::IMAGE_NT_HEADERS64;
use winapi::structs::IMAGE_OPTIONAL_HEADER64;
use winapi::structs::IMAGE_DATA_DIRECTORY;
use winapi::structs::IMAGE_EXPORT_DIRECTORY;
use winapi::structs::IMAGE_DOS_SIGNATURE;
use winapi::structs::IMAGE_NT_SIGNATURE;
use winapi::structs::IMAGE_NT_OPTIONAL_HDR64_MAGIC;
use winapi::types::HINSTANCE;
use winapi::types::UINT_PTR;




use std::error::Error;

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub struct FunctionInfo {
    pub name: String,
    pub address: u64,
    pub ordinal: u16
}

impl FunctionInfo {
    pub fn new(name: String, address: u64, ordinal: u16) -> Self {
        Self { name: name, address: address, ordinal: ordinal }
    }
}

fn get_loaded_dlls() -> Vec<String> {
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

fn get_dll_base_address(module_name: &str) -> HINSTANCE {
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

fn get_dll_functions(module_handle: HINSTANCE) -> Result<Vec<FunctionInfo>> {
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

fn main() {
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
    let dll_name = "ntdll.dll";
    let base_address = get_dll_base_address(dll_name.to_lowercase().as_str());
    debug_ok_msg!(format!("Found dll {} at address {:?}", dll_name.to_lowercase().as_str(), base_address as *const u64));

    let func_res = get_dll_functions(base_address);
    if func_res.is_err() {
        let error = func_res.err().unwrap();
        debug_error!("Error ", &error);
        return;
    }
    
    let functions = func_res.unwrap();
    for fun_info in functions {
        debug_ok_msg!(format!("Found function {} #{} at {:?}", fun_info.name, fun_info.ordinal, fun_info.address as *const u64));
    }
}
