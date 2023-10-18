mod debug;
mod winapi;

use winapi::functions::__readgsqword;
use winapi::structs::PEB;
use winapi::structs::LDR_DATA_TABLE_ENTRY;
use winapi::structs::LIST_ENTRY;

fn show_loaded_dlls() -> Vec<String> {
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

fn main() {
    
    
    let dlls = show_loaded_dlls();

    debug_info_msg!("List of loaded dlls in current Process : ");
    for dll_name in dlls {
        debug_success!("Found dll", dll_name.to_lowercase().as_str());
    }
    
}
