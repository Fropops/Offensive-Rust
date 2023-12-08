use std::mem::{size_of, transmute};
use std::ptr::{null, null_mut};

use crate::common::output::OutputRedirector;
use crate::common::helpers::ascii_bytes_to_string;
use crate::winapi::constants::{MEM_RESERVE, MEM_COMMIT, PAGE_READWRITE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_HIGHLOW, IMAGE_ORDINAL_FLAG, PAGE_WRITECOPY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY, IMAGE_SCN_MEM_WRITE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,  DLL_PROCESS_DETACH, THREAD_ALL_ACCESS, TRUE};
use crate::winapi::dll_functions::{get_dll_proc_address, get_dll_proc_address_by_ordinal_index};
use crate::winapi::kernel32::{FlushInstructionCache, FreeLibrary};
use crate::winapi::ntdll::{RtlExitUserThread, RtlCreateUnicodeString};
use crate::winapi::structs::{IMAGE_BASE_RELOCATION, IMAGE_IMPORT_BY_NAME, UNICODE_STRING};
use crate::winapi::types::{HANDLE, BASE_RELOCATION_ENTRY, IMAGE_THUNK_DATA, PWSTR};
#[allow(unused_imports)]
use crate::{debug_error, debug_info, debug_info_msg, debug_success_msg, debug_ok_msg, debug_info_hex, debug_error_msg};
#[allow(unused_imports)]
use crate::{debug_base, debug_base_msg, debug_base_hex};

use super::constants::{IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_EXPORT, FALSE, DLL_PROCESS_ATTACH};
use super::dll_functions::get_dll_base_address;
use super::kernel32::GetCommandLineW;
use super::nt::syscall_wrapper::SyscallWrapper;
use super::structs::{IMAGE_SECTION_HEADER, IMAGE_DATA_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR, IMAGE_EXPORT_DIRECTORY};
use super::types::{PCSTR, P_IMAGE_TLS_DIRECTORY, P_FN_IMAGE_TLS_CALLBACK, P_FN_DLL_MAIN, HINSTANCE};
use super::{types::{IMAGE_NT_HEADERS, IMAGE_OPTIONAL_HEADER}, structs::IMAGE_DOS_HEADER, constants::{IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, IMAGE_NT_OPTIONAL_HDR_MAGIC, IMAGE_FILE_DLL, STATUS_SUCCESS}};

#[repr(C)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
struct PE_Infos
{
	pe_base_address: *const u8,
    pe_size: usize,
	nt_header_ptr: *const IMAGE_NT_HEADERS,
    is_dll: bool,
    image_section_header_ptr: *const IMAGE_SECTION_HEADER,
    entry_import_data_dir_ptr: *const IMAGE_DATA_DIRECTORY,
    entry_base_reloc_data_dir_ptr: *const IMAGE_DATA_DIRECTORY,
    entry_TLS_data_dir_ptr: *const IMAGE_DATA_DIRECTORY,
    entry_exception_data_dir_ptr: *const IMAGE_DATA_DIRECTORY,
    entry_export_data_dir_ptr: *const IMAGE_DATA_DIRECTORY,
    thread_handle: HANDLE,
}

impl Default for PE_Infos {
    fn default() -> Self {
        Self { 
            pe_base_address: null(), 
            pe_size : 0, 
            nt_header_ptr: null(), 
            is_dll: false,
            image_section_header_ptr: null(),
            entry_import_data_dir_ptr: null(), 
            entry_base_reloc_data_dir_ptr: null(), 
            entry_TLS_data_dir_ptr: null(),
            entry_exception_data_dir_ptr: null(), 
            entry_export_data_dir_ptr: null() ,
            thread_handle : 0 as HANDLE,
        }
    }
}


#[allow(non_camel_case_types)]
pub struct PE_Loader {
    infos: PE_Infos,
    pe_bytes: Vec<u8>,
    ntdll: SyscallWrapper,
    loaded_dlls: Vec<String>,
    used_dlls: Vec<String>,

    patch_exit_functions: bool,
}

impl PE_Loader {
    pub fn new(ntdll: SyscallWrapper) -> Self {
        Self{
            infos: PE_Infos::default(),
            ntdll: ntdll,
            pe_bytes: vec![0],
            used_dlls: vec![],
            loaded_dlls: vec![],
            patch_exit_functions: false,
        }
    }

    fn init(&mut self, pe_bytes: Vec<u8>) -> bool {
        debug_info_msg!(format!("Reading PE Infos ..."));
        let dos_headers: *const IMAGE_DOS_HEADER;
        let nt_headers: *const IMAGE_NT_HEADERS;
        let optional_header: * const IMAGE_OPTIONAL_HEADER;
        
        let pe_base_address = pe_bytes.as_ptr();
        self.pe_bytes = pe_bytes;

        self.used_dlls = vec![];
        self.loaded_dlls = vec![];

        unsafe {
            dos_headers = pe_base_address as *const IMAGE_DOS_HEADER;
            if (*dos_headers).e_magic != IMAGE_DOS_SIGNATURE {
                debug_error!("Invalid dos signature!");
                return false;
            }

            nt_headers = (pe_base_address as usize + (*dos_headers).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
            if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
                debug_error!("Invalid NT signature!");
                return false;
            }
            self.infos.nt_header_ptr = nt_headers;

            optional_header	= &(*nt_headers).OptionalHeader;
            if (*optional_header).Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC {
                debug_error!("Invalid Optional Header signature!");
                return false;
            }

            self.infos.is_dll = false;
            if (*nt_headers).FileHeader.Characteristics & IMAGE_FILE_DLL != 0 {
                self.infos.is_dll = true;
            }
            self.infos.image_section_header_ptr = (nt_headers as usize + std::mem::size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER;

            self.infos.entry_import_data_dir_ptr = (&(*optional_header).DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]) as *const IMAGE_DATA_DIRECTORY;
            self.infos.entry_base_reloc_data_dir_ptr = (&(*optional_header).DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]) as *const IMAGE_DATA_DIRECTORY;
            self.infos.entry_TLS_data_dir_ptr = (&(*optional_header).DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]) as *const IMAGE_DATA_DIRECTORY;
            self.infos.entry_exception_data_dir_ptr = (&(*optional_header).DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]) as *const IMAGE_DATA_DIRECTORY;
            self.infos.entry_export_data_dir_ptr = (&(*optional_header).DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]) as *const IMAGE_DATA_DIRECTORY;

            #[cfg(feature = "verbose")]
            debug_info_msg!(format!("Import : Size {} at {:#x}",(*self.infos.entry_import_data_dir_ptr).Size, (*self.infos.entry_import_data_dir_ptr).VirtualAddress as usize));
            #[cfg(feature = "verbose")]
            debug_info_msg!(format!("Reloc : Size {} at {:#x}",(*self.infos.entry_base_reloc_data_dir_ptr).Size, (*self.infos.entry_base_reloc_data_dir_ptr).VirtualAddress as usize));
            #[cfg(feature = "verbose")]
            debug_info_msg!(format!("TLS : Size {} at {:#x}",(*self.infos.entry_TLS_data_dir_ptr).Size, (*self.infos.entry_TLS_data_dir_ptr).VirtualAddress as usize));
            #[cfg(feature = "verbose")]
            debug_info_msg!(format!("Exc : Size {} at {:#x}",(*self.infos.entry_exception_data_dir_ptr).Size, (*self.infos.entry_exception_data_dir_ptr).VirtualAddress as usize));
            #[cfg(feature = "verbose")]
            debug_info_msg!(format!("Export : Size {} at {:#x}",(*self.infos.entry_export_data_dir_ptr).Size, (*self.infos.entry_export_data_dir_ptr).VirtualAddress as usize));
        }
        debug_success_msg!(format!("Done."));
        true
    }

    fn write_pe_sections(&mut self) -> bool {
        debug_info_msg!(format!("Writing PE Sections ..."));
        let process_handle: HANDLE = -1;
        let mut size: usize = unsafe { (*self.infos.nt_header_ptr).OptionalHeader.SizeOfImage as usize };
        let mut address: usize = 0;
        let res = self.ntdll.nt_allocate_virtual_memory(process_handle, &mut address,  &mut size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if res != STATUS_SUCCESS {
            crate::debug_error_msg!(format!("Failed to allocate memory (size = {})!", size));
            return false;
        }

        #[cfg(feature = "verbose")]
        debug_success_msg!(format!("Memory allocated : {}b at {:#x}", size, address));

        unsafe {
            let mut img_section_hdr_ptr = (self.infos.nt_header_ptr as usize + std::mem::size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER;
            for _ in 0..(*self.infos.nt_header_ptr).FileHeader.NumberOfSections {
                let src = (self.pe_bytes.as_ptr() as usize + (*img_section_hdr_ptr).PointerToRawData as usize) as *const u8;
                let dst = (address + (*img_section_hdr_ptr).VirtualAddress as usize) as *mut u8;
                let size = (*img_section_hdr_ptr).SizeOfRawData as usize;
                std::ptr::copy_nonoverlapping(src, dst, size);

                #[cfg(feature = "verbose")]
                debug_ok_msg!(format!("section {} copied (size={}) dst : {:#x} src : {:#x} ...", ascii_bytes_to_string(&(*img_section_hdr_ptr).Name), size, dst as usize, src as usize));

                img_section_hdr_ptr = (img_section_hdr_ptr as usize + std::mem::size_of::<IMAGE_SECTION_HEADER>()) as *const IMAGE_SECTION_HEADER;
            }
        }

        self.infos.pe_base_address = address as *const u8;
        self.infos.pe_size = size;
        debug_success_msg!(format!("Done."));
        true
    }

    fn adapt_relocations(&self) -> bool {
        debug_info_msg!(format!("Adapting relocations ..."));
        unsafe {
             let mut image_base_relocation_ptr = ((self.infos.pe_base_address as usize + (*self.infos.entry_base_reloc_data_dir_ptr).VirtualAddress as usize)) as *const IMAGE_BASE_RELOCATION;
            let pe_offset = self.infos.pe_base_address as usize - (*self.infos.nt_header_ptr).OptionalHeader.ImageBase as usize;
            let mut base_relocation_entry: *const BASE_RELOCATION_ENTRY;

            while (*image_base_relocation_ptr).VirtualAddress != 0 {

                base_relocation_entry = (image_base_relocation_ptr as usize  + size_of::<IMAGE_BASE_RELOCATION>()) as *const BASE_RELOCATION_ENTRY;

                let mut entry_count = 0;
                while base_relocation_entry as usize != image_base_relocation_ptr as usize + (*image_base_relocation_ptr).SizeOfBlock as usize {
                    entry_count = entry_count + 1;

                    let reloc_type = (*base_relocation_entry) >> 12;
                    let reloc_offset = (*base_relocation_entry) & 0xFFF;

                    //debug_info_msg!(format!("Entry #{} : type = {}, offset = {:#x}", entry_count, reloc_type, reloc_offset));
                    match reloc_type {
                        IMAGE_REL_BASED_DIR64 => {


                            let address = (self.infos.pe_base_address as usize + (*image_base_relocation_ptr).VirtualAddress as usize + reloc_offset as usize) as *mut usize;
                            #[cfg(feature = "verbose")]
                            let before = *address;
                            //(*address) = (*address) + pe_offset;
                            let existing = core::ptr::read(address);
                            core::ptr::write(address as *mut usize, existing + pe_offset as usize);
                            #[cfg(feature = "verbose")]
                            let after = *address;
                            #[cfg(feature = "verbose")]
                            debug_info_msg!(format!("Address {:#x} fixed from {:#x} to {:#x} [offset = {:#x}, pe_offset = {:#x}]", (*address) as usize, before as usize, after as usize, reloc_offset as usize, pe_offset as usize));
                        },
                        IMAGE_REL_BASED_HIGHLOW => {
                            //let finaladdress = baseptr as usize + unsafe { (*relocptr).VirtualAddress } as usize + (temp & 0x0fff) as usize;
                            let address = (self.infos.pe_base_address as usize + (*image_base_relocation_ptr).VirtualAddress as usize + reloc_offset as usize) as *mut u32;
                            //(*address) = (*address) + pe_offset as u32;
                            let existing = core::ptr::read(address);
                            core::ptr::write(address as *mut u32, existing + pe_offset as u32);
                        },
                        IMAGE_REL_BASED_ABSOLUTE => (),
                        _ => {
                            crate::debug_error_msg!(format!("Failed to relocate : unknown type {}!", reloc_type));
                            return false;
                        }
                    }

                    base_relocation_entry = (base_relocation_entry as usize  + size_of::<u16>()) as *const BASE_RELOCATION_ENTRY;
                }

                image_base_relocation_ptr = base_relocation_entry as *const IMAGE_BASE_RELOCATION;
            }
        }
        debug_success_msg!(format!("Done."));
        true
    }

    fn adapt_iat(&mut self) -> bool {

        debug_info_msg!(format!("Adapting Import Adress Table ..."));
        let mut img_desc_ptr : *const IMAGE_IMPORT_DESCRIPTOR;

        unsafe  {
            for index in 0..(*self.infos.entry_import_data_dir_ptr).Size {

                let offset = index * size_of::<IMAGE_IMPORT_DESCRIPTOR>() as u32;
                img_desc_ptr = (self.infos.pe_base_address as usize + (*self.infos.entry_import_data_dir_ptr).VirtualAddress as usize + offset as usize) as *const IMAGE_IMPORT_DESCRIPTOR;

                if (*img_desc_ptr).Anonymous.OriginalFirstThunk == 0 && (*img_desc_ptr).FirstThunk == 0 {
                    break;
                }

                let dll_name_address = (self.infos.pe_base_address as usize + (*img_desc_ptr).Name as usize) as *const u8;
                let dll_name_pcstr = PCSTR::from_raw(dll_name_address);
                let dll_name = dll_name_pcstr.to_string().unwrap().to_lowercase();

                

                let int_thunk_rva = (*img_desc_ptr).Anonymous.OriginalFirstThunk as usize;
		        let iat_thunk_rva = (*img_desc_ptr).FirstThunk as usize;
                let mut img_thunk_offset = 0usize;

                //debug_info_hex!(int_thunk_rva as usize);
                //debug_info_hex!(iat_thunk_rva as usize);

                //update iat by recalculating function address using int offsets
                loop {
                    let int_thunk_ptr = (self.infos.pe_base_address as usize + int_thunk_rva + img_thunk_offset) as *const IMAGE_THUNK_DATA;
                    let iat_thunk_ptr = (self.infos.pe_base_address as usize + iat_thunk_rva + img_thunk_offset) as *mut IMAGE_THUNK_DATA;

                    if (*int_thunk_ptr).u1.Function == 0 && (*iat_thunk_ptr).u1.Function == 0 {
                        break;
                    }
                    //debug_info!((*original_first_thunk_ptr).u1.Ordinal);
        
                    if  (*int_thunk_ptr).u1.Ordinal & IMAGE_ORDINAL_FLAG != 0 {

                        //load by ordinal                    
                        let ordinal = ((*int_thunk_ptr).u1.Ordinal & 0xffff) as u16;
                        let info = get_dll_proc_address_by_ordinal_index(&dll_name, ordinal);
                        if info.address.is_none() { 
                            crate::debug_error_msg!(format!("Failed importing {}", ordinal));
                            return false;
                        }
                        (*iat_thunk_ptr).u1.Function = info.address.unwrap();

                        let mut real_dll = dll_name.clone();
                        if info.dll_name.is_some() {
                            real_dll = info.dll_name.unwrap();
                        }

                        if !self.used_dlls.contains(&real_dll) {
                            self.used_dlls.push(real_dll.clone());
                            //debug_info_msg!(format!("used dlls += {}", &real_dll));
                        }

                        if info.loaded_in_memory && !self.loaded_dlls.contains(&real_dll)  {
                            self.loaded_dlls.push(real_dll.clone());
                            //debug_info_msg!(format!("loaded dlls += {}", &real_dll));
                        }

                        #[cfg(feature = "verbose")]
                        debug_info_msg!(format!("loading function {}#{} at {:#x}", dll_name, ordinal, info.address.unwrap()));
                    }
                    else {
                        //load by name
                        let img_import_name_ptr = (self.infos.pe_base_address as usize + (*int_thunk_ptr).u1.AddressOfData as usize) as *const IMAGE_IMPORT_BY_NAME;
                        let function_name = ascii_bytes_to_string(&(*img_import_name_ptr).Name);

                        // if dll_name.to_lowercase() == "kernel32.dll" {
                        //     debug_info_msg!(format!("test {} {}", &dll_name, &function_name));
                        // }

                        let info = get_dll_proc_address(&dll_name, &function_name);
                        if  info.address.is_none()  {
                            crate::debug_error_msg!(format!("Failed importing {}", function_name));
                            return false;
                        }
                        #[cfg(feature = "verbose")]
                        debug_info_msg!(format!("loading function {} at {:#x}", function_name, info.address.unwrap()));
                        (*iat_thunk_ptr).u1.Function = info.address.unwrap();

                        let mut real_dll = dll_name.clone();
                        if info.dll_name.is_some() {
                            real_dll = info.dll_name.unwrap();
                        }

                        if !self.used_dlls.contains(&real_dll) {
                            self.used_dlls.push(real_dll.clone());
                            //debug_info_msg!(format!("used dlls += {}", &real_dll));
                        }

                        if info.loaded_in_memory && !self.loaded_dlls.contains(&real_dll)  {
                            self.loaded_dlls.push(real_dll.clone());
                            //debug_info_msg!(format!("loaded dlls += {}", &real_dll));
                        }


                        //Hook exit functions to prevent process to be closed
                        if self.patch_exit_functions {
                            if function_name == "ExitProcess" || function_name == "exit" || function_name == "_Exit" || function_name == "_exit" || function_name == "quick_exit" {
                                (*iat_thunk_ptr).u1.Function = RtlExitUserThread as usize;
                                #[cfg(feature = "verbose")]
                                debug_info_msg!(format!("Patching {} at {:#x}", function_name, info.address.unwrap()));
                            }
                        }
                    }

                    img_thunk_offset += size_of::<IMAGE_THUNK_DATA>();
                }
            }
        }
        debug_success_msg!(format!("Done."));
        true
    }

    fn adapt_permissions(&mut self) -> bool {
        debug_info_msg!(format!("Adapting Memory region permissions ..."));
        unsafe {
            let mut img_section_hdr_ptr = (self.infos.nt_header_ptr as usize + std::mem::size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER;
            for _ in 0..(*self.infos.nt_header_ptr).FileHeader.NumberOfSections {
                let mut protection = 0u32;
                let mut old_protection = 0u32;
                if (*img_section_hdr_ptr).SizeOfRawData == 0 || (*img_section_hdr_ptr).VirtualAddress == 0 {
                    continue;
                }

                if (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_WRITE != 0 {
			        protection = PAGE_WRITECOPY;
                }

                if (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_READ != 0 {
                    protection = PAGE_READONLY;
                }

                if ((*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_WRITE) != 0 && (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_READ != 0 {
                    protection = PAGE_READWRITE;
                }

                if (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
                    protection = PAGE_EXECUTE;
                }

                if (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_EXECUTE != 0 && (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_WRITE != 0 {
                    protection = PAGE_EXECUTE_WRITECOPY;
                }

                if (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_EXECUTE != 0 && (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_READ != 0 {
                    protection = PAGE_EXECUTE_READ;
                }

                if (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_EXECUTE != 0 && (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_WRITE != 0 && (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_READ != 0 {
                    protection = PAGE_EXECUTE_READWRITE;
                }

                #[cfg(feature = "verbose")]
                debug_ok_msg!(format!("change memory protection of {} (size={}) at {:#x} to value {}", ascii_bytes_to_string(&(*img_section_hdr_ptr).Name), (*img_section_hdr_ptr).SizeOfRawData, self.infos.pe_base_address as usize + (*img_section_hdr_ptr).VirtualAddress as usize, protection));

                let res =  self.ntdll.nt_protect_virtual_memory(-1, &mut (self.infos.pe_base_address as usize + (*img_section_hdr_ptr).VirtualAddress as usize), &mut ((*img_section_hdr_ptr).SizeOfRawData as usize), protection, &mut old_protection);
                if res != STATUS_SUCCESS {
                    crate::debug_error_msg!(format!("Failed to change memory protection of section {}!", ascii_bytes_to_string(&(*img_section_hdr_ptr).Name)));
                    return false;
                }

                img_section_hdr_ptr = (img_section_hdr_ptr as usize + std::mem::size_of::<IMAGE_SECTION_HEADER>()) as *const IMAGE_SECTION_HEADER;
            }
        }
        debug_success_msg!(format!("Done."));
        true
    }

    fn patch_arguments(&mut self, args: String) -> bool {
        //create the new unicode_string containing the new args
        let fake_exe_name = lc!("mefl.exe");//could be anything
        let mut full_cmd = String::new();
        full_cmd.push_str(&fake_exe_name);
        full_cmd.push(' ');
        full_cmd.push_str(&args.trim());
        
        let mut vec: Vec<u16> = full_cmd.encode_utf16().collect();
        vec.push(0);
        let cmd_line_pwstr = PWSTR::from_raw(vec.as_mut_ptr());

        let mut new_args_us = UNICODE_STRING {Buffer: PWSTR::from_raw(null_mut()), MaximumLength :0, Length:0};
        let new_args_us_pointer = &mut new_args_us as *mut UNICODE_STRING;
        //debug_info_hex!(new_args_us_pointer as usize);
        unsafe {
            if RtlCreateUnicodeString(new_args_us_pointer, cmd_line_pwstr) == FALSE {
                debug_error_msg!("Failed to create new arguments Unicode_string!");
                return false;
            }
            //debug_info_msg!(format!("__warg = {:#x}", new_args_us_pointer as usize));
            //debug_info_msg!(format!("__warg buffer = {:#x}", (*new_args_us_pointer).Buffer.as_ptr() as usize));
        }

        


        //hijack command line
        let mut pointers_count = 0;
        let mut data_section_ptr = 0;

        unsafe {
            let kernel_base_handle = get_dll_base_address("kernelbase.dll").unwrap();

            let dos_headers_ptr = kernel_base_handle as *const IMAGE_DOS_HEADER;
            let nt_headers_ptr = (kernel_base_handle as usize + (*dos_headers_ptr).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
            let mut img_section_hdr_ptr = (nt_headers_ptr as usize + std::mem::size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER;
                for _ in 0..(*self.infos.nt_header_ptr).FileHeader.NumberOfSections {
                    //debug_ok_msg!(format!("section {} ", ascii_bytes_to_string(&(*img_section_hdr_ptr).Name)));
                    if ascii_bytes_to_string(&(*img_section_hdr_ptr).Name) == lc!(".data") {
                        pointers_count = (*img_section_hdr_ptr).Misc.VirtualSize as usize / size_of::<usize>();
                        data_section_ptr = (kernel_base_handle as usize + (*img_section_hdr_ptr).VirtualAddress as usize) as usize;
                        break;
                    }

                    img_section_hdr_ptr = (img_section_hdr_ptr as usize + std::mem::size_of::<IMAGE_SECTION_HEADER>()) as *const IMAGE_SECTION_HEADER;
                }

            
            //patch GetCommandLineW
            let get_command_line_w_pwstr = GetCommandLineW();
            for _ in 0..pointers_count {
                let current_pointer = data_section_ptr as *mut UNICODE_STRING;
                data_section_ptr = data_section_ptr + size_of::<usize>();

                if (*current_pointer).Buffer.as_ptr() as usize != get_command_line_w_pwstr.as_ptr() as usize {
                    continue;
                }
                #[cfg(feature = "verbose")]
                debug_ok_msg!(format!("patching GetCommandLineW at {:#x} (Buffer = {:#x})", current_pointer as usize, (*current_pointer).Buffer.as_ptr() as usize));
                *current_pointer = *new_args_us_pointer;
                #[cfg(feature = "verbose")]
                debug_ok_msg!(format!("New value for GetCommandLineW = {}", GetCommandLineW().to_string().unwrap()));
                #[cfg(feature = "verbose")]
                debug_ok_msg!(format!("patced GetCommandLineW at {:#x} (Buffer = {:#x})", current_pointer as usize, (*current_pointer).Buffer.as_ptr() as usize));
                break;
            }

            for dll in self.used_dlls.iter() {
                //debug_info_msg!(format!("Iteration into {}!", dll));
                //_wcmdln;__wargv;__p__wcmdln;__p___wargv
                type WCHAR = u16;
                type PWCHAR = *mut WCHAR;
                type PPWCHAR = *mut PWCHAR;

                let mut func_info = get_dll_proc_address(dll, "__p__wcmdln");
                if func_info.address.is_some() {
                    //#[cfg(feature = "verbose")]
                    debug_ok_msg!(format!("Patching {}!{} at {:#x}", dll, "__p__wcmdln", func_info.address.unwrap()));
                    let p_wcmdln: unsafe extern "system" fn() -> usize = core::mem::transmute(func_info.address.unwrap());
                    let wargv = p_wcmdln() as PPWCHAR;
                    *wargv = (*new_args_us_pointer).Buffer.as_ptr();
                }

                func_info = get_dll_proc_address(dll, "_wcmdln");
                if func_info.address.is_some() {
                    #[cfg(feature = "verbose")]
                    debug_ok_msg!(format!("Patching {}!{} at {:#x}", dll, "_wcmdln", func_info.address.unwrap()));
                    let wargv = func_info.address.unwrap() as PPWCHAR;
                    *wargv = (*new_args_us_pointer).Buffer.as_ptr();
                }

                func_info = get_dll_proc_address(dll, "__wargv");
                if func_info.address.is_some() {
                    #[cfg(feature = "verbose")]
                    debug_ok_msg!(format!("Patching {}!{} at {:#x}", dll, "__wargv", func_info.address.unwrap()));
                    let wargv = func_info.address.unwrap() as PPWCHAR;
                    *wargv = null_mut();
                }

                func_info = get_dll_proc_address(dll, "__p___wargv");
                if func_info.address.is_some() {
                    //#[cfg(feature = "verbose")]
                    debug_ok_msg!(format!("Patching {}!{} at {:#x}", dll, "__p___wargv", func_info.address.unwrap()));
                    let p_wcmdln: unsafe extern "system" fn() -> usize = core::mem::transmute(func_info.address.unwrap());
                    let wargv = p_wcmdln() as PPWCHAR;
                    *wargv = (*new_args_us_pointer).Buffer.as_ptr();
                }

                //TODO patch GetCommandLineA & handle _acmdln;__argv;__p__acmdln;__p___argv
            }
        }

        true
    }

    fn inject(&mut self, pe_bytes: Vec<u8>) -> bool {
        if !self.init(pe_bytes) {
            return false;
        }

        if !self.write_pe_sections() {
            return false;
        }

        if !self.adapt_relocations() {
            return false;
        }

        if !self.adapt_iat() {
            return false;
        }

        if !self.adapt_permissions() {
            return false;
        }
        true
    }

    fn execute_tls_callbacks(&mut self, attach: bool) -> bool {
        unsafe {
            if (*self.infos.entry_TLS_data_dir_ptr).Size == 0 {
                return true;
            }

            // if attach {
            // debug_info_msg!(format!("Executing TLS Callbacks before execution ..."));
            // }
            // else {
            //     debug_info_msg!(format!("Executing TLS Callbacks after execution ..."));
            // }

            let img_tls_directory_ptr : P_IMAGE_TLS_DIRECTORY = (self.infos.pe_base_address as usize + (*self.infos.entry_TLS_data_dir_ptr).VirtualAddress as usize)as P_IMAGE_TLS_DIRECTORY;
            let mut img_fn_tls_callback_array = (*img_tls_directory_ptr).AddressOfCallBacks as *mut usize;
            
            let mut ctxt = [0u8;1232];
            while (*img_fn_tls_callback_array) as usize != 0 {
                
                let img_fn_tls_callback_ptr = transmute::<usize, P_FN_IMAGE_TLS_CALLBACK>(*img_fn_tls_callback_array);
                if attach {
                    (img_fn_tls_callback_ptr)(self.infos.pe_base_address as *mut u8, DLL_PROCESS_ATTACH, ctxt.as_mut_ptr());
                }
                else {
                    (img_fn_tls_callback_ptr)(self.infos.pe_base_address as *mut u8, DLL_PROCESS_DETACH, ctxt.as_mut_ptr());
                }

                img_fn_tls_callback_array = (img_fn_tls_callback_array as usize + size_of::<usize>()) as *mut usize;
                
            }
        }

        //debug_info_msg!(format!("Done."));

        true
    }

    fn clean(&self) -> bool {
        debug_info_msg!(format!("Cleaning ..."));

        #[cfg(feature = "verbose")]
        debug_info_msg!(format!("Cleaning Handles"));
        let res = self.ntdll.nt_close(self.infos.thread_handle);
        if res != STATUS_SUCCESS {
            debug_error_msg!("Failed to close Thread Handle!");
            return false;
        }


        //release dll loaded
        for dll_name in self.loaded_dlls.iter() {
            let address = get_dll_base_address(dll_name);
            if address.is_some() {
                #[cfg(feature = "verbose")]
                debug_info_msg!(format!("Freeing {}", dll_name));
                if unsafe { FreeLibrary(address.unwrap()) } != TRUE {
                    #[cfg(feature = "verbose")]
                    debug_error_msg!(format!("Freeing {} failed !", dll_name));
                }
            }
        }

        //With some PE (rust for example this cleaning crash the main thread) but seems to work with dlls

        //revert permission to RW
        #[cfg(feature = "verbose")]
        debug_info_msg!(format!("Reverting Memory to RW"));
        let mut address = self.infos.pe_base_address as usize;
        let mut size =  self.infos.pe_size;
        let mut old_protection = 0u32;
        let res =  self.ntdll.nt_protect_virtual_memory(-1, &mut address, &mut size, PAGE_READWRITE, &mut old_protection);
        if res != STATUS_SUCCESS {
            crate::debug_error_msg!("Failed to revert memory protection of allocateed space!");
            return false;
        }
        
        //simply erase data
        #[cfg(feature = "verbose")]
        debug_info_msg!(format!("Erasing Memory"));
        unsafe { std::ptr::write_bytes(address as *mut u8, 0, self.infos.pe_size) };

        #[cfg(feature = "verbose")]
        debug_info_msg!(format!("releasing Memory"));
        let mut address = self.infos.pe_base_address as usize;
        let mut size =  self.infos.pe_size;
        let res = self.ntdll.nt_free_virtual_memory(-1, &mut address,  &mut size, crate::winapi::constants::MEM_RELEASE);
        if res != STATUS_SUCCESS {
            crate::debug_error_msg!(format!("Failed to free memory : {:#x}!", res as usize));
            return false;
        }

        debug_success_msg!(format!("Done."));
        true
    }

    #[allow(unused)]
    pub fn execute_exe(&mut self, pe_bytes:Vec<u8>, redirect_output: bool, patch_exit_functions: bool, args: Option<String>) -> (bool, Option<String>) {
        let mut success : bool = true;
        let mut redirector = OutputRedirector::new();
        self.patch_exit_functions = patch_exit_functions;

        //preparing
        if !self.inject(pe_bytes) {
            debug_error_msg!("Failed to inject PE.");
            return (false ,None);
        }

        if self.infos.is_dll {
            debug_error_msg!("PE is a dll");
            return (false, None)
        }

        //Patching args
        let mut real_args = String::new();
        if args.is_some() {
            real_args = args.unwrap();
        }

        if real_args.is_empty() {
            debug_info_msg!("Executing without args...");
        }
        else {
            debug_info_msg!(format!("Executing with args '{}' ...", real_args));
        }
        
        if !self.patch_arguments(real_args) {
            return (false,None);
        }


        let mut output = String::new();

        unsafe {
            FlushInstructionCache(-1 as HANDLE, null_mut(), 0);
        }

        if !self.execute_tls_callbacks(true) {
            return (false, None);
        }

        unsafe {
            let entry_point = self.infos.pe_base_address as usize + (*self.infos.nt_header_ptr).OptionalHeader.AddressOfEntryPoint as usize;

            if redirect_output {
                let mut msvcrt_used = false;
                let mut ucrtbase_used = false;

                if self.used_dlls.contains(&lc!("msvcrt.dll")) {
                    msvcrt_used = true;
                }

                if self.used_dlls.contains(&lc!("ucrtbase.dll")) {
                    ucrtbase_used = true;
                }

                let sub: Vec<&String> = self.loaded_dlls.iter().filter(|x| x.starts_with(&lc!("api-ms-win-crt-"))).collect();
                if sub.len() != 0 {
                    ucrtbase_used = true;
                }

                redirector.redirect_outputs(msvcrt_used, ucrtbase_used);
            }

            let mut thread_handle: HANDLE = 0;
            let mut res =  self.ntdll.nt_create_thread_ex(&mut thread_handle, THREAD_ALL_ACCESS,-1, entry_point);
            if res != STATUS_SUCCESS {
                debug_error_msg!("Failed to start thread!");
                return (false, None);
            }

            self.infos.thread_handle = thread_handle;

            //std::thread::sleep(std::time::Duration::from_secs(5));
            res =  self.ntdll.nt_wait_for_single_object(thread_handle);
            if res != STATUS_SUCCESS {
                debug_error_msg!("Failed to wait!");
                return (false,None);
            }

            if redirect_output {
                while let Some(buff) = redirector.read_outputs() {
                    output.push_str(String::from_utf8(buff).unwrap().as_str());
                }

                redirector.revert_redirection();
            }
        }

        let _ = self.execute_tls_callbacks(false);

        //cleaning
        if !self.clean() {
            debug_error_msg!("Failed to clean PE.");
            success = false;
        }
        
        if redirect_output {
            (success, Some(output))
        } else {
            (success, None)
        }
    }

    fn fetch_exported_function_address(&mut self, func_name: Option<String>) -> Option<usize> {
        if func_name.is_none() {
            return None;
        }

        let func = func_name.unwrap();

        unsafe {
            let img_exp_ptr = (self.infos.pe_base_address as usize + (*self.infos.entry_export_data_dir_ptr).VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY; 
            let function_address_array = (self.infos.pe_base_address as usize + (*img_exp_ptr).AddressOfFunctions as usize) as usize;
            let mut function_name_array = (self.infos.pe_base_address as usize + (*img_exp_ptr).AddressOfNames as usize) as usize;
            let mut function_ordinals_array = (self.infos.pe_base_address as usize + (*img_exp_ptr).AddressOfNameOrdinals as usize) as usize;

            for _index in 0..(*img_exp_ptr).NumberOfNames { 
                let name_offest: u32 = *(function_name_array as *const u32);

                let fun_name = std::ffi::CStr::from_ptr(
                    (self.infos.pe_base_address as usize + name_offest as usize) as *const i8
                ).to_str().unwrap();

                debug_info!(fun_name);

                let fun_ord = *(function_ordinals_array as *const u16);
                let address_ptr = function_address_array + fun_ord as usize * (std::mem::size_of::<u32>() as usize);
    
                if fun_name.to_lowercase() == func.to_lowercase() {
                    return Some(self.infos.pe_base_address as usize + *(address_ptr as *const u32) as usize);
                }

                function_name_array = function_name_array + std::mem::size_of::<u32>() as usize;
                function_ordinals_array = function_ordinals_array + std::mem::size_of::<u16>() as usize;
            }
        }
        None
    }

    #[allow(unused)]
    pub fn execute_dll(&mut self, pe_bytes:Vec<u8>, entry_function: Option<String>) -> bool {
        let mut success : bool = true;
        self.patch_exit_functions = false;

        //preparing
        if !self.inject(pe_bytes) {
            debug_error_msg!("Failed to inject PE.");
            return false;
        }

        if !self.infos.is_dll {
            debug_error_msg!("PE is an exe");
            return false;
        }

        unsafe {
            FlushInstructionCache(-1 as HANDLE, null_mut(), 0);
        }

        if !self.execute_tls_callbacks(true) {
            return false;
        }

        let func_address = self.fetch_exported_function_address(entry_function.clone());
        if func_address.is_none() && entry_function.is_some() {
            debug_error_msg!(format!("Entry Function {} not found !", entry_function.unwrap()));
            return false;
        }

        unsafe {
            let entry_point = self.infos.pe_base_address as usize + (*self.infos.nt_header_ptr).OptionalHeader.AddressOfEntryPoint as usize;

            let dll_main = transmute::<usize, P_FN_DLL_MAIN>(entry_point);
            (dll_main)(self.infos.pe_base_address as HINSTANCE, DLL_PROCESS_ATTACH , null_mut());

            if func_address.is_some() {
                let mut thread_handle: HANDLE = 0;
                let mut res =  self.ntdll.nt_create_thread_ex(&mut thread_handle, THREAD_ALL_ACCESS,-1, func_address.unwrap());
                if res != STATUS_SUCCESS {
                    debug_error_msg!("Failed to start thread!");
                    return false;
                }

                self.infos.thread_handle = thread_handle;

                //std::thread::sleep(std::time::Duration::from_secs(5));
                res =  self.ntdll.nt_wait_for_single_object(thread_handle);
                if res != STATUS_SUCCESS {
                    debug_error_msg!("Failed to wait!");
                    return false;
                }
            }
        }

        let _ = self.execute_tls_callbacks(false);

        //cleaning
        if !self.clean() {
            debug_error_msg!("Failed to clean PE.");
            success = false;
        }
        
        success
    }
}