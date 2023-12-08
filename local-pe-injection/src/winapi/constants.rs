
use super::{types::{NT_STATUS, PROCESS_ACCESS_RIGHTS, VIRTUAL_ALLOCATION_TYPE, PAGE_PROTECTION_FLAGS, THREAD_ACCESS_RIGHTS, SYSTEM_INFORMATION_CLASS, BASE_RELOCATION_TYPE, IMAGE_SCN_MEM_FLAGS, VIRTUAL_FREE_TYPE, STD_HANDLE}, structs::IMAGE_FILE_CHARACTERISTICS};

#[allow(dead_code)]
pub const NULL: usize = 0;
#[allow(dead_code)]
pub const TRUE: u8 = 1;
#[allow(dead_code)]
pub const FALSE: u8 = 0;

pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;
pub const IMAGE_DOS_SIGNATURE: u16 = 23117u16;
pub const IMAGE_NT_SIGNATURE: u32 = 17744u32;
// #[allow(dead_code)]
// pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 267u16;
// #[allow(dead_code)]
// pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 523u16;

#[cfg(target_arch = "x86_64")]
pub const IMAGE_NT_OPTIONAL_HDR_MAGIC: u16 = 523u16;
#[cfg(target_arch = "x86")]
pub const IMAGE_NT_OPTIONAL_HDR_MAGIC: u16 = 267u16;

#[allow(dead_code)]
pub const PROCESS_VM_READ: PROCESS_ACCESS_RIGHTS = 16u32;
#[allow(dead_code)]
pub const PROCESS_VM_WRITE: PROCESS_ACCESS_RIGHTS = 32u32;
#[allow(dead_code)]
pub const PROCESS_ALL_ACCESS: PROCESS_ACCESS_RIGHTS = 2097151u32;

#[allow(dead_code)]
pub const STATUS_SUCCESS: NT_STATUS = 0i32;

#[allow(dead_code)]
pub const MEM_COMMIT: VIRTUAL_ALLOCATION_TYPE = 4096u32;
#[allow(dead_code)]
pub const MEM_RESERVE: VIRTUAL_ALLOCATION_TYPE = 8192u32;
#[allow(dead_code)]
pub const MEM_RELEASE: VIRTUAL_FREE_TYPE = 32768u32;
#[allow(dead_code)]
pub const MEM_DECOMMIT: VIRTUAL_FREE_TYPE = 16384u32;

#[allow(dead_code)]
pub const PAGE_READONLY: PAGE_PROTECTION_FLAGS = 2u32;
#[allow(dead_code)]
pub const PAGE_READWRITE: PAGE_PROTECTION_FLAGS = 4u32;
#[allow(dead_code)]
pub const PAGE_WRITECOPY: PAGE_PROTECTION_FLAGS = 8u32;
#[allow(dead_code)]
pub const PAGE_EXECUTE: PAGE_PROTECTION_FLAGS = 16u32;
#[allow(dead_code)]
pub const PAGE_EXECUTE_READ: PAGE_PROTECTION_FLAGS = 32u32;
#[allow(dead_code)]
pub const PAGE_EXECUTE_READWRITE: PAGE_PROTECTION_FLAGS = 64u32;
#[allow(dead_code)]
pub const PAGE_EXECUTE_WRITECOPY: PAGE_PROTECTION_FLAGS = 128u32;
#[allow(dead_code)]
pub const IMAGE_SCN_MEM_WRITE: IMAGE_SCN_MEM_FLAGS = 0x80000000;
#[allow(dead_code)]
pub const IMAGE_SCN_MEM_READ: IMAGE_SCN_MEM_FLAGS = 0x40000000;
#[allow(dead_code)]
pub const IMAGE_SCN_MEM_EXECUTE: IMAGE_SCN_MEM_FLAGS = 0x20000000;

#[allow(dead_code)]
pub const THREAD_ALL_ACCESS: THREAD_ACCESS_RIGHTS = 2097151u32;
#[allow(dead_code)]
pub const SYSTEM_PROCESS_INFORMATION: SYSTEM_INFORMATION_CLASS = 5i32;
#[allow(dead_code)]
pub const IMAGE_FILE_DLL: IMAGE_FILE_CHARACTERISTICS = 8192u16;

#[allow(dead_code)]
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
#[allow(dead_code)]
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
#[allow(dead_code)]
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
#[allow(dead_code)]
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
#[allow(dead_code)]
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
#[allow(dead_code)]
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
#[allow(dead_code)]
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
#[allow(dead_code)]
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
#[allow(dead_code)]
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
#[allow(dead_code)]
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
#[allow(dead_code)]
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
#[allow(dead_code)]
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
#[allow(dead_code)]
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
#[allow(dead_code)]
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
#[allow(dead_code)]
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

#[allow(dead_code)]
pub const IMAGE_REL_BASED_ABSOLUTE: BASE_RELOCATION_TYPE = 0;
#[allow(dead_code)]
pub const IMAGE_REL_BASED_HIGH: BASE_RELOCATION_TYPE = 1;
#[allow(dead_code)]
pub const IMAGE_REL_BASED_LOW: BASE_RELOCATION_TYPE = 2;
#[allow(dead_code)]
pub const IMAGE_REL_BASED_HIGHLOW: BASE_RELOCATION_TYPE = 3;
#[allow(dead_code)]
pub const IMAGE_REL_BASED_DIR64: BASE_RELOCATION_TYPE = 10;

#[allow(dead_code)]
#[cfg(target_arch = "x86")]
pub const IMAGE_ORDINAL_FLAG32: usize =  2147483648usize;
#[allow(dead_code)]
#[cfg(target_arch = "x86")]
pub const IMAGE_ORDINAL_FLAG: usize =  IMAGE_ORDINAL_FLAG32;

#[allow(dead_code)]
#[cfg(target_arch = "x86_64")]
pub const IMAGE_ORDINAL_FLAG64: usize =  9223372036854775808u64 as usize;
#[allow(dead_code)]
#[cfg(target_arch = "x86_64")]
pub const IMAGE_ORDINAL_FLAG: usize =  IMAGE_ORDINAL_FLAG64;

#[allow(dead_code)]
pub const STD_ERROR_HANDLE: STD_HANDLE = 4294967284u32;
#[allow(dead_code)]
pub const STD_OUTPUT_HANDLE: STD_HANDLE = 4294967285u32;

#[allow(dead_code)]
pub const DLL_PROCESS_ATTACH: u32 = 1u32;
#[allow(dead_code)]
pub const DLL_PROCESS_DETACH: u32 = 0u32;

