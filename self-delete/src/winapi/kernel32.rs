use super::types::{HANDLE, PWSTR, BOOL};

#[allow(non_camel_case_types)]
pub type FILE_INFO_BY_HANDLE_CLASS = i32;
#[allow(non_camel_case_types)]
pub type FILE_CREATION_DISPOSITION = u32;
#[allow(non_camel_case_types)]
pub type FILE_SHARE_MODE = u32;
#[allow(non_camel_case_types)]
pub type FILE_ACCESS_RIGHTS = u32;

#[allow(non_upper_case_globals)]
pub const FileRenameInfo: FILE_INFO_BY_HANDLE_CLASS = 3i32;
#[allow(non_upper_case_globals)]
pub const FileDispositionInfo: FILE_INFO_BY_HANDLE_CLASS = 4i32;
pub const MAX_PATH16: u32 = 255u32;
pub const OPEN_EXISTING: FILE_CREATION_DISPOSITION = 3u32;
pub const FILE_SHARE_READ: FILE_SHARE_MODE = 1u32;
pub const DELETE: FILE_ACCESS_RIGHTS = 65536u32;
pub const SYNCHRONIZE: FILE_ACCESS_RIGHTS = 1048576u32;

#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)]
pub struct FILE_RENAME_INFO {
    pub Anonymous: FILE_RENAME_INFO_0,
    pub RootDirectory: HANDLE,
    pub FileNameLength: u32,
    pub FileName: [u16;MAX_PATH16 as usize],
}

impl Default for FILE_RENAME_INFO {
    fn default() -> Self {
        Self {
            Anonymous: FILE_RENAME_INFO_0 {
                    Flags: 0u32
            },
            FileNameLength: 0,
            RootDirectory: 0,
            FileName: [0u16;MAX_PATH16 as usize],
        }
    }
}

#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)]
pub union FILE_RENAME_INFO_0 {
        pub ReplaceIfExists: u8,
        pub Flags: u32,
    }

#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)]
pub struct FILE_DISPOSITION_INFO  {
    pub DeleteFile: u8,
}

#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)]
#[repr(C)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: u32,
    pub lpSecurityDescriptor: usize,
    pub bInheritHandle: u8,
}



// BOOL SetFileInformationByHandle(
//         [in] HANDLE                    hFile,
//         [in] FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
//         [in] LPVOID                    lpFileInformation,
//         [in] DWORD                     dwBufferSize
//       );
pub type SetFileInformationByHandle = unsafe extern "system" fn (HANDLE, FILE_INFO_BY_HANDLE_CLASS, usize, u32) -> BOOL;

// DWORD GetModuleFileNameW(
//         [in, optional] HMODULE hModule,
//         [out]          LPWSTR  lpFilename,
//         [in]           DWORD   nSize
//       );
pub type GetModuleFileNameW = unsafe extern "system" fn (HANDLE, PWSTR, u32) -> u8;

// HANDLE CreateFileW(
//         [in]           LPCWSTR               lpFileName,
//         [in]           DWORD                 dwDesiredAccess,
//         [in]           DWORD                 dwShareMode,
//         [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
//         [in]           DWORD                 dwCreationDisposition,
//         [in]           DWORD                 dwFlagsAndAttributes,
//         [in, optional] HANDLE                hTemplateFile
//       );
pub type CreateFileW = unsafe extern "system" fn (PWSTR, u32, u32, *mut SECURITY_ATTRIBUTES, u32, u32, HANDLE) -> HANDLE;

// BOOL CloseHandle(
//         [in] HANDLE hObject
//       );
pub type CloseHandle = unsafe extern "system" fn (HANDLE) -> BOOL;

// DWORD GetLastError();
pub type GetLastError = unsafe extern "system" fn () -> u32;