// adapted from https://www.coresecurity.com/core-labs/articles/running-pes-inline-without-console
use std::{mem::{self, size_of}, ptr::{null_mut, write_bytes}};

use crate::winapi::{types::HANDLE, dll_functions::{get_dll_proc_address, get_peb}, kernel32::{SECURITY_ATTRIBUTES, CreatePipe, CloseHandle, PeekNamedPipe, ReadFile}, constants::{TRUE, NULL, FALSE}};

#[allow(unused)]
pub const _O_WRONLY : i32 = 0x0001;
#[allow(unused)]
pub const _IONBF : i32 = 0x0004;
#[allow(unused)]
pub const _IOWRT : i32 = 0x0002;

#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)]
#[derive(Copy, Clone)]
struct MSVCRT_FILE {
    ptr :*mut u8,
    cnt: i32,
    base: *mut u8,
    flag: i32,
    pub file: i32,
    charbuf: i32,
    bufsiz: i32,
    tmpfname:*mut u8,
}

#[allow(non_camel_case_types)]
type P_MSVCRT_FILE = *mut MSVCRT_FILE;

impl Default for MSVCRT_FILE {
    fn default() -> Self {
        Self { ptr: null_mut(), cnt: Default::default(), base: null_mut(), flag: Default::default(), file: Default::default(), charbuf: Default::default(), bufsiz: Default::default(), tmpfname: null_mut() }
    }
}

type MsvcrtOpenOsfhandle = fn (usize, i32) -> i32;
type MsvcrtIobFunc = fn() -> P_MSVCRT_FILE;


#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)]
#[derive(Copy, Clone)]
struct CRITICAL_SECTION {
    DebugInfo: usize,
    LockCount: i32,
    RecursionCount: i32,
    OwningThread: HANDLE,       // from the thread's ClientId->UniqueThread
    LockSemaphore: HANDLE,
    SpinCount: usize
}

#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)]
#[derive(Copy, Clone)]
struct UCRTBASE_FILE {
    ptr: *mut u8,
    base: *mut u8,
    cnt : i32,
    flags: i32,
    file: i32,
    bufsiz: i32,
    charbuf: *mut u8,
    tmpfname: usize,
    lock: CRITICAL_SECTION,
}

#[allow(non_camel_case_types)]
type P_UCRTBASE_FILE = *mut UCRTBASE_FILE;

type UcrtOpenOsfhandle = fn (usize, i32) -> i32;
type UcrtIobFunc = fn(u32) -> P_UCRTBASE_FILE;


struct APICalls {
    msvcrt_open_osfhandle: Option<MsvcrtOpenOsfhandle>,
    msvcrt_iob_func: Option<MsvcrtIobFunc>,

    ucrt_open_osfhandle: Option<UcrtOpenOsfhandle>,
    ucrt_iob_func: Option<UcrtIobFunc>,
}

impl APICalls {
    pub fn new() -> Self {
        Self {
            msvcrt_open_osfhandle: None,
            msvcrt_iob_func: None,
            ucrt_open_osfhandle: None,
            ucrt_iob_func: None,
        }
    }
}


// #[allow(unused)]
// #[link(name = "ucrt")]
// extern "cdecl" {
//     fn __acrt_iob_func(id: u32) -> P_UCRTBASE_FILE;
// }

fn set_std_out_handle(id: isize) {
    unsafe {
        let peb = get_peb();
        (*peb.ProcessParameters).StandardOutput = id;
    }
}

fn set_std_err_handle(id: isize) {
    unsafe {
        let peb = get_peb();
        (*peb.ProcessParameters).StandardError = id;
    }
}

fn get_std_output_handle() -> HANDLE {
    unsafe {
        let peb = get_peb();
        return (*peb.ProcessParameters).StandardOutput;
    }
}

fn get_std_err_handle() -> HANDLE {
    unsafe {
        let peb = get_peb();
        return (*peb.ProcessParameters).StandardError;
    }
}

struct OutpRedirectHandles {
    msvcrt_os_handle: i32,

    current_msvc_stdout_ptr: P_MSVCRT_FILE,
    saved_msvc_stdout: Option<MSVCRT_FILE>,
    current_msvc_stderr_ptr: P_MSVCRT_FILE,
    saved_msvc_stderr: Option<MSVCRT_FILE>,

    ucrt_os_handle: i32,

    current_ucrt_stdout_ptr: P_UCRTBASE_FILE,
    saved_ucrt_stdout: Option<UCRTBASE_FILE>,
    current_ucrt_stderr_ptr: P_UCRTBASE_FILE,
    saved_ucrt_stderr: Option<UCRTBASE_FILE>,

    saved_generic_stdout_handle: Option<HANDLE>,
    saved_generic_stderr_handle: Option<HANDLE>,
}

impl Default for OutpRedirectHandles {
    fn default() -> Self {
        Self { msvcrt_os_handle: Default::default(), current_msvc_stdout_ptr: null_mut(), saved_msvc_stdout: Default::default(),
            current_msvc_stderr_ptr: null_mut(), saved_msvc_stderr: Default::default(),
            ucrt_os_handle: Default::default(), current_ucrt_stdout_ptr: null_mut(), saved_ucrt_stdout: Default::default(),
            current_ucrt_stderr_ptr: null_mut(), saved_ucrt_stderr: Default::default(),
            saved_generic_stdout_handle: Default::default(), saved_generic_stderr_handle: Default::default(),
        }
    }
}


pub struct OutputRedirector {
    api_calls: APICalls,
    handles: OutpRedirectHandles,

    read_pipe_handle: HANDLE,
    write_pipe_handle: HANDLE,

    redirected_msvc: bool,
    redirected_ucrt: bool,
    redirected_generic: bool,
}

impl OutputRedirector {
    pub fn new() -> Self {
        let mut instance = Self { 
            api_calls: APICalls::new(),
            handles: OutpRedirectHandles::default(),
            read_pipe_handle: 0,
            write_pipe_handle: 0,
            redirected_msvc: false,
            redirected_ucrt: false,
            redirected_generic: false,
         };

         instance.init();
         instance
    }

    fn init(&mut self) {
        let security_attributes: SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES{
            nLength: size_of::<SECURITY_ATTRIBUTES> as u32,
            bInheritHandle: TRUE,
            lpSecurityDescriptor: NULL
        };
        let security_attributes_ptr = &security_attributes as *const SECURITY_ATTRIBUTES;

        let _  = unsafe {CreatePipe(&mut self.read_pipe_handle, &mut self.write_pipe_handle, security_attributes_ptr, 0) };
    }

    pub fn redirect_outputs(&mut self, msvcrt: bool, ucrt: bool) -> bool {
        if self.write_pipe_handle == 0 || self.read_pipe_handle == 0 {
            return false;
        }

        unsafe {
            if msvcrt {
                if self.api_calls.msvcrt_open_osfhandle.is_none() {
                    self.api_calls.msvcrt_open_osfhandle = Some(mem::transmute::<usize, MsvcrtOpenOsfhandle>(get_dll_proc_address("msvcrt.dll","_open_osfhandle").address.unwrap()));
                }
                if self.api_calls.msvcrt_iob_func.is_none() {
                    self.api_calls.msvcrt_iob_func = Some(mem::transmute::<usize, MsvcrtIobFunc>(get_dll_proc_address("msvcrt.dll","__iob_func").address.unwrap()));
                }

                if self.handles.msvcrt_os_handle == 0 { 
                    self.handles.msvcrt_os_handle = (self.api_calls.msvcrt_open_osfhandle.unwrap())(self.write_pipe_handle as usize, _O_WRONLY);
                }

                if self.handles.msvcrt_os_handle == -1 {
                    return false;
                }

                let std_pointer = (self.api_calls.msvcrt_iob_func.unwrap())();
                let stdout = (std_pointer as usize + size_of::<MSVCRT_FILE>()) as P_MSVCRT_FILE;
                let stderr = (std_pointer as usize + 2 * size_of::<MSVCRT_FILE>()) as P_MSVCRT_FILE;
                //backup stdout
                self.handles.saved_msvc_stdout = Some((*stdout).clone());
                self.handles.current_msvc_stdout_ptr = stdout;
                // modify stdout
                write_bytes(stdout, 0, 1);
                (*stdout).flag = _IOWRT | _IONBF;
                (*stdout).file = self.handles.msvcrt_os_handle;
                //backup stderr
                self.handles.saved_msvc_stderr = Some((*stderr).clone());
                self.handles.current_msvc_stderr_ptr = stderr;
                // modify stderr
                write_bytes(stderr, 0, 1);
                (*stderr).flag = _IOWRT | _IONBF;
                (*stderr).file = self.handles.msvcrt_os_handle;

                self.redirected_msvc = true;
            }
            
            if ucrt {
                if self.api_calls.ucrt_open_osfhandle.is_none() {
                    self.api_calls.ucrt_open_osfhandle = Some(mem::transmute::<usize, UcrtOpenOsfhandle>(get_dll_proc_address("ucrtbase.dll","_open_osfhandle").address.unwrap()));
                }
                if self.api_calls.ucrt_iob_func.is_none() {
                    self.api_calls.ucrt_iob_func = Some(mem::transmute::<usize, UcrtIobFunc>(get_dll_proc_address("ucrtbase.dll","__acrt_iob_func").address.unwrap()));
                }

                if self.handles.ucrt_os_handle == 0 { 
                    self.handles.ucrt_os_handle = (self.api_calls.ucrt_open_osfhandle.unwrap())(self.write_pipe_handle as usize, _O_WRONLY);
                }

                if self.handles.ucrt_os_handle == -1 {
                    return false;
                }

                let stdout= (self.api_calls.ucrt_iob_func.unwrap())(1);
                //backup stdout
                self.handles.saved_ucrt_stdout = Some((*stdout).clone());
                self.handles.current_ucrt_stdout_ptr = stdout;
                // modify stdout
                write_bytes(stdout, 0, 1);
                (*stdout).flags = 0x2000 | 0x400 | 0x2;
                (*stdout).file = self.handles.ucrt_os_handle;
                (*stdout).lock.LockCount = -1;

                let stderr = (self.api_calls.ucrt_iob_func.unwrap())(2);
                //backup stderr
                self.handles.saved_ucrt_stderr = Some((*stderr).clone());
                self.handles.current_ucrt_stderr_ptr = stderr;
                // modify stderr
                write_bytes(stderr, 0, 1);
                (*stderr).flags = 0x2000 | 0x400 | 0x2;
                (*stderr).file = self.handles.ucrt_os_handle;
                (*stderr).lock.LockCount = -1;

                self.redirected_ucrt = true;
            }

            self.handles.saved_generic_stdout_handle = Some(get_std_output_handle());
            self.handles.saved_generic_stderr_handle = Some(get_std_err_handle());

            set_std_out_handle(self.write_pipe_handle);
            set_std_err_handle(self.write_pipe_handle);

            self.redirected_generic = true;
        }

        true
    }

    pub fn revert_redirection(&mut self) {
        if self.redirected_msvc {
            unsafe {
                (*self.handles.current_msvc_stdout_ptr) = self.handles.saved_msvc_stdout.unwrap();
                (*self.handles.current_msvc_stderr_ptr) = self.handles.saved_msvc_stderr.unwrap();
            }
            self.redirected_msvc = false;
        }

        if self.redirected_ucrt {
            unsafe {
                (*self.handles.current_ucrt_stdout_ptr) = self.handles.saved_ucrt_stdout.unwrap();
                (*self.handles.current_ucrt_stderr_ptr) = self.handles.saved_ucrt_stderr.unwrap();
            }
            self.redirected_ucrt = false;
        }

        if self.redirected_generic { 
            set_std_out_handle(self.handles.saved_generic_stdout_handle.unwrap());
            set_std_err_handle(self.handles.saved_generic_stderr_handle.unwrap());
            self.redirected_generic = false;
        }
    }

    pub fn read_outputs(&mut self) -> Option<Vec<u8>> {
        unsafe {
            if self.read_pipe_handle == 0 {
                return None;
            }

            let mut nb_of_byte_read: u32 = 0;

            if PeekNamedPipe(self.read_pipe_handle, null_mut(), 0, null_mut(), &mut nb_of_byte_read, null_mut()) == FALSE {
                return None;
            }

            if nb_of_byte_read == 0 {
                return None;
            }

            let mut buffer: [u8; 1024] = [0u8;1024];
            if ReadFile(self.read_pipe_handle, &mut buffer as *mut u8, 1024, &mut nb_of_byte_read, null_mut()) == FALSE {
                return None;
            }
            return Some(buffer[0..nb_of_byte_read as usize].to_vec());
        }
    }
}

impl Drop for OutputRedirector {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.read_pipe_handle) };
        unsafe { CloseHandle(self.write_pipe_handle) };
    }
}