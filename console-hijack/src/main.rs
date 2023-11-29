#![windows_subsystem = "windows"] 

use std::fs::File;
use std::io::Write;
use std::mem::size_of;
use std::{ffi::CStr, ptr::null_mut};

use windows::Win32::Foundation::{HANDLE, TRUE, CloseHandle};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::ReadFile;
use windows::Win32::System::Console::{SetStdHandle, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE, GetStdHandle, AllocConsole, FreeConsole};
use windows::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};


static mut READ_PIPE_HANDLE: HANDLE = HANDLE(0);
static mut WRITE_PIPE_HANDLE : HANDLE = HANDLE(0);

static mut BACKED_STDOUT :i32 = 0;
static mut BACKED_STDERR :i32 = 0;

pub enum FILE {}
type PFILE = *mut FILE;

#[allow(unused)]
#[link(name = "ucrt")]
extern "cdecl" {
    pub fn freopen_s(stream: *mut PFILE, filename: *const i8, mode: *const i8, file: *mut FILE) -> u32;
    pub fn __acrt_iob_func(id: u32) -> *mut FILE;
    pub fn _dup(fd: i32) -> i32;
    pub fn _dup2(fd1: i32, fd2 :i32 ) -> i32;
    pub fn _fileno(stream: PFILE) -> i32;
    pub fn _fdopen(fd: i32,  mode: *const i8) -> PFILE;
    pub fn _open_osfhandle (osfhandle: usize, flags: i32) -> i32;
    pub fn _get_osfhandle(fd: i32) -> isize;
    pub fn _setmode (fd: i32, mode: i32) -> i32;
}

pub const STDOUT : u32 = 1;
pub const STDERR : u32 = 2;
pub const _O_TEXT : i32 = 0x4000;

pub fn redirect_outputs() -> i32 {
    unsafe {
        let stdout = __acrt_iob_func(STDOUT);
        let stderr = __acrt_iob_func(STDERR);

        let mut stream: PFILE = null_mut();
        if  let Err(_) = GetStdHandle(STD_OUTPUT_HANDLE) {
            /****************************************/
            // not needed in c++ version but in rust if a console is not allocated, the stdout is not redircted correctly. 
            // maybe it's related to https://github.com/rust-lang/rust/issues/25977 , https://github.com/rust-lang/rust/issues/9486 & https://rust-lang.github.io/rfcs/1014-stdout-existential-crisis.html
            // have to try with the pe loader...
            if let Err(_) = AllocConsole() {
                return 1;
            }
        
            if let Err(_) = FreeConsole() {
                return 2;
            }
            /****************************************/
            
            if freopen_s(&mut stream, CStr::from_bytes_with_nul(b"NUL\0").unwrap().as_ptr(), CStr::from_bytes_with_nul(b"w\0").unwrap().as_ptr(), stdout) != 0 {
                return 3;
            }
            if freopen_s(&mut stream, CStr::from_bytes_with_nul(b"NUL\0").unwrap().as_ptr(), CStr::from_bytes_with_nul(b"w\0").unwrap().as_ptr(), stderr) != 0 {
                return 4;
            }
            
        }

        //refresh the WINAPI stdout & stderr handles
        if let Err(_) = SetStdHandle(STD_OUTPUT_HANDLE, HANDLE(_get_osfhandle(_fileno(stdout)))) {
            return 5;
        }
        if let Err(_) = SetStdHandle(STD_ERROR_HANDLE, HANDLE(_get_osfhandle(_fileno(stderr)))) {
            return 6;
        }

        BACKED_STDOUT = _dup(_fileno(stdout));
        BACKED_STDERR = _dup(_fileno(stderr));

        let security_attributes: SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES{
            nLength: size_of::<SECURITY_ATTRIBUTES> as u32,
            bInheritHandle: TRUE,
            lpSecurityDescriptor: null_mut()
        };
        let security_attributes_ptr = &security_attributes as *const SECURITY_ATTRIBUTES;

        if let Err(_) = CreatePipe(&mut READ_PIPE_HANDLE, &mut WRITE_PIPE_HANDLE, Some(security_attributes_ptr), 0) {
            return 7;
        }

        // Attach stdout & stderr to the write end of the pipe
        let f: PFILE= _fdopen(_open_osfhandle(WRITE_PIPE_HANDLE.0 as usize, _O_TEXT), CStr::from_bytes_with_nul(b"w\0").unwrap().as_ptr());
        if f == null_mut() {
            return 8;
        }

        if _dup2(_fileno(f), _fileno(stdout)) != 0 {
            return 9;
        }

        if _dup2(_fileno(f), _fileno(stderr)) != 0  {
            return 10;
        }

        0
    }
}

pub fn revert_outputs() {
    unsafe {
        let stdout = __acrt_iob_func(STDOUT);
        let stderr = __acrt_iob_func(STDERR);
        if _dup2(BACKED_STDOUT, _fileno(stdout)) != 0 {
            return;
        }

        if _dup2(BACKED_STDERR, _fileno(stderr)) != 0  {
            return;
        }
    }
}

pub fn read_outputs() -> Option<Vec<u8>> {
    unsafe {
        let mut nb_of_byte_read: u32 = 0;


        if let Err(_) = PeekNamedPipe(READ_PIPE_HANDLE, None, 0, None, Some(&mut nb_of_byte_read), None) {
            return None;
        }

        if nb_of_byte_read == 0 {
            return None;
        }

        let mut buffer: [u8; 1024] = [0u8;1024];
        if let Err(_) = ReadFile(READ_PIPE_HANDLE, Some(&mut buffer), Some(&mut nb_of_byte_read), None) {
            return None;
        }
        return Some(buffer[0..nb_of_byte_read as usize].to_vec());
    }
}

fn main() {
    println!("Message in the console (if existing)!");

    if redirect_outputs() != 0 {
        eprintln!("Failed to redirect outputs!");
        return
    };

    println!("This is an STDOUT msg redirected !");
    eprintln!("This is an STDERR msg redirected !");

    let mut file = File::create("log.txt").unwrap();
    while let Some(buff) = read_outputs() {
        file.write(&buff).unwrap();
    }
    
    revert_outputs();

    unsafe {
        let _ = CloseHandle(READ_PIPE_HANDLE);
        let _ = CloseHandle(WRITE_PIPE_HANDLE);
    }

    println!("Back in the console (if existing)!");
}
