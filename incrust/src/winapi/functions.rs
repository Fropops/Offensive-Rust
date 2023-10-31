
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

#[cfg(target_arch = "x86_64")]
pub fn get_syscall_function_size() -> isize {
    32
}

#[cfg(target_arch = "x86")]
pub fn get_syscall_function_size() -> isize {
    16
}