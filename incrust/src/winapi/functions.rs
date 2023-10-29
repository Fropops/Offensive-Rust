
use core::arch::asm;
use super::types::DWORD;

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