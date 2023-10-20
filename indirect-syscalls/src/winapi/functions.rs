
use core::arch::asm;
use super::types::DWORD;
use super::types::DWORD64;

#[inline]
#[cfg(target_pointer_width = "64")]
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