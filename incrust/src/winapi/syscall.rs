//
// Credits: Yxel / janoglezcampos / @httpyxel (https://github.com/janoglezcampos/rust_syscalls/blob/main/src/syscall.rs)
//


#[allow(unused_imports)]
use std::arch::global_asm;

// #[macro_export]
// macro_rules! syscall {
//     ($function_name:expr, $($y:expr), +) => {
//         {
//         let (ssn, addr) = $crate::syscall_resolve::get_ssn($crate::obf!($function_name)).expect("Failed to get SSN");
//         let mut cnt:u32 = 0;
//         $(
//             let _ = $y;
//             cnt += 1;
//         )+
//         crate::syscall::do_syscall(ssn, addr, cnt, $($y), +)
//     }}
// }

#[macro_export]
macro_rules! syscall {
    ($ssn:expr, $addr:expr, $($y:expr), +) => {
        {
        let mut cnt:u32 = 0;
        $(
            let _ = $y;
            cnt += 1;
        )+
        crate::winapi::syscall::do_syscall($ssn, $addr, cnt, $($y), +)
    }}
}

// #[macro_export]
// macro_rules! syscall {
//     ($ssn:expr, $($y:expr), +) => {
//         {
//         let mut cnt:u32 = 0;
//         $(
//             let _ = $y;
//             cnt += 1;
//         )+
//         crate::winapi::syscall::do_syscall($ssn, cnt, $($y), +)
//     }}
// }



// #[cfg(target_arch = "x86")]
// extern "C" {
//     pub fn do_syscall(ssn: u16, n_args: u32, ...) -> i32;
// }

#[cfg(target_arch = "x86_64")]
extern "C" {
    pub fn do_syscall(ssn: u16, syscall_addr: u64, n_args: u32, ...) -> i32;
}

// #[cfg(target_arch = "x86_64")]
// extern "C" {
//     pub fn do_syscall(ssn: u16, n_args: u32, ...) -> i32;
// }


// #[cfg(target_arch = "x86_64")]
// global_asm!(
//     "
// .global do_syscall

// .section .text

// do_syscall:

//     mov [rsp - 0x8],  rsi
//     mov [rsp - 0x10], rdi

//     mov eax, ecx
//     mov rcx, rdx

//     mov r10, r8
//     mov rdx, r9
    
//     mov  r8,  [rsp + 0x28]
//     mov  r9,  [rsp + 0x30]

//     sub rcx, 0x4
//     jle skip

//     lea rsi,  [rsp + 0x38]
//     lea rdi,  [rsp + 0x28]

//     rep movsq
// skip:
//     syscall

//     mov rsi, [rsp - 0x8]
//     mov rdi, [rsp - 0x10]

//     ret
// "
// );

#[cfg(target_arch = "x86_64")]
global_asm!(
    "
.global do_syscall

.section .text

do_syscall:
    mov [rsp - 0x8],  rsi
    mov [rsp - 0x10], rdi
    mov [rsp - 0x18], r12

    mov eax, ecx
    mov r12, rdx
    mov rcx, r8

    mov r10, r9
    mov  rdx,  [rsp + 0x28]
    mov  r8,   [rsp + 0x30]
    mov  r9,   [rsp + 0x38]

    sub rcx, 0x4
    jle skip

    lea rsi,  [rsp + 0x40]
    lea rdi,  [rsp + 0x28]

    rep movsq
skip:

    mov rcx, r12

    mov rsi, [rsp - 0x8]
    mov rdi, [rsp - 0x10]
    mov r12, [rsp - 0x18]

    jmp rcx
"
);

#[cfg(target_arch = "x86")]
global_asm!(
    "
.global _do_syscall

.section .text

_do_syscall:
    mov [esp - 0x04], esi
    mov [esp - 0x08], edi

    mov eax, [esp + 0x04]
    mov ecx, [esp + 0x08]

    lea esi, [esp + 0x0C]
    lea edi, [esp + 0x04]

    rep movsd

    mov esi, [esp - 0x04]
    mov edi, [esp - 0x08]

    mov edx, fs:[0xc0]
    test edx, edx
    je native

    call edx
    ret

native:
    call sysenter
    ret

sysenter:
    mov edx,esp
    sysenter

"
);


