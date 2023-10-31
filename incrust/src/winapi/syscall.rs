// Adapted from
// Credits: Yxel / janoglezcampos / @httpyxel (https://github.com/janoglezcampos/rust_syscalls/blob/main/src/syscall.rs)
//

#[allow(unused_imports)]
use std::arch::global_asm;

#[cfg(all(feature = "syscall_indirect", not(feature = "syscall_direct")))]
#[macro_export]
macro_rules! syscall {
    ($ntdll:expr, $func_name:expr, $($y:expr), +) => {
        {
            let ssn = $ntdll.resolver.retrieve_ssn($func_name.as_str()).unwrap();
            let addr = $ntdll.resolver.get_random_syscall_addr().unwrap();
            // println!("{:#x}",ssn);
            // println!("{:#x}", addr);
        let mut cnt:usize = 0;
        $(
            let _ = $y;
            cnt += 1;
        )+
        crate::winapi::syscall::do_syscall(ssn, addr, cnt, $($y), +)
    }}
}



#[cfg(all(feature = "syscall_direct", not(feature = "syscall_indirect")))]
#[macro_export]
macro_rules! syscall {
    ($ntdll:expr, $func_name:expr, $($y:expr), +) => {
        {
            let ssn = $ntdll.resolver.retrieve_ssn($func_name.as_str()).unwrap();
            debug_info(ssn);
        let mut cnt:usize = 0;
        $(
            let _ = $y;
            cnt += 1;
        )+
        crate::winapi::syscall::do_syscall(ssn, cnt, $($y), +)
    }}
}


#[cfg(all(feature = "syscall_direct", not(feature = "syscall_indirect")))]
#[cfg(target_arch = "x86")]
extern "C" {
    pub fn do_syscall(ssn: u16, n_args: usize, ...) -> i32;
}

#[cfg(all(feature = "syscall_direct", not(feature = "syscall_indirect")))]
#[cfg(target_arch = "x86_64")]
extern "C" {
    pub fn do_syscall(ssn: u16, n_args: usize, ...) -> i32;
}

#[cfg(all(feature = "syscall_indirect", not(feature = "syscall_direct")))]
#[cfg(target_arch = "x86")]
extern "C" {
    pub fn do_syscall(ssn: u16, syscall_addr: usize, n_args: usize, ...) -> i32;
}

#[cfg(all(feature = "syscall_indirect", not(feature = "syscall_direct")))]
#[cfg(target_arch = "x86_64")]
extern "C" {
    pub fn do_syscall(ssn: u16, syscall_addr: usize, n_args: usize, ...) -> i32;
}




#[cfg(all(feature = "syscall_direct", not(feature = "syscall_indirect")))]
#[cfg(target_arch = "x86_64")]
global_asm!(
    "
.global do_syscall

.section .text

do_syscall:

    mov [rsp - 0x8],  rsi
    mov [rsp - 0x10], rdi

    mov eax, ecx
    mov rcx, rdx

    mov r10, r8
    mov rdx, r9
    
    mov  r8,  [rsp + 0x28]
    mov  r9,  [rsp + 0x30]

    sub rcx, 0x4
    jle skip

    lea rsi,  [rsp + 0x38]
    lea rdi,  [rsp + 0x28]

    rep movsq
skip:
    syscall

    mov rsi, [rsp - 0x8]
    mov rdi, [rsp - 0x10]

    ret
"
);

#[cfg(all(feature = "syscall_indirect", not(feature = "syscall_direct")))]
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

#[cfg(all(feature = "syscall_direct", not(feature = "syscall_indirect")))]
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

#[cfg(target_arch = "x86")]
#[cfg(all(feature = "syscall_indirect", not(feature = "syscall_direct")))]
global_asm!("
.global _do_syscall

.section .text

_do_syscall:
    mov [esp - 0x04], esi //backup esi
    mov [esp - 0x08], edi //backup edi

    mov eax, [esp + 0x04] //copy param 1 in eax = ssn
    mov ebx, [esp + 0x08] //copy param 2 in ebx = addr
    mov ecx, [esp + 0x0C] //copy param 3 in ecx = nb of real parameters

    lea esi, [esp + 0x10] //set esi on the adress of th 1st real param
    lea edi, [esp + 0x04] //set edi on the addres of the 1st param (ssn)

    rep movsd             //recurse copy => shift params on stack for n params (n is ecx)

    mov esi, [esp - 0x04] //restore esi
    mov edi, [esp - 0x08] //restore edi

    mov edx, fs:[0xC0]  // undocumented : void*                       WOW32Reserved;                              //0x00C0 / user-mode 32-bit (WOW64) -> 64-bit context switch function prior to kernel-mode transition (https://bytepointer.com/resources/tebpeb32.htm)
    test edx, edx
    je native

    jmp ebx                 //jump to addr

native:
    sub ebx, 0x05    // jump 5 bytecode before the call instruction => allow to get coorect edx value before call edx
                     // got to : mov edx, <&kiFastSystemCall> => maybe we should be able to get the value when parsing syscall functions and reuse it (best for unhooking)
    jmp ebx
");


