use super::{structs::UNICODE_STRING, types::{PWSTR, BOOL}};

#[allow(unused)]
#[link(name = "ntdll")]
extern "system" {
    pub fn RtlExitUserThread(uExitCode: u32);
}

// RtlCreateUnicodeString(
//     [out] PUNICODE_STRING DestinationString,
//     [in]  PCWSTR          SourceString
//   );      
#[allow(unused)]
#[link(name = "ntdll")]
extern "system" {
    pub fn RtlCreateUnicodeString(DestinationString: *mut UNICODE_STRING, SourceString: PWSTR) -> BOOL;
}
       