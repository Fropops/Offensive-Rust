
use std::os::raw::c_ulong;

//From windows-rs
//BYTE -> u8
//WORD -> u16
//DWORD -> u32
//DWORD64 -> u64
//ULONGLONG -> u64

pub type DWORD = c_ulong;
#[allow(non_camel_case_types)]
pub type __uint64 = u64;
pub type DWORD64 = __uint64;
//pub type ULONGLONG = c_ulonglong;
pub type HINSTANCE = isize;
#[allow(non_camel_case_types)]
pub type UINT_PTR = __uint64;
//pub type PVOID = *mut ::core::ffi::c_void;
pub type HANDLE = isize;

#[allow(non_camel_case_types)]
pub type NT_STATUS = i32;

#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub type PROCESS_ACCESS_RIGHTS = u32;
#[allow(non_camel_case_types)]
pub type VIRTUAL_ALLOCATION_TYPE = u32;
#[allow(non_camel_case_types)]
pub type PAGE_PROTECTION_FLAGS = u32;

#[allow(dead_code)]
extern "C" {
    #[doc(hidden)]
    pub fn strlen(s: PCSTR) -> usize;
    #[doc(hidden)]
    pub fn wcslen(s: PCWSTR) -> usize;
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PWSTR(pub *mut u16);

#[allow(dead_code)]
impl PWSTR {
    /// Construct a new `PWSTR` from a raw pointer.
    pub const fn from_raw(ptr: *mut u16) -> Self {
        Self(ptr)
    }

    /// Construct a null `PWSTR`.
    pub fn null() -> Self {
        Self(std::ptr::null_mut())
    }

    /// Returns a raw pointer to the `PWSTR`.
    pub fn as_ptr(&self) -> *mut u16 {
        self.0
    }

    /// Checks whether the `PWSTR` is null.
    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }

    /// String data without the trailing 0.
    ///
    /// # Safety
    ///
    /// The `PWSTR`'s pointer needs to be valid for reads up until and including the next `\0`.
    pub unsafe fn as_wide(&self) -> &[u16] {
        let len = wcslen(PCWSTR::from_raw(self.0));
        std::slice::from_raw_parts(self.0, len)
    }

    /// Copy the `PWSTR` into a Rust `String`.
    ///
    /// # Safety
    ///
    /// See the safety information for `PWSTR::as_wide`.
    pub unsafe fn to_string(&self) -> std::result::Result<String, std::string::FromUtf16Error> {
        String::from_utf16(self.as_wide())
    }

    // /// Copy the `PWSTR` into an `HSTRING`.
    // ///
    // /// # Safety
    // ///
    // /// See the safety information for `PWSTR::as_wide`.
    // pub unsafe fn to_hstring(&self) -> Result<HSTRING> {
    //     HSTRING::from_wide(self.as_wide())
    // }

    // /// Allow this string to be displayed.
    // ///
    // /// # Safety
    // ///
    // /// See the safety information for `PWSTR::as_wide`.
    // pub unsafe fn display(&self) -> impl std::fmt::Display + '_ {
    //     Decode(move || std::char::decode_utf16(self.as_wide().iter().cloned()))
    // }
}


/// A pointer to a constant null-terminated string of 16-bit Unicode characters.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PCWSTR(pub *const u16);

#[allow(dead_code)]
impl PCWSTR {
    /// Construct a new `PCWSTR` from a raw pointer
    pub const fn from_raw(ptr: *const u16) -> Self {
        Self(ptr)
    }

    /// Construct a null `PCWSTR`
    pub const fn null() -> Self {
        Self(std::ptr::null())
    }

    /// Returns a raw pointer to the `PCWSTR`
    pub const fn as_ptr(&self) -> *const u16 {
        self.0
    }

    /// Checks whether the `PCWSTR` is null
    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }

    /// String data without the trailing 0
    ///
    /// # Safety
    ///
    /// The `PCWSTR`'s pointer needs to be valid for reads up until and including the next `\0`.
    pub unsafe fn as_wide(&self) -> &[u16] {
        let len = wcslen(*self);
        std::slice::from_raw_parts(self.0, len)
    }

    /// Copy the `PCWSTR` into a Rust `String`.
    ///
    /// # Safety
    ///
    /// See the safety information for `PCWSTR::as_wide`.
    pub unsafe fn to_string(&self) -> std::result::Result<String, std::string::FromUtf16Error> {
        String::from_utf16(self.as_wide())
    }

    // /// Copy the `PCWSTR` into an `HSTRING`.
    // ///
    // /// # Safety
    // ///
    // /// See the safety information for `PCWSTR::as_wide`.
    // pub unsafe fn to_hstring(&self) -> Result<HSTRING> {
    //     HSTRING::from_wide(self.as_wide())
    // }

    // /// Allow this string to be displayed.
    // ///
    // /// # Safety
    // ///
    // /// See the safety information for `PCWSTR::as_wide`.
    // pub unsafe fn display(&self) -> impl std::fmt::Display + '_ {
    //     Decode(move || std::char::decode_utf16(self.as_wide().iter().cloned()))
    // }
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PCSTR(pub *const u8);

#[allow(dead_code)]
impl PCSTR {
    /// Construct a new `PCSTR` from a raw pointer
    pub const fn from_raw(ptr: *const u8) -> Self {
        Self(ptr)
    }

    /// Construct a null `PCSTR`
    pub fn null() -> Self {
        Self(std::ptr::null())
    }

    /// Returns a raw pointer to the `PCSTR`
    pub fn as_ptr(&self) -> *const u8 {
        self.0
    }

    /// Checks whether the `PCSTR` is null
    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }

    /// String data without the trailing 0
    ///
    /// # Safety
    ///
    /// The `PCSTR`'s pointer needs to be valid for reads up until and including the next `\0`.
    pub unsafe fn as_bytes(&self) -> &[u8] {
        let len = strlen(*self);
        std::slice::from_raw_parts(self.0, len)
    }

    /// Copy the `PCSTR` into a Rust `String`.
    ///
    /// # Safety
    ///
    /// See the safety information for `PCSTR::as_bytes`.
    pub unsafe fn to_string(&self) -> std::result::Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.as_bytes().into())
    }

    // /// Allow this string to be displayed.
    // ///
    // /// # Safety
    // ///
    // /// See the safety information for `PCSTR::as_bytes`.
    // pub unsafe fn display(&self) -> impl std::fmt::Display + '_ {
    //     Decode(move || decode_utf8(self.as_bytes()))
    // }
}