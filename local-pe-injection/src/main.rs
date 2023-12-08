#![cfg_attr(
    all(
      target_os = "windows",
      feature = "no_console",
    ),
    windows_subsystem = "windows"
  )]

#[macro_use]
extern crate litcrypt;
use_litcrypt!();

mod loader;
mod common;
mod winapi;

fn main() {
    debug_simple_msg!("====================================");
    debug_simple_msg!("=====     PE Local Injector    =====");
    debug_simple_msg!("====================================");
    loader::do_load();

    debug_simple_msg!("====================================");
    debug_simple_msg!("===== END PE Local Injector    =====");
    debug_simple_msg!("====================================");
}