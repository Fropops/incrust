
use std::mem::size_of;
use std::ptr::null;

use crate::common::helpers::ascii_bytes_to_string;
use crate::winapi::constants::{MEM_RESERVE, MEM_COMMIT, PAGE_READWRITE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_HIGHLOW, IMAGE_ORDINAL_FLAG, PAGE_WRITECOPY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY, IMAGE_SCN_MEM_WRITE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, THREAD_ALL_ACCESS, MEM_RELEASE};
use crate::winapi::dll_functions::{get_dll_proc_address, get_dll_proc_address_by_ordinal_index};
use crate::winapi::kernel32::{hook_exit_process, hook_wgetmainargs};
use crate::winapi::structs::{IMAGE_BASE_RELOCATION, IMAGE_IMPORT_BY_NAME, RTL_USER_PROCESS_PARAMETERS, UNICODE_STRING};
use crate::winapi::types::{HANDLE, BASE_RELOCATION_ENTRY, IMAGE_THUNK_DATA, PWSTR};
#[allow(unused_imports)]
use crate::{debug_error, debug_info, debug_info_msg, debug_success_msg, debug_ok_msg, debug_info_hex, debug_error_msg};
#[allow(unused_imports)]
use crate::{debug_base, debug_base_msg, debug_base_hex};

use super::constants::{IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_EXPORT};
use super::dll_functions::get_peb;
use super::nt::syscall_wrapper::SyscallWrapper;
use super::structs::{IMAGE_SECTION_HEADER, IMAGE_DATA_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR};
use super::types::PCSTR;
use super::{types::{IMAGE_NT_HEADERS, IMAGE_OPTIONAL_HEADER}, structs::IMAGE_DOS_HEADER, constants::{IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, IMAGE_NT_OPTIONAL_HDR_MAGIC, IMAGE_FILE_DLL, STATUS_SUCCESS}};

#[repr(C)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
struct PE_Infos
{
	pe_base_address: *const u8,
    pe_size: usize,
	nt_header_ptr: *const IMAGE_NT_HEADERS,
    is_dll: bool,
    image_section_header_ptr: *const IMAGE_SECTION_HEADER,
    entry_import_data_dir_ptr: *const IMAGE_DATA_DIRECTORY,
    entry_base_reloc_data_dir_ptr: *const IMAGE_DATA_DIRECTORY,
    entry_TLS_data_dir_ptr: *const IMAGE_DATA_DIRECTORY,
    entry_exception_data_dir_ptr: *const IMAGE_DATA_DIRECTORY,
    entry_export_data_dir_ptr: *const IMAGE_DATA_DIRECTORY,
    thread_handle: HANDLE,
}

impl Default for PE_Infos {
    fn default() -> Self {
        Self { 
            pe_base_address: null(), 
            pe_size : 0, 
            nt_header_ptr: null(), 
            is_dll: false,
            image_section_header_ptr: null(),
            entry_import_data_dir_ptr: null(), 
            entry_base_reloc_data_dir_ptr: null(), 
            entry_TLS_data_dir_ptr: null(),
            entry_exception_data_dir_ptr: null(), 
            entry_export_data_dir_ptr: null() ,
            thread_handle : 0 as HANDLE,
        }
    }
}

#[repr(C)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
struct PE_Args{
    existing_args : String,
    existing_arg_length: u16,
    existing_arg_max_length: u16,
    new_args : String,
}

impl Default for PE_Args {
    fn default() -> Self {
        Self { existing_args: String::default(),existing_arg_length: 0, existing_arg_max_length: 0 , new_args: String::default() }
    }
}


#[allow(non_camel_case_types)]
pub struct PE_Loader {
    infos: PE_Infos,
    pe_bytes: Vec<u8>,
    arguments: PE_Args,
    ntdll: SyscallWrapper,
}



impl PE_Loader {
    pub fn new(ntdll: SyscallWrapper) -> Self {
        Self{
            infos: PE_Infos::default(),
            ntdll: ntdll,
            arguments: PE_Args::default(),
            pe_bytes: vec![0]
        }
    }

    fn init(&mut self, pe_bytes: Vec<u8>, args: String) -> bool {
        debug_info_msg!(format!("Reading PE Infos ..."));
        let dos_headers: *const IMAGE_DOS_HEADER;
        let nt_headers: *const IMAGE_NT_HEADERS;
        let optional_header: * const IMAGE_OPTIONAL_HEADER;

        self.arguments.new_args = args;
        
        let pe_base_address = pe_bytes.as_ptr();
        self.pe_bytes = pe_bytes;

        unsafe {
            dos_headers = pe_base_address as *const IMAGE_DOS_HEADER;
            if (*dos_headers).e_magic != IMAGE_DOS_SIGNATURE {
                debug_error!("Invalid dos signature!");
                return false;
            }

            nt_headers = (pe_base_address as usize + (*dos_headers).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
            if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
                debug_error!("Invalid NT signature!");
                return false;
            }
            self.infos.nt_header_ptr = nt_headers;

            optional_header	= &(*nt_headers).OptionalHeader;
            if (*optional_header).Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC {
                debug_error!("Invalid Optional Header signature!");
                return false;
            }

            self.infos.is_dll = false;
            if (*nt_headers).FileHeader.Characteristics & IMAGE_FILE_DLL != 0 {
                self.infos.is_dll = true;
            }
            self.infos.image_section_header_ptr = (nt_headers as usize + std::mem::size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER;

            self.infos.entry_import_data_dir_ptr = (&(*optional_header).DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]) as *const IMAGE_DATA_DIRECTORY;
            self.infos.entry_base_reloc_data_dir_ptr = (&(*optional_header).DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]) as *const IMAGE_DATA_DIRECTORY;
            self.infos.entry_TLS_data_dir_ptr = (&(*optional_header).DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]) as *const IMAGE_DATA_DIRECTORY;
            self.infos.entry_exception_data_dir_ptr = (&(*optional_header).DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]) as *const IMAGE_DATA_DIRECTORY;
            self.infos.entry_export_data_dir_ptr = (&(*optional_header).DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]) as *const IMAGE_DATA_DIRECTORY;

            #[cfg(feature = "verbose")]
            debug_info_msg!(format!("Import : Size {} at {:#x}",(*self.infos.entry_import_data_dir_ptr).Size, (*self.infos.entry_import_data_dir_ptr).VirtualAddress as usize));
            #[cfg(feature = "verbose")]
            debug_info_msg!(format!("Reloc : Size {} at {:#x}",(*self.infos.entry_base_reloc_data_dir_ptr).Size, (*self.infos.entry_base_reloc_data_dir_ptr).VirtualAddress as usize));
            #[cfg(feature = "verbose")]
            debug_info_msg!(format!("TLS : Size {} at {:#x}",(*self.infos.entry_TLS_data_dir_ptr).Size, (*self.infos.entry_TLS_data_dir_ptr).VirtualAddress as usize));
            #[cfg(feature = "verbose")]
            debug_info_msg!(format!("Exc : Size {} at {:#x}",(*self.infos.entry_exception_data_dir_ptr).Size, (*self.infos.entry_exception_data_dir_ptr).VirtualAddress as usize));
            #[cfg(feature = "verbose")]
            debug_info_msg!(format!("Export : Size {} at {:#x}",(*self.infos.entry_export_data_dir_ptr).Size, (*self.infos.entry_export_data_dir_ptr).VirtualAddress as usize));
        }
        debug_success_msg!(format!("Done."));
        true
    }

    fn write_pe_sections(&mut self) -> bool {
        debug_info_msg!(format!("Writing PE Sections ..."));
        let process_handle: HANDLE = -1;
        let mut size: usize = unsafe { (*self.infos.nt_header_ptr).OptionalHeader.SizeOfImage as usize };
        let mut address: usize = 0;
        let res = self.ntdll.nt_allocate_virtual_memory(process_handle, &mut address,  &mut size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if res != STATUS_SUCCESS {
            crate::debug_error_msg!(format!("Failed to allocate memory (size = {})!", size));
            return false;
        }

        #[cfg(feature = "verbose")]
        debug_success_msg!(format!("Memory allocated : {}b at {:#x}", size, address));

        unsafe {
            let mut img_section_hdr_ptr = (self.infos.nt_header_ptr as usize + std::mem::size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER;
            for _ in 0..(*self.infos.nt_header_ptr).FileHeader.NumberOfSections {
                let src = (self.pe_bytes.as_ptr() as usize + (*img_section_hdr_ptr).PointerToRawData as usize) as *const u8;
                let dst = (address + (*img_section_hdr_ptr).VirtualAddress as usize) as *mut u8;
                let size = (*img_section_hdr_ptr).SizeOfRawData as usize;
                std::ptr::copy_nonoverlapping(src, dst, size);

                //#[cfg(any(feature = "verbose", feature= "print_debug" ))]
                #[cfg(feature = "verbose")]
                debug_ok_msg!(format!("section {} copied (size={}) dst : {:#x} src : {:#x} ...", ascii_bytes_to_string(&(*img_section_hdr_ptr).Name), size, dst as usize, src as usize));

                img_section_hdr_ptr = (img_section_hdr_ptr as usize + std::mem::size_of::<IMAGE_SECTION_HEADER>()) as *const IMAGE_SECTION_HEADER;
            }
        }

        self.infos.pe_base_address = address as *const u8;
        self.infos.pe_size = size;
        debug_success_msg!(format!("Done."));
        true
    }

    fn adapt_relocations(&self) -> bool {
        debug_info_msg!(format!("Adapting relocations ..."));
        unsafe {
             let mut image_base_relocation_ptr = ((self.infos.pe_base_address as usize + (*self.infos.entry_base_reloc_data_dir_ptr).VirtualAddress as usize)) as *const IMAGE_BASE_RELOCATION;
            let pe_offset = self.infos.pe_base_address as usize - (*self.infos.nt_header_ptr).OptionalHeader.ImageBase as usize;
            let mut base_relocation_entry: *const BASE_RELOCATION_ENTRY;

            while (*image_base_relocation_ptr).VirtualAddress != 0 {

                base_relocation_entry = (image_base_relocation_ptr as usize  + size_of::<IMAGE_BASE_RELOCATION>()) as *const BASE_RELOCATION_ENTRY;

                let mut entry_count = 0;
                while base_relocation_entry as usize != image_base_relocation_ptr as usize + (*image_base_relocation_ptr).SizeOfBlock as usize {
                    entry_count = entry_count + 1;

                    let reloc_type = (*base_relocation_entry) >> 12;
                    let reloc_offset = (*base_relocation_entry) & 0xFFF;

                    //debug_info_msg!(format!("Entry #{} : type = {}, offset = {:#x}", entry_count, reloc_type, reloc_offset));
                    match reloc_type {
                        IMAGE_REL_BASED_DIR64 => {


                            let address = (self.infos.pe_base_address as usize + (*image_base_relocation_ptr).VirtualAddress as usize + reloc_offset as usize) as *mut usize;
                            #[cfg(feature = "verbose")]
                            let before = *address;
                            (*address) = (*address) + pe_offset;
                            #[cfg(feature = "verbose")]
                            let after = *address;
                            #[cfg(feature = "verbose")]
                            debug_info_msg!(format!("Address {:#x} fixed from {:#x} to {:#x} [offset = {:#x}, pe_offset = {:#x}]", (*address) as usize, before as usize, after as usize, reloc_offset as usize, pe_offset as usize));
                        },
                        IMAGE_REL_BASED_HIGHLOW => {
                            let address = (self.infos.pe_base_address as usize + (*image_base_relocation_ptr).VirtualAddress as usize + reloc_offset as usize) as *mut u32;
                            (*address) = (*address) + pe_offset as u32;
                        },
                        IMAGE_REL_BASED_ABSOLUTE => (),
                        _ => {
                            crate::debug_error_msg!(format!("Failed to relocate : unknown type {}!", reloc_type));
                            return false;
                        }
                    }

                    base_relocation_entry = (base_relocation_entry as usize  + size_of::<u16>()) as *const BASE_RELOCATION_ENTRY;
                }

                image_base_relocation_ptr = base_relocation_entry as *const IMAGE_BASE_RELOCATION;
            }
        }
        debug_success_msg!(format!("Done."));
        true
    }

    fn adapt_iat(&mut self) -> bool {
        debug_info_msg!(format!("Adapting Import Adress Table ..."));
        let mut img_desc_ptr : *const IMAGE_IMPORT_DESCRIPTOR;

        unsafe  {
            for index in 0..(*self.infos.entry_import_data_dir_ptr).Size {

                let offset = index * size_of::<IMAGE_IMPORT_DESCRIPTOR>() as u32;
                img_desc_ptr = (self.infos.pe_base_address as usize + (*self.infos.entry_import_data_dir_ptr).VirtualAddress as usize + offset as usize) as *const IMAGE_IMPORT_DESCRIPTOR;

                if (*img_desc_ptr).Anonymous.OriginalFirstThunk == 0 && (*img_desc_ptr).FirstThunk == 0 {
                    break;
                }

                let dll_name_address = (self.infos.pe_base_address as usize + (*img_desc_ptr).Name as usize) as *const u8;
                let dll_name_pcstr = PCSTR::from_raw(dll_name_address);
                let dll_name = dll_name_pcstr.to_string().unwrap();

                let int_thunk_rva = (*img_desc_ptr).Anonymous.OriginalFirstThunk as usize;
		        let iat_thunk_rva = (*img_desc_ptr).FirstThunk as usize;
                let mut img_thunk_offset = 0usize;

                //debug_info_hex!(int_thunk_rva as usize);
                //debug_info_hex!(iat_thunk_rva as usize);

                //update iat by recalculating function address using int offsets
                loop {
                    let int_thunk_ptr = (self.infos.pe_base_address as usize + int_thunk_rva + img_thunk_offset) as *const IMAGE_THUNK_DATA;
                    let iat_thunk_ptr = (self.infos.pe_base_address as usize + iat_thunk_rva + img_thunk_offset) as *mut IMAGE_THUNK_DATA;

                    if (*int_thunk_ptr).u1.Function == 0 && (*iat_thunk_ptr).u1.Function == 0 {
                        break;
                    }
                    //debug_info!((*original_first_thunk_ptr).u1.Ordinal);
        
                    if  (*int_thunk_ptr).u1.Ordinal & IMAGE_ORDINAL_FLAG != 0 {

                        //load by ordinal                    
                        let ordinal = ((*int_thunk_ptr).u1.Ordinal & 0xffff) as u16;
                        let function_address = get_dll_proc_address_by_ordinal_index(&dll_name, ordinal) as usize;
                        if  function_address == 0  {
                            crate::debug_error_msg!(format!("Failed importing {}", ordinal));
                            return false;
                        }
                        (*iat_thunk_ptr).u1.Function = function_address;
                        #[cfg(feature = "verbose")]
                        debug_info_msg!(format!("loading function {}#{} at {:#x}", dll_name, ordinal, function_address));
                    }
                    else {
                        //load by name
                        let img_import_name_ptr = (self.infos.pe_base_address as usize + (*int_thunk_ptr).u1.AddressOfData as usize) as *const IMAGE_IMPORT_BY_NAME;
                        let function_name = ascii_bytes_to_string(&(*img_import_name_ptr).Name);
                        let function_address = get_dll_proc_address(&dll_name, &function_name) as usize;
                        if  function_address == 0  {
                            crate::debug_error_msg!(format!("Failed importing {}", function_name));
                            return false;
                        }
                        #[cfg(feature = "verbose")]
                        debug_info_msg!(format!("loading function {} at {:#x}", function_name, function_address));
                        (*iat_thunk_ptr).u1.Function = function_address;


                        //Hook exit functions to prevent process to be closed
                        if function_name == "ExitProcess" || function_name == "exit" || function_name == "_Exit" || function_name == "_exit" || function_name == "quick_exit" {
                            (*iat_thunk_ptr).u1.Function = hook_exit_process as usize;
                            #[cfg(feature = "verbose")]
                            debug_info_msg!(format!("Patching {} at {:#x} instead of {:#x}", function_name, function_address, before));
                        }

                        if function_name == "GetCommandLineA" {
                            debug_info_msg!(format!("Found arg function {}", function_name));
                            (*iat_thunk_ptr).u1.Function = hook_wgetmainargs as usize;
                        }
                        else if function_name == "GetCommandLineW" {
                            debug_info_msg!(format!("Found arg function {}", function_name));
                        }
                        else if function_name == "__getmainargs" {
                            debug_info_msg!(format!("Found arg function {}", function_name));
                        }
                        else if function_name == "__wgetmainargs" {
                            debug_info_msg!(format!("Found arg function {}", function_name));
                        }
                        else if function_name == "__p___argv" {
                            debug_info_msg!(format!("Found arg function {}", function_name));
                        }
                        else if function_name == "__p___wargv" {
                            debug_info_msg!(format!("Found arg function {}", function_name));
                        }
                        else if function_name == "hook__p___argc" {
                            debug_info_msg!(format!("Found arg function {}", function_name));
                        } 
                        // else if function_name == "CommandLineToArgvW" {
                        //     debug_info_msg!(format!("Found arg function {}", function_name));
                        //     (*iat_thunk_ptr).u1.Function = hook_CommandLineToArgvW as usize;
                        //     crate::winapi::kernel32::real_CommandLineToArgvW = function_address;
                        // }

                        
                        
                    }

                    img_thunk_offset += size_of::<IMAGE_THUNK_DATA>();
                }
            }
        }
        debug_success_msg!(format!("Done."));
        true
    }

    fn adapt_permissions(&mut self) -> bool {
        debug_info_msg!(format!("Adapting Memory region permissions ..."));
        unsafe {
            let mut img_section_hdr_ptr = (self.infos.nt_header_ptr as usize + std::mem::size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER;
            for _ in 0..(*self.infos.nt_header_ptr).FileHeader.NumberOfSections {
                let mut protection = 0u32;
                let mut old_protection = 0u32;
                if (*img_section_hdr_ptr).SizeOfRawData == 0 || (*img_section_hdr_ptr).VirtualAddress == 0 {
                    continue;
                }

                if (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_WRITE != 0 {
			        protection = PAGE_WRITECOPY;
                }

                if (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_READ != 0 {
                    protection = PAGE_READONLY;
                }

                if ((*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_WRITE) != 0 && (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_READ != 0 {
                    protection = PAGE_READWRITE;
                }

                if (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
                    protection = PAGE_EXECUTE;
                }

                if (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_EXECUTE != 0 && (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_WRITE != 0 {
                    protection = PAGE_EXECUTE_WRITECOPY;
                }

                if (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_EXECUTE != 0 && (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_READ != 0 {
                    protection = PAGE_EXECUTE_READ;
                }

                if (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_EXECUTE != 0 && (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_WRITE != 0 && (*img_section_hdr_ptr).Characteristics & IMAGE_SCN_MEM_READ != 0 {
                    protection = PAGE_EXECUTE_READWRITE;
                }

                #[cfg(feature = "verbose")]
                debug_ok_msg!(format!("change memory protection of {} (size={}) at {:#x} to value {}", ascii_bytes_to_string(&(*img_section_hdr_ptr).Name), (*img_section_hdr_ptr).SizeOfRawData, self.infos.pe_section_address as usize + (*img_section_hdr_ptr).VirtualAddress as usize, protection));

                let res =  self.ntdll.nt_protect_virtual_memory(-1, &mut (self.infos.pe_base_address as usize + (*img_section_hdr_ptr).VirtualAddress as usize), &mut ((*img_section_hdr_ptr).SizeOfRawData as usize), protection, &mut old_protection);
                if res != STATUS_SUCCESS {
                    crate::debug_error_msg!(format!("Failed to change memory protection of section {}!", ascii_bytes_to_string(&(*img_section_hdr_ptr).Name)));
                    return false;
                }

                img_section_hdr_ptr = (img_section_hdr_ptr as usize + std::mem::size_of::<IMAGE_SECTION_HEADER>()) as *const IMAGE_SECTION_HEADER;
            }
        }
        debug_success_msg!(format!("Done."));
        true
    }


    //tried to overwrite the value of the PWSTR of the UNICODE_STRING => not working
    // fn patch_arguments(&mut self) -> bool {
    //     unsafe {
    //         let peb = get_peb();
    //         let peb_addr = &peb as *const _;
    //         debug_info_msg!(format!("Found PEB at {:#x}", peb_addr as usize));
    //         debug_info_msg!(format!("Found ProcessParameters at {:#x}", peb.ProcessParameters as usize));
    //         let rtl_param = *(peb.ProcessParameters as *const RTL_USER_PROCESS_PARAMETERS);
    //         let cmd_line_ptr = &rtl_param.CommandLine as *const UNICODE_STRING;
    //         debug_info_msg!(format!("Current Parameters = {}", (*cmd_line_ptr).to_string().unwrap()));
            



    //         let cmd_line_length_ptr = (cmd_line_ptr as usize) as *mut u16;
    //         let cmd_line_max_length_ptr = ((cmd_line_ptr as usize) + 2) as *mut u16;
    //         let cmd_line_data_ptr_addr = ((cmd_line_ptr as usize) + 8) as *mut usize;
            
    //         let mut cmd_line_data_ptr = PWSTR::from_raw(*(((cmd_line_ptr as usize) + 8) as *const usize)  as *mut u16);

    //         debug_info_hex!(cmd_line_data_ptr_addr as usize);
    //         debug_info_hex!(cmd_line_data_ptr.as_ptr() as usize);

    //         debug_info_msg!(format!("param length = {}", *cmd_line_length_ptr));
    //         debug_info_msg!(format!("param max length = {}", *cmd_line_max_length_ptr));
    //         debug_info_msg!(format!("pwstr addr = {:#x}", *(((cmd_line_ptr as usize) + 8) as *const usize) as usize));
    //         debug_info_msg!(format!("param pwstr = {}", cmd_line_data_ptr.to_string().unwrap()));

    //         //let new_pcwst = PWSTR::from_raw(self.arguments.new_args.as_mut_ptr() as *mut u16);
    //         let mut vec: Vec<u16> = self.arguments.new_args.encode_utf16().collect();
    //         vec.push(0);
    //         //debug_info_hex!(*(vec.as_mut_ptr()) as usize);

    //         let mut address= 0;
    //         let mut size: usize = vec.len() * 2;
    //         debug_info!(vec.len());
    //         let res = self.ntdll.nt_allocate_virtual_memory(-1, &mut address,  &mut size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    //         if res != STATUS_SUCCESS {
    //             crate::debug_error_msg!(format!("Failed to allocate memory (size = {})!", size));
    //             return false;
    //         }

    //         std::ptr::copy_nonoverlapping(vec.as_ptr(), address as *mut u16, vec.len());

    //         debug_info_msg!(format!("allocated address = {:#x}", address as usize));
    //         let new_pcwst = PWSTR::from_raw(address as *mut u16);
    //         debug_info_msg!(format!("allocated pwstr = {}", new_pcwst.to_string().unwrap()));

    //         *(cmd_line_data_ptr_addr) = address;
    //         *(cmd_line_length_ptr) = (vec.len() * 2) as u16;
    //         *(cmd_line_max_length_ptr) = (vec.len() * 2) as u16;


    //         debug_info_msg!(format!("param length = {}", *cmd_line_length_ptr));
    //         debug_info_msg!(format!("param max length = {}", *cmd_line_max_length_ptr));
    //         debug_info_msg!(format!("pwstr addr = {:#x}", *(((cmd_line_ptr as usize) + 8) as *const usize) as usize));
    //         cmd_line_data_ptr = PWSTR::from_raw(*(((cmd_line_ptr as usize) + 8) as *const usize)  as *mut u16);
    //         debug_info_msg!(format!("param pwstr = {}", cmd_line_data_ptr.to_string().unwrap()));
    //         debug_info_msg!(format!("New Parameters = {}", (*cmd_line_ptr).to_string().unwrap()));
    //     }
        

    //     //same
    //     // unsafe {
    //     //     let parm_addr = (peb_addr as usize + 32) as *const usize;
    //     //     debug_info_msg!(format!("Found ProcessParameters at {:#x} ",*(parm_addr)));
    //     // }
    //     // debug_info_msg!(format!("Found PEB ProcessParameters address at {:#x}", peb_addr as usize + 32));


    //     true
    // }

    fn patch_arguments(&mut self) -> bool {
        let (existing_args_length, existing_args_max_length, existing_args) = self.read_args();

        let mut full_cmd = String::new();
        full_cmd.push_str(" "); //should start with a space because the firs param should be the exe name. if we put just a space, exe name is empty
        full_cmd.push_str(&self.arguments.new_args.trim());
        let full_cmd_length = (full_cmd.len() * 2 + 2) as u16;

        if full_cmd_length > existing_args_max_length {
            crate::debug_error_msg!(format!("Too long parameter string for the current peb (length of {}, authorized : {})",full_cmd_length, existing_args_max_length));
                return false;
        }

        //saving existing args
        self.arguments.existing_args = existing_args;
        self.arguments.existing_arg_length = existing_args_length;
        self.arguments.existing_arg_max_length = existing_args_max_length;


        self.write_args(full_cmd_length, full_cmd_length, full_cmd);
        true
    }

    fn restore_arguments(&self) {
        self.write_args(self.arguments.existing_arg_length, self.arguments.existing_arg_max_length, self.arguments.existing_args.clone())
    }

    fn write_args(&self, length: u16, max_length: u16, args: String) {
        unsafe {
            let peb = get_peb();
            let rtl_param = *(peb.ProcessParameters as *const RTL_USER_PROCESS_PARAMETERS);
            let cmd_line_ptr = &rtl_param.CommandLine as *const UNICODE_STRING;
            let cmd_line_length_ptr = (cmd_line_ptr as usize) as *mut u16;
            let cmd_line_max_length_ptr = ((cmd_line_ptr as usize) + 2) as *mut u16;
            let cmd_line_data_ptr = PWSTR::from_raw(*(((cmd_line_ptr as usize) + 8) as *const usize)  as *mut u16);

            let mut vec: Vec<u16> = args.encode_utf16().collect();
            vec.push(0);

            *(cmd_line_length_ptr) = length;
            *(cmd_line_max_length_ptr) = max_length;
            std::ptr::copy_nonoverlapping(vec.as_ptr(), cmd_line_data_ptr.as_ptr() as *mut u16, vec.len());
        }
    }

    fn read_args(&self) -> (u16, u16, String) {
        unsafe {
            let peb = get_peb();
            let rtl_param = *(peb.ProcessParameters as *const RTL_USER_PROCESS_PARAMETERS);
            let cmd_line_ptr = &rtl_param.CommandLine as *const UNICODE_STRING;
            let cmd_line_length_ptr = (cmd_line_ptr as usize) as *mut u16;
            let cmd_line_max_length_ptr = ((cmd_line_ptr as usize) + 2) as *mut u16;
            (*(cmd_line_length_ptr),*(cmd_line_max_length_ptr),(*cmd_line_ptr).to_string().unwrap())
        }
    }

    pub fn inject(&mut self, pe_bytes: Vec<u8>, args: String) -> bool {
        if !self.init(pe_bytes, args) {
            return false;
        }

        if !self.write_pe_sections() {
            return false;
        }

        if !self.adapt_relocations() {
            return false;
        }

        if !self.adapt_iat() {
            return false;
        }

        if !self.adapt_permissions() {
            return false;
        }

        if !self.patch_arguments() {
            return false;
        }

        true
    }

    pub fn execute(&mut self) -> bool {
        debug_info_msg!(format!("Executing ..."));
        if self.infos.is_dll {
            // We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
            //FlushInstructionCache(-1 as _, null_mut(), 0);
        
            // call our respective entry point, fudging our hInstance value
            // #[allow(non_camel_case_types)]
            // type fnDllMain = unsafe extern "system" fn(module: HINSTANCE, call_reason: u32, reserved: *mut c_void) -> BOOL;
        
            // #[allow(non_snake_case)]
            // let DllMain = transmute::<_, fnDllMain>(entry_point);
        
            // DllMain(new_base_address as _, DLL_PROCESS_ATTACH, loaded_module_base as _);
            // let func: extern "C" fn() -> u32 = core::mem::transmute(entry_point);
            // func();
        }
        else {
            unsafe {
                let entry_point = self.infos.pe_base_address as usize + (*self.infos.nt_header_ptr).OptionalHeader.AddressOfEntryPoint as usize;

                let mut thread_handle: HANDLE = 0;
                let mut res =  self.ntdll.nt_create_thread_ex(&mut thread_handle, THREAD_ALL_ACCESS,-1, entry_point);
                if res != STATUS_SUCCESS {
                    debug_error_msg!("Failed to start thread!");
                    return false;
                }
                debug_success_msg!("Thread executed");
            
                self.infos.thread_handle = thread_handle;
                res =  self.ntdll.nt_wait_for_single_object(thread_handle);
                if res != STATUS_SUCCESS {
                    debug_error_msg!("Failed to wait!");
                    return false;
                }
            }
        }
        debug_success_msg!(format!("Done."));
        true
    }

    pub fn clean(&self) -> bool {
        debug_info_msg!(format!("Cleaning ..."));

        #[cfg(feature = "verbose")]
        debug_info_msg!(format!("Cleaning Handles"));
        let mut res = self.ntdll.nt_close(self.infos.thread_handle);
        if res != STATUS_SUCCESS {
            debug_error_msg!("Failed to close Thread Handle!");
            return false;
        }

        #[cfg(feature = "verbose")]
        debug_info_msg!(format!("Cleaning Memory"));
        let mut address = self.infos.pe_base_address as usize;
        let mut size =  0;
        res = self.ntdll.nt_free_virtual_memory(-1, &mut address,  &mut size, MEM_RELEASE);
        if res != STATUS_SUCCESS {
            crate::debug_error_msg!(format!("Failed to free memory : {:#x}!", res as usize));
            return false;
        }

        #[cfg(feature = "verbose")]
        debug_info_msg!(format!("restoring args"));
        self.restore_arguments();

        debug_success_msg!(format!("Done."));
        true
    }

}