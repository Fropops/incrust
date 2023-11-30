use std::{ptr::null_mut, ffi::CStr, mem::size_of};

use crate::winapi::{types::HANDLE, libc::{__acrt_iob_func, STDOUT, STDERR, PFILE, freopen_s, _fileno, _get_osfhandle, _dup, _fdopen, _open_osfhandle, _O_TEXT, _dup2}, kernel32::{SECURITY_ATTRIBUTES, GetStdHandle, SetStdHandle, AllocConsole, FreeConsole, CreatePipe, PeekNamedPipe, ReadFile}, constants::{TRUE, NULL, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE, FALSE}};


static mut READ_PIPE_HANDLE: HANDLE = 0;
static mut WRITE_PIPE_HANDLE : HANDLE = 0;

static mut BACKED_STDOUT :i32 = 0;
static mut BACKED_STDERR :i32 = 0;

static mut ALREADY_REDIRECTED: bool = false;

#[allow(unused)]
pub fn redirect_outputs() -> i32 {
    unsafe {

        if ALREADY_REDIRECTED {
            return 0;
        }

    
        let stdout = __acrt_iob_func(STDOUT);
        let stderr = __acrt_iob_func(STDERR);

        let mut stream: PFILE = null_mut();
        if  GetStdHandle(STD_OUTPUT_HANDLE) == NULL as HANDLE {
            /****************************************/
            // not needed in c++ version but in rust if a console is not allocated, the stdout is not redircted correctly. Tryed it in c program => same issue :/
            // maybe it's related to https://github.com/rust-lang/rust/issues/25977 , https://github.com/rust-lang/rust/issues/9486 & https://rust-lang.github.io/rfcs/1014-stdout-existential-crisis.html
            // have to try with the pe loader...
            if AllocConsole() == 0 {
                return 1;
            }
        
            if FreeConsole() == 0 {
                return 2;
            }
            /****************************************/
            
            if freopen_s(&mut stream, CStr::from_bytes_with_nul(b"NUL\0").unwrap().as_ptr(), CStr::from_bytes_with_nul(b"w\0").unwrap().as_ptr(), stdout) != 0 {
                return 3;
            }
            if freopen_s(&mut stream, CStr::from_bytes_with_nul(b"NUL\0").unwrap().as_ptr(), CStr::from_bytes_with_nul(b"w\0").unwrap().as_ptr(), stderr) != 0 {
                return 4;
            }
            
        }

        //refresh the WINAPI stdout & stderr handles
        if SetStdHandle(STD_OUTPUT_HANDLE, _get_osfhandle(_fileno(stdout)) as HANDLE) == FALSE {
            return 5;
        }
        if SetStdHandle(STD_ERROR_HANDLE, _get_osfhandle(_fileno(stderr)) as HANDLE) == FALSE {
            return 6;
        }

        BACKED_STDOUT = _dup(_fileno(stdout));
        BACKED_STDERR = _dup(_fileno(stderr));

        let security_attributes: SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES{
            nLength: size_of::<SECURITY_ATTRIBUTES> as u32,
            bInheritHandle: TRUE,
            lpSecurityDescriptor: NULL
        };
        let security_attributes_ptr = &security_attributes as *const SECURITY_ATTRIBUTES;

        if CreatePipe(&mut READ_PIPE_HANDLE, &mut WRITE_PIPE_HANDLE, security_attributes_ptr, 0) == FALSE {
            return 7;
        }

        // Attach stdout & stderr to the write end of the pipe
        let f: PFILE= _fdopen(_open_osfhandle(WRITE_PIPE_HANDLE as usize, _O_TEXT), CStr::from_bytes_with_nul(b"w\0").unwrap().as_ptr());
        if f == null_mut() {
            return 8;
        }

        if _dup2(_fileno(f), _fileno(stdout)) != 0 {
            return 9;
        }

        if _dup2(_fileno(f), _fileno(stderr)) != 0  {
            return 10;
        }

        ALREADY_REDIRECTED = true;
        0
    }
}

#[allow(unused)]
pub fn revert_outputs() {
    unsafe {
        if !ALREADY_REDIRECTED {
            return;
        }

        let stdout = __acrt_iob_func(STDOUT);
        let stderr = __acrt_iob_func(STDERR);
        if _dup2(BACKED_STDOUT, _fileno(stdout)) != 0 {
            return;
        }

        if _dup2(BACKED_STDERR, _fileno(stderr)) != 0  {
            return;
        }

        ALREADY_REDIRECTED = false;
    }
}

#[allow(unused)]
pub fn read_outputs() -> Option<Vec<u8>> {
    unsafe {
        let mut nb_of_byte_read: u32 = 0;


        if PeekNamedPipe(READ_PIPE_HANDLE, null_mut(), 0, null_mut(), &mut nb_of_byte_read, null_mut()) == FALSE {
            return None;
        }

        if nb_of_byte_read == 0 {
            return None;
        }

        let mut buffer: [u8; 1024] = [0u8;1024];
        if ReadFile(READ_PIPE_HANDLE, &mut buffer as *mut u8, 1024, &mut nb_of_byte_read, null_mut()) == FALSE {
            return None;
        }
        return Some(buffer[0..nb_of_byte_read as usize].to_vec());
    }
}