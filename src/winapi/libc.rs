pub enum FILE {}
pub type PFILE = *mut FILE;

#[allow(unused)]
#[link(name = "ucrt")]
extern "cdecl" {
    pub fn freopen_s(stream: *mut PFILE, filename: *const i8, mode: *const i8, file: *mut FILE) -> u32;
    pub fn __acrt_iob_func(id: u32) -> *mut FILE;
    pub fn _dup(fd: i32) -> i32;
    pub fn _dup2(fd1: i32, fd2 :i32 ) -> i32;
    pub fn _fileno(stream: PFILE) -> i32;
    pub fn _fdopen(fd: i32,  mode: *const i8) -> PFILE;
    pub fn _open_osfhandle (osfhandle: usize, flags: i32) -> i32;
    pub fn _get_osfhandle(fd: i32) -> isize;
    pub fn _setmode (fd: i32, mode: i32) -> i32;
    pub fn setvbuf(stream: PFILE, buffer: *mut u8, mode: i32, size: usize) -> i32;
}

#[allow(unused)]
pub const STDOUT : u32 = 1;
#[allow(unused)]
pub const STDERR : u32 = 2;
#[allow(unused)]
pub const _O_TEXT : i32 = 0x4000;
#[allow(unused)]
pub const _O_WRONLY : i32 = 0x0001;
#[allow(unused)]
pub const _IONBF : i32 = 0x0004;