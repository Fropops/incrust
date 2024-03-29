
use super::types::{NT_STATUS, PROCESS_ACCESS_RIGHTS, VIRTUAL_ALLOCATION_TYPE, PAGE_PROTECTION_FLAGS, THREAD_ACCESS_RIGHTS, SYSTEM_INFORMATION_CLASS};

pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;
pub const IMAGE_DOS_SIGNATURE: u16 = 23117u16;
pub const IMAGE_NT_SIGNATURE: u32 = 17744u32;
// #[allow(dead_code)]
// pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 267u16;
// #[allow(dead_code)]
// pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 523u16;

#[cfg(target_arch = "x86_64")]
pub const IMAGE_NT_OPTIONAL_HDR_MAGIC: u16 = 523u16;
#[cfg(target_arch = "x86")]
pub const IMAGE_NT_OPTIONAL_HDR_MAGIC: u16 = 267u16;

#[allow(dead_code)]
pub const PROCESS_VM_READ: PROCESS_ACCESS_RIGHTS = 16u32;
#[allow(dead_code)]
pub const PROCESS_VM_WRITE: PROCESS_ACCESS_RIGHTS = 32u32;
#[allow(dead_code)]
pub const PROCESS_ALL_ACCESS: PROCESS_ACCESS_RIGHTS = 2097151u32;

#[allow(dead_code)]
pub const STATUS_SUCCESS: NT_STATUS = 0i32;

#[allow(dead_code)]
pub const MEM_COMMIT: VIRTUAL_ALLOCATION_TYPE = 4096u32;
#[allow(dead_code)]
pub const MEM_RESERVE: VIRTUAL_ALLOCATION_TYPE = 8192u32;

#[allow(dead_code)]
pub const PAGE_READWRITE: PAGE_PROTECTION_FLAGS = 4u32;
#[allow(dead_code)]
pub const PAGE_EXECUTE_READ: PAGE_PROTECTION_FLAGS = 32u32;
#[allow(dead_code)]
pub const PAGE_EXECUTE_READWRITE: PAGE_PROTECTION_FLAGS = 64u32;
#[allow(dead_code)]
pub const THREAD_ALL_ACCESS: THREAD_ACCESS_RIGHTS = 2097151u32;
#[allow(dead_code)]
pub const SYSTEM_PROCESS_INFORMATION: SYSTEM_INFORMATION_CLASS = 5i32;