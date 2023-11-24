#[allow(unused)]
#[link(name = "ntdll")]
extern "system" {
    pub fn RtlExitUserThread(uExitCode: u32);
}
            