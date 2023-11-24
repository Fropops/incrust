# local pe injector

# TODO
- add missing reloc
- use winapi_wrapper for kernel32 calls
- Check ntdll ordinals load on win7 32bits

source for parameter hijacking : 
https://github.com/nettitude/RunPE/blob/main/RunPE/Patchers/ArgumentPatcher.cs
https://github.com/Octoberfest7/Inline-Execute-PE/blob/bec579ed201a3ed05254f0bc06776b78e4a0940e/Inline-Execute-PE/perun.c#L311
https://github.com/TheWover/donut/blob/master/loader/inmem_pe.c
