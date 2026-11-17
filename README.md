# CS2 VEH DllMain Region Dumper

**Cyberhange benchmark research tool**

VEH + PAGE_GUARD based dumper that intercepts DllMain / entry-point execution without software breakpoints (INT3). Dumps the faulting memory region + PEB + TEB + KUSER_SHARED_DATA the moment any guarded page is first executed. Designed for pre-entrypoint / early module load dumps of `cs2.exe`.

## Features
- Separate host EXE (admin + own console + watchdog) + payload DLL
- Manual map injection (no LoadLibrary)
- PAGE_GUARD on module entry points → STATUS_GUARD_PAGE_VIOLATION → VEH
- Concurrent multi-DllMain safe (mutex + per-region once)
- Folder layout exactly as requested under `cs2.exe_dumps` next to the EXE
- Fast in-process dumps
- Logs every dumped region to the host console

## Build
See GitHub Actions or:
```
cmake -B build -A x64
cmake --build build --config Release
```
Produces `dumper.exe` + `veh_dumper.dll`

## Usage
1. Run `dumper.exe` **as Administrator** (manifest forces it).
2. It opens its own console (not attached to CMD).
3. Waits / watches for `cs2.exe`, manual-maps the DLL ASAP.
4. DLL arms PAGE_GUARD on loaded modules' entry points.
5. On any DllMain / EP hit → instant dump of that region + PEB/TEB/KUSER into the structure below.
6. Host console prints every new dump.

## Output layout
```
cs2.exe_dumps/
├─full_cpuid_dump.bin
├─region_0x7FF6XXXXXXXX/
│  ├─region_dump_0x7FF6XXXXXXXX.bin
│  ├─kuser_dump_0x7FF6XXXXXXXX.bin
│  ├─peb_dump_0x7FF6XXXXXXXX.bin
│  └─teb_dump_0x7FF6XXXXXXXX.bin
└─...
```

## Notes
- Research / benchmark only.
- PAGE_GUARD is one-shot per page; we re-arm selectively or dump-once per region base.
- Very early injection maximizes pre-OEP coverage.
