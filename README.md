# CS2 VEH DllMain Dumper

A tool that dumps memory **the exact moment** a cheat (or any DLL) starts executing its `DllMain` inside `cs2.exe`.

This is the best time to dump because the cheat is usually still fully unpacked / decrypted but has not yet initialized its protections, integrity checks, or anti-debug measures.

---

## Why this is useful

Most modern cheats are packed or encrypted. By the time you attach a debugger or dump the process normally, a lot of the interesting data is already gone or protected.

This tool catches the cheat **pre-entrypoint** (right when `DllMain` is called) and saves the memory at that exact moment. This makes reversing and cracking significantly easier because you get a clean, early dump before the cheat has a chance to hide itself.

---

## How it works (simple explanation)

1. You run `dumper.exe` as Administrator.
2. It waits for `cs2.exe` to start.
3. As soon as CS2 appears, it injects a small stealthy DLL using **manual mapping** (no module name, PE headers wiped).
4. The injected DLL places a `PAGE_GUARD` on the entry point of every loaded module.
5. The first time any module’s `DllMain` (or entry point) runs, Windows raises `STATUS_GUARD_PAGE_VIOLATION`.
6. Our VEH catches it instantly and dumps:
   - The memory region that just started executing
   - PEB
   - TEB
   - KUSER_SHARED_DATA
7. Everything is saved into a clean folder next to the dumper.

No software breakpoints (`INT3`) are used.

---

## Features

- Catches cheats at the earliest possible moment (pre-entrypoint)
- No software breakpoints
- Works with multiple DLLs loading at the same time
- Stealth injection (nameless + headers wiped)
- Very fast in-process dumps
- Colored console logs (green = success, red = failed/partial)
- Clean and organized output folder

---

## Output Folder Structure

```
cs2.exe_dumps/
├── full_cpuid_dump.bin                  ← full dump of the main CS2 module
├── region_0x7FF6A0000000/               ← one folder per dumped region
│   ├── region_dump_0x7FF6A0000000.bin   ← the actual memory that was executed
│   ├── kuser_dump_0x7FF6A0000000.bin
│   ├── peb_dump_0x7FF6A0000000.bin
│   └── teb_dump_0x7FF6A0000000.bin
├── region_0x7FF6B0000000/
│   └── ...
└── ...
```

---

## How to Build

```bash
cmake -B build -A x64
cmake --build build --config Release
```

This creates:
- `dumper.exe`
- `veh_dumper.dll`

You can also download the built files from the **Actions** tab on GitHub.

---

## How to Use

1. Put `dumper.exe` and `veh_dumper.dll` in the same folder.
2. Run `dumper.exe` **as Administrator**.
3. A console window will open by itself.
4. Start CS2 (or just wait if it’s already running).
5. The tool injects automatically and starts watching.
6. When a cheat (or any DLL) hits its `DllMain`, a new folder appears in `cs2.exe_dumps` and a message is printed in the console.

---

## Notes

- Research / educational tool for reverse engineering and analyzing cheats.
- Must be run as Administrator.
- The injected DLL is manual-mapped, has no name in the module list, and its PE headers are wiped after loading.
- Each region is only dumped once (successful dumps are not repeated).

---

Created for the cyberhange benchmark.
