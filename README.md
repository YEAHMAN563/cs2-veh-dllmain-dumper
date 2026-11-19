# CS2 VEH DllMain Dumper

A tool that dumps memory **the exact moment** a DLL’s `DllMain` (or any module entry point) starts running inside `cs2.exe`.

It does this **without** using software breakpoints (`INT3`).

---

## What is this for?

When a game or anti-cheat loads a DLL, the first code that runs is usually `DllMain`.  
At that moment the memory often still contains interesting data (unpacked code, configs, decryption keys, etc.) that later gets wiped or changed.

This tool catches that exact moment and saves the memory region + some important process structures.

It is mainly useful for:
- Reverse engineering
- Analyzing early packer/protector stages
- Researching how modules initialize inside CS2

---

## How it works (simple explanation)

1. You run `dumper.exe` as Administrator.
2. It waits for `cs2.exe` to start.
3. As soon as CS2 appears, it injects a small DLL using **manual mapping** (the DLL has no name and is hard to detect).
4. The injected DLL puts a special “guard” on the entry point of every loaded module.
5. The first time any of those entry points is executed, Windows throws a special exception (`STATUS_GUARD_PAGE_VIOLATION`).
6. Our code catches that exception instantly and dumps:
   - The memory region that was just executed
   - PEB
   - TEB
   - KUSER_SHARED_DATA
7. Everything is saved into a clean folder structure next to the dumper.

---

## Features

- No software breakpoints
- Works on multiple DLLs at the same time (thread-safe)
- Very fast (dumps happen inside the game process)
- Stealthier injection (nameless module + PE headers wiped)
- Own console window with colored logs
- Automatically creates the dump folder next to the executable

---

## Output Folder Structure

When the tool runs it creates this folder next to `dumper.exe`:

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

- Green text in the console = successful dump
- Red text = failed or partial read

---

## How to Build

### Requirements
- Windows
- Visual Studio or Build Tools with C++ workload
- CMake

### Commands
```bash
cmake -B build -A x64
cmake --build build --config Release
```

This produces:
- `build/Release/dumper.exe`
- `build/Release/veh_dumper.dll`

You can also just download the artifacts from the GitHub Actions tab.

---

## How to Use

1. Place `dumper.exe` and `veh_dumper.dll` in the same folder.
2. Right-click `dumper.exe` → **Run as administrator**.
3. A console window will open by itself.
4. Start Counter-Strike 2 (or just wait if it is already running).
5. The tool will automatically inject and start watching.
6. Every time a guarded `DllMain` runs, you will see new folders appear in `cs2.exe_dumps` and messages in the console.

---

## Important Notes

- This is a **research / educational** tool.
- It must be run as Administrator.
- The injected DLL is manual-mapped (no `LoadLibrary`), has no module name, and its PE headers are wiped after loading to make it less visible.
- PAGE_GUARD is one-shot per page. Once a region is successfully dumped it will not be dumped again.

---

## Credits

Created for the cyberhange benchmark.
