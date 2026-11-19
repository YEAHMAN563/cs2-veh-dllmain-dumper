#include "manual_map.h"
#include <iostream>
#include <fstream>
#include <cstring>

// PE helpers
static IMAGE_NT_HEADERS64* GetNtHeaders(BYTE* base) {
    auto dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    return nt;
}

static uintptr_t RvaToOffset(BYTE* base, DWORD rva) {
    auto nt = GetNtHeaders(base);
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + sec->Misc.VirtualSize)
            return (uintptr_t)(base + sec->PointerToRawData + (rva - sec->VirtualAddress));
    }
    return 0;
}

bool ReadFileToBuffer(const std::wstring& path, std::vector<BYTE>& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    auto sz = f.tellg();
    f.seekg(0);
    out.resize((size_t)sz);
    f.read((char*)out.data(), sz);
    return true;
}

// Manual map with stealth features:
// - Never inserts into PEB LDR lists → appears as anonymous executable memory (no module name)
// - PE headers wiped after DllMain so MZ/PE signature scanners find nothing
PVOID ManualMapDll(HANDLE hProcess, const std::vector<BYTE>& dllData, const char* dumpRootPath) {
    if (dllData.empty()) return nullptr;
    BYTE* local = (BYTE*)dllData.data();
    auto nt = GetNtHeaders(local);
    if (!nt) {
        std::cout << "[!] Invalid PE\n";
        return nullptr;
    }

    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    SIZE_T headersSize = nt->OptionalHeader.SizeOfHeaders;

    // Allocate as RWX for simplicity (can be tightened later)
    PVOID remoteBase = VirtualAllocEx(hProcess, nullptr, imageSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        std::cout << "[!] VirtualAllocEx failed: " << GetLastError() << "\n";
        return nullptr;
    }

    // Copy headers
    if (!WriteProcessMemory(hProcess, remoteBase, local, headersSize, nullptr)) {
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return nullptr;
    }

    // Copy sections
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (sec->SizeOfRawData == 0) continue;
        void* dest = (BYTE*)remoteBase + sec->VirtualAddress;
        void* src  = local + sec->PointerToRawData;
        if (!WriteProcessMemory(hProcess, dest, src, sec->SizeOfRawData, nullptr)) {
            VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
            return nullptr;
        }
    }

    // Relocations
    auto& relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.Size) {
        auto reloc = (IMAGE_BASE_RELOCATION*)(local + RvaToOffset(local, relocDir.VirtualAddress));
        uintptr_t delta = (uintptr_t)remoteBase - nt->OptionalHeader.ImageBase;
        while (reloc->VirtualAddress) {
            DWORD num = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* list = (WORD*)(reloc + 1);
            for (DWORD i = 0; i < num; ++i) {
                if ((list[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                    uintptr_t* p = (uintptr_t*)((BYTE*)remoteBase + reloc->VirtualAddress + (list[i] & 0xFFF));
                    uintptr_t val = 0;
                    ReadProcessMemory(hProcess, p, &val, sizeof(val), nullptr);
                    val += delta;
                    WriteProcessMemory(hProcess, p, &val, sizeof(val), nullptr);
                }
            }
            reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
        }
    }

    // Imports
    auto& impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.Size) {
        auto imp = (IMAGE_IMPORT_DESCRIPTOR*)(local + RvaToOffset(local, impDir.VirtualAddress));
        while (imp->Name) {
            char* modName = (char*)(local + RvaToOffset(local, imp->Name));
            HMODULE hMod = LoadLibraryA(modName);
            if (!hMod) { ++imp; continue; }
            auto thunk = (IMAGE_THUNK_DATA64*)(local + RvaToOffset(local,
                imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
            auto iat = (IMAGE_THUNK_DATA64*)((BYTE*)remoteBase + imp->FirstThunk);
            for (; thunk->u1.AddressOfData; ++thunk, ++iat) {
                FARPROC fn = nullptr;
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    fn = GetProcAddress(hMod, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
                } else {
                    auto ibn = (IMAGE_IMPORT_BY_NAME*)(local + RvaToOffset(local, (DWORD)thunk->u1.AddressOfData));
                    fn = GetProcAddress(hMod, ibn->Name);
                }
                if (fn) {
                    uintptr_t addr = (uintptr_t)fn;
                    WriteProcessMemory(hProcess, &iat->u1.Function, &addr, sizeof(addr), nullptr);
                }
            }
            ++imp;
        }
    }

    // Patch dump root path (marker search)
    const char* marker = "DUMPROOT_PLACEHOLDER_XXXX";
    size_t markerLen = strlen(marker);
    for (size_t i = 0; i + markerLen < dllData.size(); ++i) {
        if (memcmp(local + i, marker, markerLen) == 0) {
            DWORD rvaOfMarker = 0;
            auto sec2 = IMAGE_FIRST_SECTION(nt);
            for (WORD s = 0; s < nt->FileHeader.NumberOfSections; ++s, ++sec2) {
                if (i >= sec2->PointerToRawData && i < sec2->PointerToRawData + sec2->SizeOfRawData) {
                    rvaOfMarker = sec2->VirtualAddress + (DWORD)(i - sec2->PointerToRawData);
                    break;
                }
            }
            if (rvaOfMarker) {
                char pathBuf[MAX_PATH] = {};
                strncpy_s(pathBuf, dumpRootPath, MAX_PATH - 1);
                WriteProcessMemory(hProcess, (BYTE*)remoteBase + rvaOfMarker, pathBuf, MAX_PATH, nullptr);
            }
            break;
        }
    }

    // Call DllMain
    uintptr_t entry = (uintptr_t)remoteBase + nt->OptionalHeader.AddressOfEntryPoint;
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                        (LPTHREAD_START_ROUTINE)entry, remoteBase, 0, nullptr);
    if (hThread) {
        WaitForSingleObject(hThread, 8000);
        CloseHandle(hThread);
    } else {
        std::cout << "[!] CreateRemoteThread failed: " << GetLastError() << "\n";
    }

    // ========== STEALTH: wipe PE headers ==========
    // After DllMain has run we no longer need the headers.
    // Zeroing them removes MZ/PE signatures from the image base.
    std::vector<BYTE> zero(headersSize, 0);
    if (WriteProcessMemory(hProcess, remoteBase, zero.data(), headersSize, nullptr)) {
        std::cout << "[+] PE headers wiped (" << headersSize << " bytes)\n";
    }

    // Optional: make the header page non-readable so casual scanners get ACCESS_DENIED
    DWORD oldProt = 0;
    VirtualProtectEx(hProcess, remoteBase, headersSize, PAGE_NOACCESS, &oldProt);

    // Note: we deliberately never call any Ldr* function that would insert
    // this image into the PEB LDR lists. Result = nameless / invisible module.

    std::cout << "[+] Manual map complete (stealth), remote base = 0x"
              << std::hex << (uintptr_t)remoteBase << std::dec << "\n";
    return remoteBase;
}
