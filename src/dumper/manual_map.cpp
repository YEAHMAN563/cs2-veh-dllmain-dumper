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

static BYTE* RvaToPointer(BYTE* base, DWORD rva) {
    if (!rva) return nullptr;
    auto nt = GetNtHeaders(base);
    if (!nt) return nullptr;
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        DWORD secSize = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + secSize)
            return base + sec->PointerToRawData + (rva - sec->VirtualAddress);
    }
    return nullptr;
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

    // Allocate as RWX for mapped image
    PVOID remoteBase = VirtualAllocEx(hProcess, nullptr, imageSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        std::cout << "[!] VirtualAllocEx failed: " << GetLastError() << "\n";
        return nullptr;
    }

    // Copy headers (intact)
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
        auto reloc = (IMAGE_BASE_RELOCATION*)RvaToPointer(local, relocDir.VirtualAddress);
        if (reloc) {
            uintptr_t delta = (uintptr_t)remoteBase - nt->OptionalHeader.ImageBase;
            auto relocEnd = (BYTE*)reloc + relocDir.Size;
            while ((BYTE*)reloc < relocEnd && reloc->VirtualAddress && reloc->SizeOfBlock) {
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
    }

    // Imports
    auto& impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.Size) {
        auto imp = (IMAGE_IMPORT_DESCRIPTOR*)RvaToPointer(local, impDir.VirtualAddress);
        if (imp) {
            while (imp->Name) {
                char* modName = (char*)RvaToPointer(local, imp->Name);
                if (!modName) { ++imp; continue; }
                HMODULE hMod = LoadLibraryA(modName);
                if (!hMod) { ++imp; continue; }
                DWORD thunkRva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
                auto thunk = (IMAGE_THUNK_DATA64*)RvaToPointer(local, thunkRva);
                auto iat = (IMAGE_THUNK_DATA64*)((BYTE*)remoteBase + imp->FirstThunk);
                if (thunk && iat) {
                    for (; thunk->u1.AddressOfData; ++thunk, ++iat) {
                        FARPROC fn = nullptr;
                        if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                            fn = GetProcAddress(hMod, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
                        } else {
                            auto ibn = (IMAGE_IMPORT_BY_NAME*)RvaToPointer(local, (DWORD)thunk->u1.AddressOfData);
                            if (ibn) {
                                fn = GetProcAddress(hMod, ibn->Name);
                            }
                        }
                        if (fn) {
                            uintptr_t addr = (uintptr_t)fn;
                            WriteProcessMemory(hProcess, &iat->u1.Function, &addr, sizeof(addr), nullptr);
                        }
                    }
                }
                ++imp;
            }
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

    // Call DllMain via a small x64 stub that properly sets:
    // RCX = remoteBase (hinstDLL)
    // RDX = DLL_PROCESS_ATTACH (1)
    // R8  = NULL (lpReserved)
    // This ensures _DllMainCRTStartup runs CRT initialization (_CRT_INIT),
    // invokes C++ static constructors, and safely executes DllMain.
    uintptr_t entry = (uintptr_t)remoteBase + nt->OptionalHeader.AddressOfEntryPoint;

    BYTE stub[] = {
        0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 28h
        0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,             // mov rcx, remoteBase
        0xBA, 0x01, 0x00, 0x00, 0x00,                   // mov edx, 1 (DLL_PROCESS_ATTACH)
        0x45, 0x31, 0xC0,                               // xor r8d, r8d (lpReserved = NULL)
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,             // mov rax, entry
        0xFF, 0xD0,                                     // call rax
        0x48, 0x83, 0xC4, 0x28,                         // add rsp, 28h
        0xC3                                            // ret
    };
    *reinterpret_cast<uintptr_t*>(&stub[6])  = reinterpret_cast<uintptr_t>(remoteBase);
    *reinterpret_cast<uintptr_t*>(&stub[24]) = entry;

    PVOID pStub = VirtualAllocEx(hProcess, nullptr, sizeof(stub),
                                 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pStub) {
        std::cout << "[!] VirtualAllocEx for stub failed: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return nullptr;
    }

    if (!WriteProcessMemory(hProcess, pStub, stub, sizeof(stub), nullptr)) {
        std::cout << "[!] WriteProcessMemory for stub failed: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, pStub, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return nullptr;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                        (LPTHREAD_START_ROUTINE)pStub, nullptr, 0, nullptr);
    if (hThread) {
        WaitForSingleObject(hThread, 8000);
        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        CloseHandle(hThread);
        std::cout << "[+] Remote DllMain thread exited with code " << exitCode << "\n";
    } else {
        std::cout << "[!] CreateRemoteThread failed: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, pStub, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return nullptr;
    }

    // Clean up stub
    VirtualFreeEx(hProcess, pStub, 0, MEM_RELEASE);

    // Keep PE headers completely intact for stability and standard unwinding
    std::cout << "[+] Manual map complete (safe, headers intact), remote base = 0x"
              << std::hex << (uintptr_t)remoteBase << std::dec << "\n";
    return remoteBase;
}
