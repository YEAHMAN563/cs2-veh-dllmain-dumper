#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>
#include <vector>
#include <mutex>
#include <unordered_set>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Psapi.lib")

// Marker that the host overwrites with the real dump root path
char g_DumpRoot[MAX_PATH] = "DUMPROOT_PLACEHOLDER_XXXX";

static std::mutex g_DumpMtx;
static std::unordered_set<uintptr_t> g_DumpedRegions;   // only inserted AFTER successful main region write
static bool g_FullDumped = false;
static PVOID g_VehHandle = nullptr;

namespace fs = std::filesystem;

// Write a small text status file so the host console can pick it up and color it
static void WriteStatus(const fs::path& dir, const std::string& name, const std::string& text) {
    std::ofstream f(dir / name, std::ios::app);
    if (f) f << text << "\n";
}

// Returns bytes actually written. 0 = complete failure.
static size_t WriteBin(const fs::path& path, const void* data, size_t size) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return 0;
    f.write(reinterpret_cast<const char*>(data), size);
    if (!f) return 0;
    return size;
}

// Attempt to dump a memory range. Reports partial / full / failed via status file.
// Returns true only if the FULL requested size was read AND written.
static bool DumpMemoryRange(uintptr_t base, size_t size, const fs::path& folder,
                            const char* prefix, std::string& outStatus) {
    if (size == 0) {
        outStatus = "SKIP size=0";
        return false;
    }

    // No artificial size limit anymore.
    std::vector<BYTE> buf;
    try {
        buf.resize(size);
    } catch (...) {
        outStatus = "FAIL allocation of " + std::to_string(size) + " bytes";
        return false;
    }

    SIZE_T bytesRead = 0;
    BOOL ok = ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(base),
                                buf.data(), size, &bytesRead);

    std::ostringstream name;
    name << prefix << "_0x" << std::hex << std::uppercase << base << ".bin";
    fs::path outPath = folder / name.str();

    if (!ok || bytesRead == 0) {
        outStatus = "FAIL ReadProcessMemory base=0x" + 
                    ([&]{ std::ostringstream s; s << std::hex << base; return s.str(); })() +
                    " requested=" + std::to_string(size) + " read=0 err=" + std::to_string(GetLastError());
        WriteStatus(folder, "FAILED_READ.txt", outStatus);
        return false;
    }

    size_t written = WriteBin(outPath, buf.data(), bytesRead);
    if (written == 0) {
        outStatus = "FAIL write to disk (" + outPath.string() + ")";
        WriteStatus(folder, "FAILED_WRITE.txt", outStatus);
        return false;
    }

    if (bytesRead < size) {
        // Partial success – still write what we got, but mark as partial
        outStatus = "PARTIAL read=" + std::to_string(bytesRead) + "/" + std::to_string(size) +
                    " written to " + name.str();
        WriteStatus(folder, "PARTIAL_READ.txt", outStatus);
        return false; // not considered a complete dump
    }

    outStatus = "OK full " + std::to_string(bytesRead) + " bytes -> " + name.str();
    return true;
}

static void PerformDump(uintptr_t faultAddr) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(reinterpret_cast<LPCVOID>(faultAddr), &mbi, sizeof(mbi))) {
        return;
    }

    uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    size_t regionSize = mbi.RegionSize;

    // Quick check without locking the heavy path yet
    {
        std::lock_guard<std::mutex> lock(g_DumpMtx);
        if (g_DumpedRegions.count(regionBase))
            return;
    }

    // Create region folder
    std::ostringstream folderName;
    folderName << "region_0x" << std::hex << std::uppercase << regionBase;
    fs::path regionDir = fs::path(g_DumpRoot) / folderName.str();
    std::error_code ec;
    fs::create_directories(regionDir, ec);
    if (ec) {
        // Can't even create the folder – nothing more we can do from inside the process
        return;
    }

    std::string status;

    // 1. Main region dump – this is the critical one that decides “dumped”
    bool mainOk = DumpMemoryRange(regionBase, regionSize, regionDir, "region_dump", status);

    // Only mark as dumped AFTER a successful full write of the main region.
    // Partial or failed reads stay unmarked so a later hit can retry.
    if (mainOk) {
        std::lock_guard<std::mutex> lock(g_DumpMtx);
        g_DumpedRegions.insert(regionBase);
    } else {
        // Still write a clear status so the host console can show it in red
        WriteStatus(regionDir, "STATUS.txt", "MAIN_REGION: " + status);
    }

    // 2-4. Secondary dumps (best-effort, never block the “dumped” flag)
    std::string tmp;
    DumpMemoryRange(0x7FFE0000, 0x1000, regionDir, "kuser_dump", tmp);

    auto teb = NtCurrentTeb();
    if (teb && teb->ProcessEnvironmentBlock) {
        DumpMemoryRange(reinterpret_cast<uintptr_t>(teb->ProcessEnvironmentBlock),
                        0x1000, regionDir, "peb_dump", tmp);
    }
    if (teb) {
        DumpMemoryRange(reinterpret_cast<uintptr_t>(teb), 0x2000, regionDir, "teb_dump", tmp);
    }

    // One-time full main-module dump
    if (!g_FullDumped) {
        std::lock_guard<std::mutex> lock(g_DumpMtx);
        if (!g_FullDumped) {
            HMODULE hMain = GetModuleHandleW(nullptr);
            if (hMain) {
                MODULEINFO mi{};
                if (GetModuleInformation(GetCurrentProcess(), hMain, &mi, sizeof(mi))) {
                    std::string fullStatus;
                    bool ok = DumpMemoryRange(reinterpret_cast<uintptr_t>(mi.lpBaseOfDll),
                                              mi.SizeOfImage,
                                              fs::path(g_DumpRoot),
                                              "full_cpuid_dump", fullStatus);
                    // rename to the exact name requested
                    fs::path generated = fs::path(g_DumpRoot) / 
                        ("full_cpuid_dump_0x" + 
                         ([&]{ std::ostringstream s; s << std::hex << std::uppercase 
                              << reinterpret_cast<uintptr_t>(mi.lpBaseOfDll); return s.str(); })() + ".bin");
                    fs::path wanted = fs::path(g_DumpRoot) / "full_cpuid_dump.bin";
                    if (ok && fs::exists(generated)) {
                        std::error_code renEc;
                        fs::rename(generated, wanted, renEc);
                    }
                    if (ok) g_FullDumped = true;
                }
            }
        }
    }

    // Debug string still useful for external tools
    char msg[320];
    sprintf_s(msg, "[VEH] region 0x%llX size 0x%zX mainOk=%d\n",
              (unsigned long long)regionBase, regionSize, (int)mainOk);
    OutputDebugStringA(msg);
}

LONG CALLBACK VehHandler(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;

    PVOID fault = ep->ExceptionRecord->ExceptionAddress;
    PerformDump(reinterpret_cast<uintptr_t>(fault));

    // PAGE_GUARD is one-shot. Leave it removed so real DllMain continues.
    return EXCEPTION_CONTINUE_EXECUTION;
}

// Arm PAGE_GUARD on the entry-point page of every currently loaded module
static void ArmGuards() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32W me{ sizeof(me) };
    if (Module32FirstW(snap, &me)) {
        do {
            BYTE* base = me.modBaseAddr;
            auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
            auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) continue;

            DWORD epRva = nt->OptionalHeader.AddressOfEntryPoint;
            if (!epRva) continue;
            BYTE* ep = base + epRva;

            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(ep, &mbi, sizeof(mbi))) {
                DWORD old = 0;
                DWORD prot = mbi.Protect;
                if (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
                    DWORD newProt = (prot & ~(PAGE_GUARD | PAGE_NOACCESS)) | PAGE_GUARD;
                    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, newProt, &old);
                }
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
}

static DWORD WINAPI GuardArmThread(LPVOID) {
    for (int i = 0; i < 300; ++i) {
        ArmGuards();
        Sleep(50);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        if (strncmp(g_DumpRoot, "DUMPROOT_PLACEHOLDER", 20) == 0) {
            GetTempPathA(MAX_PATH, g_DumpRoot);
            strcat_s(g_DumpRoot, "cs2.exe_dumps");
        }
        std::error_code ec;
        fs::create_directories(g_DumpRoot, ec);

        g_VehHandle = AddVectoredExceptionHandler(1, VehHandler);
        if (!g_VehHandle) return FALSE;

        ArmGuards();
        HANDLE h = CreateThread(nullptr, 0, GuardArmThread, nullptr, 0, nullptr);
        if (h) CloseHandle(h);

        OutputDebugStringA("[veh_dumper] VEH registered + PAGE_GUARD armed\n");
    }
    else if (reason == DLL_PROCESS_DETACH) {
        if (g_VehHandle) {
            RemoveVectoredExceptionHandler(g_VehHandle);
            g_VehHandle = nullptr;
        }
    }
    return TRUE;
}
