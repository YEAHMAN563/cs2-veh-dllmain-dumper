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
static std::unordered_set<uintptr_t> g_DumpedRegions;
static bool g_FullDumped = false;
static PVOID g_VehHandle = nullptr;

namespace fs = std::filesystem;

// Fast binary dump helper
static bool WriteBin(const fs::path& path, const void* data, size_t size) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write((const char*)data, size);
    return (bool)f;
}

static void DumpRegion(uintptr_t base, size_t size, const fs::path& folder, const char* prefix) {
    if (size == 0 || size > 0x10000000) return; // sanity
    std::vector<BYTE> buf(size);
    SIZE_T read = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)base, buf.data(), size, &read) || read == 0)
        return;
    std::ostringstream name;
    name << prefix << "_0x" << std::hex << std::uppercase << base << ".bin";
    WriteBin(folder / name.str(), buf.data(), read);
}

static void PerformDump(uintptr_t faultAddr) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery((LPCVOID)faultAddr, &mbi, sizeof(mbi))) return;

    uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
    size_t regionSize = mbi.RegionSize;

    {
        std::lock_guard<std::mutex> lock(g_DumpMtx);
        if (g_DumpedRegions.count(regionBase)) return; // already done
        g_DumpedRegions.insert(regionBase);
    }

    // Create region folder
    std::ostringstream folderName;
    folderName << "region_0x" << std::hex << std::uppercase << regionBase;
    fs::path regionDir = fs::path(g_DumpRoot) / folderName.str();
    std::error_code ec;
    fs::create_directories(regionDir, ec);

    // 1. region dump
    DumpRegion(regionBase, regionSize, regionDir, "region_dump");

    // 2. KUSER_SHARED_DATA (fixed 0x7FFE0000 on x64)
    DumpRegion(0x7FFE0000, 0x1000, regionDir, "kuser_dump");

    // 3. PEB
    auto teb = NtCurrentTeb();
    if (teb && teb->ProcessEnvironmentBlock) {
        DumpRegion((uintptr_t)teb->ProcessEnvironmentBlock, 0x1000, regionDir, "peb_dump");
    }

    // 4. TEB of current thread (the one that hit the guarded page / DllMain)
    DumpRegion((uintptr_t)teb, 0x2000, regionDir, "teb_dump");

    // One-time full_cpuid_dump (main module image)
    if (!g_FullDumped) {
        std::lock_guard<std::mutex> lock(g_DumpMtx);
        if (!g_FullDumped) {
            g_FullDumped = true;
            HMODULE hMain = GetModuleHandleW(nullptr);
            if (hMain) {
                MODULEINFO mi{};
                if (GetModuleInformation(GetCurrentProcess(), hMain, &mi, sizeof(mi))) {
                    std::vector<BYTE> full(mi.SizeOfImage);
                    SIZE_T rd = 0;
                    if (ReadProcessMemory(GetCurrentProcess(), mi.lpBaseOfDll, full.data(), mi.SizeOfImage, &rd) && rd) {
                        WriteBin(fs::path(g_DumpRoot) / "full_cpuid_dump.bin", full.data(), rd);
                    }
                }
            }
        }
    }

    char msg[256];
    sprintf_s(msg, "[VEH] Dumped region 0x%llX size 0x%zX\n", (unsigned long long)regionBase, regionSize);
    OutputDebugStringA(msg);
}

LONG CALLBACK VehHandler(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;

    PVOID fault = ep->ExceptionRecord->ExceptionAddress;
    PerformDump((uintptr_t)fault);

    // PAGE_GUARD is one-shot. We leave it removed so the real DllMain continues normally.
    // Dump-once per region base keeps it fast under concurrent loads.
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
            auto dos = (IMAGE_DOS_HEADER*)base;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
            auto nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) continue;

            DWORD epRva = nt->OptionalHeader.AddressOfEntryPoint;
            if (!epRva) continue;
            BYTE* ep = base + epRva;

            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(ep, &mbi, sizeof(mbi))) {
                DWORD old = 0;
                // Preserve current protection bits and add PAGE_GUARD
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

// Background re-arm for modules that load after our injection (common for game DLLs)
static DWORD WINAPI GuardArmThread(LPVOID) {
    for (int i = 0; i < 300; ++i) { // ~15 s of aggressive coverage
        ArmGuards();
        Sleep(50);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // If host did not patch the marker, fall back to %TEMP%\cs2.exe_dumps
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

        OutputDebugStringA("[veh_dumper] VEH registered + PAGE_GUARD armed on entry points\n");
    }
    else if (reason == DLL_PROCESS_DETACH) {
        if (g_VehHandle) {
            RemoveVectoredExceptionHandler(g_VehHandle);
            g_VehHandle = nullptr;
        }
    }
    return TRUE;
}
