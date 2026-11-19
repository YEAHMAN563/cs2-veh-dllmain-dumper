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

// Real handler pointer we keep privately (for potential future cloaking)
static PVECTORED_EXCEPTION_HANDLER g_RealHandler = nullptr;

namespace fs = std::filesystem;

// ---------- status helpers ----------
static void WriteStatus(const fs::path& dir, const std::string& name, const std::string& text) {
    std::ofstream f(dir / name, std::ios::app);
    if (f) f << text << "\n";
}

static size_t WriteBin(const fs::path& path, const void* data, size_t size) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return 0;
    f.write(reinterpret_cast<const char*>(data), size);
    return f ? size : 0;
}

static bool DumpMemoryRange(uintptr_t base, size_t size, const fs::path& folder,
                            const char* prefix, std::string& outStatus) {
    if (size == 0) {
        outStatus = "SKIP size=0";
        return false;
    }

    std::vector<BYTE> buf;
    try { buf.resize(size); }
    catch (...) {
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
        std::ostringstream s;
        s << "FAIL ReadProcessMemory base=0x" << std::hex << base
          << " requested=" << std::dec << size << " read=0 err=" << GetLastError();
        outStatus = s.str();
        WriteStatus(folder, "FAILED_READ.txt", outStatus);
        return false;
    }

    size_t written = WriteBin(outPath, buf.data(), bytesRead);
    if (written == 0) {
        outStatus = "FAIL write to disk";
        WriteStatus(folder, "FAILED_WRITE.txt", outStatus);
        return false;
    }

    if (bytesRead < size) {
        outStatus = "PARTIAL read=" + std::to_string(bytesRead) + "/" + std::to_string(size);
        WriteStatus(folder, "PARTIAL_READ.txt", outStatus);
        return false;
    }

    outStatus = "OK full " + std::to_string(bytesRead) + " bytes";
    return true;
}

static void PerformDump(uintptr_t faultAddr) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(reinterpret_cast<LPCVOID>(faultAddr), &mbi, sizeof(mbi)))
        return;

    uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    size_t regionSize = mbi.RegionSize;

    {
        std::lock_guard<std::mutex> lock(g_DumpMtx);
        if (g_DumpedRegions.count(regionBase))
            return;
    }

    std::ostringstream folderName;
    folderName << "region_0x" << std::hex << std::uppercase << regionBase;
    fs::path regionDir = fs::path(g_DumpRoot) / folderName.str();
    std::error_code ec;
    fs::create_directories(regionDir, ec);
    if (ec) return;

    std::string status;
    bool mainOk = DumpMemoryRange(regionBase, regionSize, regionDir, "region_dump", status);

    // Only mark as dumped after a full successful write
    if (mainOk) {
        std::lock_guard<std::mutex> lock(g_DumpMtx);
        g_DumpedRegions.insert(regionBase);
    } else {
        WriteStatus(regionDir, "STATUS.txt", "MAIN_REGION: " + status);
    }

    // Secondary dumps (best-effort)
    std::string tmp;
    DumpMemoryRange(0x7FFE0000, 0x1000, regionDir, "kuser_dump", tmp);

    auto teb = NtCurrentTeb();
    if (teb && teb->ProcessEnvironmentBlock)
        DumpMemoryRange(reinterpret_cast<uintptr_t>(teb->ProcessEnvironmentBlock), 0x1000, regionDir, "peb_dump", tmp);
    if (teb)
        DumpMemoryRange(reinterpret_cast<uintptr_t>(teb), 0x2000, regionDir, "teb_dump", tmp);

    // One-time full main module
    if (!g_FullDumped) {
        std::lock_guard<std::mutex> lock(g_DumpMtx);
        if (!g_FullDumped) {
            HMODULE hMain = GetModuleHandleW(nullptr);
            if (hMain) {
                MODULEINFO mi{};
                if (GetModuleInformation(GetCurrentProcess(), hMain, &mi, sizeof(mi))) {
                    std::string fullStatus;
                    bool ok = DumpMemoryRange(reinterpret_cast<uintptr_t>(mi.lpBaseOfDll),
                                              mi.SizeOfImage, fs::path(g_DumpRoot),
                                              "full_cpuid_dump", fullStatus);
                    if (ok) {
                        // rename to the exact name requested by user
                        std::ostringstream genName;
                        genName << "full_cpuid_dump_0x" << std::hex << std::uppercase
                                << reinterpret_cast<uintptr_t>(mi.lpBaseOfDll) << ".bin";
                        fs::path generated = fs::path(g_DumpRoot) / genName.str();
                        fs::path wanted    = fs::path(g_DumpRoot) / "full_cpuid_dump.bin";
                        std::error_code renEc;
                        if (fs::exists(generated))
                            fs::rename(generated, wanted, renEc);
                        g_FullDumped = true;
                    }
                }
            }
        }
    }
}

// The real VEH handler
LONG CALLBACK RealVehHandler(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;

    PerformDump(reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress));
    return EXCEPTION_CONTINUE_EXECUTION;
}

// Thin trampoline that just forwards (lives in the same image for now).
// Future improvement: copy this tiny stub into a completely anonymous RWX page.
LONG CALLBACK VehTrampoline(PEXCEPTION_POINTERS ep) {
    return RealVehHandler(ep);
}

// Arm PAGE_GUARD on entry-point pages
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

        // Resolve dump root (host already patched the marker if possible)
        if (strncmp(g_DumpRoot, "DUMPROOT_PLACEHOLDER", 20) == 0) {
            GetTempPathA(MAX_PATH, g_DumpRoot);
            strcat_s(g_DumpRoot, "cs2.exe_dumps");
        }

        // Clear the marker string from memory so it can't be signature-scanned
        SecureZeroMemory(g_DumpRoot + strlen(g_DumpRoot), MAX_PATH - strlen(g_DumpRoot));

        std::error_code ec;
        fs::create_directories(g_DumpRoot, ec);

        // Register VEH (first handler)
        g_RealHandler = RealVehHandler;
        g_VehHandle = AddVectoredExceptionHandler(1, VehTrampoline);
        if (!g_VehHandle) return FALSE;

        // Note on VEH stealth:
        // Fully unlinking the VEH entry from LdrpVectorHandlerList while keeping
        // the handler callable is fragile and can break exception dispatch under
        // concurrent faults. The main stealth we rely on is:
        //   1. Image is never in the LDR lists (nameless)
        //   2. PE headers are wiped by the host after DllMain returns
        //   3. No obvious strings left in the image
        // The VEH entry will still exist, but it points into anonymous-looking memory
        // once headers are gone and the module has no name.

        ArmGuards();
        HANDLE h = CreateThread(nullptr, 0, GuardArmThread, nullptr, 0, nullptr);
        if (h) CloseHandle(h);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        if (g_VehHandle) {
            RemoveVectoredExceptionHandler(g_VehHandle);
            g_VehHandle = nullptr;
        }
    }
    return TRUE;
}
