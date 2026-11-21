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

static std::recursive_mutex g_DumpMtx;
static std::unordered_set<uintptr_t> g_DumpedRegions;
static std::unordered_set<uintptr_t> g_ArmedPages;    // pages we've already armed (avoid re-arming)
static bool g_FullDumped = false;
static PVOID g_VehHandle = nullptr;
static bool g_Running = true;

static PVECTORED_EXCEPTION_HANDLER g_RealHandler = nullptr;

namespace fs = std::filesystem;

// ---------- status helpers ----------
static void WriteStatus(const fs::path& dir, const std::string& name, const std::string& text) {
    try {
        std::ofstream f(dir / name, std::ios::app);
        if (f) f << text << "\n";
    } catch (...) {}
}

static size_t WriteBin(const fs::path& path, const void* data, size_t size) {
    try {
        std::ofstream f(path, std::ios::binary);
        if (!f) return 0;
        f.write(reinterpret_cast<const char*>(data), size);
        return f ? size : 0;
    } catch (...) {
        return 0;
    }
}

static bool DumpMemoryRange(uintptr_t base, size_t size, const fs::path& folder,
                            const char* prefix, std::string& outStatus) {
    if (size == 0) {
        outStatus = "SKIP size=0";
        return false;
    }

    std::vector<BYTE> buf;
    try { buf.resize(size, 0); }
    catch (...) {
        outStatus = "FAIL allocation of " + std::to_string(size) + " bytes";
        return false;
    }

    // Read page-by-page so that guarded/inaccessible pages don't abort the whole dump.
    // Temporarily lift PAGE_GUARD on each page while reading.
    static const size_t PAGE = 0x1000;
    size_t totalRead = 0;
    size_t skipped   = 0;

    for (size_t off = 0; off < size; off += PAGE) {
        uintptr_t pageAddr = base + off;
        size_t    chunk    = (off + PAGE <= size) ? PAGE : (size - off);

        // Check/clear PAGE_GUARD temporarily
        MEMORY_BASIC_INFORMATION mbi{};
        DWORD oldProt = 0;
        bool hadGuard = false;
        if (VirtualQuery(reinterpret_cast<LPCVOID>(pageAddr), &mbi, sizeof(mbi))) {
            if (mbi.Protect & PAGE_GUARD) {
                DWORD tmp = 0;
                DWORD stripped = mbi.Protect & ~PAGE_GUARD;
                if (VirtualProtect(reinterpret_cast<LPVOID>(pageAddr), PAGE, stripped, &tmp)) {
                    oldProt  = tmp;
                    hadGuard = true;
                }
            }
        }

        SIZE_T bytesRead = 0;
        BOOL ok = ReadProcessMemory(GetCurrentProcess(),
                                    reinterpret_cast<LPCVOID>(pageAddr),
                                    buf.data() + off, chunk, &bytesRead);
        if (ok && bytesRead > 0)
            totalRead += bytesRead;
        else
            skipped += chunk;   // leave as zeroes in buf

        // Restore PAGE_GUARD
        if (hadGuard) {
            DWORD tmp2 = 0;
            VirtualProtect(reinterpret_cast<LPVOID>(pageAddr), PAGE, oldProt, &tmp2);
        }
    }

    std::ostringstream name;
    name << prefix << "_0x" << std::hex << std::uppercase << base << ".bin";
    fs::path outPath = folder / name.str();

    if (totalRead == 0) {
        outStatus = "FAIL all pages unreadable base=0x" + [&]{ std::ostringstream o; o << std::hex << base; return o.str(); }();
        WriteStatus(folder, "FAILED_READ.txt", outStatus);
        return false;
    }

    size_t written = WriteBin(outPath, buf.data(), size);
    if (written == 0) {
        outStatus = "FAIL write to disk";
        WriteStatus(folder, "FAILED_WRITE.txt", outStatus);
        return false;
    }

    if (skipped > 0) {
        outStatus = "PARTIAL read=" + std::to_string(totalRead) + " zeroed=" + std::to_string(skipped) + "/" + std::to_string(size);
    } else {
        outStatus = "OK full " + std::to_string(totalRead) + " bytes";
    }
    return true;  // we got something useful
}

static void PerformDump(uintptr_t faultAddr) {
    try {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(faultAddr), &mbi, sizeof(mbi)))
            return;

        uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        size_t regionSize = mbi.RegionSize;

        // Dedupe: mark attempted immediately so concurrent/repeated VEH hits don't re-enter
        {
            std::lock_guard<std::recursive_mutex> lock(g_DumpMtx);
            if (!g_DumpedRegions.insert(regionBase).second)
                return;  // already attempted
        }

        std::ostringstream folderName;
        folderName << "region_0x" << std::hex << std::uppercase << regionBase;
        fs::path regionDir = fs::path(g_DumpRoot) / folderName.str();
        std::error_code ec;
        fs::create_directories(regionDir, ec);
        if (ec) return;

        std::string status;
        DumpMemoryRange(regionBase, regionSize, regionDir, "region_dump", status);
        if (status.rfind("FAIL all", 0) == 0 || status.rfind("FAIL write", 0) == 0)
            WriteStatus(regionDir, "STATUS.txt", "MAIN_REGION: " + status);

        // Secondary dumps (best-effort)
        std::string tmp;
        DumpMemoryRange(0x7FFE0000, 0x1000, regionDir, "kuser_dump", tmp);

        auto teb = NtCurrentTeb();
        if (teb && teb->ProcessEnvironmentBlock)
            DumpMemoryRange(reinterpret_cast<uintptr_t>(teb->ProcessEnvironmentBlock), 0x1000, regionDir, "peb_dump", tmp);
        if (teb)
            DumpMemoryRange(reinterpret_cast<uintptr_t>(teb), 0x2000, regionDir, "teb_dump", tmp);

        // One-time full main module — set flag FIRST so we never retry on failure
        {
            std::lock_guard<std::recursive_mutex> lock(g_DumpMtx);
            if (g_FullDumped) return;
            g_FullDumped = true;  // mark before attempt — no retry on failure
        }
        try {
            HMODULE hMain = GetModuleHandleW(nullptr);
            if (hMain) {
                MODULEINFO mi{};
                if (GetModuleInformation(GetCurrentProcess(), hMain, &mi, sizeof(mi))) {
                    std::string fullStatus;
                    DumpMemoryRange(reinterpret_cast<uintptr_t>(mi.lpBaseOfDll),
                                    mi.SizeOfImage, fs::path(g_DumpRoot),
                                    "full_main_dump", fullStatus);

                    // Rename to a clean filename regardless of partial/full success
                    std::ostringstream genName;
                    genName << "full_main_dump_0x" << std::hex << std::uppercase
                            << reinterpret_cast<uintptr_t>(mi.lpBaseOfDll) << ".bin";
                    fs::path generated = fs::path(g_DumpRoot) / genName.str();
                    fs::path wanted    = fs::path(g_DumpRoot) / "full_main_dump.bin";
                    std::error_code renEc;
                    if (fs::exists(wanted))   fs::remove(wanted, renEc);
                    if (fs::exists(generated)) fs::rename(generated, wanted, renEc);
                }
            }
        } catch (...) {}
    } catch (...) {}
}

// The real VEH handler
LONG CALLBACK RealVehHandler(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;

    try {
        PerformDump(reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress));
    } catch (...) {}

    return EXCEPTION_CONTINUE_EXECUTION;
}

LONG CALLBACK VehTrampoline(PEXCEPTION_POINTERS ep) {
    return RealVehHandler(ep);
}

// Arm PAGE_GUARD on a single entry-point page of all loaded modules
static void ArmGuards() {
    try {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (snap == INVALID_HANDLE_VALUE) return;

        MODULEENTRY32W me{ sizeof(me) };
        if (Module32FirstW(snap, &me)) {
            do {
                BYTE* base = me.modBaseAddr;
                auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
                if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
                if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x1000) continue;

                auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
                if (nt->Signature != IMAGE_NT_SIGNATURE) continue;

                DWORD epRva = nt->OptionalHeader.AddressOfEntryPoint;
                if (!epRva) continue;
                BYTE* ep = base + epRva;

                // Guard only the single 4 KB page containing the entry point
                uintptr_t epPage = reinterpret_cast<uintptr_t>(ep) & ~static_cast<uintptr_t>(0xFFF);

                {
                    std::lock_guard<std::recursive_mutex> lock(g_DumpMtx);
                    if (g_ArmedPages.count(epPage))
                        continue;  // already armed this page
                }

                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQuery(reinterpret_cast<LPCVOID>(epPage), &mbi, sizeof(mbi))) {
                    DWORD prot = mbi.Protect;
                    if ((prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
                        !(prot & (PAGE_GUARD | PAGE_NOACCESS))) {
                        DWORD old = 0;
                        DWORD newProt = (prot & ~(PAGE_GUARD | PAGE_NOACCESS)) | PAGE_GUARD;
                        if (VirtualProtect(reinterpret_cast<LPVOID>(epPage), 0x1000, newProt, &old)) {
                            std::lock_guard<std::recursive_mutex> lock(g_DumpMtx);
                            g_ArmedPages.insert(epPage);
                        }
                    }
                }
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
    } catch (...) {}
}

static DWORD WINAPI GuardArmThread(LPVOID) {
    while (g_Running) {
        ArmGuards();
        Sleep(50);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    try {
        if (reason == DLL_PROCESS_ATTACH) {
            DisableThreadLibraryCalls(hModule);

            // Resolve dump root (host already patched the marker if possible)
            if (strncmp(g_DumpRoot, "DUMPROOT_PLACEHOLDER", 20) == 0) {
                GetTempPathA(MAX_PATH, g_DumpRoot);
                strcat_s(g_DumpRoot, "cs2.exe_dumps");
            }

            std::error_code ec;
            fs::create_directories(g_DumpRoot, ec);

            // Register VEH (first handler)
            g_RealHandler = RealVehHandler;
            g_VehHandle = AddVectoredExceptionHandler(1, VehTrampoline);
            if (!g_VehHandle) return FALSE;

            // Start guard thread asynchronously (do not block DllMain)
            HANDLE h = CreateThread(nullptr, 0, GuardArmThread, nullptr, 0, nullptr);
            if (h) CloseHandle(h);
        }
        else if (reason == DLL_PROCESS_DETACH) {
            g_Running = false;
            if (g_VehHandle) {
                RemoveVectoredExceptionHandler(g_VehHandle);
                g_VehHandle = nullptr;
            }
        }
    } catch (...) {}
    return TRUE;
}
