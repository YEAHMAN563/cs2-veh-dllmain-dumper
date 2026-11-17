#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <thread>
#include <chrono>
#include <set>
#include <mutex>
#include "manual_map.h"

namespace fs = std::filesystem;

std::wstring GetExeDir() {
    wchar_t buf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    fs::path p(buf);
    return p.parent_path().wstring();
}

DWORD FindProcessId(const std::wstring& name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name.c_str()) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

bool IsElevated() {
    BOOL elev = FALSE;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION te{};
        DWORD sz = sizeof(te);
        if (GetTokenInformation(token, TokenElevation, &te, sizeof(te), &sz))
            elev = te.TokenIsElevated;
        CloseHandle(token);
    }
    return elev;
}

void EnableDebugPriv() {
    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        TOKEN_PRIVILEGES tp{};
        LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        CloseHandle(token);
    }
}

// Watchdog: scan dumps folder and print new region folders
void WatchDumpsFolder(const fs::path& root) {
    std::set<std::string> seen;
    while (true) {
        try {
            if (fs::exists(root)) {
                for (auto& e : fs::directory_iterator(root)) {
                    if (e.is_directory()) {
                        auto name = e.path().filename().string();
                        if (name.rfind("region_", 0) == 0 && seen.insert(name).second) {
                            std::cout << "[DUMP] New region folder: " << name << "\n";
                            for (auto& f : fs::directory_iterator(e.path())) {
                                std::cout << "       -> " << f.path().filename().string()
                                          << " (" << fs::file_size(f) << " bytes)\n";
                            }
                        }
                    }
                    if (e.is_regular_file() && e.path().filename() == "full_cpuid_dump.bin" && seen.insert("full_cpuid_dump.bin").second) {
                        std::cout << "[DUMP] full_cpuid_dump.bin written (" << fs::file_size(e) << " bytes)\n";
                    }
                }
            }
        } catch (...) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
}

int main() {
    // Own console (not inherited from CMD)
    AllocConsole();
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
    freopen_s((FILE**)stderr, "CONOUT$", "w", stderr);
    freopen_s((FILE**)stdin, "CONIN$", "r", stdin);
    SetConsoleTitleW(L"CS2 VEH DllMain Dumper - cyberhange");

    std::cout << "=============================================\n";
    std::cout << " CS2 VEH DllMain Region Dumper (cyberhange)\n";
    std::cout << "=============================================\n\n";

    if (!IsElevated()) {
        std::cout << "[!] Not running as admin. Relaunch elevated.\n";
        system("pause");
        return 1;
    }
    std::cout << "[+] Running elevated\n";
    EnableDebugPriv();

    auto exeDir = GetExeDir();
    fs::path dumpRoot = fs::path(exeDir) / "cs2.exe_dumps";
    fs::create_directories(dumpRoot);
    std::cout << "[+] Dump root: " << dumpRoot.string() << "\n";

    // Start folder watcher thread for live console logs
    std::thread watcher(WatchDumpsFolder, dumpRoot);
    watcher.detach();

    // Locate DLL next to us
    fs::path dllPath = fs::path(exeDir) / "veh_dumper.dll";
    if (!fs::exists(dllPath)) {
        std::cout << "[!] veh_dumper.dll not found next to exe\n";
        system("pause");
        return 1;
    }

    std::vector<BYTE> dllBuf;
    if (!ReadFileToBuffer(dllPath.wstring(), dllBuf)) {
        std::cout << "[!] Failed to read DLL\n";
        return 1;
    }
    std::cout << "[+] Loaded veh_dumper.dll (" << dllBuf.size() << " bytes)\n";

    std::cout << "[*] Watching for cs2.exe ...\n";

    DWORD lastPid = 0;
    while (true) {
        DWORD pid = FindProcessId(L"cs2.exe");
        if (pid && pid != lastPid) {
            lastPid = pid;
            std::cout << "[+] Found cs2.exe PID " << pid << " - injecting\n";

            HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if (!hProc) {
                std::cout << "[!] OpenProcess failed: " << GetLastError() << "\n";
                continue;
            }

            std::string dumpRootA = dumpRoot.string();
            PVOID base = ManualMapDll(hProc, dllBuf, dumpRootA.c_str());
            if (base) {
                std::cout << "[+] Injected. VEH armed. Waiting for DllMain hits...\n";
            } else {
                std::cout << "[!] Manual map failed\n";
            }
            CloseHandle(hProc);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200)); // fast poll
    }
    return 0;
}
