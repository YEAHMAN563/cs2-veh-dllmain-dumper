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
#include <fstream>
#include "manual_map.h"

namespace fs = std::filesystem;

// Console colors
enum class Color : WORD {
    Default = 7,
    Green   = 10,
    Red     = 12,
    Yellow  = 14,
    Cyan    = 11
};

static HANDLE g_hCon = nullptr;

static void SetColor(Color c) {
    if (g_hCon) SetConsoleTextAttribute(g_hCon, static_cast<WORD>(c));
}

static void Print(Color c, const std::string& msg) {
    SetColor(c);
    std::cout << msg << std::flush;
    SetColor(Color::Default);
}

std::wstring GetExeDir() {
    wchar_t buf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return fs::path(buf).parent_path().wstring();
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
        LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        CloseHandle(token);
    }
}

// Improved watcher – never silently swallows errors, colors failures red
void WatchDumpsFolder(const fs::path& root) {
    std::set<std::string> seenFolders;
    std::set<std::string> seenFiles;

    while (true) {
        try {
            if (!fs::exists(root)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(400));
                continue;
            }

            for (auto& entry : fs::directory_iterator(root, fs::directory_options::skip_permission_denied)) {
                std::error_code ec;

                if (entry.is_directory(ec)) {
                    if (ec) {
                        Print(Color::Red, "[FS] directory_iterator error: " + ec.message() + "\n");
                        continue;
                    }
                    auto name = entry.path().filename().string();
                    if (name.rfind("region_", 0) == 0 && seenFolders.insert(name).second) {
                        // Check for failure markers first
                        bool hasFail = fs::exists(entry.path() / "FAILED_READ.txt") ||
                                       fs::exists(entry.path() / "FAILED_WRITE.txt") ||
                                       fs::exists(entry.path() / "PARTIAL_READ.txt") ||
                                       fs::exists(entry.path() / "STATUS.txt");

                        if (hasFail) {
                            Print(Color::Red, "[DUMP FAIL/PARTIAL] " + name + "\n");
                            // Print the status files
                            for (auto& f : { "FAILED_READ.txt", "FAILED_WRITE.txt", "PARTIAL_READ.txt", "STATUS.txt" }) {
                                fs::path sp = entry.path() / f;
                                if (fs::exists(sp)) {
                                    std::ifstream in(sp);
                                    std::string line;
                                    while (std::getline(in, line)) {
                                        Print(Color::Red, "         " + line + "\n");
                                    }
                                }
                            }
                        } else {
                            Print(Color::Green, "[DUMP OK] " + name + "\n");
                        }

                        // List actual dump files
                        for (auto& f : fs::directory_iterator(entry.path(), fs::directory_options::skip_permission_denied)) {
                            if (f.is_regular_file()) {
                                auto fname = f.path().filename().string();
                                if (fname.size() > 4 && fname.substr(fname.size()-4) == ".bin") {
                                    uintmax_t sz = fs::file_size(f, ec);
                                    if (ec) {
                                        Print(Color::Yellow, "         -> " + fname + " (size error)\n");
                                    } else {
                                        Print(Color::Cyan, "         -> " + fname + " (" + std::to_string(sz) + " bytes)\n");
                                    }
                                }
                            }
                        }
                    }
                }
                else if (entry.is_regular_file(ec)) {
                    auto name = entry.path().filename().string();
                    if (name == "full_cpuid_dump.bin" && seenFiles.insert(name).second) {
                        uintmax_t sz = fs::file_size(entry, ec);
                        if (ec)
                            Print(Color::Yellow, "[DUMP] full_cpuid_dump.bin (size error)\n");
                        else
                            Print(Color::Green, "[DUMP] full_cpuid_dump.bin (" + std::to_string(sz) + " bytes)\n");
                    }
                }
            }
        }
        catch (const std::exception& ex) {
            Print(Color::Red, std::string("[FS EXCEPTION] ") + ex.what() + "\n");
        }
        catch (...) {
            Print(Color::Red, "[FS EXCEPTION] unknown\n");
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
}

int main() {
    AllocConsole();
    freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);
    freopen_s(reinterpret_cast<FILE**>(stderr), "CONOUT$", "w", stderr);
    freopen_s(reinterpret_cast<FILE**>(stdin),  "CONIN$",  "r", stdin);
    SetConsoleTitleW(L"CS2 VEH DllMain Dumper - cyberhange");

    g_hCon = GetStdHandle(STD_OUTPUT_HANDLE);

    Print(Color::Cyan, "=============================================\n");
    Print(Color::Cyan, " CS2 VEH DllMain Region Dumper (cyberhange)\n");
    Print(Color::Cyan, "=============================================\n\n");

    if (!IsElevated()) {
        Print(Color::Red, "[!] Not running as admin. Relaunch elevated.\n");
        system("pause");
        return 1;
    }
    Print(Color::Green, "[+] Running elevated\n");
    EnableDebugPriv();

    auto exeDir = GetExeDir();
    fs::path dumpRoot = fs::path(exeDir) / "cs2.exe_dumps";
    std::error_code ec;
    fs::create_directories(dumpRoot, ec);
    if (ec) {
        Print(Color::Red, "[!] Failed to create dump root: " + ec.message() + "\n");
        system("pause");
        return 1;
    }
    Print(Color::Green, "[+] Dump root: " + dumpRoot.string() + "\n");

    std::thread watcher(WatchDumpsFolder, dumpRoot);
    watcher.detach();

    fs::path dllPath = fs::path(exeDir) / "veh_dumper.dll";
    if (!fs::exists(dllPath)) {
        Print(Color::Red, "[!] veh_dumper.dll not found next to exe\n");
        system("pause");
        return 1;
    }

    std::vector<BYTE> dllBuf;
    if (!ReadFileToBuffer(dllPath.wstring(), dllBuf)) {
        Print(Color::Red, "[!] Failed to read DLL\n");
        return 1;
    }
    Print(Color::Green, "[+] Loaded veh_dumper.dll (" + std::to_string(dllBuf.size()) + " bytes)\n");

    Print(Color::Yellow, "[*] Watching for cs2.exe ...\n");

    DWORD lastPid = 0;
    while (true) {
        DWORD pid = FindProcessId(L"cs2.exe");
        if (pid && pid != lastPid) {
            lastPid = pid;
            Print(Color::Green, "[+] Found cs2.exe PID " + std::to_string(pid) + " - injecting\n");

            HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if (!hProc) {
                Print(Color::Red, "[!] OpenProcess failed: " + std::to_string(GetLastError()) + "\n");
                continue;
            }

            std::string dumpRootA = dumpRoot.string();
            PVOID base = ManualMapDll(hProc, dllBuf, dumpRootA.c_str());
            if (base) {
                Print(Color::Green, "[+] Injected. VEH armed. Waiting for DllMain hits...\n");
            } else {
                Print(Color::Red, "[!] Manual map failed\n");
            }
            CloseHandle(hProc);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    return 0;
}
