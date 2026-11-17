#pragma once
#include <Windows.h>
#include <string>
#include <vector>

// Simple x64 manual mapper. Returns remote base or nullptr on failure.
// Patches a global char g_DumpRoot[MAX_PATH] inside the image if the symbol offset is known,
// or we write by pattern / fixed offset after mapping.
PVOID ManualMapDll(HANDLE hProcess, const std::vector<BYTE>& dllData, const char* dumpRootPath);

// Helper: read whole file
bool ReadFileToBuffer(const std::wstring& path, std::vector<BYTE>& out);
