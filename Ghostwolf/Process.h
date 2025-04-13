#pragma once
#include "Application.h"

BOOL FindProcessPID(LPCWSTR processName, DWORD* pid, HANDLE* hProcess, AppMode mode);
BOOL GetRemoteModuleBaseAddress(HANDLE hProcess, const wchar_t* moduleName, uintptr_t& baseAddress, DWORD* moduleSize);