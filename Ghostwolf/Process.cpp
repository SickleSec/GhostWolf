#define _AMD64_
#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "Helper.h"
#include "PEB.h"
#include "Process.h"
#define MAX_NAME 256

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessTlsInformation,
    ProcessCookie,
    ProcessImageInformation,
    ProcessCycleTime,
    ProcessPagePriority,
    ProcessInstrumentationCallback,
    ProcessThreadStackAllocation,
    ProcessWorkingSetWatchEx,
    ProcessImageFileNameWin32,
    ProcessImageFileMapping,
    ProcessAffinityUpdateMode,
    ProcessMemoryAllocationMode,
    ProcessGroupInformation,
    ProcessTokenVirtualizationEnabled,
    ProcessConsoleHostProcess,
    ProcessWindowInformation,
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef LONG KPRIORITY;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef NTSTATUS(NTAPI* NtQueryInformationProcess)(
    IN  HANDLE ProcessHandle,
    IN  PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN  ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

BOOL ReadRemoteProcessPEB(IN HANDLE hProcess, OUT PEB* peb) {
    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    if (hNtDll == NULL || hNtDll == INVALID_HANDLE_VALUE) {
        PRINT("LoadLibrary could not load ntdll\n");
        return FALSE;
    }
    NtQueryInformationProcess pNtQueryInformationProcess = (NtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    PROCESS_BASIC_INFORMATION processInfo{ 0 };
    ULONG szInfo = 0;

    if (SUCCEEDED(pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &processInfo, sizeof(PROCESS_BASIC_INFORMATION), &szInfo)) && szInfo == sizeof(PROCESS_BASIC_INFORMATION) && processInfo.PebBaseAddress) {
        size_t szPEB = 0;
        if (!ReadProcessMemory(hProcess, processInfo.PebBaseAddress, peb, sizeof(PEB), &szPEB) || szPEB < sizeof(PEB)) {
            PRINT("Failed to read Browser PEB\n");
            return FALSE;
        }
        else {
            return TRUE;
        }
    }
    else {
        PRINT("ProcessBasicInfomation failed\n");
        return FALSE;
    }
    return FALSE;
}

BOOL ReadPEBProcessParameters(HANDLE hProcess, PEB* peb, WCHAR** args) {
    UNICODE_STRING commandLine;
    if (!ReadProcessMemory(hProcess, &peb->ProcessParameters->CommandLine, &commandLine, sizeof(commandLine), NULL)) {
        PRINT("Could not read CommandLine\n");
    }
    *args = (WCHAR*)malloc(commandLine.MaximumLength);
    if (*args != 0 && !ReadProcessMemory(hProcess, commandLine.Buffer, *args, commandLine.MaximumLength, NULL))
    {
        PRINT("Could not read the command line string\n");
        free(*args);
        return FALSE;
    }
    return TRUE;
}

BOOL GetTokenUser(IN HANDLE hProcess) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        PRINT("OpenProcessToken failed");
        return FALSE;
    }

    PTOKEN_USER hTokenUser = { 0 };
    DWORD dwSize = 0;
    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize)) {
        DWORD dwError = GetLastError();
        if (dwError != ERROR_INSUFFICIENT_BUFFER) {
            PRINT("GetTokenInformation querying buffer size failed!");
            return FALSE;
        }
    }
    hTokenUser = (PTOKEN_USER)malloc(dwSize);

    if (!GetTokenInformation(hToken, TokenUser, hTokenUser, dwSize, &dwSize)) {
        PRINT("GetTokenInformation failed!");
        return FALSE;
    }

    if (hTokenUser == NULL) {
        free(hTokenUser);
        return FALSE;
    }

    wchar_t* UserName = new wchar_t[MAX_NAME];
    UserName[0] = L'\0';
    wchar_t* DomainName = new wchar_t[MAX_NAME];
    DomainName[0] = L'\0';

    DWORD dwMaxUserName = MAX_NAME;
    DWORD dwMaxDomainName = MAX_NAME;
    SID_NAME_USE SidUser = SidTypeUser;
    if (!LookupAccountSidW(NULL, hTokenUser->User.Sid, UserName, &dwMaxUserName, DomainName, &dwMaxDomainName, &SidUser))
    {
        PRINT("LookupAccountSidw failed!");
        free(hTokenUser);
        return FALSE;
    }

    PRINTW(DomainName);
    PRINTW(L"\\");
    PRINTW(UserName);

    free(hTokenUser);
    CloseHandle(hToken);
    delete[] UserName;
    delete[] DomainName;
    return FALSE;
}

BOOL FindProcessPID(LPCWSTR processName, DWORD* pid, HANDLE* hProcess, AppMode mode)
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        PRINT("Create SnapShot Failed!\n");
        return FALSE;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        PRINT("GET First Process Failed!\n");
        CloseHandle(hProcessSnap);
        return FALSE;
    }
    const WCHAR* flags = TEXT("--utility-sub-type=network.mojom.NetworkService");
    if (processName == L"ToDesk.exe") {
        flags = TEXT("--localPort");
    }

    do {
        if (wcscmp(pe32.szExeFile, processName) == 0) {
            PEB peb = { 0 };
            HANDLE hHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (ReadRemoteProcessPEB(hHandle, &peb))
            {
                WCHAR* commandLine{ 0 };
                if (ReadPEBProcessParameters(hHandle, &peb, &commandLine) && commandLine != 0)
                {
                    if (processName == L"chrome.exe" || (processName == L"msedge.exe" && mode != Pass) || processName == L"ToDesk.exe") {
                        if (wcsstr(commandLine, flags) != 0) {
                            PRINT("[+] Fund AppLication process: %d\n", pe32.th32ProcessID);
                            PRINT("    Process owner: ");
                            GetTokenUser(hHandle);
                            PRINTW(L"\n\n");

                            *pid = pe32.th32ProcessID;
                            *hProcess = hHandle;
                            free(commandLine);
                            CloseHandle(hProcessSnap);
                            return TRUE;
                        }
                    }
                    else
                    {
                        PRINT("[+] Fund AppLication process: %d\n", pe32.th32ProcessID);
                        PRINT("    Process owner: ");
                        GetTokenUser(hHandle);
                        PRINTW(L"\n\n");

                        *pid = pe32.th32ProcessID;
                        *hProcess = hHandle;
                        free(commandLine);
                        CloseHandle(hProcessSnap);

                        return TRUE;
                    }
                    free(commandLine);
                }
            }
            CloseHandle(hHandle);
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return FALSE;
}
BOOL GetRemoteModuleBaseAddress(HANDLE hProcess, const wchar_t* moduleName, uintptr_t& baseAddress, DWORD* moduleSize) {

    DWORD szModules = sizeof(HMODULE) * 1024;
    HMODULE* hModules = (HMODULE*)malloc(szModules);
    DWORD cbNeeded;

    if (hModules == 0 || !EnumProcessModulesEx(hProcess, hModules, szModules, &cbNeeded, LIST_MODULES_ALL)) {
        PRINT("EnumProcessModulesEx failed");
        free(hModules);
        return FALSE;
    }

    for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
        wchar_t szModuleName[MAX_PATH];
        if (GetModuleBaseName(hProcess, hModules[i], szModuleName, sizeof(szModuleName) / sizeof(wchar_t)) == 0) {
            PRINT("GetModuleBaseName failed");
            continue;
        }
        if (_wcsicmp(szModuleName, moduleName) == 0) {
            MODULEINFO moduleInfo;
            if (!GetModuleInformation(hProcess, hModules[i], &moduleInfo, sizeof(moduleInfo))) {
                PRINT("GetModuleInformation failed");
                free(hModules);
                return FALSE;
            }
            baseAddress = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
            *moduleSize = moduleInfo.SizeOfImage;
            free(hModules);
            return TRUE;
        }
    }
    free(hModules);
    return FALSE;
}