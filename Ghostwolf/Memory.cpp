#include <Windows.h>
#include "Helper.h"
#include "Memory.h"


BOOL FindLargestSection(HANDLE hProcess, uintptr_t moduleAddr, uintptr_t& resultAddress) {

    MEMORY_BASIC_INFORMATION memoryInfo;
    uintptr_t offset = moduleAddr;

    SIZE_T largestRegion = 0;

    while (VirtualQueryEx(hProcess, reinterpret_cast<LPVOID>(offset), &memoryInfo, sizeof(memoryInfo)))
    {
        if (memoryInfo.State == MEM_COMMIT && (memoryInfo.Protect & PAGE_READONLY) != 0 && memoryInfo.Type == MEM_IMAGE)
        {
            if (memoryInfo.RegionSize > largestRegion) {
                largestRegion = memoryInfo.RegionSize;
                resultAddress = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress);
            }
        }
        offset += memoryInfo.RegionSize;
    }
    if (largestRegion > 0)
        return TRUE;

    return FALSE;
}

void PatchPattern(BYTE* pattern, BYTE baseAddrPattern[], size_t offset) {
    size_t szAddr = sizeof(uintptr_t) - 1;
    for (offset -= 1; szAddr > 3; offset--) {
        pattern[offset] = baseAddrPattern[szAddr];
        szAddr--;
    }
}

BOOL MyMemCmp(BYTE* source, const BYTE* searchPattern, size_t num) {
    for (size_t i = 0; i < num; ++i) {
        if (searchPattern[i] == 0xAA)
            continue;
        if (searchPattern[i] == 0xAF && (source[i] & 0x0F) == 0x0F) {
            continue;
        }
        if (searchPattern[i] == 0xFF && source[i] != 0x00 && source[i] != 0x2E) {
            continue;
        }
        if (source[i] != searchPattern[i]) {
            return FALSE;
        }
    }

    return TRUE;
}

BYTE* PatchBaseAddress(const BYTE* pattern, size_t patternSize, uintptr_t baseAddress, AppLication targetApp, AppMode mode) {

    BYTE* newPattern = (BYTE*)malloc(sizeof(BYTE) * patternSize);
    for (size_t i = 0; i < patternSize; i++)
        newPattern[i] = pattern[i];
    BYTE baseAddrPattern[sizeof(uintptr_t)];
    ConvertToByteArray(baseAddress, baseAddrPattern, sizeof(uintptr_t));
    if (targetApp == Chrome or targetApp == Edge) {
        if (mode == Pass) {
            PatchPattern(newPattern, baseAddrPattern, 16);
            PatchPattern(newPattern, baseAddrPattern, 40);
            PatchPattern(newPattern, baseAddrPattern, 48);
            PatchPattern(newPattern, baseAddrPattern, 56);
            PatchPattern(newPattern, baseAddrPattern, 64);
        }
        else
        {
            PatchPattern(newPattern, baseAddrPattern, 16);
            PatchPattern(newPattern, baseAddrPattern, 24);
            PatchPattern(newPattern, baseAddrPattern, 56);
            PatchPattern(newPattern, baseAddrPattern, 80);
            PatchPattern(newPattern, baseAddrPattern, 136);
            PatchPattern(newPattern, baseAddrPattern, 168);
            PatchPattern(newPattern, baseAddrPattern, 176);
            PatchPattern(newPattern, baseAddrPattern, 184);
        }
    }
    if (targetApp == FireFox) {
        PatchPattern(newPattern, baseAddrPattern, 8);
        PatchPattern(newPattern, baseAddrPattern, 88);
    }

    return newPattern;
}

BOOL FindPattern(HANDLE hProcess, const BYTE* pattern, size_t patternSize, uintptr_t* cookieMonsterInstances, size_t& szCookieMonster, AppLication targetApp, AppMode mode) {

    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);

    uintptr_t startAddress = reinterpret_cast<uintptr_t>(systemInfo.lpMinimumApplicationAddress);
    uintptr_t endAddress = reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress);

    MEMORY_BASIC_INFORMATION memoryInfo;

    while (startAddress < endAddress) {
        if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(startAddress), &memoryInfo, sizeof(memoryInfo)) == sizeof(memoryInfo)) {
            if (memoryInfo.State == MEM_COMMIT && (memoryInfo.Protect & PAGE_READWRITE) != 0 && memoryInfo.Type == MEM_PRIVATE) {
                BYTE* buffer = new BYTE[memoryInfo.RegionSize];
                SIZE_T bytesRead;
                BYTE* newPattern = PatchBaseAddress(pattern, patternSize, reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress), targetApp, mode);
                if (ReadProcessMemory(hProcess, memoryInfo.BaseAddress, buffer, memoryInfo.RegionSize, &bytesRead)) {
                    uintptr_t baseAddr = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress);
                    for (size_t i = 0; i <= bytesRead - patternSize; ++i) {
                        if (MyMemCmp(buffer + i, newPattern, patternSize)) {
                            uintptr_t resultAddress = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + i;
                            uintptr_t offset = resultAddress - reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress);
#ifdef DEBUG
                            PRINT("[+] 找到 CookieMonster 实例地址:\n");
                            PRINT("    分配基址: 0x%p\n", memoryInfo.AllocationBase);
                            PRINT("    区域基址: 0x%p\n", memoryInfo.BaseAddress);
                            PRINT("    偏移量:   0x%08x\n", offset);
                            PRINT("    绝对地址: 0x%p\n\n", (void*)resultAddress);
#endif
                            if (szCookieMonster >= 1000) {
                                free(newPattern);
                                return TRUE;
                            }

                            cookieMonsterInstances[szCookieMonster] = resultAddress;
                            szCookieMonster++;
                        }
                    }
                }
                else {
#ifdef DEBUG
                    PRINT("ReadProcessMemory failed\n");
#endif
                }
                free(newPattern);
                delete[] buffer;
            }

            startAddress += memoryInfo.RegionSize;
        }
        else {
            PRINT("VirtualQueryEx failed\n");
            break;
        }
    }
    if (szCookieMonster > 0)
        return TRUE;
    return FALSE;
}