#pragma once
#include <minwindef.h>

BOOL FindPattern(HANDLE hProcess, const BYTE* pattern, size_t patternSize, uintptr_t* cookieMonsterInstances, size_t& szCookieMonster, BOOL isBrowser);
BOOL FindLargestSection(HANDLE hProcess, uintptr_t moduleAddr, uintptr_t& resultAddress);
void PatchPattern(BYTE* pattern, BYTE baseAddrPattern[], size_t offset);
