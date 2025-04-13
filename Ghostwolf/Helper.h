#pragma once
void ConvertToByteArray(uintptr_t value, BYTE* byteArray, size_t size);
void PrintMessageA(char const* const Message, ...);
void PrintMessageW(wchar_t const* const Message, ...);
void usage();
void banner();
#define PRINT(...) PrintMessageA(__VA_ARGS__)
#define PRINTW(...) PrintMessageW(__VA_ARGS__)