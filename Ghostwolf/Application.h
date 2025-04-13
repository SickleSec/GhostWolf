#pragma once
#include <minwindef.h>
enum AppLication {
	Chrome,
	Edge,
	FireFox,
	ToDesk,
};
enum AppMode {
	Normal,
	List,
	Pass
};
struct BrowserVersion {
	WORD highMajor;
	WORD lowMajor;
	WORD highMinor;
	WORD lowMinor;
};

struct OptimizedString {
	char buf[23];
	UCHAR len;
};

struct CookieStruct {
	char buf[8];
	uintptr_t cookieDataAddress;
};
struct NsCString {
	uintptr_t address;
	UCHAR len;
	char padding[7];
};

struct BoolString {
	bool value;
	char padding[7];
};

struct RootNode {
	uintptr_t beginNode;
	uintptr_t firstNode;
	size_t size;
};

struct Node {
	uintptr_t left;
	uintptr_t right;
	uintptr_t parent;
	bool is_black;
	char padding[7];
	OptimizedString key;
	uintptr_t valueAddress;
};
struct PassNode {
	uintptr_t left;
	uintptr_t right;
	uintptr_t parent;
	bool is_black;
	char padding[7];
	uintptr_t valueAddress;
	char len;
	char buf[14];
	unsigned char tag;
};


struct RemoteString {
	uintptr_t dataAddress;
	size_t strLen;
	int strMax;
	char unk[3];
	UCHAR strAlloc;
};
struct TodeskString {
	uintptr_t string_part_1;
	uintptr_t string_part_2;
	char len;
	char paddinglen[7];
	char maxlen;
	char paddingmaxlen[7];
};

#pragma region Chrome
enum class CookieSameSite {
	UNSPECIFIED = -1,
	NO_RESTRICTION = 0,
	LAX_MODE = 1,
	STRICT_MODE = 2,
	kMaxValue = STRICT_MODE
};

enum class CookieSourceScheme {
	kUnset = 0,
	kNonSecure = 1,
	kSecure = 2,

	kMaxValue = kSecure
};

enum CookiePriority {
	COOKIE_PRIORITY_LOW = 0,
	COOKIE_PRIORITY_MEDIUM = 1,
	COOKIE_PRIORITY_HIGH = 2,
	COOKIE_PRIORITY_DEFAULT = COOKIE_PRIORITY_MEDIUM
};

enum class CookieSourceType {
	kUnknown = 0,
	kHTTP = 1,
	kScript = 2,
	kOther = 3,
	kMaxValue = kOther
};

struct RemoteVector {
	uintptr_t begin_;
	uintptr_t end_;
	uintptr_t unk;
};

struct ProcessBoundString {
	RemoteVector maybe_encrypted_data_;
	size_t original_size_;
	BYTE unk[8];
	bool encrypted_ = false;
};
BOOL GetBrowserVersion(HANDLE hProcess, BrowserVersion& browserVersion);
void WalkCookieMap(HANDLE hProcess, uintptr_t cookieMapAddress, AppLication targetBrowser, AppMode mode);
void WalkRemoteApp(HANDLE hProcess, uintptr_t patternAddress, AppLication targetApplication, AppMode mode);