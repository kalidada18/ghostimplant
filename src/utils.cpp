#include "utils.hpp"
#include <windows.h>
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>
#include <lmcons.h>

// ---------------------------------------------------------------------------
// String conversion — WideChar <-> UTF-8
// ---------------------------------------------------------------------------

std::string WStringToUTF8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(
        CP_UTF8, 0,
        wstr.c_str(), static_cast<int>(wstr.size()),
        nullptr, 0, nullptr, nullptr
    );
    if (size <= 0) return "";
    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0,
        wstr.c_str(), static_cast<int>(wstr.size()),
        &result[0], size, nullptr, nullptr
    );
    return result;
}

std::wstring UTF8ToWString(const std::string& utf8) {
    if (utf8.empty()) return L"";
    int size = MultiByteToWideChar(
        CP_UTF8, 0,
        utf8.c_str(), static_cast<int>(utf8.size()),
        nullptr, 0
    );
    if (size <= 0) return L"";
    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(
        CP_UTF8, 0,
        utf8.c_str(), static_cast<int>(utf8.size()),
        &result[0], size
    );
    return result;
}

// ---------------------------------------------------------------------------
// Base64 — RFC 4648 standard alphabet
// ---------------------------------------------------------------------------

static const char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64Encode(const BYTE* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    for (size_t i = 0; i < len; i += 3) {
        uint32_t block = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) block |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) block |= static_cast<uint32_t>(data[i + 2]);

        out.push_back(B64_TABLE[(block >> 18) & 0x3F]);
        out.push_back(B64_TABLE[(block >> 12) & 0x3F]);
        out.push_back((i + 1 < len) ? B64_TABLE[(block >> 6) & 0x3F] : '=');
        out.push_back((i + 2 < len) ? B64_TABLE[block & 0x3F] : '=');
    }
    return out;
}

std::vector<BYTE> Base64Decode(const std::string& b64) {
    // Build reverse lookup on first call
    static int inv[256] = {0};
    static bool init = false;
    if (!init) {
        for (int i = 0; i < 256; ++i) inv[i] = -1;
        for (int i = 0; i < 64; ++i) inv[static_cast<unsigned char>(B64_TABLE[i])] = i;
        inv[static_cast<unsigned char>('=')] = 0;
        init = true;
    }

    std::vector<BYTE> out;
    if (b64.size() % 4 != 0) return out;
    out.reserve((b64.size() / 4) * 3);

    for (size_t i = 0; i < b64.size(); i += 4) {
        uint32_t block = 0;
        for (int j = 0; j < 4; ++j) {
            int v = inv[static_cast<unsigned char>(b64[i + j])];
            if (v < 0) return {};  // invalid char
            block = (block << 6) | static_cast<uint32_t>(v);
        }
        out.push_back(static_cast<BYTE>((block >> 16) & 0xFF));
        if (b64[i + 2] != '=') out.push_back(static_cast<BYTE>((block >> 8) & 0xFF));
        if (b64[i + 3] != '=') out.push_back(static_cast<BYTE>(block & 0xFF));
    }
    return out;
}

// ---------------------------------------------------------------------------
// XOR cipher — in-place
// ---------------------------------------------------------------------------

VOID XorBuffer(BYTE* data, size_t len, const BYTE* key, size_t keyLen) {
    if (keyLen == 0) return;
    for (size_t i = 0; i < len; ++i)
        data[i] ^= key[i % keyLen];
}

// ---------------------------------------------------------------------------
// System info
// ---------------------------------------------------------------------------

std::wstring GetHostnameHash() {
    wchar_t hostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(hostname, &size))
        return L"00000000";

    // FNV-1a 32-bit — better distribution than simple XOR rotate
    uint32_t hash = 0x811c9dc5u;
    for (DWORD i = 0; i < size; ++i) {
        hash ^= static_cast<uint32_t>(hostname[i]);
        hash *= 0x01000193u;
    }

    std::wstringstream ss;
    ss << std::hex << std::setfill(L'0') << std::setw(8) << hash;
    return ss.str();
}

std::wstring GetUsername() {
    wchar_t user[UNLEN + 1] = {0};
    DWORD size = UNLEN + 1;
    if (GetUserNameW(user, &size))
        return std::wstring(user, size > 0 ? size - 1 : 0);
    return L"unknown";
}

std::wstring GetHostname() {
    wchar_t hostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(hostname, &size))
        // GetComputerNameW sets size to the number of characters written
        // excluding the null terminator on success, same contract as GetUserNameW.
        return std::wstring(hostname, size);
    return L"unknown";
}

DWORD GetOSBuild() {
    // RtlGetVersion is immune to compatibility shims, unlike GetVersionEx
    typedef NTSTATUS(NTAPI* RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;

    auto pRtlGetVersion = reinterpret_cast<RtlGetVersion_t>(
        GetProcAddress(ntdll, "RtlGetVersion")
    );
    if (!pRtlGetVersion) return 0;

    RTL_OSVERSIONINFOW vi = {0};
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (pRtlGetVersion(&vi) == 0)  // STATUS_SUCCESS
        return vi.dwBuildNumber;

    return 0;
}

BOOL IsElevated() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;

    TOKEN_ELEVATION te = {0};
    DWORD retLen = 0;
    BOOL result = FALSE;
    if (GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &retLen))
        result = te.TokenIsElevated;

    CloseHandle(hToken);
    return result;
}

// ---------------------------------------------------------------------------
// Jitter sleep — uniform distribution between [minSec, maxSec]
// ---------------------------------------------------------------------------

VOID JitterSleep(DWORD minSec, DWORD maxSec) {
    if (minSec > maxSec) minSec = maxSec;

    // Static generator seeded once from random_device.
    // Re-seeding per call from high_resolution_clock produces near-identical
    // seeds when called within the same scheduler tick (rapid failure bursts).
    static std::mt19937 gen = [] {
        std::random_device rd;
        // XOR with thread ID for additional entropy on platforms where
        // random_device is deterministic (some embedded/VM environments).
        return std::mt19937(
            rd() ^ static_cast<unsigned>(GetCurrentThreadId())
        );
    }();
    static CRITICAL_SECTION cs = [] {
        CRITICAL_SECTION c;
        InitializeCriticalSection(&c);
        return c;
    }();

    DWORD seconds;
    EnterCriticalSection(&cs);
    seconds = std::uniform_int_distribution<DWORD>(minSec, maxSec)(gen);
    LeaveCriticalSection(&cs);

    Sleep(seconds * 1000);
}