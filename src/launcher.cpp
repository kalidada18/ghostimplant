// launcher.cpp — Ghost system-tray launcher
//
// Compiles under x86_64-w64-mingw32-g++ (MinGW-w64) and MSVC.
// Links: user32, shell32 only — no WinHTTP, no COM.
//
// Place launcher.exe next to ghost.exe (both in build/).
// Tray icon: right-click → Start ghost.exe / Exit Launcher

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <string>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

static constexpr UINT WM_TRAY_MSG  = WM_USER + 1;
static constexpr UINT ID_TRAY_ICON = 1;
static constexpr UINT ID_START     = 100;
static constexpr UINT ID_EXIT      = 101;

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
// Launch ghost.exe from the same directory as launcher.exe
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

    if (GetFileAttributesW(ghostPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(nullptr,
            (std::wstring(L"Not found: ") + ghostPath).c_str(),
            L"Ghost Launcher", MB_ICONERROR | MB_OK);
        return FALSE;
    }

    STARTUPINFOW si      = {};
    si.cb                = sizeof(si);
    si.dwFlags           = STARTF_USESHOWWINDOW;
    si.wShowWindow       = SW_HIDE;

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

    // Required so the menu closes when clicking elsewhere
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

    WNDCLASSW wc      = {};
    wc.lpfnWndProc    = WndProc;
    wc.hInstance      = hInst;
    wc.lpszClassName  = WINDOW_CLASS;
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
