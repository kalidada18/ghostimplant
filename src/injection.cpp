#include "injection.hpp"
#include "syscalls.hpp"
#include <windows.h>
#include <tlhelp32.h>

BOOL SpawnWithPPID(const wchar_t* targetPath, DWORD parentPid, HANDLE* hProcess) {
    // Use InitializeProcThreadAttributeList, UpdateProcThreadAttribute with parent handle.
    // Then CreateProcess with EXTENDED_STARTUPINFO_PRESENT.
    // Stub.
    return FALSE;
}

BOOL InjectRemoteProcess(DWORD pid, const BYTE* payload, SIZE_T payloadSize, HANDLE* hThread) {
    // 1. NtOpenProcess
    // 2. NtAllocateVirtualMemory (RW)
    // 3. NtWriteVirtualMemory
    // 4. NtProtectVirtualMemory (RX)
    // 5. NtCreateThreadEx
    // 6. NtClose
    return FALSE;
}

BOOL StompModule(DWORD pid, const wchar_t* dllPath, const BYTE* shellcode, SIZE_T shellcodeSize) {
    // 1. Open target process
    // 2. Load DLL via NtMapViewOfSection (or use LoadLibrary in remote)
    // 3. Parse remote PE to find .text section RVA.
    // 4. NtProtectVirtualMemory on .text to RW, write shellcode, restore RX.
    // 5. Execute via export or thread.
    return FALSE;
}