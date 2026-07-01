#pragma once
#include <windows.h>
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#include <winternl.h>

// Typedefs for all required NT functions
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *NtOpenProcess_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS (NTAPI *NtClose_t)(HANDLE);
typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtQueueApcThread_t)(HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS (NTAPI *NtSuspendThread_t)(HANDLE, PULONG);
typedef NTSTATUS (NTAPI *NtResumeThread_t)(HANDLE, PULONG);

// Global syscall table
struct SyscallTable {
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory;
    NtWriteVirtualMemory_t NtWriteVirtualMemory;
    NtProtectVirtualMemory_t NtProtectVirtualMemory;
    NtCreateThreadEx_t NtCreateThreadEx;
    NtOpenProcess_t NtOpenProcess;
    NtClose_t NtClose;
    NtQuerySystemInformation_t NtQuerySystemInformation;
    NtMapViewOfSection_t NtMapViewOfSection;
    NtQueueApcThread_t NtQueueApcThread;
    NtSuspendThread_t  NtSuspendThread;
    NtResumeThread_t   NtResumeThread;
};

extern SyscallTable g_Syscalls;

// Initialization: parse ntdll, extract SSNs, build stubs
BOOL InitializeSyscalls();

// Utility to get ntdll base
HMODULE GetNtDllBase();