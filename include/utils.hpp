#pragma once
#include <windows.h>
#include <string>
#include <vector>

// Convert between UTF-8 and UTF-16
std::string WStringToUTF8(const std::wstring& wstr);
std::wstring UTF8ToWString(const std::string& utf8);

// Base64 encode/decode
std::string Base64Encode(const BYTE* data, size_t len);
std::vector<BYTE> Base64Decode(const std::string& b64);

// Simple XOR cipher (in-place)
VOID XorBuffer(BYTE* data, size_t len, const BYTE* key, size_t keyLen);

// Get hostname hash (used as XOR key)
std::wstring GetHostnameHash();

// Get username
std::wstring GetUsername();

// Get OS build number
DWORD GetOSBuild();

// Check if process is elevated
BOOL IsElevated();

// Sleep with jitter
VOID JitterSleep(DWORD minSec, DWORD maxSec);