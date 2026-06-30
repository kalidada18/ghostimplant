#pragma once
#include <windows.h>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// String conversion
// ---------------------------------------------------------------------------

// UTF-16 (wstring) -> UTF-8 (string)
std::string WStringToUTF8(const std::wstring& wstr);

// UTF-8 (string) -> UTF-16 (wstring)
std::wstring UTF8ToWString(const std::string& utf8);

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

// Base64 encode raw bytes -> ASCII string
std::string Base64Encode(const BYTE* data, size_t len);

// Base64 decode ASCII string -> raw bytes
std::vector<BYTE> Base64Decode(const std::string& b64);

// ---------------------------------------------------------------------------
// Crypto
// ---------------------------------------------------------------------------

// In-place XOR cipher with repeating key
VOID XorBuffer(BYTE* data, size_t len, const BYTE* key, size_t keyLen);

// ---------------------------------------------------------------------------
// System info
// ---------------------------------------------------------------------------

// FNV-1a hash of the computer name, returned as 8-char hex wstring
std::wstring GetHostnameHash();

// Current username
std::wstring GetUsername();

// Computer name (raw, not hashed)
std::wstring GetHostname();

// OS build number via RtlGetVersion (immune to compatibility shims)
DWORD GetOSBuild();

// TRUE if the current process token has elevation
BOOL IsElevated();

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

// Sleep for a uniformly random duration in [minSec, maxSec]
VOID JitterSleep(DWORD minSec, DWORD maxSec);