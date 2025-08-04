#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <atomic>
#include <thread>
#include <utility> // For std::pair
#include <map>
#include <set> // For the new firewall logic
#include <memory> // For std::unique_ptr
#include <shlwapi.h>
#include <tlhelp32.h>
#include <shellapi.h> // For SHFileOperationW
#include <shlobj.h>   // For SHGetKnownFolderPath and KNOWNFOLDERID
#include <netfw.h>    // For Firewall COM API
#include <winreg.h>   // For Registry functions
#include <iomanip>    // For std::hex formatting

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "OleAut32.lib")

// --- Function pointer types for NTDLL functions ---
typedef LONG (NTAPI *pfnNtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG (NTAPI *pfnNtResumeProcess)(IN HANDLE ProcessHandle);
pfnNtSuspendProcess g_NtSuspendProcess = nullptr;
pfnNtResumeProcess g_NtResumeProcess = nullptr;

// --- FORWARD DECLARATIONS for helper functions ---
bool RunCommand(const std::wstring& command, bool showWindow);
void PerformFileSystemOperation(int func, const std::wstring& from, const std::wstring& to);
bool ParseRegistryPath(const std::wstring& fullPath, bool isKey, HKEY& hRootKey, std::wstring& rootKeyStr, std::wstring& subKey, std::wstring& valueName);
bool RenameRegistryKey(HKEY hRoot, const std::wstring& rootStr, const std::wstring& subKey, const std::wstring& newSubKey);
bool RenameRegistryValue(HKEY hRoot, const std::wstring& subKey, const std::wstring& valueName, const std::wstring& newValueName);
bool ExportRegistryKey(const std::wstring& fullKeyPath, const std::wstring& filePath);
bool ExportRegistryValue(HKEY hRoot, const std::wstring& rootStr, const std::wstring& subKey, const std::wstring& valueName, const std::wstring& filePath);
bool ImportRegistryFile(const std::wstring& filePath);
void CleanupFirewallRules(); // CORRECTED: Added forward declaration
class Operation; // Forward declare base class for ProcessAllSettings
void ProcessAllSettings(const std::wstring& iniContent, const std::map<std::wstring, std::wstring>& variables, std::vector<std::unique_ptr<Operation>>& operations);
void LaunchApplication(const std::wstring& iniContent);

// --- Polymorphic Base Class for all Operations ---
class Operation {
public:
    virtual ~Operation() = default;
    virtual void PerformStartup() = 0;
    virtual void PerformShutdown() = 0;
};

// --- Global lists for operations that need collective cleanup ---
std::vector<std::wstring> g_createdFirewallRuleNames;

// --- Operation Implementations ---

// Filesystem: Save/Restore Directory
class SaveRestoreDirOperation : public Operation {
private:
    std::wstring sourcePath;
    std::wstring destPath;
    std::wstring destBackupPath;
    bool destBackupCreated = false;

public:
    SaveRestoreDirOperation(std::wstring src, std::wstring dest)
        : sourcePath(std::move(src)), destPath(std::move(dest)) {
        destBackupPath = destPath + L"_Backup";
    }

    void PerformStartup() override {
        if (PathFileExistsW(destPath.c_str())) {
            if (MoveFileW(destPath.c_str(), destBackupPath.c_str())) {
                destBackupCreated = true;
            }
        }
        if (PathFileExistsW(sourcePath.c_str())) {
            PerformFileSystemOperation(FO_COPY, sourcePath, destPath);
        }
    }

    void PerformShutdown() override {
        if (PathFileExistsW(destPath.c_str())) {
            std::wstring sourceBackupPath = sourcePath + L"_Backup";
            if (PathFileExistsW(sourcePath.c_str())) {
                MoveFileW(sourcePath.c_str(), sourceBackupPath.c_str());
            }
            PerformFileSystemOperation(FO_COPY, destPath, sourcePath);
            if (PathFileExistsW(sourceBackupPath.c_str())) {
                PerformFileSystemOperation(FO_DELETE, sourceBackupPath);
            }
        }
        PerformFileSystemOperation(FO_DELETE, destPath);
        if (destBackupCreated && PathFileExistsW(destBackupPath.c_str())) {
            MoveFileW(destBackupPath.c_str(), destPath.c_str());
        }
    }
};

// Filesystem: Save/Restore File
class SaveRestoreFileOperation : public Operation {
private:
    std::wstring sourcePath;
    std::wstring destPath;
    std::wstring destBackupPath;
    bool destBackupCreated = false;

public:
    SaveRestoreFileOperation(std::wstring src, std::wstring dest)
        : sourcePath(std::move(src)), destPath(std::move(dest)) {
        destBackupPath = destPath + L"_Backup";
    }

    void PerformStartup() override {
        if (PathFileExistsW(destPath.c_str())) {
            if (MoveFileW(destPath.c_str(), destBackupPath.c_str())) {
                destBackupCreated = true;
            }
        }
        if (PathFileExistsW(sourcePath.c_str())) {
            CopyFileW(sourcePath.c_str(), destPath.c_str(), FALSE);
        }
    }

    void PerformShutdown() override {
        if (PathFileExistsW(destPath.c_str())) {
            std::wstring sourceBackupPath = sourcePath + L"_Backup";
            if (PathFileExistsW(sourcePath.c_str())) {
                MoveFileW(sourcePath.c_str(), sourceBackupPath.c_str());
            }
            CopyFileW(destPath.c_str(), sourcePath.c_str(), FALSE);
            if (PathFileExistsW(sourceBackupPath.c_str())) {
                DeleteFileW(sourceBackupPath.c_str());
            }
        }
        DeleteFileW(destPath.c_str());
        if (destBackupCreated && PathFileExistsW(destBackupPath.c_str())) {
            MoveFileW(destBackupPath.c_str(), destPath.c_str());
        }
    }
};

// Filesystem: Restore-Only Directory
class RestoreOnlyDirOperation : public Operation {
private:
    std::wstring targetPath;
    std::wstring backupPath;
    bool backupCreated = false;

public:
    RestoreOnlyDirOperation(std::wstring target) : targetPath(std::move(target)) {
        backupPath = targetPath + L"_Backup";
    }

    void PerformStartup() override {
        if (PathFileExistsW(targetPath.c_str())) {
            if (MoveFileW(targetPath.c_str(), backupPath.c_str())) {
                backupCreated = true;
            }
        }
    }

    void PerformShutdown() override {
        if (PathFileExistsW(targetPath.c_str())) {
            PerformFileSystemOperation(FO_DELETE, targetPath);
        }
        if (backupCreated && PathFileExistsW(backupPath.c_str())) {
            MoveFileW(backupPath.c_str(), targetPath.c_str());
        }
    }
};

// Filesystem: Restore-Only File
class RestoreOnlyFileOperation : public Operation {
private:
    std::wstring targetPath;
    std::wstring backupPath;
    bool backupCreated = false;

public:
    RestoreOnlyFileOperation(std::wstring target) : targetPath(std::move(target)) {
        backupPath = targetPath + L"_Backup";
    }

    void PerformStartup() override {
        if (PathFileExistsW(targetPath.c_str())) {
            if (MoveFileW(targetPath.c_str(), backupPath.c_str())) {
                backupCreated = true;
            }
        }
    }

    void PerformShutdown() override {
        if (PathFileExistsW(targetPath.c_str())) {
            DeleteFileW(targetPath.c_str());
        }
        if (backupCreated && PathFileExistsW(backupPath.c_str())) {
            MoveFileW(backupPath.c_str(), targetPath.c_str());
        }
    }
};

// Registry: Base class for common registry data
class RegistryOperation : public Operation {
public:
    HKEY hRootKey;
    std::wstring rootKeyStr;
    std::wstring subKey;
    std::wstring valueName;
    std::wstring backupName;
    bool backupCreated = false;
};

// Registry: Save/Restore Key
class SaveRestoreRegKeyOperation : public RegistryOperation {
private:
    std::wstring filePath;
public:
    SaveRestoreRegKeyOperation(HKEY hR, std::wstring rStr, std::wstring sKey, std::wstring fPath) {
        hRootKey = hR;
        rootKeyStr = std::move(rStr);
        subKey = std::move(sKey);
        filePath = std::move(fPath);
        backupName = subKey + L"_Backup";
    }

    void PerformStartup() override {
        if (RenameRegistryKey(hRootKey, rootKeyStr, subKey, backupName)) {
            backupCreated = true;
        }
        ImportRegistryFile(filePath);
    }

    void PerformShutdown() override {
        ExportRegistryKey(rootKeyStr + L"\\" + subKey, filePath);
        SHDeleteKeyW(hRootKey, subKey.c_str());
        if (backupCreated) {
            RenameRegistryKey(hRootKey, rootKeyStr, backupName, subKey);
        }
    }
};

// Registry: Save/Restore Value
class SaveRestoreRegValueOperation : public RegistryOperation {
private:
    std::wstring filePath;
public:
    SaveRestoreRegValueOperation(HKEY hR, std::wstring rStr, std::wstring sKey, std::wstring vName, std::wstring fPath) {
        hRootKey = hR;
        rootKeyStr = std::move(rStr);
        subKey = std::move(sKey);
        valueName = std::move(vName);
        filePath = std::move(fPath);
        backupName = valueName + L"_Backup";
    }

    void PerformStartup() override {
        if (RenameRegistryValue(hRootKey, subKey, valueName, backupName)) {
            backupCreated = true;
        }
        ImportRegistryFile(filePath);
    }

    void PerformShutdown() override {
        ExportRegistryValue(hRootKey, rootKeyStr, subKey, valueName, filePath);
        HKEY hKey;
        if (RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            RegDeleteValueW(hKey, valueName.c_str());
            RegCloseKey(hKey);
        }
        if (backupCreated) {
            RenameRegistryValue(hRootKey, subKey, backupName, valueName);
        }
    }
};

// Registry: Restore-Only Key
class RestoreOnlyRegKeyOperation : public RegistryOperation {
public:
    RestoreOnlyRegKeyOperation(HKEY hR, std::wstring rStr, std::wstring sKey) {
        hRootKey = hR;
        rootKeyStr = std::move(rStr);
        subKey = std::move(sKey);
        backupName = subKey + L"_Backup";
    }

    void PerformStartup() override {
        if (RenameRegistryKey(hRootKey, rootKeyStr, subKey, backupName)) {
            backupCreated = true;
        }
    }

    void PerformShutdown() override {
        SHDeleteKeyW(hRootKey, subKey.c_str());
        if (backupCreated) {
            RenameRegistryKey(hRootKey, rootKeyStr, backupName, subKey);
        }
    }
};

// Registry: Restore-Only Value
class RestoreOnlyRegValueOperation : public RegistryOperation {
public:
    RestoreOnlyRegValueOperation(HKEY hR, std::wstring rStr, std::wstring sKey, std::wstring vName) {
        hRootKey = hR;
        rootKeyStr = std::move(rStr);
        subKey = std::move(sKey);
        valueName = std::move(vName);
        backupName = valueName + L"_Backup";
    }

    void PerformStartup() override {
        if (RenameRegistryValue(hRootKey, subKey, valueName, backupName)) {
            backupCreated = true;
        }
    }

    void PerformShutdown() override {
        HKEY hKey;
        if (RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            RegDeleteValueW(hKey, valueName.c_str());
            RegCloseKey(hKey);
        }
        if (backupCreated) {
            RenameRegistryValue(hRootKey, subKey, backupName, valueName);
        }
    }
};

// Firewall Operation
class FirewallOperation : public Operation {
private:
    std::wstring ruleName, appPath, direction, action;
public:
    FirewallOperation(std::wstring rn, std::wstring ap, std::wstring dir, std::wstring act)
        : ruleName(std::move(rn)), appPath(std::move(ap)), direction(std::move(dir)), action(std::move(act)) {}

    void PerformStartup() override {
        INetFwPolicy2* pFwPolicy = NULL;
        INetFwRules* pFwRules = NULL;
        INetFwRule* pFwRule = NULL;

        HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pFwPolicy);
        if (FAILED(hr)) return;
        hr = pFwPolicy->get_Rules(&pFwRules);
        if (FAILED(hr)) { pFwPolicy->Release(); return; }
        hr = CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), (void**)&pFwRule);
        if (FAILED(hr)) { pFwRules->Release(); pFwPolicy->Release(); return; }

        BSTR bstrRuleName = SysAllocString(ruleName.c_str());
        BSTR bstrAppPath = SysAllocString(appPath.c_str());
        pFwRule->put_Name(bstrRuleName);
        pFwRule->put_ApplicationName(bstrAppPath);
        if (_wcsicmp(direction.c_str(), L"in") == 0) pFwRule->put_Direction(NET_FW_RULE_DIR_IN);
        else if (_wcsicmp(direction.c_str(), L"out") == 0) pFwRule->put_Direction(NET_FW_RULE_DIR_OUT);
        if (_wcsicmp(action.c_str(), L"allow") == 0) pFwRule->put_Action(NET_FW_ACTION_ALLOW);
        else if (_wcsicmp(action.c_str(), L"block") == 0) pFwRule->put_Action(NET_FW_ACTION_BLOCK);
        pFwRule->put_Enabled(VARIANT_TRUE);
        pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
        pFwRule->put_Profiles(NET_FW_PROFILE2_ALL);

        hr = pFwRules->Add(pFwRule);
        if (SUCCEEDED(hr)) {
            g_createdFirewallRuleNames.push_back(ruleName);
        }

        SysFreeString(bstrRuleName);
        SysFreeString(bstrAppPath);
        if (pFwRule) pFwRule->Release();
        if (pFwRules) pFwRules->Release();
        if (pFwPolicy) pFwPolicy->Release();
    }

    void PerformShutdown() override {
        // Shutdown is handled collectively by CleanupFirewallRules
    }
};

// --- Privilege Elevation Functions ---
bool EnablePrivilege(LPCWSTR privilegeName) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        CloseHandle(hToken);
        return false;
    }
    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}

void EnableAllPrivileges() {
    const LPCWSTR privileges[] = {
        L"SeDebugPrivilege", L"SeTakeOwnershipPrivilege", L"SeBackupPrivilege", L"SeRestorePrivilege",
        L"SeLoadDriverPrivilege", L"SeSystemEnvironmentPrivilege", L"SeSecurityPrivilege",
        L"SeIncreaseQuotaPrivilege", L"SeChangeNotifyPrivilege", L"SeSystemProfilePrivilege",
        L"SeSystemtimePrivilege", L"SeProfileSingleProcessPrivilege", L"SeIncreaseBasePriorityPrivilege",
        L"SeCreatePagefilePrivilege", L"SeShutdownPrivilege", L"SeRemoteShutdownPrivilege",
        L"SeUndockPrivilege", L"SeManageVolumePrivilege", L"SeIncreaseWorkingSetPrivilege",
        L"SeTimeZonePrivilege", L"SeCreateSymbolicLinkPrivilege", L"SeDelegateSessionUserImpersonatePrivilege"
    };
    for (const auto& priv : privileges) {
        EnablePrivilege(priv);
    }
}

// --- Path and INI Parsing Utilities ---
std::wstring trim(const std::wstring& s) {
    const std::wstring WHITESPACE = L" \t\n\r\f\v";
    size_t first = s.find_first_not_of(WHITESPACE);
    if (std::wstring::npos == first) return L"";
    size_t last = s.find_last_not_of(WHITESPACE);
    return s.substr(first, (last - first + 1));
}

std::wstring GetKnownFolderPath(const KNOWNFOLDERID& rfid) {
    PWSTR pszPath = nullptr;
    HRESULT hr = SHGetKnownFolderPath(rfid, 0, NULL, &pszPath);
    if (SUCCEEDED(hr)) {
        std::wstring path = pszPath;
        CoTaskMemFree(pszPath);
        return path;
    }
    return L"";
}

std::wstring ResolveToAbsolutePath(const std::wstring& path) {
    if (path.empty()) return L"";
    wchar_t absolutePath[MAX_PATH];
    if (GetFullPathNameW(path.c_str(), MAX_PATH, absolutePath, NULL) == 0) {
        return path;
    }
    return absolutePath;
}

std::wstring ExpandVariables(std::wstring path, const std::map<std::wstring, std::wstring>& variables) {
    int safety_counter = 0;
    while (path.find(L'{') != std::wstring::npos && safety_counter < 100) {
        size_t start_pos = path.find(L'{');
        size_t end_pos = path.find(L'}', start_pos);
        if (end_pos == std::wstring::npos) break;
        std::wstring varName = path.substr(start_pos + 1, end_pos - start_pos - 1);
        auto it = variables.find(varName);
        if (it != variables.end()) {
            path.replace(start_pos, end_pos - start_pos + 1, it->second);
        } else {
            path.replace(start_pos, end_pos - start_pos + 1, L"");
        }
        safety_counter++;
    }
    DWORD requiredSize = ExpandEnvironmentStringsW(path.c_str(), NULL, 0);
    if (requiredSize > 0) {
        std::vector<wchar_t> buffer(requiredSize);
        if (ExpandEnvironmentStringsW(path.c_str(), buffer.data(), requiredSize) > 0) {
            path = std::wstring(buffer.data());
        }
    }
    return path;
}

std::wstring GetValueFromIniContent(const std::wstring& content, const std::wstring& section, const std::wstring& key) {
    std::wstringstream stream(content);
    std::wstring line;
    std::wstring currentSection;
    std::wstring searchKey = trim(key);
    std::wstring searchSection = L"[" + trim(section) + L"]";
    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty() || line[0] == L';' || line[0] == L'#') continue;
        if (line[0] == L'[' && line.back() == L']') {
            currentSection = line;
            continue;
        }
        if (_wcsicmp(currentSection.c_str(), searchSection.c_str()) == 0) {
            size_t delimiterPos = line.find(L'=');
            if (delimiterPos != std::wstring::npos) {
                std::wstring currentKey = trim(line.substr(0, delimiterPos));
                if (_wcsicmp(currentKey.c_str(), searchKey.c_str()) == 0) {
                    return trim(line.substr(delimiterPos + 1));
                }
            }
        }
    }
    return L"";
}

// --- Helper Function Definitions ---
bool RunCommand(const std::wstring& command, bool showWindow) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = showWindow ? SW_SHOW : SW_HIDE;
    std::vector<wchar_t> cmdBuffer(command.begin(), command.end());
    cmdBuffer.push_back(0);
    if (!CreateProcessW(NULL, cmdBuffer.data(), NULL, NULL, FALSE, showWindow ? 0 : CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return exitCode == 0;
}

void PerformFileSystemOperation(int func, const std::wstring& from, const std::wstring& to) {
    wchar_t fromPath[MAX_PATH * 2] = {0};
    wcscpy_s(fromPath, from.c_str());
    fromPath[from.length() + 1] = L'\0';
    wchar_t toPath[MAX_PATH * 2] = {0};
    if (!to.empty()) {
        wcscpy_s(toPath, to.c_str());
        toPath[to.length() + 1] = L'\0';
    }
    SHFILEOPSTRUCTW sfos = {0};
    sfos.wFunc = func;
    sfos.pFrom = fromPath;
    sfos.pTo = to.empty() ? NULL : toPath;
    sfos.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    if (func == FO_COPY) {
        sfos.fFlags |= FOF_NOCONFIRMMKDIR;
    }
    SHFileOperationW(&sfos);
}

bool ParseRegistryPath(const std::wstring& fullPath, bool isKey, HKEY& hRootKey, std::wstring& rootKeyStr, std::wstring& subKey, std::wstring& valueName) {
    size_t firstSlash = fullPath.find(L'\\');
    if (firstSlash == std::wstring::npos) return false;
    std::wstring rootStrRaw = fullPath.substr(0, firstSlash);
    std::wstring restOfPath = fullPath.substr(firstSlash + 1);
    if (_wcsicmp(rootStrRaw.c_str(), L"HKCU") == 0) { hRootKey = HKEY_CURRENT_USER; rootKeyStr = L"HKEY_CURRENT_USER"; }
    else if (_wcsicmp(rootStrRaw.c_str(), L"HKLM") == 0) { hRootKey = HKEY_LOCAL_MACHINE; rootKeyStr = L"HKEY_LOCAL_MACHINE"; }
    else if (_wcsicmp(rootStrRaw.c_str(), L"HKCR") == 0) { hRootKey = HKEY_CLASSES_ROOT; rootKeyStr = L"HKEY_CLASSES_ROOT"; }
    else if (_wcsicmp(rootStrRaw.c_str(), L"HKU") == 0) { hRootKey = HKEY_USERS; rootKeyStr = L"HKEY_USERS"; }
    else return false;
    if (isKey) {
        subKey = restOfPath;
        valueName = L"";
    } else {
        size_t lastSlash = restOfPath.find_last_of(L'\\');
        if (lastSlash == std::wstring::npos) return false;
        subKey = restOfPath.substr(0, lastSlash);
        valueName = restOfPath.substr(lastSlash + 1);
    }
    return true;
}

bool RenameRegistryKey(HKEY hRoot, const std::wstring& rootStr, const std::wstring& subKey, const std::wstring& newSubKey) {
    std::wstring fullSourcePath = rootStr + L"\\" + subKey;
    std::wstring fullDestPath = rootStr + L"\\" + newSubKey;
    HKEY hKey;
    if (RegOpenKeyExW(hRoot, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) return false;
    RegCloseKey(hKey);
    if (!RunCommand(L"reg copy \"" + fullSourcePath + L"\" \"" + fullDestPath + L"\" /s /f")) return false;
    return SHDeleteKeyW(hRoot, subKey.c_str()) == ERROR_SUCCESS;
}

bool RenameRegistryValue(HKEY hRoot, const std::wstring& subKey, const std::wstring& valueName, const std::wstring& newValueName) {
    HKEY hKey;
    if (RegOpenKeyExW(hRoot, subKey.c_str(), 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) return false;
    DWORD type, size = 0;
    if (RegQueryValueExW(hKey, valueName.c_str(), NULL, &type, NULL, &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey); return false;
    }
    std::vector<BYTE> data(size);
    if (RegQueryValueExW(hKey, valueName.c_str(), NULL, &type, data.data(), &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey); return false;
    }
    if (RegSetValueExW(hKey, newValueName.c_str(), 0, type, data.data(), size) != ERROR_SUCCESS) {
        RegCloseKey(hKey); return false;
    }
    RegDeleteValueW(hKey, valueName.c_str());
    RegCloseKey(hKey);
    return true;
}

bool ExportRegistryKey(const std::wstring& fullKeyPath, const std::wstring& filePath) {
    return RunCommand(L"reg export \"" + fullKeyPath + L"\" \"" + filePath + L"\" /y");
}

bool ExportRegistryValue(HKEY hRoot, const std::wstring& rootStr, const std::wstring& subKey, const std::wstring& valueName, const std::wstring& filePath) {
    HKEY hKey;
    if (RegOpenKeyExW(hRoot, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) return false;
    DWORD type, size = 0;
    if (RegQueryValueExW(hKey, valueName.c_str(), NULL, &type, NULL, &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey); return false;
    }
    std::vector<BYTE> data(size);
    if (RegQueryValueExW(hKey, valueName.c_str(), NULL, &type, data.data(), &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey); return false;
    }
    RegCloseKey(hKey);

    std::ofstream regFile(filePath, std::ios::binary | std::ios::trunc);
    if (!regFile.is_open()) return false;
    auto write_wstring = [&](const std::wstring& s) {
        regFile.write(reinterpret_cast<const char*>(s.c_str()), s.length() * sizeof(wchar_t));
    };
    regFile.put((char)0xFF); regFile.put((char)0xFE);
    write_wstring(L"Windows Registry Editor Version 5.00\r\n\r\n");
    write_wstring(L"[" + rootStr + L"\\" + subKey + L"]\r\n");
    std::wstring displayName = valueName.empty() ? L"@" : L"\"" + valueName + L"\"";
    write_wstring(displayName + L"=");
    std::wstringstream wss;
    if (type == REG_SZ) {
        std::wstring strValue(reinterpret_cast<const wchar_t*>(data.data()));
        std::wstring escapedStr;
        for (wchar_t c : strValue) {
            if (c == L'\\') escapedStr += L"\\\\"; else if (c == L'"') escapedStr += L"\\\""; else escapedStr += c;
        }
        wss << L"\"" << escapedStr << L"\"";
    } else if (type == REG_DWORD) {
        DWORD dwordValue = *reinterpret_cast<DWORD*>(data.data());
        wss << L"dword:" << std::hex << std::setw(8) << std::setfill(L'0') << dwordValue;
    } else if (type == REG_QWORD) {
        ULONGLONG qwordValue = *reinterpret_cast<ULONGLONG*>(data.data());
        const BYTE* qwordBytes = reinterpret_cast<const BYTE*>(&qwordValue);
        wss << L"hex(b):";
        for (int i = 0; i < 8; ++i) {
            wss << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(qwordBytes[i]);
            if (i < 7) wss << L",";
        }
    } else {
        wss << L"hex";
        if (type == REG_EXPAND_SZ) wss << L"(2)";
        else if (type == REG_MULTI_SZ) wss << L"(7)";
        else if (type != REG_BINARY) wss << L"(" << type << L")";
        wss << L":";
        for (DWORD i = 0; i < size; ++i) {
            wss << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(data[i]);
            if (i < size - 1) {
                wss << L",";
                if ((i + 1) % 38 == 0) wss << L"\\\r\n  ";
            }
        }
    }
    write_wstring(wss.str());
    write_wstring(L"\r\n");
    regFile.close();
    return true;
}

bool ImportRegistryFile(const std::wstring& filePath) {
    if (!PathFileExistsW(filePath.c_str())) return true;
    return RunCommand(L"reg import \"" + filePath + L"\"", false);
}

void CleanupFirewallRules() {
    if (g_createdFirewallRuleNames.empty()) return;
    INetFwPolicy2* pFwPolicy = NULL;
    INetFwRules* pFwRules = NULL;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pFwPolicy);
    if (FAILED(hr)) return;
    hr = pFwPolicy->get_Rules(&pFwRules);
    if (FAILED(hr)) { pFwPolicy->Release(); return; }
    for (const auto& ruleName : g_createdFirewallRuleNames) {
        BSTR bstrRuleName = SysAllocString(ruleName.c_str());
        if (bstrRuleName) {
            pFwRules->Remove(bstrRuleName);
            SysFreeString(bstrRuleName);
        }
    }
    if (pFwRules) pFwRules->Release();
    if (pFwPolicy) pFwPolicy->Release();
}

// --- Master Parser ---
void ProcessAllSettings(const std::wstring& iniContent, const std::map<std::wstring, std::wstring>& variables, std::vector<std::unique_ptr<Operation>>& operations) {
    std::wstringstream stream(iniContent);
    std::wstring line;
    std::wstring currentSection;
    std::wstring searchSection = L"[Settings]";

    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty() || line[0] == L';' || line[0] == L'#') continue;
        if (line[0] == L'[' && line.back() == L']') {
            currentSection = line;
            continue;
        }

        if (_wcsicmp(currentSection.c_str(), searchSection.c_str()) == 0) {
            size_t delimiterPos = line.find(L'=');
            if (delimiterPos == std::wstring::npos) continue;

            std::wstring key = trim(line.substr(0, delimiterPos));
            std::wstring value = trim(line.substr(delimiterPos + 1));

            if (_wcsicmp(key.c_str(), L"dir") == 0) {
                size_t sep = value.find(L" :: ");
                if (sep != std::wstring::npos) {
                    std::wstring dest = ResolveToAbsolutePath(ExpandVariables(trim(value.substr(0, sep)), variables));
                    std::wstring src = ResolveToAbsolutePath(ExpandVariables(trim(value.substr(sep + 4)), variables));
                    operations.push_back(std::make_unique<SaveRestoreDirOperation>(src, dest));
                }
            } else if (_wcsicmp(key.c_str(), L"file") == 0) {
                size_t sep = value.find(L" :: ");
                if (sep != std::wstring::npos) {
                    std::wstring dest = ResolveToAbsolutePath(ExpandVariables(trim(value.substr(0, sep)), variables));
                    std::wstring srcRaw = trim(value.substr(sep + 4));
                    std::wstring src = ResolveToAbsolutePath(ExpandVariables(srcRaw, variables));
                    if (srcRaw.back() == L'\\') {
                        src = src + PathFindFileNameW(dest.c_str());
                    }
                    operations.push_back(std::make_unique<SaveRestoreFileOperation>(src, dest));
                }
            } else if (_wcsicmp(key.c_str(), L"(dir)") == 0) {
                operations.push_back(std::make_unique<RestoreOnlyDirOperation>(ResolveToAbsolutePath(ExpandVariables(value, variables))));
            } else if (_wcsicmp(key.c_str(), L"(file)") == 0) {
                operations.push_back(std::make_unique<RestoreOnlyFileOperation>(ResolveToAbsolutePath(ExpandVariables(value, variables))));
            }
            else if (_wcsicmp(key.c_str(), L"regkey") == 0 || _wcsicmp(key.c_str(), L"regvalue") == 0 || _wcsicmp(key.c_str(), L"(regkey)") == 0 || _wcsicmp(key.c_str(), L"(regvalue)") == 0) {
                bool isSaveRestore = (key.front() != L'(');
                bool isKey = (key.find(L"key") != std::wstring::npos);
                
                std::wstring regPathRaw, filePath;
                if (isSaveRestore) {
                    size_t sep = value.find(L" :: ");
                    if (sep == std::wstring::npos) continue;
                    regPathRaw = trim(value.substr(0, sep));
                    filePath = ResolveToAbsolutePath(ExpandVariables(trim(value.substr(sep + 4)), variables));
                } else {
                    regPathRaw = value;
                }

                HKEY hRoot; std::wstring rootStr, subKey, valName;
                if (!ParseRegistryPath(regPathRaw, isKey, hRoot, rootStr, subKey, valName)) continue;

                if (isSaveRestore) {
                    if (isKey) operations.push_back(std::make_unique<SaveRestoreRegKeyOperation>(hRoot, rootStr, subKey, filePath));
                    else operations.push_back(std::make_unique<SaveRestoreRegValueOperation>(hRoot, rootStr, subKey, valName, filePath));
                } else {
                    if (isKey) operations.push_back(std::make_unique<RestoreOnlyRegKeyOperation>(hRoot, rootStr, subKey));
                    else operations.push_back(std::make_unique<RestoreOnlyRegValueOperation>(hRoot, rootStr, subKey, valName));
                }
            }
            else if (_wcsicmp(key.c_str(), L"firewall") == 0) {
                std::vector<std::wstring> parts;
                std::wstring temp_value = value;
                size_t pos = 0;
                while ((pos = temp_value.find(L" :: ")) != std::wstring::npos) {
                    parts.push_back(trim(temp_value.substr(0, pos)));
                    temp_value.erase(0, pos + 4);
                }
                parts.push_back(trim(temp_value));

                if (parts.size() == 4) {
                    std::wstring appPath = ResolveToAbsolutePath(ExpandVariables(parts[3], variables));
                    operations.push_back(std::make_unique<FirewallOperation>(parts[0], appPath, parts[1], parts[2]));
                }
            }
        }
    }
}

// --- Main Application Logic ---
void LaunchApplication(const std::wstring& iniContent) {
    std::map<std::wstring, std::wstring> variables;
    wchar_t launcherFullPath[MAX_PATH];
    GetModuleFileNameW(NULL, launcherFullPath, MAX_PATH);
    variables[L"Local"] = GetKnownFolderPath(FOLDERID_LocalAppData);
    variables[L"LocalLow"] = GetKnownFolderPath(FOLDERID_LocalAppDataLow);
    variables[L"Roaming"] = GetKnownFolderPath(FOLDERID_RoamingAppData);
    variables[L"Documents"] = GetKnownFolderPath(FOLDERID_Documents);
    variables[L"ProgramData"] = GetKnownFolderPath(FOLDERID_ProgramData);
    variables[L"SavedGames"] = GetKnownFolderPath(FOLDERID_SavedGames);
    variables[L"PublicDocuments"] = GetKnownFolderPath(FOLDERID_PublicDocuments);
    wchar_t drive[_MAX_DRIVE];
    _wsplitpath_s(launcherFullPath, drive, _MAX_DRIVE, NULL, 0, NULL, 0, NULL, 0);
    variables[L"DRIVE"] = drive;
    wchar_t launcherDir[MAX_PATH];
    wcscpy_s(launcherDir, launcherFullPath);
    PathRemoveFileSpecW(launcherDir);
    variables[L"YAPROOT"] = launcherDir;
    std::wstring appPathRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"Settings", L"application"), variables);
    if (appPathRaw.empty()) return;
    wchar_t absoluteAppPath[MAX_PATH];
    GetFullPathNameW(appPathRaw.c_str(), MAX_PATH, absoluteAppPath, NULL);
    std::wstring workDirRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"Settings", L"workdir"), variables);
    std::wstring finalWorkDir;
    wchar_t appDir[MAX_PATH];
    wcscpy_s(appDir, absoluteAppPath);
    PathRemoveFileSpecW(appDir);
    if (!workDirRaw.empty()) {
        wchar_t absoluteWorkDir[MAX_PATH];
        GetFullPathNameW(workDirRaw.c_str(), MAX_PATH, absoluteWorkDir, NULL);
        if (PathFileExistsW(absoluteWorkDir)) finalWorkDir = absoluteWorkDir;
        else finalWorkDir = appDir;
    } else {
        finalWorkDir = appDir;
    }
    std::wstring commandLine = ExpandVariables(GetValueFromIniContent(iniContent, L"Settings", L"commandline"), variables);
    std::wstring fullCommandLine = L"\"" + std::wstring(absoluteAppPath) + L"\" " + commandLine;
    wchar_t commandLineBuffer[4096];
    wcscpy_s(commandLineBuffer, fullCommandLine.c_str());
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (CreateProcessW(NULL, commandLineBuffer, NULL, NULL, FALSE, 0, NULL, finalWorkDir.c_str(), &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    EnableAllPrivileges();

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        g_NtSuspendProcess = (pfnNtSuspendProcess)GetProcAddress(hNtdll, "NtSuspendProcess");
        g_NtResumeProcess = (pfnNtResumeProcess)GetProcAddress(hNtdll, "NtResumeProcess");
    }

    wchar_t launcherFullPath[MAX_PATH];
    GetModuleFileNameW(NULL, launcherFullPath, MAX_PATH);
    std::wstring iniPath = launcherFullPath;
    size_t pos = iniPath.find_last_of(L".");
    if (pos != std::wstring::npos) iniPath.replace(pos, std::wstring::npos, L".ini");
    std::wstring iniContent;
    std::wifstream iniFile(iniPath);
    if (iniFile) {
        std::wstringstream wss;
        wss << iniFile.rdbuf();
        iniContent = wss.str();
    }

    std::map<std::wstring, std::wstring> variables;
    variables[L"Local"] = GetKnownFolderPath(FOLDERID_LocalAppData);
    variables[L"LocalLow"] = GetKnownFolderPath(FOLDERID_LocalAppDataLow);
    variables[L"Roaming"] = GetKnownFolderPath(FOLDERID_RoamingAppData);
    variables[L"Documents"] = GetKnownFolderPath(FOLDERID_Documents);
    variables[L"ProgramData"] = GetKnownFolderPath(FOLDERID_ProgramData);
    variables[L"SavedGames"] = GetKnownFolderPath(FOLDERID_SavedGames);
    variables[L"PublicDocuments"] = GetKnownFolderPath(FOLDERID_PublicDocuments);
    wchar_t drive[_MAX_DRIVE];
    _wsplitpath_s(launcherFullPath, drive, _MAX_DRIVE, NULL, 0, NULL, 0, NULL, 0);
    variables[L"DRIVE"] = drive;
    wchar_t launcherDir[MAX_PATH];
    wcscpy_s(launcherDir, launcherFullPath);
    PathRemoveFileSpecW(launcherDir);
    variables[L"YAPROOT"] = launcherDir;
    std::wstring appPathRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"Settings", L"application"), variables);
    wchar_t absoluteAppPath[MAX_PATH];
    GetFullPathNameW(appPathRaw.c_str(), MAX_PATH, absoluteAppPath, NULL);
    variables[L"APPEXE"] = absoluteAppPath;
    wchar_t appDir[MAX_PATH];
    wcscpy_s(appDir, absoluteAppPath);
    PathRemoveFileSpecW(appDir);
    variables[L"EXEPATH"] = appDir;
    std::wstring workDirRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"Settings", L"workdir"), variables);
    std::wstring finalWorkDir;
    if (!workDirRaw.empty()) {
        wchar_t absoluteWorkDir[MAX_PATH];
        GetFullPathNameW(workDirRaw.c_str(), MAX_PATH, absoluteWorkDir, NULL);
        if (PathFileExistsW(absoluteWorkDir)) finalWorkDir = absoluteWorkDir;
        else finalWorkDir = appDir;
    } else {
        finalWorkDir = appDir;
    }
    variables[L"WORKDIR"] = finalWorkDir;

    wchar_t launcherBaseName[MAX_PATH];
    wcscpy_s(launcherBaseName, PathFindFileNameW(launcherFullPath));
    PathRemoveExtensionW(launcherBaseName);
    wchar_t appBaseName[MAX_PATH] = L"";
    if (!appPathRaw.empty()) {
        wcscpy_s(appBaseName, PathFindFileNameW(appPathRaw.c_str()));
        PathRemoveExtensionW(appBaseName);
    }
    std::wstring mutexName = L"Global\\" + std::wstring(launcherBaseName) + L"_" + std::wstring(appBaseName);

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = FALSE;
    HANDLE hMutex = CreateMutexW(&sa, TRUE, mutexName.c_str());
    bool isFirstInstance = (GetLastError() != ERROR_ALREADY_EXISTS);

    if (isFirstInstance) {
        CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        if (appPathRaw.empty()) {
            MessageBoxW(NULL, L"INI配置文件中未找到或未设置 'application' 路径。", L"配置错误", MB_ICONERROR);
            CloseHandle(hMutex);
            CoUninitialize();
            return 1;
        }
        
        std::vector<std::unique_ptr<Operation>> operations;
        ProcessAllSettings(iniContent, variables, operations);

        for (const auto& op : operations) {
            op->PerformStartup();
        }

        STARTUPINFOW si; PROCESS_INFORMATION pi; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si); ZeroMemory(&pi, sizeof(pi));
        std::wstring commandLine = ExpandVariables(GetValueFromIniContent(iniContent, L"Settings", L"commandline"), variables);
        std::wstring fullCommandLine = L"\"" + std::wstring(absoluteAppPath) + L"\" " + commandLine;
        wchar_t commandLineBuffer[4096]; wcscpy_s(commandLineBuffer, fullCommandLine.c_str());
        
        if (!CreateProcessW(NULL, commandLineBuffer, NULL, NULL, FALSE, 0, NULL, finalWorkDir.c_str(), &si, &pi)) {
            MessageBoxW(NULL, (L"启动程序失败: \n" + std::wstring(absoluteAppPath)).c_str(), L"启动错误", MB_ICONERROR);
        } else {
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        for (auto it = operations.rbegin(); it != operations.rend(); ++it) {
            (*it)->PerformShutdown();
        }
        CleanupFirewallRules();
        
        CloseHandle(hMutex);
        CoUninitialize();
    } else {
        CloseHandle(hMutex);
        if (GetValueFromIniContent(iniContent, L"Settings", L"multiple") == L"1") {
            LaunchApplication(iniContent);
        }
    }
    return 0;
}