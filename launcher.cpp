#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <atomic>
#include <thread>
#include <utility>
#include <map>
#include <set>
#include <variant> // For the unified operation structure
#include <shlwapi.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <shlobj.h>
#include <netfw.h>
#include <winreg.h>
#include <iomanip>

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

// --- Unified Operation Data Structures ---

struct FileOp {
    std::wstring sourcePath;
    std::wstring destPath;
    std::wstring destBackupPath;
    bool isDirectory;
    bool destBackupCreated = false;
};

struct RestoreOnlyFileOp {
    std::wstring targetPath;
    std::wstring backupPath;
    bool isDirectory;
    bool backupCreated = false;
};

struct RegistryOp {
    bool isSaveRestore;
    bool isKey;
    HKEY hRootKey;
    std::wstring rootKeyStr;
    std::wstring subKey;
    std::wstring valueName;
    std::wstring backupName;
    std::wstring filePath;
    bool backupCreated = false;
};

struct LinkOp {
    std::wstring linkPath;
    std::wstring targetPath;
    std::wstring backupPath;
    bool isDirectory;
    bool isHardlink;
    bool backupCreated = false;
    std::vector<std::pair<std::wstring, std::wstring>> createdLinks; // path, backup_path
};

struct FirewallOp {
    std::wstring ruleName;
    std::wstring appPath;
    NET_FW_RULE_DIRECTION direction;
    NET_FW_ACTION action;
    bool ruleCreated = false;
};

using OperationData = std::variant<FileOp, RestoreOnlyFileOp, RegistryOp, LinkOp, FirewallOp>;

struct Operation {
    OperationData data;
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

// --- File System & Command Helpers ---
bool RunCommand(const std::wstring& command, bool showWindow = false) {
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

void PerformFileSystemOperation(int func, const std::wstring& from, const std::wstring& to = L"") {
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

// --- Registry Helpers ---
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

bool RenameRegistryKey(const std::wstring& rootKeyStr, HKEY hRootKey, const std::wstring& subKey, const std::wstring& newSubKey) {
    std::wstring fullSourcePath = rootKeyStr + L"\\" + subKey;
    std::wstring fullDestPath = rootKeyStr + L"\\" + newSubKey;
    
    HKEY hKey;
    if (RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    RegCloseKey(hKey);

    if (!RunCommand(L"reg copy \"" + fullSourcePath + L"\" \"" + fullDestPath + L"\" /s /f")) {
        return false;
    }
    return SHDeleteKeyW(hRootKey, subKey.c_str()) == ERROR_SUCCESS;
}

bool RenameRegistryValue(HKEY hRootKey, const std::wstring& subKey, const std::wstring& valueName, const std::wstring& newValueName) {
    HKEY hKey;
    if (RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) return false;

    DWORD type, size = 0;
    if (RegQueryValueExW(hKey, valueName.c_str(), NULL, &type, NULL, &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }

    std::vector<BYTE> data(size);
    if (RegQueryValueExW(hKey, valueName.c_str(), NULL, &type, data.data(), &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }

    if (RegSetValueExW(hKey, newValueName.c_str(), 0, type, data.data(), size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }

    RegDeleteValueW(hKey, valueName.c_str());
    RegCloseKey(hKey);
    return true;
}

bool ExportRegistryKey(const std::wstring& rootKeyStr, const std::wstring& subKey, const std::wstring& filePath) {
    std::wstring fullKeyPath = rootKeyStr + L"\\" + subKey;
    return RunCommand(L"reg export \"" + fullKeyPath + L"\" \"" + filePath + L"\" /y");
}

bool ExportRegistryValue(HKEY hRootKey, const std::wstring& subKey, const std::wstring& valueName, const std::wstring& rootKeyStr, const std::wstring& filePath) {
    HKEY hKey;
    if (RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) return false;

    DWORD type, size = 0;
    if (RegQueryValueExW(hKey, valueName.c_str(), NULL, &type, NULL, &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }
    std::vector<BYTE> data(size);
    if (RegQueryValueExW(hKey, valueName.c_str(), NULL, &type, data.data(), &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }
    RegCloseKey(hKey);

    std::ofstream regFile(filePath, std::ios::binary | std::ios::trunc);
    if (!regFile.is_open()) return false;

    auto write_wstring = [&](const std::wstring& s) {
        regFile.write(reinterpret_cast<const char*>(s.c_str()), s.length() * sizeof(wchar_t));
    };

    regFile.put((char)0xFF);
    regFile.put((char)0xFE);

    write_wstring(L"Windows Registry Editor Version 5.00\r\n\r\n");
    write_wstring(L"[" + rootKeyStr + L"\\" + subKey + L"]\r\n");
    
    std::wstring displayName = valueName.empty() ? L"@" : L"\"" + valueName + L"\"";
    write_wstring(displayName + L"=");

    std::wstringstream wss;
    if (type == REG_SZ) {
        std::wstring strValue(reinterpret_cast<const wchar_t*>(data.data()));
        std::wstring escapedStr;
        for (wchar_t c : strValue) {
            if (c == L'\\') escapedStr += L"\\\\";
            else if (c == L'"') escapedStr += L"\\\"";
            else escapedStr += c;
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
                if ((i + 1) % 38 == 0) {
                    wss << L"\\\r\n  ";
                }
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
    return RunCommand(L"reg import \"" + filePath + L"\"");
}

// --- Process Management Functions ---
bool AreWaitProcessesRunning(const std::vector<std::wstring>& waitProcesses) {
    if (waitProcesses.empty()) return false;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            for (const auto& processName : waitProcesses) {
                if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return false;
}

std::wstring GetProcessNameByPid(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return L"";
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                CloseHandle(hSnapshot);
                return pe32.szExeFile;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return L"";
}

void SetAllProcessesState(const std::vector<std::wstring>& processList, bool suspend) {
    if (processList.empty() || !g_NtSuspendProcess || !g_NtResumeProcess) return;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            for (const auto& processName : processList) {
                if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        if (suspend) g_NtSuspendProcess(hProcess);
                        else g_NtResumeProcess(hProcess);
                        CloseHandle(hProcess);
                    }
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
}

// --- Background Thread Functions ---
struct MonitorThreadData {
    std::atomic<bool>* shouldStop;
    int checkInterval;
    std::wstring foregroundAppName;
    std::vector<std::wstring> suspendProcesses;
};

DWORD WINAPI ForegroundMonitorThread(LPVOID lpParam) {
    MonitorThreadData* data = static_cast<MonitorThreadData*>(lpParam);
    bool areProcessesSuspended = false;
    while (!*(data->shouldStop)) {
        HWND hForegroundWnd = GetForegroundWindow();
        if (hForegroundWnd) {
            DWORD foregroundPid = 0;
            GetWindowThreadProcessId(hForegroundWnd, &foregroundPid);
            std::wstring foregroundProcessName = GetProcessNameByPid(foregroundPid);
            if (_wcsicmp(foregroundProcessName.c_str(), data->foregroundAppName.c_str()) == 0) {
                if (!areProcessesSuspended) {
                    SetAllProcessesState(data->suspendProcesses, true);
                    areProcessesSuspended = true;
                }
            } else {
                if (areProcessesSuspended) {
                    SetAllProcessesState(data->suspendProcesses, false);
                    areProcessesSuspended = false;
                }
            }
        }
        Sleep(data->checkInterval * 1000);
    }
    return 0;
}

struct BackupThreadData {
    std::atomic<bool>* shouldStop;
    std::atomic<bool>* isWorking;
    int backupInterval;
    std::vector<std::pair<std::wstring, std::wstring>> backupDirs;
    std::vector<std::pair<std::wstring, std::wstring>> backupFiles;
};

void PerformDirectoryBackup(const std::wstring& dest, const std::wstring& src) {
    if (!PathFileExistsW(src.c_str())) return;
    std::wstring backupDest = dest + L"_Backup";
    if (PathFileExistsW(dest.c_str())) {
        MoveFileW(dest.c_str(), backupDest.c_str());
    }
    PerformFileSystemOperation(FO_COPY, src, dest);
    if (PathFileExistsW(backupDest.c_str())) {
        PerformFileSystemOperation(FO_DELETE, backupDest);
    }
}

void PerformFileBackup(const std::wstring& dest, const std::wstring& src) {
    if (!PathFileExistsW(src.c_str())) return;
    std::wstring backupDest = dest + L"_Backup";
    if (PathFileExistsW(dest.c_str())) {
        MoveFileW(dest.c_str(), backupDest.c_str());
    }
    if (CopyFileW(src.c_str(), dest.c_str(), FALSE)) {
        if (PathFileExistsW(backupDest.c_str())) {
            DeleteFileW(backupDest.c_str());
        }
    }
}

DWORD WINAPI BackupWorkerThread(LPVOID lpParam) {
    BackupThreadData* data = static_cast<BackupThreadData*>(lpParam);
    while (!*(data->shouldStop)) {
        Sleep(data->backupInterval);
        if (*(data->shouldStop)) break;
        *(data->isWorking) = true;
        for (const auto& pair : data->backupDirs) {
            PerformDirectoryBackup(pair.first, pair.second);
        }
        for (const auto& pair : data->backupFiles) {
            PerformFileBackup(pair.first, pair.second);
        }
        *(data->isWorking) = false;
    }
    return 0;
}

// --- Unified Operation Handlers ---

void CreateHardLinksRecursive(const std::wstring& srcDir, const std::wstring& destDir, LinkOp& op) {
    WIN32_FIND_DATAW findData;
    std::wstring searchPath = srcDir + L"\\*";
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        std::wstring fileName = findData.cFileName;
        if (fileName == L"." || fileName == L"..") continue;
        std::wstring srcPath = srcDir + L"\\" + fileName;
        std::wstring destPath = destDir + L"\\" + fileName;
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            CreateDirectoryW(destPath.c_str(), NULL);
            CreateHardLinksRecursive(srcPath, destPath, op);
        } else {
            std::wstring backupLinkPath = destPath + L"_Backup";
            bool fileBackupCreated = false;
            if (PathFileExistsW(destPath.c_str())) {
                if (MoveFileW(destPath.c_str(), backupLinkPath.c_str())) {
                    fileBackupCreated = true;
                }
            }
            if (CreateHardLinkW(destPath.c_str(), srcPath.c_str(), NULL)) {
                op.createdLinks.push_back({destPath, fileBackupCreated ? backupLinkPath : L""});
            } else if (fileBackupCreated) {
                MoveFileW(backupLinkPath.c_str(), destPath.c_str());
            }
        }
    } while (FindNextFileW(hFind, &findData));
    FindClose(hFind);
}

void PerformStartup(Operation& op) {
    std::visit([&](auto& arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, FileOp>) {
            if (PathFileExistsW(arg.destPath.c_str())) {
                MoveFileW(arg.destPath.c_str(), arg.destBackupPath.c_str());
                arg.destBackupCreated = true;
            }
            if (PathFileExistsW(arg.sourcePath.c_str())) {
                if (arg.isDirectory) PerformFileSystemOperation(FO_COPY, arg.sourcePath, arg.destPath);
                else CopyFileW(arg.sourcePath.c_str(), arg.destPath.c_str(), FALSE);
            }
        } else if constexpr (std::is_same_v<T, RestoreOnlyFileOp>) {
            if (PathFileExistsW(arg.targetPath.c_str())) {
                if (MoveFileW(arg.targetPath.c_str(), arg.backupPath.c_str())) {
                    arg.backupCreated = true;
                }
            }
        } else if constexpr (std::is_same_v<T, RegistryOp>) {
            bool renamed = false;
            if (arg.isKey) renamed = RenameRegistryKey(arg.rootKeyStr, arg.hRootKey, arg.subKey, arg.backupName);
            else renamed = RenameRegistryValue(arg.hRootKey, arg.subKey, arg.valueName, arg.backupName);
            if (renamed) arg.backupCreated = true;
            if (arg.isSaveRestore) ImportRegistryFile(arg.filePath);
        } else if constexpr (std::is_same_v<T, LinkOp>) {
            if (PathFileExistsW(arg.linkPath.c_str())) {
                if (MoveFileW(arg.linkPath.c_str(), arg.backupPath.c_str())) {
                    arg.backupCreated = true;
                }
            }
            if (arg.isHardlink) {
                if (arg.isDirectory) {
                    CreateDirectoryW(arg.linkPath.c_str(), NULL);
                    CreateHardLinksRecursive(arg.targetPath, arg.linkPath, arg);
                } else {
                    if (CreateHardLinkW(arg.linkPath.c_str(), arg.targetPath.c_str(), NULL)) {
                        arg.createdLinks.push_back({arg.linkPath, L""});
                    }
                }
            } else { // Symlink
                DWORD flags = arg.isDirectory ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0;
                CreateSymbolicLinkW(arg.linkPath.c_str(), arg.targetPath.c_str(), flags);
            }
        } else if constexpr (std::is_same_v<T, FirewallOp>) {
            INetFwPolicy2* pFwPolicy = NULL;
            INetFwRules* pFwRules = NULL;
            INetFwRule* pFwRule = NULL;
            HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pFwPolicy);
            if (SUCCEEDED(hr)) {
                hr = pFwPolicy->get_Rules(&pFwRules);
                if (SUCCEEDED(hr)) {
                    hr = CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), (void**)&pFwRule);
                    if (SUCCEEDED(hr)) {
                        BSTR bstrRuleName = SysAllocString(arg.ruleName.c_str());
                        BSTR bstrAppPath = SysAllocString(arg.appPath.c_str());
                        pFwRule->put_Name(bstrRuleName);
                        pFwRule->put_ApplicationName(bstrAppPath);
                        pFwRule->put_Direction(arg.direction);
                        pFwRule->put_Action(arg.action);
                        pFwRule->put_Enabled(VARIANT_TRUE);
                        pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
                        pFwRule->put_Profiles(NET_FW_PROFILE2_ALL);
                        if (SUCCEEDED(pFwRules->Add(pFwRule))) {
                            arg.ruleCreated = true;
                        }
                        SysFreeString(bstrRuleName);
                        SysFreeString(bstrAppPath);
                        pFwRule->Release();
                    }
                    pFwRules->Release();
                }
                pFwPolicy->Release();
            }
        }
    }, op.data);
}

void PerformShutdown(Operation& op) {
    std::visit([&](auto& arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, FileOp>) {
            if (PathFileExistsW(arg.destPath.c_str())) {
                std::wstring sourceBackupPath = arg.sourcePath + L"_Backup";
                if (PathFileExistsW(arg.sourcePath.c_str())) MoveFileW(arg.sourcePath.c_str(), sourceBackupPath.c_str());
                if (arg.isDirectory) PerformFileSystemOperation(FO_COPY, arg.destPath, arg.sourcePath);
                else CopyFileW(arg.destPath.c_str(), arg.sourcePath.c_str(), FALSE);
                if (PathFileExistsW(sourceBackupPath.c_str())) {
                    if (arg.isDirectory) PerformFileSystemOperation(FO_DELETE, sourceBackupPath);
                    else DeleteFileW(sourceBackupPath.c_str());
                }
            }
            if (arg.isDirectory) PerformFileSystemOperation(FO_DELETE, arg.destPath);
            else DeleteFileW(arg.destPath.c_str());
            if (arg.destBackupCreated && PathFileExistsW(arg.destBackupPath.c_str())) {
                MoveFileW(arg.destBackupPath.c_str(), arg.destPath.c_str());
            }
        } else if constexpr (std::is_same_v<T, RestoreOnlyFileOp>) {
            if (PathFileExistsW(arg.targetPath.c_str())) {
                if (arg.isDirectory) PerformFileSystemOperation(FO_DELETE, arg.targetPath);
                else DeleteFileW(arg.targetPath.c_str());
            }
            if (arg.backupCreated && PathFileExistsW(arg.backupPath.c_str())) {
                MoveFileW(arg.backupPath.c_str(), arg.targetPath.c_str());
            }
        } else if constexpr (std::is_same_v<T, RegistryOp>) {
            if (arg.isSaveRestore) {
                if (arg.isKey) ExportRegistryKey(arg.rootKeyStr, arg.subKey, arg.filePath);
                else ExportRegistryValue(arg.hRootKey, arg.subKey, arg.valueName, arg.rootKeyStr, arg.filePath);
            }
            if (arg.isKey) SHDeleteKeyW(arg.hRootKey, arg.subKey.c_str());
            else {
                HKEY hKey;
                if (RegOpenKeyExW(arg.hRootKey, arg.subKey.c_str(), 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, arg.valueName.c_str());
                    RegCloseKey(hKey);
                }
            }
            if (arg.backupCreated) {
                if (arg.isKey) RenameRegistryKey(arg.rootKeyStr, arg.hRootKey, arg.backupName, arg.subKey);
                else RenameRegistryValue(arg.hRootKey, arg.subKey, arg.backupName, arg.valueName);
            }
        } else if constexpr (std::is_same_v<T, LinkOp>) {
            if (arg.isHardlink) {
                for (auto it = arg.createdLinks.rbegin(); it != arg.createdLinks.rend(); ++it) {
                    DeleteFileW(it->first.c_str());
                    if (!it->second.empty()) MoveFileW(it->second.c_str(), it->first.c_str());
                }
                if (arg.isDirectory) PerformFileSystemOperation(FO_DELETE, arg.linkPath);
            } else { // Symlink
                if (arg.isDirectory) RemoveDirectoryW(arg.linkPath.c_str());
                else DeleteFileW(arg.linkPath.c_str());
            }
            if (arg.backupCreated && PathFileExistsW(arg.backupPath.c_str())) {
                MoveFileW(arg.backupPath.c_str(), arg.linkPath.c_str());
            }
        } else if constexpr (std::is_same_v<T, FirewallOp>) {
            if (arg.ruleCreated) {
                INetFwPolicy2* pFwPolicy = NULL;
                INetFwRules* pFwRules = NULL;
                HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pFwPolicy);
                if (SUCCEEDED(hr)) {
                    hr = pFwPolicy->get_Rules(&pFwRules);
                    if (SUCCEEDED(hr)) {
                        BSTR bstrRuleName = SysAllocString(arg.ruleName.c_str());
                        pFwRules->Remove(bstrRuleName);
                        SysFreeString(bstrRuleName);
                        pFwRules->Release();
                    }
                    pFwPolicy->Release();
                }
            }
        }
    }, op.data);
}

// --- Master Operation Parser ---
void ProcessAllOperations(const std::wstring& iniContent, const std::map<std::wstring, std::wstring>& variables, std::vector<Operation>& operations) {
    std::wstringstream stream(iniContent);
    std::wstring line;
    std::wstring currentSection;
    bool inSettings = false;

    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty() || line[0] == L';' || line[0] == L'#') continue;

        if (line[0] == L'[' && line.back() == L']') {
            currentSection = line;
            inSettings = (_wcsicmp(currentSection.c_str(), L"[Settings]") == 0);
            continue;
        }

        if (!inSettings) continue;

        size_t delimiterPos = line.find(L'=');
        if (delimiterPos == std::wstring::npos) continue;

        std::wstring key = trim(line.substr(0, delimiterPos));
        std::wstring value = trim(line.substr(delimiterPos + 1));
        Operation op;
        bool op_created = false;

        if (_wcsicmp(key.c_str(), L"dir") == 0 || _wcsicmp(key.c_str(), L"file") == 0) {
            FileOp f_op;
            f_op.isDirectory = (_wcsicmp(key.c_str(), L"dir") == 0);
            size_t sep = value.find(L" :: ");
            if (sep != std::wstring::npos) {
                f_op.destPath = ResolveToAbsolutePath(ExpandVariables(trim(value.substr(0, sep)), variables));
                std::wstring sourceRaw = trim(value.substr(sep + 4));
                std::wstring expandedSource = ResolveToAbsolutePath(ExpandVariables(sourceRaw, variables));
                if (f_op.isDirectory) f_op.sourcePath = expandedSource;
                else {
                    if (sourceRaw.back() == L'\\') f_op.sourcePath = expandedSource + PathFindFileNameW(f_op.destPath.c_str());
                    else f_op.sourcePath = expandedSource;
                }
                f_op.destBackupPath = f_op.destPath + L"_Backup";
                op.data = f_op;
                op_created = true;
            }
        } else if (_wcsicmp(key.c_str(), L"(dir)") == 0 || _wcsicmp(key.c_str(), L"(file)") == 0) {
            RestoreOnlyFileOp ro_op;
            ro_op.isDirectory = (_wcsicmp(key.c_str(), L"(dir)") == 0);
            ro_op.targetPath = ResolveToAbsolutePath(ExpandVariables(value, variables));
            ro_op.backupPath = ro_op.targetPath + L"_Backup";
            op.data = ro_op;
            op_created = true;
        } else if (_wcsicmp(key.c_str(), L"regkey") == 0 || _wcsicmp(key.c_str(), L"regvalue") == 0 || _wcsicmp(key.c_str(), L"(regkey)") == 0 || _wcsicmp(key.c_str(), L"(regvalue)") == 0) {
            RegistryOp r_op;
            r_op.isKey = (key.find(L"key") != std::wstring::npos);
            r_op.isSaveRestore = (key.front() != L'(');
            std::wstring regPathRaw = value;
            if (r_op.isSaveRestore) {
                size_t sep = value.find(L" :: ");
                if (sep != std::wstring::npos) {
                    regPathRaw = trim(value.substr(0, sep));
                    r_op.filePath = ResolveToAbsolutePath(ExpandVariables(trim(value.substr(sep + 4)), variables));
                }
            }
            if (ParseRegistryPath(regPathRaw, r_op.isKey, r_op.hRootKey, r_op.rootKeyStr, r_op.subKey, r_op.valueName)) {
                r_op.backupName = (r_op.isKey ? r_op.subKey : r_op.valueName) + L"_Backup";
                op.data = r_op;
                op_created = true;
            }
        } else if (_wcsicmp(key.c_str(), L"hardlink") == 0 || _wcsicmp(key.c_str(), L"symlink") == 0) {
            LinkOp l_op;
            l_op.isHardlink = (_wcsicmp(key.c_str(), L"hardlink") == 0);
            size_t sep = value.find(L" :: ");
            if (sep != std::wstring::npos) {
                std::wstring linkPathRaw = trim(value.substr(0, sep));
                std::wstring targetPathRaw = trim(value.substr(sep + 4));
                l_op.isDirectory = (linkPathRaw.back() == L'\\' || targetPathRaw.back() == L'\\');
                l_op.linkPath = ResolveToAbsolutePath(ExpandVariables(linkPathRaw, variables));
                l_op.targetPath = ResolveToAbsolutePath(ExpandVariables(targetPathRaw, variables));
                if (l_op.isDirectory) {
                    if (l_op.linkPath.back() == L'\\') l_op.linkPath.pop_back();
                    if (l_op.targetPath.back() == L'\\') l_op.targetPath.pop_back();
                }
                l_op.backupPath = l_op.linkPath + L"_Backup";
                op.data = l_op;
                op_created = true;
            }
        } else if (_wcsicmp(key.c_str(), L"firewall") == 0) {
            FirewallOp fw_op;
            std::vector<std::wstring> parts;
            std::wstringstream vstream(value);
            std::wstring part;
            while (std::getline(vstream, part, L':')) {
                parts.push_back(trim(part));
            }
            if (parts.size() == 4) {
                fw_op.ruleName = parts[0];
                if (_wcsicmp(parts[1].c_str(), L"in") == 0) fw_op.direction = NET_FW_RULE_DIR_IN;
                else fw_op.direction = NET_FW_RULE_DIR_OUT;
                if (_wcsicmp(parts[2].c_str(), L"allow") == 0) fw_op.action = NET_FW_ACTION_ALLOW;
                else fw_op.action = NET_FW_ACTION_BLOCK;
                fw_op.appPath = ResolveToAbsolutePath(ExpandVariables(parts[3], variables));
                op.data = fw_op;
                op_created = true;
            }
        }

        if (op_created) {
            operations.push_back(op);
        }
    }
}

// --- Main Application Logic ---
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
    std::ifstream file(iniPath);
    if (file) {
        std::wstringstream wss;
        wss << file.rdbuf();
        iniContent = wss.str();
    }

    // --- Variable Map Construction ---
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
    
    std::wstringstream stream(iniContent);
    std::wstring line;
    bool inSettings = false;
    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty() || line[0] == L';' || line[0] == L'#') continue;
        if (line[0] == L'[' && line.back() == L']') {
            inSettings = (_wcsicmp(line.c_str(), L"[Settings]") == 0);
            continue;
        }
        if (inSettings) {
            size_t delimiterPos = line.find(L'=');
            if (delimiterPos != std::wstring::npos) {
                std::wstring key = trim(line.substr(0, delimiterPos));
                std::wstring value = trim(line.substr(delimiterPos + 1));
                if (_wcsicmp(key.c_str(), L"uservar") == 0) {
                    size_t sep = value.find(L" :: ");
                    if (sep != std::wstring::npos) {
                        std::wstring name = trim(value.substr(0, sep));
                        std::wstring varValue = ExpandVariables(trim(value.substr(sep + 4)), variables);
                        variables[name] = varValue;
                    }
                }
            }
        }
    }

    std::wstring appPathRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"Settings", L"application"), variables);
    wchar_t absoluteAppPath[MAX_PATH] = {0};
    if (!appPathRaw.empty()) GetFullPathNameW(appPathRaw.c_str(), MAX_PATH, absoluteAppPath, NULL);
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

    // --- Mutex Creation ---
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

        std::vector<Operation> operations;
        ProcessAllOperations(iniContent, variables, operations);
        
        HANDLE hMonitorThread = NULL; MonitorThreadData monitorData; std::atomic<bool> stopMonitor(false);
        HANDLE hBackupThread = NULL; BackupThreadData backupData; std::atomic<bool> stopBackup(false); std::atomic<bool> isBackupWorking(false);

        // --- Startup Operations ---
        for (auto& op : operations) {
            PerformStartup(op);
        }

        // Foreground Monitor Setup
        std::wstring foregroundAppName = ExpandVariables(GetValueFromIniContent(iniContent, L"Settings", L"foreground"), variables);
        if (!foregroundAppName.empty()) {
            monitorData.shouldStop = &stopMonitor;
            monitorData.foregroundAppName = foregroundAppName;
            // ... (populate suspendProcesses)
            monitorData.checkInterval = 1; // Simplified
            hMonitorThread = CreateThread(NULL, 0, ForegroundMonitorThread, &monitorData, 0, NULL);
        }

        // Backup Thread Setup
        int backupTime = _wtoi(GetValueFromIniContent(iniContent, L"Settings", L"backuptime").c_str());
        if (backupTime > 0) {
            backupData.shouldStop = &stopBackup;
            backupData.isWorking = &isBackupWorking;
            backupData.backupInterval = backupTime * 60 * 1000;
            // ... (populate backupDirs/Files)
            hBackupThread = CreateThread(NULL, 0, BackupWorkerThread, &backupData, 0, NULL);
        }

        // --- Main Application Launch ---
        STARTUPINFOW si; PROCESS_INFORMATION pi; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si); ZeroMemory(&pi, sizeof(pi));
        std::wstring commandLine = ExpandVariables(GetValueFromIniContent(iniContent, L"Settings", L"commandline"), variables);
        std::wstring fullCommandLine = L"\"" + std::wstring(absoluteAppPath) + L"\" " + commandLine;
        wchar_t commandLineBuffer[4096]; wcscpy_s(commandLineBuffer, fullCommandLine.c_str());
        
        if (!CreateProcessW(NULL, commandLineBuffer, NULL, NULL, FALSE, 0, NULL, finalWorkDir.c_str(), &si, &pi)) {
            MessageBoxW(NULL, (L"启动程序失败: \n" + std::wstring(absoluteAppPath)).c_str(), L"启动错误", MB_ICONERROR);
            if (hMonitorThread) { stopMonitor = true; WaitForSingleObject(hMonitorThread, 1500); CloseHandle(hMonitorThread); }
            if (hBackupThread) { stopBackup = true; while(isBackupWorking) Sleep(100); WaitForSingleObject(hBackupThread, 1500); CloseHandle(hBackupThread); }
            for (auto it = operations.rbegin(); it != operations.rend(); ++it) {
                PerformShutdown(*it);
            }
            CloseHandle(hMutex);
            CoUninitialize();
            return 1;
        }
        
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        // --- Wait Process Logic ---
        // ... (wait process logic remains the same)

        // --- CRITICAL CLEANUP ---
        if (hMonitorThread) {
            stopMonitor = true;
            WaitForSingleObject(hMonitorThread, 1500);
            CloseHandle(hMonitorThread);
            // ... (resume suspended processes)
        }
        if (hBackupThread) {
            stopBackup = true;
            while (isBackupWorking) Sleep(100);
            WaitForSingleObject(hBackupThread, 1500);
            CloseHandle(hBackupThread);
        }
        
        for (auto it = operations.rbegin(); it != operations.rend(); ++it) {
            PerformShutdown(*it);
        }
        
        CloseHandle(hMutex);
        CoUninitialize();

    } else {
        CloseHandle(hMutex);
        if (GetValueFromIniContent(iniContent, L"Settings", L"multiple") == L"1") {
            // LaunchApplication(iniContent); // Simplified for this example
        }
    }
    return 0;
}