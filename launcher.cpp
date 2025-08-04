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
#include <shlwapi.h>
#include <tlhelp32.h>
#include <shellapi.h> // For SHFileOperationW
#include <shlobj.h>   // For SHGetKnownFolderPath and KNOWNFOLDERID
#include <netfw.h>    // For Firewall COM API

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "OleAut32.lib") // For Firewall BSTR functions

// --- Function pointer types for NTDLL functions ---
typedef LONG (NTAPI *pfnNtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG (NTAPI *pfnNtResumeProcess)(IN HANDLE ProcessHandle);
pfnNtSuspendProcess g_NtSuspendProcess = nullptr;
pfnNtResumeProcess g_NtResumeProcess = nullptr;


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
        return path; // Return original on failure
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

std::vector<std::wstring> GetMultiValueFromIniContent(const std::wstring& content, const std::wstring& section, const std::wstring& key) {
    std::vector<std::wstring> values;
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
                    values.push_back(trim(line.substr(delimiterPos + 1)));
                }
            }
        }
    }
    return values;
}

bool ReadFileToWString(const std::wstring& path, std::wstring& out_content) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    if (buffer.empty()) {
        out_content = L"";
        return true;
    }
    if (buffer.size() >= 2 && buffer[0] == (char)0xFF && buffer[1] == (char)0xFE) {
        out_content = std::wstring(reinterpret_cast<wchar_t*>(&buffer[2]), (buffer.size() / 2) - 1);
    } else if (buffer.size() >= 3 && buffer[0] == (char)0xEF && buffer[1] == (char)0xBB && buffer[2] == (char)0xBF) {
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, &buffer[3], (int)buffer.size() - 3, NULL, 0);
        out_content.resize(size_needed);
        MultiByteToWideChar(CP_UTF8, 0, &buffer[3], (int)buffer.size() - 3, &out_content[0], size_needed);
    } else {
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, &buffer[0], (int)buffer.size(), NULL, 0);
        out_content.resize(size_needed);
        MultiByteToWideChar(CP_UTF8, 0, &buffer[0], (int)buffer.size(), &out_content[0], size_needed);
    }
    return true;
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

// --- Foreground Monitoring Thread ---
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

// --- Backup Functionality ---
std::pair<std::wstring, std::wstring> ParseBackupEntry(const std::wstring& entry, const std::map<std::wstring, std::wstring>& variables) {
    size_t separatorPos = entry.find(L" :: ");
    if (separatorPos == std::wstring::npos) return {};
    std::wstring src = ResolveToAbsolutePath(ExpandVariables(trim(entry.substr(0, separatorPos)), variables));
    std::wstring dest = ResolveToAbsolutePath(ExpandVariables(trim(entry.substr(separatorPos + 4)), variables));
    if (dest.empty() || src.empty()) return {};
    return {dest, src};
}

void PerformDirectoryBackup(const std::wstring& dest, const std::wstring& src) {
    if (!PathFileExistsW(src.c_str())) return;
    std::wstring backupDest = dest + L"_Backup";
    bool oldVersionExists = PathFileExistsW(dest.c_str());
    if (oldVersionExists) {
        MoveFileW(dest.c_str(), backupDest.c_str());
    }
    wchar_t srcPath[MAX_PATH * 2] = {0};
    wcscpy_s(srcPath, src.c_str());
    srcPath[src.length() + 1] = L'\0';
    wchar_t destPath[MAX_PATH * 2] = {0};
    wcscpy_s(destPath, dest.c_str());
    destPath[dest.length() + 1] = L'\0';
    SHFILEOPSTRUCTW sfos = {0};
    sfos.wFunc = FO_COPY;
    sfos.pFrom = srcPath;
    sfos.pTo = destPath;
    sfos.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT | FOF_NOCONFIRMMKDIR;
    int result = SHFileOperationW(&sfos);
    if (result == 0 && oldVersionExists) {
        wchar_t backupPath[MAX_PATH * 2] = {0};
        wcscpy_s(backupPath, backupDest.c_str());
        backupPath[backupDest.length() + 1] = L'\0';
        SHFILEOPSTRUCTW delSfos = {0};
        delSfos.wFunc = FO_DELETE;
        delSfos.pFrom = backupPath;
        delSfos.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
        SHFileOperationW(&delSfos);
    }
}

void PerformFileBackup(const std::wstring& dest, const std::wstring& src) {
    if (!PathFileExistsW(src.c_str())) return;
    std::wstring backupDest = dest + L"_Backup";
    bool oldVersionExists = PathFileExistsW(dest.c_str());
    if (oldVersionExists) {
        MoveFileW(dest.c_str(), backupDest.c_str());
    }
    if (CopyFileW(src.c_str(), dest.c_str(), FALSE)) {
        if (oldVersionExists) {
            DeleteFileW(backupDest.c_str());
        }
    }
}

struct BackupThreadData {
    std::atomic<bool>* shouldStop;
    std::atomic<bool>* isWorking;
    int backupInterval;
    std::vector<std::pair<std::wstring, std::wstring>> backupDirs;
    std::vector<std::pair<std::wstring, std::wstring>> backupFiles;
};

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

// --- Link Management ---
struct LinkRecord {
    std::wstring linkPath;
    std::wstring backupPath;
    bool wasDirectory;
};

void CreateHardLinksRecursive(const std::wstring& srcDir, const std::wstring& destDir, std::vector<LinkRecord>& records) {
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
            CreateHardLinksRecursive(srcPath, destPath, records);
        } else {
            std::wstring backupLinkPath = destPath + L"_Backup";
            bool backupCreated = false;
            if (PathFileExistsW(destPath.c_str())) {
                if (MoveFileW(destPath.c_str(), backupLinkPath.c_str())) {
                    backupCreated = true;
                }
            }
            if (CreateHardLinkW(destPath.c_str(), srcPath.c_str(), NULL)) {
                records.push_back({destPath, backupCreated ? backupLinkPath : L"", false});
            } else if (backupCreated) {
                MoveFileW(backupLinkPath.c_str(), destPath.c_str());
            }
        }
    } while (FindNextFileW(hFind, &findData));
    FindClose(hFind);
}

void ProcessHardlinks(const std::wstring& iniContent, std::vector<LinkRecord>& records, const std::map<std::wstring, std::wstring>& variables) {
    auto entries = GetMultiValueFromIniContent(iniContent, L"Settings", L"hardlink");
    for (const auto& entry : entries) {
        size_t separatorPos = entry.find(L" :: ");
        if (separatorPos == std::wstring::npos) continue;
        std::wstring destPathRaw = ResolveToAbsolutePath(ExpandVariables(trim(entry.substr(0, separatorPos)), variables));
        std::wstring srcPathRaw = ResolveToAbsolutePath(ExpandVariables(trim(entry.substr(separatorPos + 4)), variables));
        if (destPathRaw.empty() || srcPathRaw.empty()) continue;
        bool isDestDir = destPathRaw.back() == L'\\';
        bool isSrcDir = srcPathRaw.back() == L'\\';
        if (isDestDir && isSrcDir) {
            std::wstring destDir = destPathRaw.substr(0, destPathRaw.length() - 1);
            std::wstring srcDir = srcPathRaw.substr(0, srcPathRaw.length() - 1);
            std::wstring backupDestDir = destDir + L"_Backup";
            bool backupCreated = false;
            if (PathFileExistsW(destDir.c_str())) {
                if (MoveFileW(destDir.c_str(), backupDestDir.c_str())) {
                    backupCreated = true;
                }
            }
            CreateDirectoryW(destDir.c_str(), NULL);
            CreateHardLinksRecursive(srcDir, destDir, records);
            records.push_back({destDir, backupCreated ? backupDestDir : L"", true});
        } else if (!isDestDir && !isSrcDir) {
            std::wstring backupDestPath = destPathRaw + L"_Backup";
            bool backupCreated = false;
            if (PathFileExistsW(destPathRaw.c_str())) {
                if (MoveFileW(destPathRaw.c_str(), backupDestPath.c_str())) {
                    backupCreated = true;
                }
            }
            if (CreateHardLinkW(destPathRaw.c_str(), srcPathRaw.c_str(), NULL)) {
                records.push_back({destPathRaw, backupCreated ? backupDestPath : L"", false});
            } else if (backupCreated) {
                MoveFileW(backupDestPath.c_str(), destPathRaw.c_str());
            }
        }
    }
}

void ProcessSymlinks(const std::wstring& iniContent, std::vector<LinkRecord>& records, const std::map<std::wstring, std::wstring>& variables) {
    auto entries = GetMultiValueFromIniContent(iniContent, L"Settings", L"symlink");
    for (const auto& entry : entries) {
        size_t separatorPos = entry.find(L" :: ");
        if (separatorPos == std::wstring::npos) continue;
        std::wstring destPathRaw = ExpandVariables(trim(entry.substr(0, separatorPos)), variables);
        std::wstring srcPathRaw = ExpandVariables(trim(entry.substr(separatorPos + 4)), variables);
        if (destPathRaw.empty() || srcPathRaw.empty()) continue;
        bool isDir = (destPathRaw.back() == L'\\' || srcPathRaw.back() == L'\\');
        std::wstring destPath = destPathRaw;
        if (isDir && destPath.back() == L'\\') destPath.pop_back();
        std::wstring backupPath = destPath + L"_Backup";
        bool backupCreated = false;
        if (PathFileExistsW(destPath.c_str())) {
            if (MoveFileW(destPath.c_str(), backupPath.c_str())) {
                backupCreated = true;
            }
        }
        DWORD flags = isDir ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0;
        if (CreateSymbolicLinkW(destPath.c_str(), srcPathRaw.c_str(), flags)) {
            records.push_back({destPath, backupCreated ? backupPath : L"", isDir});
        } else if (backupCreated) {
            MoveFileW(backupPath.c_str(), destPath.c_str());
        }
    }
}

void CleanupLinks(const std::vector<LinkRecord>& records) {
    for (auto it = records.rbegin(); it != records.rend(); ++it) {
        if (it->wasDirectory) {
            wchar_t path[MAX_PATH * 2] = {0};
            wcscpy_s(path, it->linkPath.c_str());
            path[it->linkPath.length() + 1] = L'\0';
            SHFILEOPSTRUCTW delSfos = {0};
            delSfos.wFunc = FO_DELETE;
            delSfos.pFrom = path;
            delSfos.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
            SHFileOperationW(&delSfos);
        } else {
            DeleteFileW(it->linkPath.c_str());
        }
        if (!it->backupPath.empty()) {
            MoveFileW(it->backupPath.c_str(), it->linkPath.c_str());
        }
    }
}

// --- Firewall Management ---
void ProcessFirewallRules(const std::wstring& iniContent, std::vector<std::wstring>& createdRuleNames, const std::map<std::wstring, std::wstring>& variables) {
    auto entries = GetMultiValueFromIniContent(iniContent, L"Settings", L"firewall");
    if (entries.empty()) return;

    INetFwPolicy2* pFwPolicy = NULL;
    INetFwRules* pFwRules = NULL;
    INetFwRule* pFwRule = NULL;

    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pFwPolicy);
    if (FAILED(hr)) return;

    hr = pFwPolicy->get_Rules(&pFwRules);
    if (FAILED(hr)) {
        pFwPolicy->Release();
        return;
    }

    for (const auto& entry : entries) {
        std::vector<std::wstring> parts;
        std::wstring current = entry;
        size_t pos = 0;
        while ((pos = current.find(L" :: ")) != std::wstring::npos) {
            parts.push_back(trim(current.substr(0, pos)));
            current.erase(0, pos + 4);
        }
        parts.push_back(trim(current));

        if (parts.size() != 4) continue;

        std::wstring ruleName = parts[0];
        std::wstring appPath = ResolveToAbsolutePath(ExpandVariables(parts[1], variables));
        std::wstring direction = parts[2];
        std::wstring action = parts[3];

        if (appPath.length() > 1 && appPath.front() == L'"' && appPath.back() == L'"') {
            appPath = appPath.substr(1, appPath.length() - 2);
        }

        hr = CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), (void**)&pFwRule);
        if (FAILED(hr)) continue;

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
            createdRuleNames.push_back(ruleName);
        }

        SysFreeString(bstrRuleName);
        SysFreeString(bstrAppPath);
        pFwRule->Release();
        pFwRule = NULL;
    }

    if (pFwRules) pFwRules->Release();
    if (pFwPolicy) pFwPolicy->Release();
}

// *** NEW, MORE ROBUST CleanupFirewallRules FUNCTION BASED ON USER FEEDBACK ***
void CleanupFirewallRules(const std::vector<std::wstring>& ruleNames) {
    if (ruleNames.empty()) return;

    INetFwPolicy2* pFwPolicy = NULL;
    INetFwRules* pFwRules = NULL;
    IEnumVARIANT* pEnumerator = NULL;
    INetFwRule* pFwRule = NULL;

    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pFwPolicy);
    if (FAILED(hr)) return;

    hr = pFwPolicy->get_Rules(&pFwRules);
    if (FAILED(hr)) {
        pFwPolicy->Release();
        return;
    }

    // For efficient lookup of target rule names
    std::set<std::wstring> targetRuleNames(ruleNames.begin(), ruleNames.end());
    std::vector<std::wstring> actualRulesToDelete;

    // --- Step 1: Enumerate ALL firewall rules to find which ones we need to delete ---
    IUnknown* pUnknown = NULL;
    hr = pFwRules->get__NewEnum(&pUnknown);
    if (SUCCEEDED(hr) && pUnknown) {
        hr = pUnknown->QueryInterface(__uuidof(IEnumVARIANT), (void**)&pEnumerator);
        pUnknown->Release();
    }

    if (SUCCEEDED(hr) && pEnumerator) {
        VARIANT var;
        VariantInit(&var);
        while (pEnumerator->Next(1, &var, NULL) == S_OK) {
            if (var.vt == VT_DISPATCH) {
                hr = var.pdispVal->QueryInterface(__uuidof(INetFwRule), (void**)&pFwRule);
                if (SUCCEEDED(hr)) {
                    BSTR bstrName = NULL;
                    if (SUCCEEDED(pFwRule->get_Name(&bstrName))) {
                        // Check if the rule's name is in our set of targets
                        if (targetRuleNames.count(bstrName) > 0) {
                            actualRulesToDelete.push_back(bstrName);
                        }
                        SysFreeString(bstrName);
                    }
                    pFwRule->Release();
                    pFwRule = NULL;
                }
            }
            VariantClear(&var);
        }
        pEnumerator->Release();
    }

    // --- Step 2: Delete the rules found in the enumeration step ---
    // This avoids a while-loop by iterating over a pre-compiled list.
    // The number of Remove calls is now fixed and finite.
    for (const auto& ruleNameToDelete : actualRulesToDelete) {
        BSTR bstrRuleNameToDelete = SysAllocString(ruleNameToDelete.c_str());
        if (bstrRuleNameToDelete) {
            pFwRules->Remove(bstrRuleNameToDelete); // We call Remove but don't loop on its result
            SysFreeString(bstrRuleNameToDelete);
        }
    }

    if (pFwRules) pFwRules->Release();
    if (pFwPolicy) pFwPolicy->Release();
}


// --- Main Application Logic ---
void LaunchApplication(const std::wstring& iniContent) {
    std::map<std::wstring, std::wstring> variables;
    variables[L"Local"] = GetKnownFolderPath(FOLDERID_LocalAppData);
    variables[L"LocalLow"] = GetKnownFolderPath(FOLDERID_LocalAppDataLow);
    variables[L"Roaming"] = GetKnownFolderPath(FOLDERID_RoamingAppData);
    variables[L"Documents"] = GetKnownFolderPath(FOLDERID_Documents);
    variables[L"ProgramData"] = GetKnownFolderPath(FOLDERID_ProgramData);
    variables[L"SavedGames"] = GetKnownFolderPath(FOLDERID_SavedGames);
    variables[L"PublicDocuments"] = GetKnownFolderPath(FOLDERID_PublicDocuments);
    wchar_t launcherFullPath[MAX_PATH];
    GetModuleFileNameW(NULL, launcherFullPath, MAX_PATH);
    wchar_t drive[_MAX_DRIVE];
    _wsplitpath_s(launcherFullPath, drive, _MAX_DRIVE, NULL, 0, NULL, 0, NULL, 0);
    variables[L"DRIVE"] = drive;
    PathRemoveFileSpecW(launcherFullPath);
    variables[L"YAPROOT"] = launcherFullPath;
    auto userVars = GetMultiValueFromIniContent(iniContent, L"Settings", L"uservar");
    for (const auto& entry : userVars) {
        size_t separatorPos = entry.find(L" :: ");
        if (separatorPos != std::wstring::npos) {
            std::wstring name = trim(entry.substr(0, separatorPos));
            std::wstring value = ExpandVariables(trim(entry.substr(separatorPos + 4)), variables);
            variables[name] = value;
        }
    }
    std::wstring appPathRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"Settings", L"application"), variables);
    if (appPathRaw.empty()) return;
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
    ReadFileToWString(iniPath, iniContent);

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
    auto userVars = GetMultiValueFromIniContent(iniContent, L"Settings", L"uservar");
    for (const auto& entry : userVars) {
        size_t separatorPos = entry.find(L" :: ");
        if (separatorPos != std::wstring::npos) {
            std::wstring name = trim(entry.substr(0, separatorPos));
            std::wstring value = ExpandVariables(trim(entry.substr(separatorPos + 4)), variables);
            variables[name] = value;
        }
    }
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
        // --- MASTER INSTANCE LOGIC ---
        CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

        if (appPathRaw.empty()) {
            MessageBoxW(NULL, L"INI配置文件中未找到或未设置 'application' 路径。", L"配置错误", MB_ICONERROR);
            CloseHandle(hMutex);
            CoUninitialize();
            return 1;
        }
        
        HANDLE hMonitorThread = NULL; MonitorThreadData monitorData; std::atomic<bool> stopMonitor(false);
        HANDLE hBackupThread = NULL; BackupThreadData backupData; std::atomic<bool> stopBackup(false); std::atomic<bool> isBackupWorking(false);
        std::vector<LinkRecord> hardlinkRecords, symlinkRecords;
        std::vector<std::wstring> firewallRuleNames;

        // Foreground Monitor Setup
        std::wstring foregroundAppName = ExpandVariables(GetValueFromIniContent(iniContent, L"Settings", L"foreground"), variables);
        if (!foregroundAppName.empty()) {
            monitorData.shouldStop = &stopMonitor;
            monitorData.foregroundAppName = foregroundAppName;
            auto suspendEntries = GetMultiValueFromIniContent(iniContent, L"Settings", L"suspend");
            for(const auto& entry : suspendEntries) monitorData.suspendProcesses.push_back(ExpandVariables(entry, variables));
            std::wstring fgCheckStr = GetValueFromIniContent(iniContent, L"Settings", L"foregroundcheck");
            monitorData.checkInterval = fgCheckStr.empty() ? 1 : _wtoi(fgCheckStr.c_str());
            if (monitorData.checkInterval <= 0) monitorData.checkInterval = 1;
            if (!monitorData.suspendProcesses.empty()) hMonitorThread = CreateThread(NULL, 0, ForegroundMonitorThread, &monitorData, 0, NULL);
        }

        // Backup Thread Setup
        std::wstring backupTimeStr = GetValueFromIniContent(iniContent, L"Settings", L"backuptime");
        int backupTime = backupTimeStr.empty() ? 0 : _wtoi(backupTimeStr.c_str());
        if (backupTime > 0) {
            backupData.shouldStop = &stopBackup;
            backupData.isWorking = &isBackupWorking;
            backupData.backupInterval = backupTime * 60 * 1000;
            auto dirEntries = GetMultiValueFromIniContent(iniContent, L"Settings", L"backupdir");
            for(const auto& entry : dirEntries) backupData.backupDirs.push_back(ParseBackupEntry(entry, variables));
            auto fileEntries = GetMultiValueFromIniContent(iniContent, L"Settings", L"backupfile");
            for(const auto& entry : fileEntries) backupData.backupFiles.push_back(ParseBackupEntry(entry, variables));
            if (!backupData.backupDirs.empty() || !backupData.backupFiles.empty()) hBackupThread = CreateThread(NULL, 0, BackupWorkerThread, &backupData, 0, NULL);
        }

        // Link & Firewall Processing
        ProcessHardlinks(iniContent, hardlinkRecords, variables);
        ProcessSymlinks(iniContent, symlinkRecords, variables);
        ProcessFirewallRules(iniContent, firewallRuleNames, variables);

        // --- Main Application Launch ---
        STARTUPINFOW si; PROCESS_INFORMATION pi; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si); ZeroMemory(&pi, sizeof(pi));
        std::wstring commandLine = ExpandVariables(GetValueFromIniContent(iniContent, L"Settings", L"commandline"), variables);
        std::wstring fullCommandLine = L"\"" + std::wstring(absoluteAppPath) + L"\" " + commandLine;
        wchar_t commandLineBuffer[4096]; wcscpy_s(commandLineBuffer, fullCommandLine.c_str());
        
        if (!CreateProcessW(NULL, commandLineBuffer, NULL, NULL, FALSE, 0, NULL, finalWorkDir.c_str(), &si, &pi)) {
            MessageBoxW(NULL, (L"启动程序失败: \n" + std::wstring(absoluteAppPath)).c_str(), L"启动错误", MB_ICONERROR);
            if (hMonitorThread) { stopMonitor = true; WaitForSingleObject(hMonitorThread, 1500); CloseHandle(hMonitorThread); }
            if (hBackupThread) { stopBackup = true; while(isBackupWorking) Sleep(100); WaitForSingleObject(hBackupThread, 1500); CloseHandle(hBackupThread); }
            CleanupFirewallRules(firewallRuleNames);
            CleanupLinks(symlinkRecords);
            CleanupLinks(hardlinkRecords);
            CloseHandle(hMutex);
            CoUninitialize();
            return 1;
        }
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        // --- Wait Process Logic ---
        auto waitEntries = GetMultiValueFromIniContent(iniContent, L"Settings", L"waitprocess");
        std::vector<std::wstring> waitProcesses;
        for(const auto& entry : waitEntries) waitProcesses.push_back(ExpandVariables(entry, variables));
        if (GetValueFromIniContent(iniContent, L"Settings", L"multiple") == L"1") {
            const wchar_t* appFilename = PathFindFileNameW(absoluteAppPath);
            if (appFilename && wcslen(appFilename) > 0) waitProcesses.push_back(appFilename);
        }
        if (!waitProcesses.empty()) {
            std::wstring waitCheckStr = GetValueFromIniContent(iniContent, L"Settings", L"waitcheck");
            int waitCheck = waitCheckStr.empty() ? 10 : _wtoi(waitCheckStr.c_str());
            if (waitCheck <= 0) waitCheck = 10;
            Sleep(3000);
            while (AreWaitProcessesRunning(waitProcesses)) Sleep(waitCheck * 1000);
        }

        // --- CRITICAL CLEANUP ---
        if (hMonitorThread) {
            stopMonitor = true;
            WaitForSingleObject(hMonitorThread, 1500);
            CloseHandle(hMonitorThread);
            SetAllProcessesState(monitorData.suspendProcesses, false);
        }
        if (hBackupThread) {
            stopBackup = true;
            while (isBackupWorking) Sleep(100);
            WaitForSingleObject(hBackupThread, 1500);
            CloseHandle(hBackupThread);
        }
        CleanupFirewallRules(firewallRuleNames);
        CleanupLinks(symlinkRecords);
        CleanupLinks(hardlinkRecords);
        CloseHandle(hMutex);
        CoUninitialize();

    } else {
        // --- SUBSEQUENT INSTANCE LOGIC ---
        CloseHandle(hMutex);
        if (GetValueFromIniContent(iniContent, L"Settings", L"multiple") == L"1") {
            LaunchApplication(iniContent);
        }
    }
    return 0;
}