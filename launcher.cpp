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
#include <variant>
#include <optional>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <shlobj.h>
#include <netfw.h>
#include <winreg.h>
#include <iomanip>
#include <atlbase.h>
#include <psapi.h>
#include <locale>
#include <codecvt>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Userenv.lib")

// --- Function pointer types for NTDLL functions ---
typedef LONG (NTAPI *pfnNtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG (NTAPI *pfnNtResumeProcess)(IN HANDLE ProcessHandle);
pfnNtSuspendProcess g_NtSuspendProcess = nullptr;
pfnNtResumeProcess g_NtResumeProcess = nullptr;
std::wstring g_originalPath;

// --- Data Structures ---

// Operations with startup and shutdown/cleanup logic
struct FileOp {
    std::wstring sourcePath;
    std::wstring destPath;
    std::wstring destBackupPath;
    bool isDirectory;
    bool destBackupCreated = false;
    bool wasMoved = false;
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
    std::vector<std::pair<std::wstring, std::wstring>> createdLinks;
    std::vector<std::pair<std::wstring, std::wstring>> backedUpPaths;
    bool performMoveOnCleanup = false;
    std::wstring traversalMode; // "dir", "file", "all", or empty
};


struct FirewallOp {
    std::wstring ruleName;
    std::wstring appPath;
    NET_FW_RULE_DIRECTION direction;
    NET_FW_ACTION action;
    bool ruleCreated = false;
};

// This variant is now only used for the shutdown stack
using StartupShutdownOperationData = std::variant<FileOp, RestoreOnlyFileOp, RegistryOp, LinkOp, FirewallOp>;
struct StartupShutdownOperation {
    StartupShutdownOperationData data;
};


// One-shot actions for [Before] and [After] sections
struct RunOp {
    std::wstring programPath;
    std::wstring commandLine;
    std::wstring workDir;
    bool wait;
    bool hide;
};

struct RegImportOp {
    std::wstring regPath;
};

struct RegDllOp {
    std::wstring dllPath;
    bool unregister;
};

struct DeleteFileOp {
    std::wstring pathPattern;
};

struct DeleteDirOp {
    std::wstring pathPattern;
    bool ifEmpty;
};

struct DeleteRegKeyOp {
    std::wstring keyPattern;
    bool ifEmpty;
};

struct DeleteRegValueOp {
    std::wstring keyPattern;
    std::wstring valuePattern;
};

struct CreateDirOp {
    std::wstring path;
};

struct DelayOp {
    int milliseconds;
};

struct KillProcessOp {
    std::wstring processPattern;
    bool checkParentProcess = false;
    bool checkProcessPath = false;
    std::wstring basePath;
};

enum class TextFormat { Win, Unix, Mac };
enum class TextEncoding {
    ANSI,       // System Default ANSI
    UTF8,       // UTF-8 without BOM
    UTF8_BOM,   // UTF-8 with BOM
    UTF16_LE,   // UTF-16 Little Endian
    UTF16_BE,   // UTF-16 Big Endian
    SHIFT_JIS,  // Japanese, CP932
    EUC_KR,     // Korean, CP949
    BIG5        // Traditional Chinese, CP950
};


struct CreateFileOp {
    std::wstring path;
    bool overwrite;
    TextFormat format;
    TextEncoding encoding;
    std::wstring content;
};

struct CreateRegKeyOp {
    std::wstring keyPath;
};

struct CreateRegValueOp {
    std::wstring keyPath;
    std::wstring valueName;
    std::wstring valueData;
    std::wstring typeStr;
};

struct CopyMoveOp {
    std::wstring sourcePath;
    std::wstring destPath;
    bool isDirectory;
    bool isMove;
    bool overwrite;
};

struct AttributesOp {
    std::wstring path;
    DWORD attributes;
};

struct IniWriteOp {
    std::wstring path;
    std::wstring section;
    std::wstring key;
    std::wstring value;
    bool deleteSection = false;
};

struct ReplaceOp {
    std::wstring path;
    std::wstring findText;
    std::wstring replaceText;
};

struct ReplaceLineOp {
    std::wstring path;
    std::wstring lineStart;
    std::wstring replaceLine;
};

struct EnvVarOp {
    std::wstring name;
    std::wstring value;
};


// A variant for one-shot actions, used by [Before] and [After] sections
using ActionOpData = std::variant<
    RunOp, RegImportOp, RegDllOp, DeleteFileOp, DeleteDirOp, DeleteRegKeyOp, DeleteRegValueOp,
    CreateDirOp, DelayOp, KillProcessOp, CreateFileOp, CreateRegKeyOp, CreateRegValueOp,
    CopyMoveOp, AttributesOp, IniWriteOp, ReplaceOp, ReplaceLineOp,
    EnvVarOp
>;
struct ActionOperation {
    ActionOpData data;
};

// Special marker for the [After] section to trigger cleanup
struct RestoreMarkerOp {};

// A variant for all possible operations in the [After] section
using AfterOperationData = std::variant<ActionOperation, RestoreMarkerOp>;
struct AfterOperation {
    AfterOperationData data;
};


// A new unified variant for all possible operations in the [Before] section
using BeforeOperationData = std::variant<
    FileOp, RestoreOnlyFileOp, RegistryOp, LinkOp, FirewallOp, // Startup/Shutdown types
    ActionOpData // One-shot types (using the variant directly)
>;
struct BeforeOperation {
    BeforeOperationData data;
};

// Forward declarations for thread data structures
struct MonitorThreadData;
struct BackupThreadData;

// Data structure to pass to the worker thread
struct LauncherThreadData {
    std::wstring iniContent;
    std::map<std::wstring, std::wstring> variables;
    std::vector<StartupShutdownOperation> shutdownOps;
    std::vector<AfterOperation> afterOps;
    std::wstring absoluteAppPath;
    std::wstring finalWorkDir;
    std::wstring tempFilePath;
    HANDLE hMonitorThread = NULL;
    DWORD hMonitorThreadId = 0;
    MonitorThreadData* monitorData = nullptr;
    HANDLE hBackupThread = NULL;
    BackupThreadData* backupData = nullptr;
    std::atomic<bool>* stopMonitor = nullptr;
    std::atomic<bool>* isBackupWorking = nullptr;
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

std::vector<std::wstring> split_string(const std::wstring& s, const std::wstring& delimiter) {
    std::vector<std::wstring> parts;
    std::wstring str = s;
    size_t pos = 0;
    while ((pos = str.find(delimiter)) != std::wstring::npos) {
        parts.push_back(trim(str.substr(0, pos)));
        str.erase(0, pos + delimiter.length());
    }
    parts.push_back(trim(str));
    return parts;
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

std::wstring ResolveToAbsolutePath(const std::wstring& path, const std::map<std::wstring, std::wstring>& variables) {
    if (path.empty()) {
        return L"";
    }

    if (!PathIsRelativeW(path.c_str())) {
        wchar_t canonicalPath[MAX_PATH];
        if (GetFullPathNameW(path.c_str(), MAX_PATH, canonicalPath, NULL) != 0) {
            return canonicalPath;
        }
        return path;
    }

    auto it = variables.find(L"YAPROOT");
    if (it != variables.end()) {
        const std::wstring& yapRoot = it->second;
        wchar_t combinedPath[MAX_PATH];
        if (PathCombineW(combinedPath, yapRoot.c_str(), path.c_str())) {
            return combinedPath;
        }
    }

    return path;
}

bool ArePathsOnSameVolume(const std::wstring& path1, const std::wstring& path2) {
    if (path1.empty() || path2.empty()) {
        return false;
    }

    wchar_t root1[MAX_PATH];
    if (!GetVolumePathNameW(path1.c_str(), root1, MAX_PATH)) {
        return false;
    }

    wchar_t root2[MAX_PATH];
    if (!GetVolumePathNameW(path2.c_str(), root2, MAX_PATH)) {
        return false;
    }

    return _wcsicmp(root1, root2) == 0;
}

std::wstring ExpandVariables(std::wstring path, const std::map<std::wstring, std::wstring>& variables) {
    int safety_counter = 0;
    size_t current_pos = 0;
    while ((current_pos = path.find(L'{', current_pos)) != std::wstring::npos && safety_counter < 100) {
        size_t start_pos = current_pos;
        size_t end_pos = path.find(L'}', start_pos);
        if (end_pos == std::wstring::npos) break;

        std::wstring varName = path.substr(start_pos + 1, end_pos - start_pos - 1);
        auto it = variables.find(varName);
        if (it != variables.end()) {
            path.replace(start_pos, end_pos - start_pos + 1, it->second);
            current_pos = start_pos + it->second.length();
        } else {
            current_pos = end_pos + 1;
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

// --- File System & Command Helpers ---

bool ExecuteProcess(const std::wstring& path, const std::wstring& args, const std::wstring& workDir, bool wait, bool hide) {
    if (path.empty() || !PathFileExistsW(path.c_str())) {
        return false;
    }

    std::wstring finalWorkDir;
    std::wstring exeDir;
    if (!workDir.empty() && PathIsDirectoryW(workDir.c_str())) {
        finalWorkDir = workDir;
    } else {
        exeDir = path;
        PathRemoveFileSpecW(&exeDir[0]);
        finalWorkDir = exeDir;
    }

    SHELLEXECUTEINFOW sei;
    ZeroMemory(&sei, sizeof(sei));
    sei.cbSize = sizeof(SHELLEXECUTEINFOW);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.hwnd = NULL;
    sei.lpVerb = L"open";
    sei.lpFile = path.c_str();
    sei.lpParameters = args.empty() ? NULL : args.c_str();
    sei.lpDirectory = finalWorkDir.c_str();
    sei.nShow = hide ? SW_HIDE : SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        return false;
    }

    if (sei.hProcess) {
        if (wait) {
            WaitForSingleObject(sei.hProcess, INFINITE);
        }
        CloseHandle(sei.hProcess);
    }

    return true;
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

// <-- [新增] 替换 PathMatchSpecW 的、可靠的通配符匹配函数
bool WildcardMatch(const wchar_t* text, const wchar_t* pattern) {
    const wchar_t* star_text = nullptr;
    const wchar_t* star_pattern = nullptr;

    while (*text) {
        if (*pattern == L'*') {
            star_pattern = pattern++;
            star_text = text;
        } else if (*pattern == L'?' || towlower(*pattern) == towlower(*text)) {
            pattern++;
            text++;
        } else if (star_pattern) {
            pattern = star_pattern + 1;
            text = ++star_text;
        } else {
            return false;
        }
    }

    while (*pattern == L'*') {
        pattern++;
    }

    return !*pattern;
}

// Forward declaration for recursive delete
namespace ActionHelpers {
    void DeleteRegistryKeyTree(HKEY hRootKey, const std::wstring& subKey);
}

bool ParseRegistryPath(const std::wstring& fullPath, bool isKey, HKEY& hRootKey, std::wstring& rootKeyStr, std::wstring& subKey, std::wstring& valueName) {
    if (fullPath.empty()) return false;
    size_t firstSlash = fullPath.find(L'\\');
    if (firstSlash == std::wstring::npos) return false;

    std::wstring rootStrRaw = fullPath.substr(0, firstSlash);
    std::wstring restOfPath = fullPath.substr(firstSlash + 1);

    if (_wcsicmp(rootStrRaw.c_str(), L"HKCU") == 0 || _wcsicmp(rootStrRaw.c_str(), L"HKEY_CURRENT_USER") == 0) { hRootKey = HKEY_CURRENT_USER; rootKeyStr = L"HKEY_CURRENT_USER"; }
    else if (_wcsicmp(rootStrRaw.c_str(), L"HKLM") == 0 || _wcsicmp(rootStrRaw.c_str(), L"HKEY_LOCAL_MACHINE") == 0) { hRootKey = HKEY_LOCAL_MACHINE; rootKeyStr = L"HKEY_LOCAL_MACHINE"; }
    else if (_wcsicmp(rootStrRaw.c_str(), L"HKCR") == 0 || _wcsicmp(rootStrRaw.c_str(), L"HKEY_CLASSES_ROOT") == 0) { hRootKey = HKEY_CLASSES_ROOT; rootKeyStr = L"HKEY_CLASSES_ROOT"; }
    else if (_wcsicmp(rootStrRaw.c_str(), L"HKU") == 0 || _wcsicmp(rootStrRaw.c_str(), L"HKEY_USERS") == 0) { hRootKey = HKEY_USERS; rootKeyStr = L"HKEY_USERS"; }
    else return false;

    if (isKey) {
        subKey = restOfPath;
        valueName = L"";
    } else {
        std::wstring currentPath = restOfPath;
        size_t lastSlashPos = currentPath.find_last_of(L'\\');

        while (lastSlashPos != std::wstring::npos) {
            std::wstring potentialSubKey = currentPath.substr(0, lastSlashPos);
            HKEY hTempKey;
            if (RegOpenKeyExW(hRootKey, potentialSubKey.c_str(), 0, KEY_READ, &hTempKey) == ERROR_SUCCESS) {
                RegCloseKey(hTempKey);
                subKey = potentialSubKey;
                valueName = currentPath.substr(lastSlashPos + 1);
                return true;
            }
            lastSlashPos = currentPath.find_last_of(L'\\', lastSlashPos - 1);
        }

        subKey = L"";
        valueName = restOfPath;
    }
    return true;
}

// <-- [修改] 为子键名称枚举也使用动态缓冲区
LSTATUS RecursiveRegCopyKey(HKEY hSrcKey, HKEY hDestKey) {
    DWORD dwSubKeys, dwValues, dwMaxSubKeyLen, maxValueNameLen, maxValueDataSize;

    LSTATUS status = RegQueryInfoKeyW(hSrcKey, NULL, NULL, NULL, &dwSubKeys, &dwMaxSubKeyLen, NULL, &dwValues, &maxValueNameLen, &maxValueDataSize, NULL, NULL);
    if (status != ERROR_SUCCESS) {
        return status;
    }

    std::vector<wchar_t> valueName(maxValueNameLen + 1);
    std::vector<BYTE> data(maxValueDataSize);

    // 复制所有值
    for (DWORD i = 0; i < dwValues; i++) {
        DWORD valueNameSize = (DWORD)valueName.size();
        DWORD dataSize = (DWORD)data.size();
        DWORD type;

        status = RegEnumValueW(hSrcKey, i, valueName.data(), &valueNameSize, NULL, &type, data.data(), &dataSize);
        if (status == ERROR_SUCCESS) {
            RegSetValueExW(hDestKey, valueName.data(), 0, type, data.data(), dataSize);
        }
    }

    // 递归复制所有子项
    if (dwSubKeys > 0) {
        std::vector<wchar_t> subKeyName(dwMaxSubKeyLen + 1);
        for (DWORD i = 0; i < dwSubKeys; i++) {
            DWORD subKeyNameSize = (DWORD)subKeyName.size();
            if (RegEnumKeyExW(hSrcKey, i, subKeyName.data(), &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                HKEY hSrcSubKey, hDestSubKey;
                if (RegOpenKeyExW(hSrcKey, subKeyName.data(), 0, KEY_READ, &hSrcSubKey) == ERROR_SUCCESS) {
                    if (RegCreateKeyExW(hDestKey, subKeyName.data(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hDestSubKey, NULL) == ERROR_SUCCESS) {
                        RecursiveRegCopyKey(hSrcSubKey, hDestSubKey);
                        RegCloseKey(hDestSubKey);
                    }
                    RegCloseKey(hSrcSubKey);
                }
            }
        }
    }
    return ERROR_SUCCESS;
}

// <-- [修改] 使用API重写RenameRegistryKey
bool RenameRegistryKey(HKEY hRootKey, const std::wstring& subKey, const std::wstring& newSubKey) {
    HKEY hSrcKey, hDestKey;
    if (RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ, &hSrcKey) != ERROR_SUCCESS) {
        return false;
    }
    LSTATUS createStatus = RegCreateKeyExW(hRootKey, newSubKey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hDestKey, NULL);
    if (createStatus != ERROR_SUCCESS) {
        RegCloseKey(hSrcKey);
        return false;
    }

    RecursiveRegCopyKey(hSrcKey, hDestKey);

    RegCloseKey(hSrcKey);
    RegCloseKey(hDestKey);

    ActionHelpers::DeleteRegistryKeyTree(hRootKey, subKey);
    return true;
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

// <-- [修改] 修正了 hex 值的导出换行逻辑 以精确匹配 reg.exe 的行为
void RecursiveRegExport(HKEY hKey, const std::wstring& currentPath, std::ofstream& regFile) {
    auto write_wstring = [&](const std::wstring& s) {
        regFile.write(reinterpret_cast<const char*>(s.c_str()), s.length() * sizeof(wchar_t));
    };

    write_wstring(L"[" + currentPath + L"]\r\n");

    DWORD dwSubKeys, dwValues, dwMaxSubKeyLen, maxValueNameLen, maxValueDataSize;
    if (RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &dwSubKeys, &dwMaxSubKeyLen, NULL, &dwValues, &maxValueNameLen, &maxValueDataSize, NULL, NULL) != ERROR_SUCCESS) {
        return;
    }

    std::vector<wchar_t> valueNameBuffer(maxValueNameLen + 1);
    std::vector<BYTE> data(maxValueDataSize);

    for (DWORD i = 0; i < dwValues; i++) {
        DWORD valueNameSize = (DWORD)valueNameBuffer.size();
        DWORD dataSize = (DWORD)data.size();
        DWORD type;

        if (RegEnumValueW(hKey, i, valueNameBuffer.data(), &valueNameSize, NULL, &type, data.data(), &dataSize) == ERROR_SUCCESS) {
            std::wstring valueName(valueNameBuffer.data());
            std::wstring displayName;
            if (valueName.empty()) {
                displayName = L"@";
            } else {
                std::wstring escapedValueName;
                for (wchar_t c : valueName) {
                    if (c == L'\\') escapedValueName += L"\\\\";
                    else if (c == L'"') escapedValueName += L"\\\"";
                    else escapedValueName += c;
                }
                displayName = L"\"" + escapedValueName + L"\"";
            }

            std::wstringstream wss;
            wss << displayName << L"=";

            if (type == REG_SZ) {
                std::wstring strValue(reinterpret_cast<const wchar_t*>(data.data()), dataSize / sizeof(wchar_t));
                if (!strValue.empty() && strValue.back() == L'\0') {
                    strValue.pop_back();
                }

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
            } else {
                wss << L"hex";
                if (type == REG_EXPAND_SZ) wss << L"(2)";
                else if (type == REG_MULTI_SZ) wss << L"(7)";
                else if (type == REG_QWORD) wss << L"(b)";
                else if (type != REG_BINARY) wss << L"(" << type << L")";
                wss << L":";

                // --- [核心修改] ---
                const size_t MAX_LINE_LEN = 80;
                size_t currentLineLength = wss.str().length();

                for (DWORD j = 0; j < dataSize; ++j) {
                    size_t chars_for_this_byte = (j < dataSize - 1) ? 3 : 2; // "XX," or "XX"

                    if (j > 0 && currentLineLength + chars_for_this_byte + 1 > MAX_LINE_LEN) {
                        wss << L"\\\r\n  ";
                        currentLineLength = 2;
                    }

                    wss << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(data[j]);
                    currentLineLength += 2;

                    if (j < dataSize - 1) {
                        wss << L",";
                        currentLineLength += 1;
                    }
                }
                // --- [核心修改结束] ---
            }
            wss << L"\r\n";
            write_wstring(wss.str());
        }
    }
    write_wstring(L"\r\n");

    if (dwSubKeys > 0) {
        std::vector<wchar_t> subKeyName(dwMaxSubKeyLen + 1);
        for (DWORD i = 0; i < dwSubKeys; i++) {
            DWORD subKeyNameSize = (DWORD)subKeyName.size();
            if (RegEnumKeyExW(hKey, i, subKeyName.data(), &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                HKEY hSubKey;
                if (RegOpenKeyExW(hKey, subKeyName.data(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                    RecursiveRegExport(hSubKey, currentPath + L"\\" + subKeyName.data(), regFile);
                    RegCloseKey(hSubKey);
                }
            }
        }
    }
}

// <-- [修改] 增强了根键名称解析 以同时支持缩写和完整名称
bool ExportRegistryKey(const std::wstring& rootKeyStr, const std::wstring& subKey, const std::wstring& filePath) {
    HKEY hRootKey;
    std::wstring fullRootKeyStr;
    // 同时检查缩写和完整名称
    if (_wcsicmp(rootKeyStr.c_str(), L"HKCU") == 0 || _wcsicmp(rootKeyStr.c_str(), L"HKEY_CURRENT_USER") == 0) { hRootKey = HKEY_CURRENT_USER; fullRootKeyStr = L"HKEY_CURRENT_USER"; }
    else if (_wcsicmp(rootKeyStr.c_str(), L"HKLM") == 0 || _wcsicmp(rootKeyStr.c_str(), L"HKEY_LOCAL_MACHINE") == 0) { hRootKey = HKEY_LOCAL_MACHINE; fullRootKeyStr = L"HKEY_LOCAL_MACHINE"; }
    else if (_wcsicmp(rootKeyStr.c_str(), L"HKCR") == 0 || _wcsicmp(rootKeyStr.c_str(), L"HKEY_CLASSES_ROOT") == 0) { hRootKey = HKEY_CLASSES_ROOT; fullRootKeyStr = L"HKEY_CLASSES_ROOT"; }
    else if (_wcsicmp(rootKeyStr.c_str(), L"HKU") == 0 || _wcsicmp(rootKeyStr.c_str(), L"HKEY_USERS") == 0) { hRootKey = HKEY_USERS; fullRootKeyStr = L"HKEY_USERS"; }
    else return false;

    HKEY hKeyToExport;
    if (RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ, &hKeyToExport) != ERROR_SUCCESS) {
        return false;
    }

    wchar_t dirPath[MAX_PATH];
    wcscpy_s(dirPath, MAX_PATH, filePath.c_str());
    PathRemoveFileSpecW(dirPath);
    if (wcslen(dirPath) > 0) {
        SHCreateDirectoryExW(NULL, dirPath, NULL);
    }

    std::ofstream regFile(filePath, std::ios::binary | std::ios::trunc);
    if (!regFile.is_open()) {
        RegCloseKey(hKeyToExport);
        return false;
    }

    regFile.put((char)0xFF);
    regFile.put((char)0xFE);

    auto write_wstring = [&](const std::wstring& s) {
        regFile.write(reinterpret_cast<const char*>(s.c_str()), s.length() * sizeof(wchar_t));
    };

    write_wstring(L"Windows Registry Editor Version 5.00\r\n\r\n");
    RecursiveRegExport(hKeyToExport, fullRootKeyStr + L"\\" + subKey, regFile);

    RegCloseKey(hKeyToExport);
    regFile.close();
    return true;
}

// <-- [修改] 修正了 hex 值的导出换行逻辑 以精确匹配 reg.exe 的行为
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

    wchar_t dirPath[MAX_PATH];
    wcscpy_s(dirPath, MAX_PATH, filePath.c_str());
    PathRemoveFileSpecW(dirPath);
    if (wcslen(dirPath) > 0) {
        SHCreateDirectoryExW(NULL, dirPath, NULL);
    }

    std::ofstream regFile(filePath, std::ios::binary | std::ios::trunc);
    if (!regFile.is_open()) return false;

    regFile.put((char)0xFF);
    regFile.put((char)0xFE);

    auto write_wstring = [&](const std::wstring& s) {
        regFile.write(reinterpret_cast<const char*>(s.c_str()), s.length() * sizeof(wchar_t));
    };

    write_wstring(L"Windows Registry Editor Version 5.00\r\n\r\n");
    write_wstring(L"[" + rootKeyStr + L"\\" + subKey + L"]\r\n");

    std::wstring displayName;
    if (valueName.empty()) {
        displayName = L"@";
    } else {
        std::wstring escapedValueName;
        for (wchar_t c : valueName) {
            if (c == L'\\') escapedValueName += L"\\\\";
            else if (c == L'"') escapedValueName += L"\\\"";
            else escapedValueName += c;
        }
        displayName = L"\"" + escapedValueName + L"\"";
    }

    std::wstringstream wss;
    wss << displayName << L"=";

    if (type == REG_SZ) {
        std::wstring strValue(reinterpret_cast<const wchar_t*>(data.data()), size / sizeof(wchar_t));
        if (!strValue.empty() && strValue.back() == L'\0') {
            strValue.pop_back();
        }
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
    } else {
        wss << L"hex";
        if (type == REG_EXPAND_SZ) wss << L"(2)";
        else if (type == REG_MULTI_SZ) wss << L"(7)";
        else if (type == REG_QWORD) wss << L"(b)";
        else if (type != REG_BINARY) wss << L"(" << type << L")";
        wss << L":";

        // --- [核心修改] ---
        const size_t MAX_LINE_LEN = 80;
        size_t currentLineLength = wss.str().length();

        for (DWORD i = 0; i < size; ++i) {
            size_t chars_for_this_byte = (i < size - 1) ? 3 : 2; // "XX," or "XX"

            if (i > 0 && currentLineLength + chars_for_this_byte + 1 > MAX_LINE_LEN) {
                wss << L"\\\r\n  ";
                currentLineLength = 2;
            }

            wss << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(data[i]);
            currentLineLength += 2;

            if (i < size - 1) {
                wss << L",";
                currentLineLength += 1;
            }
        }
        // --- [核心修改结束] ---
    }
    wss << L"\r\n";
    write_wstring(wss.str());
    regFile.close();
    return true;
}

bool ImportRegistryFile(const std::wstring& filePath) {
    if (!PathFileExistsW(filePath.c_str())) return true;

    wchar_t windir[MAX_PATH];
    GetWindowsDirectoryW(windir, MAX_PATH);
    std::wstring regeditPath = std::wstring(windir) + L"\\regedit.exe";
    std::wstring args = L"/s \"" + filePath + L"\"";

    return ExecuteProcess(regeditPath, args, L"", true, true);
}

// <-- [新增] 将Win32路径转换为NT设备路径的辅助函数
std::wstring GetNtPath(const std::wstring& path) {
    // 以非独占方式打开文件句柄
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return L""; // 如果文件不存在或无法打开 则返回空
    }

    // 准备一个缓冲区来接收路径
    std::vector<wchar_t> buffer(MAX_PATH);
    // 调用API获取NT格式的卷名路径
    DWORD size = GetFinalPathNameByHandleW(hFile, buffer.data(), (DWORD)buffer.size(), VOLUME_NAME_NT);

    // 如果缓冲区太小 则调整大小后重试
    if (size > buffer.size()) {
        buffer.resize(size);
        size = GetFinalPathNameByHandleW(hFile, buffer.data(), (DWORD)buffer.size(), VOLUME_NAME_NT);
    }

    CloseHandle(hFile);

    // 如果成功获取路径 则返回
    if (size > 0 && size < buffer.size()) {
        return std::wstring(buffer.data());
    }

    // 失败则返回空
    return L"";
}

// <-- [新增] 获取进程完整路径的辅助函数 支持长路径
std::wstring GetProcessFullPathByPid(DWORD pid) {
    if (pid == 0) return L"";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        std::vector<wchar_t> buffer(MAX_PATH);
        DWORD size = (DWORD)buffer.size();
        // 循环以处理可能超过MAX_PATH的路径
        while (true) {
            if (QueryFullProcessImageNameW(hProcess, 0, buffer.data(), &size)) {
                CloseHandle(hProcess);
                return std::wstring(buffer.data());
            } else {
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    size *= 2; // 如果缓冲区太小 则加倍
                    buffer.resize(size);
                } else {
                    // 因其他错误失败
                    CloseHandle(hProcess);
                    return L"";
                }
            }
        }
    }
    return L"";
}

// Deletion and Action Helpers
namespace ActionHelpers {

    void HandleKillProcess(const KillProcessOp& op, const std::set<DWORD>& trustedPids) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return;

        // --- [最终修正] ---
        // 在循环开始前 将INI中的Win32路径转换为NT设备路径
        std::wstring ntBasePath;
        if (op.checkProcessPath && !op.basePath.empty()) {
            ntBasePath = GetNtPath(op.basePath);
        }
        // --- [修正结束] ---

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (!WildcardMatch(pe32.szExeFile, op.processPattern.c_str())) {
                    continue;
                }

                bool shouldTerminate = true;

                if (op.checkParentProcess) {
                    if (trustedPids.count(pe32.th32ParentProcessID) == 0) {
                        shouldTerminate = false;
                    }
                }

                if (shouldTerminate && op.checkProcessPath) {
                    // --- [最终修正] ---
                    // 仅当成功转换NT路径后才进行比较
                    if (ntBasePath.empty()) {
                        shouldTerminate = false;
                    } else {
                        // 获取进程的NT路径
                        std::wstring processNtPath = GetProcessFullPathByPid(pe32.th32ProcessID);
                        // 比较两个NT路径
                        if (_wcsicmp(processNtPath.c_str(), ntBasePath.c_str()) != 0) {
                            shouldTerminate = false;
                        }
                    }
                    // --- [修正结束] ---
                }

                if (shouldTerminate) {
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                    }
                }

            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

     // <-- [修改] 使用新的 WildcardMatch 函数
    void HandleDeleteFile(const std::wstring& pathPattern) {
        wchar_t dirPath_w[MAX_PATH];
        wcscpy_s(dirPath_w, pathPattern.c_str());
        PathRemoveFileSpecW(dirPath_w);
        std::wstring dirPath = dirPath_w;

        const wchar_t* filePattern = PathFindFileNameW(pathPattern.c_str());

        if (dirPath == pathPattern) {
            dirPath = L".";
        }

        std::wstring searchPattern = dirPath + L"\\*";

        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) {
            return;
        }

        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                continue;
            }

            if (WildcardMatch(findData.cFileName, filePattern)) { // <-- 修改点
                std::wstring fullPathToDelete = dirPath + L"\\" + findData.cFileName;

                DWORD attributes = GetFileAttributesW(fullPathToDelete.c_str());
                if (attributes != INVALID_FILE_ATTRIBUTES) {
                    if (attributes & FILE_ATTRIBUTE_READONLY) {
                        SetFileAttributesW(fullPathToDelete.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY);
                    }
                }

                DeleteFileW(fullPathToDelete.c_str());
            }
        } while (FindNextFileW(hFind, &findData));

        FindClose(hFind);
    }

    // <-- [修改] 使用新的 WildcardMatch 函数
    void HandleDeleteDir(const std::wstring& pathPattern, bool ifEmpty) {
        wchar_t dirPart_w[MAX_PATH];
        wcscpy_s(dirPart_w, pathPattern.c_str());
        PathRemoveFileSpecW(dirPart_w);
        std::wstring dirPart = dirPart_w;
        std::wstring patternPart = PathFindFileNameW(pathPattern.c_str());

        if (dirPart == pathPattern) {
            dirPart = L".";
        }

        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW((dirPart + L"\\*").c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) {
            return;
        }
        do {
            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && wcscmp(findData.cFileName, L".") != 0 && wcscmp(findData.cFileName, L"..") != 0) {
                if (WildcardMatch(findData.cFileName, patternPart.c_str())) { // <-- 修改点
                    std::wstring fullPath = dirPart + L"\\" + findData.cFileName;
                    if (ifEmpty) {
                        if (PathIsDirectoryEmptyW(fullPath.c_str())) {
                            RemoveDirectoryW(fullPath.c_str());
                        }
                    } else {
                        PerformFileSystemOperation(FO_DELETE, fullPath);
                    }
                }
            }
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }

    LSTATUS RecursiveRegDeleteKey_Internal(HKEY hKeyParent, const std::wstring& subKey, REGSAM samAccess) {
        HKEY hKey;
        LSTATUS res = RegOpenKeyExW(hKeyParent, subKey.c_str(), 0, KEY_ENUMERATE_SUB_KEYS | samAccess, &hKey);
        if (res != ERROR_SUCCESS) {
            return res;
        }

        wchar_t subKeyName[MAX_PATH];
        DWORD subKeyNameSize = MAX_PATH;
        while (RegEnumKeyExW(hKey, 0, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            res = RecursiveRegDeleteKey_Internal(hKey, subKeyName, samAccess);
            if (res != ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return res;
            }
            subKeyNameSize = MAX_PATH;
        }

        RegCloseKey(hKey);
        return RegDeleteKeyExW(hKeyParent, subKey.c_str(), samAccess, 0);
    }

    void DeleteRegistryKeyTree(HKEY hRootKey, const std::wstring& subKey) {
        if (hRootKey == HKEY_LOCAL_MACHINE) {
            RecursiveRegDeleteKey_Internal(hRootKey, subKey, KEY_WOW64_64KEY);
            RecursiveRegDeleteKey_Internal(hRootKey, subKey, KEY_WOW64_32KEY);
        } else {
            RecursiveRegDeleteKey_Internal(hRootKey, subKey, 0);
        }
    }

    bool IsKeyEmptyInView(HKEY hRootKey, const std::wstring& subKey, REGSAM samAccess) {
        HKEY hKey;
        if (RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_QUERY_VALUE | samAccess, &hKey) != ERROR_SUCCESS) {
            return true;
        }
        DWORD subKeyCount = 0;
        DWORD valueCount = 0;
        RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &subKeyCount, NULL, NULL, &valueCount, NULL, NULL, NULL, NULL);
        RegCloseKey(hKey);
        return (subKeyCount == 0 && valueCount == 0);
    }

    void FindMatchingRegKeys(HKEY hRoot, const std::wstring& subKeyPattern, std::vector<std::wstring>& foundKeys) {
        std::vector<std::wstring> pathSegments;
        std::wstringstream ss(subKeyPattern);
        std::wstring segment;
        while(std::getline(ss, segment, L'\\')) {
            pathSegments.push_back(segment);
        }

        std::vector<std::wstring> pathsToSearch;
        pathsToSearch.push_back(L"");

        for (const auto& patternSegment : pathSegments) {
            std::vector<std::wstring> nextPathsToSearch;
            bool hasWildcard = (patternSegment.find(L'*') != std::wstring::npos || patternSegment.find(L'?') != std::wstring::npos);

            for (const auto& currentPath : pathsToSearch) {
                if (!hasWildcard) {
                    std::wstring nextPath = currentPath.empty() ? patternSegment : currentPath + L"\\" + patternSegment;
                    HKEY hTempKey;
                    if (RegOpenKeyExW(hRoot, nextPath.c_str(), 0, KEY_READ, &hTempKey) == ERROR_SUCCESS) {
                        nextPathsToSearch.push_back(nextPath);
                        RegCloseKey(hTempKey);
                    }
                    continue;
                }

                std::set<std::wstring> foundSubKeys;
                std::vector<REGSAM> viewsToSearch;
                if (hRoot == HKEY_LOCAL_MACHINE) {
                    viewsToSearch.push_back(KEY_WOW64_64KEY);
                    viewsToSearch.push_back(KEY_WOW64_32KEY);
                } else {
                    viewsToSearch.push_back(0);
                }

                for (REGSAM view : viewsToSearch) {
                    HKEY hKey;
                    if (RegOpenKeyExW(hRoot, currentPath.c_str(), 0, KEY_ENUMERATE_SUB_KEYS | view, &hKey) != ERROR_SUCCESS) {
                        continue;
                    }
                    wchar_t keyName[256];
                    DWORD keyNameSize = 256;
                    for (DWORD i = 0; RegEnumKeyExW(hKey, i, keyName, &keyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS; i++, keyNameSize = 256) {
                        if (WildcardMatch(keyName, patternSegment.c_str())) {
                            foundSubKeys.insert(keyName);
                        }
                    }
                    RegCloseKey(hKey);
                }

                for(const auto& subKey : foundSubKeys) {
                    nextPathsToSearch.push_back(currentPath.empty() ? subKey : currentPath + L"\\" + subKey);
                }
            }
            pathsToSearch = nextPathsToSearch;
        }
        foundKeys = pathsToSearch;
    }

    void HandleDeleteRegKey(const std::wstring& keyPattern, bool ifEmpty) {
        HKEY hRootKey;
        std::wstring rootKeyStr, subKeyPattern, valueName;
        if (!ParseRegistryPath(keyPattern, true, hRootKey, rootKeyStr, subKeyPattern, valueName)) return;

        std::vector<std::wstring> keysToDelete;
        FindMatchingRegKeys(hRootKey, subKeyPattern, keysToDelete);

        for (const auto& key : keysToDelete) {
            if (ifEmpty) {
                if (hRootKey == HKEY_LOCAL_MACHINE) {
                    if (IsKeyEmptyInView(hRootKey, key, KEY_WOW64_64KEY)) {
                        RegDeleteKeyExW(hRootKey, key.c_str(), KEY_WOW64_64KEY, 0);
                    }
                    if (IsKeyEmptyInView(hRootKey, key, KEY_WOW64_32KEY)) {
                        RegDeleteKeyExW(hRootKey, key.c_str(), KEY_WOW64_32KEY, 0);
                    }
                } else {
                    if (IsKeyEmptyInView(hRootKey, key, 0)) {
                        RegDeleteKeyW(hRootKey, key.c_str());
                    }
                }
            } else {
                DeleteRegistryKeyTree(hRootKey, key.c_str());
            }
        }
    }

    // <-- [修改] 使用新的 WildcardMatch 函数
    void HandleDeleteRegValue(const std::wstring& keyPattern, const std::wstring& valuePattern) {
        HKEY hRootKey;
        std::wstring rootKeyStr, subKeyPattern, valueName;
        if (!ParseRegistryPath(keyPattern, true, hRootKey, rootKeyStr, subKeyPattern, valueName)) return;

        std::vector<std::wstring> keysToSearch;
        FindMatchingRegKeys(hRootKey, subKeyPattern, keysToSearch);

        for (const auto& keyPath : keysToSearch) {
            std::vector<REGSAM> viewsToSearch;
            if (hRootKey == HKEY_LOCAL_MACHINE) {
                viewsToSearch.push_back(KEY_WOW64_64KEY);
                viewsToSearch.push_back(KEY_WOW64_32KEY);
            } else {
                viewsToSearch.push_back(0);
            }

            for (REGSAM view : viewsToSearch) {
                HKEY hKey;
                if (RegOpenKeyExW(hRootKey, keyPath.c_str(), 0, KEY_READ | KEY_SET_VALUE | view, &hKey) == ERROR_SUCCESS) {
                    DWORD dwValues, maxValueNameLen;
                    if (RegQueryInfoKeyW(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &dwValues, &maxValueNameLen, NULL, NULL, NULL) == ERROR_SUCCESS) {
                        std::vector<wchar_t> valNameBuffer(maxValueNameLen + 1);
                        for (DWORD i = 0; i < dwValues; ) {
                            DWORD valNameSize = (DWORD)valNameBuffer.size();
                            if (RegEnumValueW(hKey, i, valNameBuffer.data(), &valNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                                if (WildcardMatch(valNameBuffer.data(), valuePattern.c_str())) {
                                    RegDeleteValueW(hKey, valNameBuffer.data());
                                    // 删除后不递增i 因为列表会变化
                                } else {
                                    i++;
                                }
                            } else {
                                i++; // 如果枚举失败 继续下一个
                            }
                        }
                    }
                    RegCloseKey(hKey);
                }
            }
        }
    }

    void HandleCreateFile(const CreateFileOp& op) {
        if (!op.overwrite && PathFileExistsW(op.path.c_str())) {
            return;
        }

        wchar_t dirPath[MAX_PATH];
        wcscpy_s(dirPath, MAX_PATH, op.path.c_str());
        PathRemoveFileSpecW(dirPath);
        if (wcslen(dirPath) > 0) {
            SHCreateDirectoryExW(NULL, dirPath, NULL);
        }

        std::wstring lineBreak;
        if (op.format == TextFormat::Unix) lineBreak = L"\n";
        else if (op.format == TextFormat::Mac) lineBreak = L"\r";
        else lineBreak = L"\r\n";

        std::wstring content = op.content;
        const std::wstring toFind = L"{LINEBREAK}";
        size_t pos = content.find(toFind);
        while(pos != std::wstring::npos) {
            content.replace(pos, toFind.size(), lineBreak);
            pos = content.find(toFind, pos + lineBreak.size());
        }

        std::ofstream file(op.path, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) return;

        if (op.encoding == TextEncoding::UTF8_BOM) {
            file.put((char)0xEF); file.put((char)0xBB); file.put((char)0xBF);
        } else if (op.encoding == TextEncoding::UTF16_LE) {
            file.put((char)0xFF); file.put((char)0xFE);
        } else if (op.encoding == TextEncoding::UTF16_BE) {
            file.put((char)0xFE); file.put((char)0xFF);
        }

        if (op.encoding == TextEncoding::UTF8 || op.encoding == TextEncoding::UTF8_BOM) {
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, content.c_str(), (int)content.length(), NULL, 0, NULL, NULL);
            std::string utf8_str(size_needed, 0);
            WideCharToMultiByte(CP_UTF8, 0, content.c_str(), (int)content.length(), &utf8_str[0], size_needed, NULL, NULL);
            file.write(utf8_str.c_str(), utf8_str.length());
        } else if (op.encoding == TextEncoding::ANSI) {
            int size_needed = WideCharToMultiByte(CP_ACP, 0, content.c_str(), (int)content.length(), NULL, 0, NULL, NULL);
            std::string ansi_str(size_needed, 0);
            WideCharToMultiByte(CP_ACP, 0, content.c_str(), (int)content.length(), &ansi_str[0], size_needed, NULL, NULL);
            file.write(ansi_str.c_str(), ansi_str.length());
        } else { // UTF-16
            if (op.encoding == TextEncoding::UTF16_LE) {
                 file.write(reinterpret_cast<const char*>(content.c_str()), content.length() * sizeof(wchar_t));
            } else { // UTF-16 BE
                std::vector<wchar_t> swapped_content(content.begin(), content.end());
                for(wchar_t& ch : swapped_content) {
                    ch = _byteswap_ushort(ch);
                }
                file.write(reinterpret_cast<const char*>(swapped_content.data()), swapped_content.size() * sizeof(wchar_t));
            }
        }
        file.close();
    }

    void HandleCreateRegKey(const std::wstring& keyPath) {
        HKEY hRootKey;
        std::wstring rootKeyStr, subKey, valueName;
        if (!ParseRegistryPath(keyPath, true, hRootKey, rootKeyStr, subKey, valueName)) return;

        HKEY hKey;
        RegCreateKeyExW(hRootKey, subKey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
        RegCloseKey(hKey);
    }

    void HandleCreateRegValue(const CreateRegValueOp& op) {
        HKEY hRootKey;
        std::wstring rootKeyStr, subKey, ignoredValueName;

        if (!ParseRegistryPath(op.keyPath, true, hRootKey, rootKeyStr, subKey, ignoredValueName)) return;

        const wchar_t* finalValueName = (_wcsicmp(op.valueName.c_str(), L"null") == 0) ? NULL : op.valueName.c_str();

        HKEY hKey;
        if (RegCreateKeyExW(hRootKey, subKey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            if (_wcsicmp(op.typeStr.c_str(), L"REG_SZ") == 0 || _wcsicmp(op.typeStr.c_str(), L"REG_EXPAND_SZ") == 0) {
                std::wstring finalData = op.valueData;
                const std::wstring toFind = L"{LINEBREAK}";
                const std::wstring toReplace = L"\r\n";
                size_t pos = finalData.find(toFind);
                while(pos != std::wstring::npos) {
                    finalData.replace(pos, toFind.size(), toReplace);
                    pos = finalData.find(toFind, pos + toReplace.size());
                }
                DWORD type = (_wcsicmp(op.typeStr.c_str(), L"REG_SZ") == 0) ? REG_SZ : REG_EXPAND_SZ;
                RegSetValueExW(hKey, finalValueName, 0, type, (const BYTE*)finalData.c_str(), (DWORD)(finalData.length() + 1) * sizeof(wchar_t));
            } else if (_wcsicmp(op.typeStr.c_str(), L"REG_DWORD") == 0) {
                DWORD data = _wtol(op.valueData.c_str());
                RegSetValueExW(hKey, finalValueName, 0, REG_DWORD, (const BYTE*)&data, sizeof(data));
            } else if (_wcsicmp(op.typeStr.c_str(), L"REG_QWORD") == 0) {
                ULONGLONG data = 0;
                BYTE* pBytes = reinterpret_cast<BYTE*>(&data);
                std::wstringstream ss(op.valueData);
                std::wstring byteStr;
                int i = 0;
                while(i < 8 && std::getline(ss, byteStr, L',')) {
                    pBytes[i++] = (BYTE)wcstol(byteStr.c_str(), NULL, 16);
                }
                RegSetValueExW(hKey, finalValueName, 0, REG_QWORD, (const BYTE*)&data, sizeof(data));
            } else if (_wcsicmp(op.typeStr.c_str(), L"REG_BINARY") == 0) {
                std::vector<BYTE> data;
                std::wstringstream ss(op.valueData);
                std::wstring byteStr;
                while(std::getline(ss, byteStr, L',')) {
                    data.push_back((BYTE)wcstol(byteStr.c_str(), NULL, 16));
                }
                RegSetValueExW(hKey, finalValueName, 0, REG_BINARY, data.data(), (DWORD)data.size());
            } else if (_wcsicmp(op.typeStr.c_str(), L"REG_MULTI_SZ") == 0) {
                std::vector<wchar_t> buffer;
                std::wstring source = op.valueData;
                std::wstring toFind = L"{LINEBREAK}";
                size_t startPos = 0;
                size_t findPos;
                while ((findPos = source.find(toFind, startPos)) != std::wstring::npos) {
                    std::wstring segment = source.substr(startPos, findPos - startPos);
                    buffer.insert(buffer.end(), segment.begin(), segment.end());
                    buffer.push_back(L'\0');
                    startPos = findPos + toFind.length();
                }
                std::wstring lastSegment = source.substr(startPos);
                buffer.insert(buffer.end(), lastSegment.begin(), lastSegment.end());
                buffer.push_back(L'\0');
                buffer.push_back(L'\0');
                RegSetValueExW(hKey, finalValueName, 0, REG_MULTI_SZ, (const BYTE*)buffer.data(), (DWORD)buffer.size() * sizeof(wchar_t));
            }
            RegCloseKey(hKey);
        }
    }

    void HandleCopyMove(const CopyMoveOp& op) {
        if (!op.overwrite && PathFileExistsW(op.destPath.c_str())) {
            return;
        }

        wchar_t dirPath[MAX_PATH];
        wcscpy_s(dirPath, MAX_PATH, op.destPath.c_str());
        PathRemoveFileSpecW(dirPath);
        if (wcslen(dirPath) > 0) {
            SHCreateDirectoryExW(NULL, dirPath, NULL);
        }

        if (op.overwrite && PathFileExistsW(op.destPath.c_str())) {
            std::wstring backupPath = op.destPath + L"_Backup";
            if (PathIsDirectoryW(backupPath.c_str())) {
                 PerformFileSystemOperation(FO_DELETE, backupPath);
            } else {
                DeleteFileW(backupPath.c_str());
            }
            MoveFileW(op.destPath.c_str(), backupPath.c_str());
        }

        wchar_t fromPath[MAX_PATH * 2] = {0};
        wcscpy_s(fromPath, op.sourcePath.c_str());
        fromPath[op.sourcePath.length() + 1] = L'\0';

        wchar_t toPath[MAX_PATH * 2] = {0};
        wcscpy_s(toPath, op.destPath.c_str());
        toPath[op.destPath.length() + 1] = L'\0';

        SHFILEOPSTRUCTW sfos = {0};
        sfos.wFunc = op.isMove ? FO_MOVE : FO_COPY;
        sfos.pFrom = fromPath;
        sfos.pTo = toPath;
        sfos.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
        if (!op.overwrite) {
            sfos.fFlags |= FOF_RENAMEONCOLLISION;
        }
        if (sfos.wFunc == FO_COPY) {
            sfos.fFlags |= FOF_NOCONFIRMMKDIR;
        }

        SHFileOperationW(&sfos);

        std::wstring backupPath = op.destPath + L"_Backup";
        if (PathFileExistsW(backupPath.c_str())) {
            if (op.isDirectory) {
                PerformFileSystemOperation(FO_DELETE, backupPath);
            } else {
                DeleteFileW(backupPath.c_str());
            }
        }
    }

    void HandleAttributes(const AttributesOp& op) {
        SetFileAttributesW(op.path.c_str(), op.attributes);
    }

    struct FileContentInfo {
        std::vector<char> raw_bytes;
        TextEncoding encoding = TextEncoding::ANSI;
        std::wstring line_ending = L"\r\n";
    };

    bool ReadFileWithFormatDetection(const std::wstring& path, FileContentInfo& info) {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) return false;
        info.raw_bytes = std::vector<char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        if (info.raw_bytes.empty()) {
            info.encoding = TextEncoding::UTF8;
            info.line_ending = L"\r\n";
            return true;
        }

        const char* data = info.raw_bytes.data();
        const int size = static_cast<int>(info.raw_bytes.size());

        if (size >= 3 && (BYTE)data[0] == 0xEF && (BYTE)data[1] == 0xBB && (BYTE)data[2] == 0xBF) {
            info.encoding = TextEncoding::UTF8_BOM;
        } else if (size >= 2 && (BYTE)data[0] == 0xFF && (BYTE)data[1] == 0xFE) {
            info.encoding = TextEncoding::UTF16_LE;
        } else if (size >= 2 && (BYTE)data[0] == 0xFE && (BYTE)data[1] == 0xFF) {
            info.encoding = TextEncoding::UTF16_BE;
        } else {
            auto is_valid_for_codepage = [&](UINT cp) -> bool {
                if (size == 0) return true;
                int wsize = MultiByteToWideChar(cp, MB_ERR_INVALID_CHARS, data, size, NULL, 0);
                return wsize > 0;
            };

            if (is_valid_for_codepage(CP_UTF8)) {
                info.encoding = TextEncoding::UTF8;
            } else if (is_valid_for_codepage(932)) {
                info.encoding = TextEncoding::SHIFT_JIS;
            } else if (is_valid_for_codepage(949)) {
                info.encoding = TextEncoding::EUC_KR;
            } else if (is_valid_for_codepage(950)) {
                info.encoding = TextEncoding::BIG5;
            } else {
                info.encoding = TextEncoding::ANSI;
            }
        }

        std::string sample(info.raw_bytes.begin(), info.raw_bytes.begin() + min(1024, info.raw_bytes.size()));
        size_t cr_count = std::count(sample.begin(), sample.end(), '\r');
        size_t lf_count = std::count(sample.begin(), sample.end(), '\n');
        size_t crlf_count = sample.find("\r\n") != std::string::npos ? 1 : 0;

        if (crlf_count > 0 || (cr_count > 0 && cr_count == lf_count)) {
            info.line_ending = L"\r\n";
        } else if (lf_count > cr_count) {
            info.line_ending = L"\n";
        } else if (cr_count > 0) {
            info.line_ending = L"\r";
        }

        return true;
    }

    std::vector<std::wstring> GetLinesFromFile(const FileContentInfo& info) {
        std::wstring content;
        const char* start_ptr = info.raw_bytes.data();
        int byte_count = (int)info.raw_bytes.size();

        if (info.encoding == TextEncoding::UTF16_LE) {
            if (byte_count < 2) return {};
            content = std::wstring(reinterpret_cast<const wchar_t*>(start_ptr + 2), (byte_count / 2) - 1);
        } else if (info.encoding == TextEncoding::UTF16_BE) {
            if (byte_count < 2) return {};
            std::vector<wchar_t> temp_buffer(byte_count / 2);
            for(int i=0; i < byte_count/2; ++i) {
                temp_buffer[i] = _byteswap_ushort(((const wchar_t*)start_ptr)[i]);
            }
            content = std::wstring(temp_buffer.data() + 1, (byte_count / 2) - 1);
        } else {
            UINT codePage = CP_ACP;
            if (info.encoding == TextEncoding::UTF8_BOM) {
                codePage = CP_UTF8;
                if (byte_count >= 3) {
                    start_ptr += 3;
                    byte_count -= 3;
                }
            } else if (info.encoding == TextEncoding::UTF8) {
                codePage = CP_UTF8;
            } else if (info.encoding == TextEncoding::SHIFT_JIS) {
                codePage = 932;
            } else if (info.encoding == TextEncoding::EUC_KR) {
                codePage = 949;
            } else if (info.encoding == TextEncoding::BIG5) {
                codePage = 950;
            }

            if (byte_count > 0) {
                int wsize = MultiByteToWideChar(codePage, 0, start_ptr, byte_count, NULL, 0);
                content.resize(wsize);
                MultiByteToWideChar(codePage, 0, start_ptr, byte_count, &content[0], wsize);
            }
        }

        std::wstring normalized_content;
        normalized_content.reserve(content.length());
        for (size_t i = 0; i < content.length(); ++i) {
            if (content[i] == L'\r') {
                if (i + 1 < content.length() && content[i+1] == L'\n') {
                    normalized_content += L'\n';
                    i++;
                } else {
                    normalized_content += L'\n';
                }
            } else {
                normalized_content += content[i];
            }
        }

        std::vector<std::wstring> lines;
        std::wstringstream ss(normalized_content);
        std::wstring line;
        while (std::getline(ss, line, L'\n')) {
            lines.push_back(line);
        }
        if (normalized_content.empty() && !info.raw_bytes.empty()) lines.clear();
        return lines;
    }


    bool WriteFileWithFormat(const std::wstring& path, const std::vector<std::wstring>& lines, const FileContentInfo& info) {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) return false;

        if (info.encoding == TextEncoding::UTF8_BOM) {
            file.write("\xEF\xBB\xBF", 3);
        } else if (info.encoding == TextEncoding::UTF16_LE) {
            file.write("\xFF\xFE", 2);
        } else if (info.encoding == TextEncoding::UTF16_BE) {
            file.write("\xFE\xFF", 2);
        }

        for (size_t i = 0; i < lines.size(); ++i) {
            std::wstring line_to_write = lines[i];
            if (i < lines.size() - 1 || !lines.back().empty()) {
                 line_to_write += info.line_ending;
            }

            UINT codePage = 0;
            switch(info.encoding) {
                case TextEncoding::UTF8:
                case TextEncoding::UTF8_BOM:
                    codePage = CP_UTF8;
                    break;
                case TextEncoding::ANSI:
                    codePage = CP_ACP;
                    break;
                case TextEncoding::SHIFT_JIS:
                    codePage = 932;
                    break;
                case TextEncoding::EUC_KR:
                    codePage = 949;
                    break;
                case TextEncoding::BIG5:
                    codePage = 950;
                    break;
                case TextEncoding::UTF16_LE: {
                    file.write(reinterpret_cast<const char*>(line_to_write.c_str()), line_to_write.length() * sizeof(wchar_t));
                    continue;
                }
                case TextEncoding::UTF16_BE: {
                    std::vector<wchar_t> swapped_content(line_to_write.begin(), line_to_write.end());
                    for(wchar_t& ch : swapped_content) { ch = _byteswap_ushort(ch); }
                    file.write(reinterpret_cast<const char*>(swapped_content.data()), swapped_content.size() * sizeof(wchar_t));
                    continue;
                }
            }

            if (codePage != 0) {
                if (line_to_write.empty()) continue;
                int size = WideCharToMultiByte(codePage, 0, line_to_write.c_str(), -1, NULL, 0, NULL, NULL);
                if (size > 1) {
                    std::string mb_str(size - 1, 0);
                    WideCharToMultiByte(codePage, 0, line_to_write.c_str(), -1, &mb_str[0], size, NULL, NULL);
                    file.write(mb_str.c_str(), mb_str.length());
                }
            }
        }
        file.close();
        return true;
    }

    void HandleIniWrite(const IniWriteOp& op) {
        if (!PathFileExistsW(op.path.c_str())) {
            return;
        }

        FileContentInfo formatInfo;
        if (!ReadFileWithFormatDetection(op.path, formatInfo)) return;

        std::vector<std::wstring> lines = GetLinesFromFile(formatInfo);

        if (op.deleteSection) {
            std::vector<std::wstring> new_lines;
            std::wstring section_to_delete_header = L"[" + op.section + L"]";
            bool in_section_to_delete = false;

            for (const auto& l : lines) {
                std::wstring trimmed_line = trim(l);
                if (!trimmed_line.empty() && trimmed_line.front() == L'[' && trimmed_line.back() == L']') {
                    if (_wcsicmp(trimmed_line.c_str(), section_to_delete_header.c_str()) == 0) {
                        in_section_to_delete = true;
                    } else {
                        in_section_to_delete = false;
                    }
                }

                if (!in_section_to_delete) {
                    new_lines.push_back(l);
                }
            }
            WriteFileWithFormat(op.path, new_lines, formatInfo);
            return;
        }

        bool key_found_and_handled = false;
        bool is_null_section = _wcsicmp(op.section.c_str(), L"null") == 0;
        bool in_target_section = is_null_section;
        std::wstring search_section_header = L"[" + op.section + L"]";

        for (size_t i = 0; i < lines.size(); ++i) {
            std::wstring& l = lines[i];
            std::wstring trimmed_line = trim(l);

            if (!trimmed_line.empty() && trimmed_line.front() == L'[' && trimmed_line.back() == L']') {
                if (is_null_section) {
                    in_target_section = false;
                } else {
                    in_target_section = (_wcsicmp(trimmed_line.c_str(), search_section_header.c_str()) == 0);
                }
            }

            if (in_target_section) {
                size_t eq_pos = trimmed_line.find(L'=');
                if (eq_pos != std::wstring::npos) {
                    std::wstring current_key = trim(trimmed_line.substr(0, eq_pos));
                    if (_wcsicmp(current_key.c_str(), op.key.c_str()) == 0) {
                        if (_wcsicmp(op.value.c_str(), L"null") != 0) { // Modify
                            size_t original_eq_pos = l.find(L'=');
                            size_t value_start_pos = l.find_first_not_of(L" \t", original_eq_pos + 1);
                            if (value_start_pos == std::wstring::npos) { // key=
                                l = l.substr(0, original_eq_pos + 1) + op.value;
                            } else {
                                l = l.substr(0, value_start_pos) + op.value;
                            }
                        } else { // Delete
                            lines.erase(lines.begin() + i);
                            --i;
                        }
                        key_found_and_handled = true;
                        if (is_null_section) break;
                    }
                }
            }
        }

        if (!key_found_and_handled && _wcsicmp(op.value.c_str(), L"null") != 0) {
            if (is_null_section) {
                lines.insert(lines.begin(), op.key + L"=" + op.value);
            } else {
                int section_line = -1;
                for (int i = 0; i < (int)lines.size(); ++i) {
                    if (_wcsicmp(trim(lines[i]).c_str(), search_section_header.c_str()) == 0) {
                        section_line = i;
                        break;
                    }
                }
                if (section_line != -1) {
                    lines.insert(lines.begin() + section_line + 1, op.key + L"=" + op.value);
                } else {
                    if (!lines.empty() && !trim(lines.back()).empty()) {
                        lines.push_back(L"");
                    }
                    lines.push_back(search_section_header);
                    lines.push_back(op.key + L"=" + op.value);
                }
            }
        }

        WriteFileWithFormat(op.path, lines, formatInfo);
    }

    void HandleReplace(const ReplaceOp& op) {
        FileContentInfo formatInfo;
        if (!ReadFileWithFormatDetection(op.path, formatInfo)) return;

        std::vector<std::wstring> lines = GetLinesFromFile(formatInfo);
        std::wstring content;
        for(size_t i = 0; i < lines.size(); ++i) {
            content += lines[i];
            if (i < lines.size() - 1) content += L"\n";
        }

        const std::wstring toFindToken = L"{LINEBREAK}";
        const std::wstring normalizedNewline = L"\n";

        std::wstring finalFindText = op.findText;
        size_t lb_pos_find = 0;
        while ((lb_pos_find = finalFindText.find(toFindToken, lb_pos_find)) != std::wstring::npos) {
            finalFindText.replace(lb_pos_find, toFindToken.length(), normalizedNewline);
            lb_pos_find += normalizedNewline.length();
        }

        std::wstring finalReplaceText = op.replaceText;
        size_t lb_pos_replace = 0;
        while ((lb_pos_replace = finalReplaceText.find(toFindToken, lb_pos_replace)) != std::wstring::npos) {
            finalReplaceText.replace(lb_pos_replace, toFindToken.length(), normalizedNewline);
            lb_pos_replace += normalizedNewline.length();
        }

        size_t pos = 0;
        while ((pos = content.find(finalFindText, pos)) != std::wstring::npos) {
            content.replace(pos, finalFindText.length(), finalReplaceText);
            pos += finalReplaceText.length();
        }

        std::vector<std::wstring> new_lines;
        std::wstringstream ss(content);
        std::wstring line;
        while (std::getline(ss, line, L'\n')) {
            new_lines.push_back(line);
        }
        if (content.empty() && !lines.empty()) new_lines.clear();

        WriteFileWithFormat(op.path, new_lines, formatInfo);
    }

    void HandleReplaceLine(const ReplaceLineOp& op) {
        FileContentInfo formatInfo;
        if (!ReadFileWithFormatDetection(op.path, formatInfo)) return;

        std::wstring finalReplaceLine = op.replaceLine;
        const std::wstring toFindToken = L"{LINEBREAK}";
        size_t lb_pos = 0;
        while ((lb_pos = finalReplaceLine.find(toFindToken, lb_pos)) != std::wstring::npos) {
            finalReplaceLine.replace(lb_pos, toFindToken.length(), formatInfo.line_ending);
            lb_pos += formatInfo.line_ending.length();
        }

        std::vector<std::wstring> lines = GetLinesFromFile(formatInfo);
        std::vector<std::wstring> new_lines;
        for (const auto& l : lines) {
            if (l.rfind(op.lineStart, 0) == 0) {
                new_lines.push_back(finalReplaceLine);
            } else {
                new_lines.push_back(l);
            }
        }

        WriteFileWithFormat(op.path, new_lines, formatInfo);
    }

} // namespace ActionHelpers


// --- Process Management Functions ---

// Helper for single-instance wait
std::vector<HANDLE> FindNewDescendantsAndWaitTargets(
    std::set<DWORD>& trustedPids,
    const std::vector<std::wstring>& waitProcessNames,
    std::set<DWORD>& pidsToIgnore)
{
    std::vector<HANDLE> handlesToWaitOn;
    std::set<DWORD> newlyTrustedPids;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return handlesToWaitOn;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (trustedPids.count(pe32.th32ParentProcessID)) {
                newlyTrustedPids.insert(pe32.th32ProcessID);
                if (pidsToIgnore.count(pe32.th32ProcessID)) {
                    continue;
                }
                for (const auto& name : waitProcessNames) {
                    if (_wcsicmp(pe32.szExeFile, name.c_str()) == 0) {
                        HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, pe32.th32ProcessID);
                        if (hProcess) {
                            handlesToWaitOn.push_back(hProcess);
                            pidsToIgnore.insert(pe32.th32ProcessID);
                        }
                        break;
                    }
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    trustedPids.insert(newlyTrustedPids.begin(), newlyTrustedPids.end());
    return handlesToWaitOn;
}

// Helper for multi-instance wait: Scans and returns handles for all matching processes
std::vector<HANDLE> ScanForWaitProcessHandles(const std::vector<std::wstring>& processNames) {
    std::vector<HANDLE> handles;
    if (processNames.empty()) return handles;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return handles;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            for (const auto& name : processNames) {
                if (_wcsicmp(pe32.szExeFile, name.c_str()) == 0) {
                    HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        handles.push_back(hProcess);
                    }
                    break;
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return handles;
}


std::wstring GetProcessNameByPid(DWORD pid) {
    if (pid == 0) return L"";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        wchar_t processName[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, processName, &size) > 0) {
            CloseHandle(hProcess);
            return PathFindFileNameW(processName);
        }
        CloseHandle(hProcess);
    }
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


// --- Foreground Monitoring, Backup, Link, Firewall Sections ---

// <-- [新增] 用于存储解析后的备份条目的结构体
struct BackupEntry {
    std::wstring source;
    std::wstring destination;
    bool overwrite = true; // 默认为覆盖 以兼容旧格式
};

// <-- [新增] 生成格式化时间戳字符串的辅助函数
std::wstring GetTimestampString() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    std::wstringstream wss;
    wss << L"["
        << st.wYear << L"-" // 使用4位数年份和连字符
        << std::setw(2) << std::setfill(L'0') << st.wMonth << L"-"
        << std::setw(2) << std::setfill(L'0') << st.wDay << L" " // 使用空格分隔日期和时间
        << std::setw(2) << std::setfill(L'0') << st.wHour << L"."
        << std::setw(2) << std::setfill(L'0') << st.wMinute
        << L"]";
    return wss.str();
}

struct MonitorThreadData {
    std::wstring foregroundAppName;
    std::vector<std::wstring> suspendProcesses;
};

static std::vector<std::wstring>* g_suspendProcesses = nullptr;
static std::wstring g_foregroundAppName;
static std::atomic<bool> g_areProcessesSuspended = false;

VOID CALLBACK WinEventProc(
    HWINEVENTHOOK hWinEventHook,
    DWORD event,
    HWND hwnd,
    LONG idObject,
    LONG idChild,
    DWORD dwEventThread,
    DWORD dwmsEventTime)
{
    if (event == EVENT_SYSTEM_FOREGROUND && hwnd) {
        DWORD foregroundPid = 0;
        GetWindowThreadProcessId(hwnd, &foregroundPid);
        if (foregroundPid > 0) {
            std::wstring foregroundProcessName = GetProcessNameByPid(foregroundPid);

            if (_wcsicmp(foregroundProcessName.c_str(), g_foregroundAppName.c_str()) == 0) {
                if (!g_areProcessesSuspended) {
                    SetAllProcessesState(*g_suspendProcesses, true);
                    g_areProcessesSuspended = true;
                }
            } else {
                if (g_areProcessesSuspended.exchange(false)) {
                    SetAllProcessesState(*g_suspendProcesses, false);
                }
            }
        }
    }
}

DWORD WINAPI ForegroundMonitorThread(LPVOID lpParam) {
    MonitorThreadData* data = static_cast<MonitorThreadData*>(lpParam);

    g_suspendProcesses = &(data->suspendProcesses);
    g_foregroundAppName = data->foregroundAppName;
    g_areProcessesSuspended = false;

    HWINEVENTHOOK hHook = SetWinEventHook(
        EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND,
        NULL, WinEventProc, 0, 0, WINEVENT_OUTOFCONTEXT);

    if (hHook) {
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        UnhookWinEvent(hHook);
    }

    if (g_areProcessesSuspended.exchange(false)) {
        SetAllProcessesState(*g_suspendProcesses, false);
    }

    return 0;
}

// <-- [修改] 解析备份条目 以支持新的 "overwrite" 选项
BackupEntry ParseBackupEntry(const std::wstring& entry, const std::map<std::wstring, std::wstring>& variables) {
    BackupEntry result;
    const std::wstring delimiter = L" :: ";

    auto parts = split_string(entry, delimiter);

    if (parts.size() < 2) return {}; // 至少需要源和目标

    result.source = ResolveToAbsolutePath(ExpandVariables(parts[0], variables), variables);
    result.destination = ResolveToAbsolutePath(ExpandVariables(parts[1], variables), variables);

    if (parts.size() > 2 && _wcsicmp(parts[2].c_str(), L"no overwrite") == 0) {
        result.overwrite = false;
    } else {
        result.overwrite = true; // 默认或显式 "overwrite"
    }

    if (result.source.empty() || result.destination.empty()) return {};

    return result;
}

// <-- [修改] 目录备份函数 以处理新的 "no overwrite" 逻辑
void PerformDirectoryBackup(const BackupEntry& entry) {
    if (!PathFileExistsW(entry.source.c_str())) return;

    if (entry.overwrite) {
        // 保持原始的覆盖逻辑
        std::wstring backupDest = entry.destination + L"_Backup";
        if (PathFileExistsW(entry.destination.c_str())) {
            MoveFileW(entry.destination.c_str(), backupDest.c_str());
        }
        PerformFileSystemOperation(FO_COPY, entry.source, entry.destination);
        if (PathFileExistsW(backupDest.c_str())) {
            PerformFileSystemOperation(FO_DELETE, backupDest);
        }
    } else {
        // 新的、已修正的时间戳备份逻辑
        wchar_t destParentDir[MAX_PATH];
        wcscpy_s(destParentDir, entry.destination.c_str());
        PathRemoveFileSpecW(destParentDir); // 获取目标父目录, e.g., "Data\#Backup"

        const wchar_t* destName = PathFindFileNameW(entry.destination.c_str()); // 获取目标名称, e.g., "Portable"

        // 直接构建最终的、带时间戳的目标路径
        std::wstring finalDestPath = std::wstring(destParentDir) + L"\\" + GetTimestampString() + destName;

        // 将源目录直接复制到最终的时间戳路径
        PerformFileSystemOperation(FO_COPY, entry.source, finalDestPath);
    }
}

// <-- [修改] 文件备份函数 以处理新的 "no overwrite" 逻辑
void PerformFileBackup(const BackupEntry& entry) {
    if (!PathFileExistsW(entry.source.c_str())) return;

    if (entry.overwrite) {
        // 保持原始的覆盖逻辑
        std::wstring backupDest = entry.destination + L"_Backup";
        if (PathFileExistsW(entry.destination.c_str())) {
            MoveFileW(entry.destination.c_str(), backupDest.c_str());
        }
        if (CopyFileW(entry.source.c_str(), entry.destination.c_str(), FALSE)) {
            if (PathFileExistsW(backupDest.c_str())) {
                DeleteFileW(backupDest.c_str());
            }
        }
    } else {
        // 新的、已修正的时间戳备份逻辑
        wchar_t destParentDir[MAX_PATH];
        wcscpy_s(destParentDir, entry.destination.c_str());
        PathRemoveFileSpecW(destParentDir); // 获取目标父目录, e.g., "Data\#Backup"

        const wchar_t* destName = PathFindFileNameW(entry.destination.c_str()); // 获取目标名称, e.g., "Portable.ini"

        // 直接构建最终的、带时间戳的目标路径
        std::wstring finalDestPath = std::wstring(destParentDir) + L"\\" + GetTimestampString() + destName;

        // 将源文件直接复制到最终的时间戳路径
        CopyFileW(entry.source.c_str(), finalDestPath.c_str(), FALSE);
    }
}

// <-- [修改] BackupThreadData 结构体以使用新的 BackupEntry
struct BackupThreadData {
    std::atomic<bool>* shouldStop;
    std::atomic<bool>* isWorking;
    int backupInterval;
    std::vector<BackupEntry> backupDirs;  // <-- 修改点
    std::vector<BackupEntry> backupFiles; // <-- 修改点
};

// <-- [修改] 备份工作线程 以调用新的备份函数
DWORD WINAPI BackupWorkerThread(LPVOID lpParam) {
    BackupThreadData* data = static_cast<BackupThreadData*>(lpParam);
    while (!*(data->shouldStop)) {
        Sleep(data->backupInterval);
        if (*(data->shouldStop)) break;
        *(data->isWorking) = true;
        for (const auto& entry : data->backupDirs) {
            PerformDirectoryBackup(entry);
        }
        for (const auto& entry : data->backupFiles) {
            PerformFileBackup(entry);
        }
        *(data->isWorking) = false;
    }
    return 0;
}

void CreateHardLinksRecursive(const std::wstring& srcDir, const std::wstring& destDir, std::vector<std::pair<std::wstring, std::wstring>>& createdLinks) {
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
            CreateHardLinksRecursive(srcPath, destPath, createdLinks);
        } else {
            if (CreateHardLinkW(destPath.c_str(), srcPath.c_str(), NULL)) {
                createdLinks.push_back({destPath, srcPath});
            }
        }
    } while (FindNextFileW(hFind, &findData));
    FindClose(hFind);
}

void CreateFirewallRule(FirewallOp& op) {
    INetFwPolicy2* pFwPolicy = NULL;
    INetFwRules* pFwRules = NULL;
    INetFwRule* pFwRule = NULL;
    BSTR bstrRuleName = NULL;
    BSTR bstrAppPath = NULL;

    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pFwPolicy);
    if (FAILED(hr)) goto cleanup;

    hr = pFwPolicy->get_Rules(&pFwRules);
    if (FAILED(hr)) goto cleanup;

    hr = CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), (void**)&pFwRule);
    if (FAILED(hr)) goto cleanup;

    bstrRuleName = SysAllocString(op.ruleName.c_str());
    bstrAppPath = SysAllocString(op.appPath.c_str());

    pFwRule->put_Name(bstrRuleName);
    pFwRule->put_ApplicationName(bstrAppPath);
    pFwRule->put_Direction(op.direction);
    pFwRule->put_Action(op.action);
    pFwRule->put_Enabled(VARIANT_TRUE);
    pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
    pFwRule->put_Profiles(NET_FW_PROFILE2_ALL);

    hr = pFwRules->Add(pFwRule);
    if (SUCCEEDED(hr)) {
        op.ruleCreated = true;
    }

cleanup:
    if (bstrRuleName) SysFreeString(bstrRuleName);
    if (bstrAppPath) SysFreeString(bstrAppPath);
    if (pFwRule) pFwRule->Release();
    if (pFwRules) pFwRules->Release();
    if (pFwPolicy) pFwPolicy->Release();
}

void DeleteFirewallRule(const std::wstring& ruleName) {
    INetFwPolicy2* pFwPolicy = NULL;
    INetFwRules* pFwRules = NULL;
    IEnumVARIANT* pEnum = NULL;
    IUnknown* pUnknown = NULL;
    HRESULT hr = S_OK;

    hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pFwPolicy);
    if (FAILED(hr)) goto cleanup;

    hr = pFwPolicy->get_Rules(&pFwRules);
    if (FAILED(hr)) goto cleanup;

    int rulesToDelete = 0;
    hr = pFwRules->get__NewEnum(&pUnknown);
    if (FAILED(hr) || !pUnknown) goto cleanup;

    hr = pUnknown->QueryInterface(__uuidof(IEnumVARIANT), (void**)&pEnum);
    if (FAILED(hr) || !pEnum) goto cleanup;

    VARIANT var;
    VariantInit(&var);
    while (pEnum->Next(1, &var, NULL) == S_OK) {
        if (var.vt == VT_DISPATCH) {
            INetFwRule* pFwRule = NULL;
            hr = var.pdispVal->QueryInterface(__uuidof(INetFwRule), (void**)&pFwRule);
            if (SUCCEEDED(hr)) {
                BSTR bstrName = NULL;
                hr = pFwRule->get_Name(&bstrName);
                if (SUCCEEDED(hr) && bstrName) {
                    if (_wcsicmp(bstrName, ruleName.c_str()) == 0) {
                        rulesToDelete++;
                    }
                    SysFreeString(bstrName);
                }
                pFwRule->Release();
            }
        }
        VariantClear(&var);
    }

    if (rulesToDelete > 0) {
        BSTR bstrRuleName = SysAllocString(ruleName.c_str());
        if (bstrRuleName) {
            for (int i = 0; i < rulesToDelete; i++) {
                pFwRules->Remove(bstrRuleName);
            }
            SysFreeString(bstrRuleName);
        }
    }

cleanup:
    if (pUnknown) pUnknown->Release();
    if (pEnum) pEnum->Release();
    if (pFwRules) pFwRules->Release();
    if (pFwPolicy) pFwPolicy->Release();
}

// --- Unified Operation Handlers ---

void PerformStartupOperation(StartupShutdownOperationData& opData) {
    std::visit([&](auto& arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, FileOp>) {
            wchar_t dirPath[MAX_PATH];
            wcscpy_s(dirPath, MAX_PATH, arg.destPath.c_str());
            PathRemoveFileSpecW(dirPath);
            if (wcslen(dirPath) > 0) {
                SHCreateDirectoryExW(NULL, dirPath, NULL);
            }

            if (PathFileExistsW(arg.destPath.c_str())) {
                MoveFileW(arg.destPath.c_str(), arg.destBackupPath.c_str());
                arg.destBackupCreated = true;
            }
            if (PathFileExistsW(arg.sourcePath.c_str())) {
                if (arg.wasMoved) {
                    if (arg.isDirectory) PerformFileSystemOperation(FO_MOVE, arg.sourcePath, arg.destPath);
                    else MoveFileW(arg.sourcePath.c_str(), arg.destPath.c_str());
                } else {
                    if (arg.isDirectory) PerformFileSystemOperation(FO_COPY, arg.sourcePath, arg.destPath);
                    else CopyFileW(arg.sourcePath.c_str(), arg.destPath.c_str(), FALSE);
                }
            }
        } else if constexpr (std::is_same_v<T, RestoreOnlyFileOp>) {
            if (PathFileExistsW(arg.targetPath.c_str())) {
                if (MoveFileW(arg.targetPath.c_str(), arg.backupPath.c_str())) {
                    arg.backupCreated = true;
                }
            }
        } else if constexpr (std::is_same_v<T, RegistryOp>) {
            bool renamed = false;
            if (arg.isKey) {
                // <-- [修改] 修正了函数调用 移除了多余的第一个参数
                renamed = RenameRegistryKey(arg.hRootKey, arg.subKey, arg.backupName);
            } else {
                renamed = RenameRegistryValue(arg.hRootKey, arg.subKey, arg.valueName, arg.backupName);
            }
            if (renamed) {
                arg.backupCreated = true;
            }
            if (arg.isSaveRestore) {
                ImportRegistryFile(arg.filePath);
            }
        } else if constexpr (std::is_same_v<T, LinkOp>) {
            if (!arg.traversalMode.empty()) {
                SHCreateDirectoryExW(NULL, arg.linkPath.c_str(), NULL);
                WIN32_FIND_DATAW findData;
                std::wstring searchPath = arg.targetPath + L"\\*";
                HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        std::wstring itemName = findData.cFileName;
                        if (itemName == L"." || itemName == L"..") continue;
                        bool isItemDirectory = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
                        bool shouldLink = false;
                        if (_wcsicmp(arg.traversalMode.c_str(), L"all") == 0) shouldLink = true;
                        else if (_wcsicmp(arg.traversalMode.c_str(), L"dir") == 0) shouldLink = isItemDirectory;
                        else if (_wcsicmp(arg.traversalMode.c_str(), L"file") == 0) shouldLink = !isItemDirectory;

                        if (arg.isHardlink && isItemDirectory) shouldLink = false;

                        if (shouldLink) {
                            std::wstring srcFullPath = arg.targetPath + L"\\" + itemName;
                            std::wstring destFullPath = arg.linkPath + L"\\" + itemName;
                            if (PathFileExistsW(destFullPath.c_str())) {
                                std::wstring backupDestPath = destFullPath + L"_Backup";
                                MoveFileW(destFullPath.c_str(), backupDestPath.c_str());
                                arg.backedUpPaths.push_back({backupDestPath, destFullPath});
                                arg.backupCreated = true;
                            }
                            if (arg.isHardlink) {
                                if (CreateHardLinkW(destFullPath.c_str(), srcFullPath.c_str(), NULL)) {
                                    arg.createdLinks.push_back({destFullPath, L""});
                                }
                            } else {
                                DWORD flags = isItemDirectory ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0;
                                if (CreateSymbolicLinkW(destFullPath.c_str(), srcFullPath.c_str(), flags)) {
                                    arg.createdLinks.push_back({destFullPath, L""});
                                }
                            }
                        }
                    } while (FindNextFileW(hFind, &findData));
                    FindClose(hFind);
                }
            } else {
                wchar_t dirPath[MAX_PATH];
                wcscpy_s(dirPath, MAX_PATH, arg.linkPath.c_str());
                PathRemoveFileSpecW(dirPath);
                if (wcslen(dirPath) > 0) SHCreateDirectoryExW(NULL, dirPath, NULL);

                if (PathFileExistsW(arg.linkPath.c_str())) {
                    if (MoveFileW(arg.linkPath.c_str(), arg.backupPath.c_str())) {
                        arg.backedUpPaths.push_back({arg.backupPath, arg.linkPath});
                        arg.backupCreated = true;
                    }
                }

                if (arg.performMoveOnCleanup) {
                    // DO NOTHING. Let the application create the directory at linkPath.
                } else {
                    if (arg.isHardlink) {
                        if (arg.isDirectory) {
                            CreateDirectoryW(arg.linkPath.c_str(), NULL);
                            CreateHardLinksRecursive(arg.targetPath, arg.linkPath, arg.createdLinks);
                        } else {
                            CreateHardLinkW(arg.linkPath.c_str(), arg.targetPath.c_str(), NULL);
                        }
                    } else {
                        DWORD flags = arg.isDirectory ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0;
                        CreateSymbolicLinkW(arg.linkPath.c_str(), arg.targetPath.c_str(), flags);
                    }
                }
            }
        } else if constexpr (std::is_same_v<T, FirewallOp>) {
            CreateFirewallRule(arg);
        }
    }, opData);
}

void PerformShutdownOperation(StartupShutdownOperationData& opData) {
    std::visit([&](auto& arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, FileOp>) {
            if (arg.wasMoved) {
                if (PathFileExistsW(arg.destPath.c_str())) {
                    if (PathFileExistsW(arg.sourcePath.c_str())) {
                         if (arg.isDirectory) PerformFileSystemOperation(FO_DELETE, arg.sourcePath);
                         else DeleteFileW(arg.sourcePath.c_str());
                    }
                    if (arg.isDirectory) PerformFileSystemOperation(FO_MOVE, arg.destPath, arg.sourcePath);
                    else MoveFileW(arg.destPath.c_str(), arg.sourcePath.c_str());
                }
            } else {
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
            }
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
            if (arg.isKey) ActionHelpers::DeleteRegistryKeyTree(arg.hRootKey, arg.subKey.c_str());
            else {
                HKEY hKey;
                if (RegOpenKeyExW(arg.hRootKey, arg.subKey.c_str(), 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, arg.valueName.c_str());
                    RegCloseKey(hKey);
                }
            }
            if (arg.backupCreated) {
                if (arg.isKey) {
                    // <-- [修改] 修正了函数调用 移除了多余的第一个参数
                    RenameRegistryKey(arg.hRootKey, arg.backupName, arg.subKey);
                }
                else {
                    RenameRegistryValue(arg.hRootKey, arg.subKey, arg.backupName, arg.valueName);
                }
            }
        } else if constexpr (std::is_same_v<T, LinkOp>) {
            if (arg.performMoveOnCleanup) {
                if (PathFileExistsW(arg.linkPath.c_str())) {
                    wchar_t targetParentDir[MAX_PATH];
                    wcscpy_s(targetParentDir, MAX_PATH, arg.targetPath.c_str());
                    PathRemoveFileSpecW(targetParentDir);
                    if (wcslen(targetParentDir) > 0) {
                        SHCreateDirectoryExW(NULL, targetParentDir, NULL);
                    }
                    MoveFileW(arg.linkPath.c_str(), arg.targetPath.c_str());
                }
            } else if (!arg.traversalMode.empty()) {
                for (const auto& linkPair : arg.createdLinks) {
                    const std::wstring& pathToDelete = linkPair.first;
                    if (PathIsDirectoryW(pathToDelete.c_str())) {
                        RemoveDirectoryW(pathToDelete.c_str());
                    } else {
                        DeleteFileW(pathToDelete.c_str());
                    }
                }
            } else {
                if (arg.isHardlink && arg.isDirectory) {
                    for (auto it = arg.createdLinks.rbegin(); it != arg.createdLinks.rend(); ++it) {
                        DeleteFileW(it->first.c_str());
                    }
                    PerformFileSystemOperation(FO_DELETE, arg.linkPath);
                } else {
                    if (arg.isDirectory) PerformFileSystemOperation(FO_DELETE, arg.linkPath);
                    else DeleteFileW(arg.linkPath.c_str());
                }
            }
            if (arg.backupCreated) {
                for (const auto& backupPair : arg.backedUpPaths) {
                    if (PathFileExistsW(backupPair.first.c_str())) {
                        MoveFileW(backupPair.first.c_str(), backupPair.second.c_str());
                    }
                }
            }
        } else if constexpr (std::is_same_v<T, FirewallOp>) {
            if (arg.ruleCreated) {
                DeleteFirewallRule(arg.ruleName);
            }
        }
    }, opData);
}


// --- Master Parser ---
void ParseIniSections(const std::wstring& iniContent, std::map<std::wstring, std::wstring>& variables,
                      std::vector<BeforeOperation>& beforeOps,
                      std::vector<AfterOperation>& afterOps,
                      BackupThreadData& backupData) {

    const std::wstring delimiter = L" :: ";
    std::wstringstream stream(iniContent);
    std::wstring line;
    enum class Section { None, General, Before, After };
    Section currentSection = Section::None;

    auto parse_action_op = [&](const std::wstring& key, const std::wstring& value) -> std::optional<ActionOpData> {
        if (_wcsicmp(key.c_str(), L"run") == 0) {
            auto parts = split_string(value, delimiter);
            if (!parts.empty() && !parts[0].empty()) {
                RunOp op;
                op.programPath = parts[0];
                op.wait = (parts.size() > 1 && _wcsicmp(parts[1].c_str(), L"wait") == 0);
                op.hide = (parts.size() > 2 && _wcsicmp(parts[2].c_str(), L"hide") == 0);
                op.commandLine = (parts.size() > 3 && _wcsicmp(parts[3].c_str(), L"null") != 0) ? parts[3] : L"";
                op.workDir = (parts.size() > 4 && !parts[4].empty()) ? parts[4] : L"";
                return op;
            }
        }
        else if (_wcsicmp(key.c_str(), L"regimport") == 0) {
            return RegImportOp{value};
        } else if (_wcsicmp(key.c_str(), L"regdll") == 0) {
            auto parts = split_string(value, delimiter);
            if (!parts.empty() && !parts[0].empty()) {
                RegDllOp op; op.dllPath = parts[0];
                op.unregister = (parts.size() > 1 && _wcsicmp(parts[1].c_str(), L"unregister") == 0);
                return op;
            }
        } else if (_wcsicmp(key.c_str(), L"-file") == 0) {
            return DeleteFileOp{value};
        } else if (_wcsicmp(key.c_str(), L"-dir") == 0) {
            auto parts = split_string(value, delimiter);
            DeleteDirOp op; op.pathPattern = parts[0];
            op.ifEmpty = (parts.size() > 1 && _wcsicmp(parts[1].c_str(), L"ifempty") == 0);
            return op;
        } else if (_wcsicmp(key.c_str(), L"-regkey") == 0) {
            auto parts = split_string(value, delimiter);
            DeleteRegKeyOp op; op.keyPattern = parts[0];
            op.ifEmpty = (parts.size() > 1 && _wcsicmp(parts[1].c_str(), L"ifempty") == 0);
            return op;
        } else if (_wcsicmp(key.c_str(), L"-regvalue") == 0) {
            auto parts = split_string(value, delimiter);
            if (parts.size() == 2) {
                return DeleteRegValueOp{parts[0], parts[1]};
            }
        } else if (_wcsicmp(key.c_str(), L"+dir") == 0) {
            return CreateDirOp{value};
        } else if (_wcsicmp(key.c_str(), L"delay") == 0) {
            return DelayOp{_wtoi(value.c_str())};
        } else if (_wcsicmp(key.c_str(), L"killprocess") == 0) {
            // <-- [修改] 增强 killprocess 的解析逻辑以支持 "path" 关键字
            auto parts = split_string(value, delimiter);
            KillProcessOp op;
            if (parts.empty()) {
                return std::nullopt;
            }

            op.processPattern = parts[0];

            if (parts.size() > 1) {
                if (_wcsicmp(parts[1].c_str(), L"ppid") == 0) {
                    op.checkParentProcess = true;
                } else if (_wcsicmp(parts[1].c_str(), L"path") == 0) {
                    op.checkProcessPath = true;
                    if (parts.size() > 2 && !parts[2].empty()) {
                        // 用户提供了路径 直接使用
                        op.basePath = parts[2];
                    } else {
                        // 用户未提供路径 使用默认的 {YAPROOT}
                        op.basePath = L"{YAPROOT}";
                    }
                }
            }
            return op;
        }
        else if (_wcsicmp(key.c_str(), L"+file") == 0) {
            auto parts = split_string(value, delimiter);
            if (parts.empty() || parts[0].empty()) {
                return std::nullopt;
            }

            CreateFileOp op;
            op.path = parts[0];
            op.overwrite = (parts.size() > 1) ? (_wcsicmp(parts[1].c_str(), L"overwrite") == 0) : false;

            std::wstring formatStr = (parts.size() > 2) ? parts[2] : L"win";
            if (_wcsicmp(formatStr.c_str(), L"unix") == 0) op.format = TextFormat::Unix;
            else if (_wcsicmp(formatStr.c_str(), L"mac") == 0) op.format = TextFormat::Mac;
            else op.format = TextFormat::Win;

            std::wstring encodingStr = (parts.size() > 3) ? parts[3] : L"utf8";
            if (_wcsicmp(encodingStr.c_str(), L"utf8bom") == 0) op.encoding = TextEncoding::UTF8_BOM;
            else if (_wcsicmp(encodingStr.c_str(), L"utf16le") == 0) op.encoding = TextEncoding::UTF16_LE;
            else if (_wcsicmp(encodingStr.c_str(), L"utf16be") == 0) op.encoding = TextEncoding::UTF16_BE;
            else if (_wcsicmp(encodingStr.c_str(), L"ansi") == 0) op.encoding = TextEncoding::ANSI;
            else op.encoding = TextEncoding::UTF8;

            op.content = (parts.size() > 4) ? parts[4] : L"";

            return op;
        }
        else if (_wcsicmp(key.c_str(), L"+regkey") == 0) {
            return CreateRegKeyOp{value};
        }
        else if (_wcsicmp(key.c_str(), L"+regvalue") == 0) {
            auto parts = split_string(value, delimiter);
            if (parts.size() >= 3) {
                std::wstring valueData = (parts.size() > 3) ? parts[3] : L"";
                return CreateRegValueOp{parts[0], parts[1], valueData, parts[2]};
            }
        }
        else if (_wcsicmp(key.c_str(), L"<-dir") == 0 || _wcsicmp(key.c_str(), L"->dir") == 0 || _wcsicmp(key.c_str(), L"<-file") == 0 || _wcsicmp(key.c_str(), L"->file") == 0) {
            auto parts = split_string(value, delimiter);
            if (parts.size() >= 2) {
                CopyMoveOp op;
                op.isDirectory = (key.find(L"dir") != std::wstring::npos);
                bool is_reversed = (key.find(L"->") != std::wstring::npos);
                op.destPath = is_reversed ? parts[1] : parts[0];
                op.sourcePath = is_reversed ? parts[0] : parts[1];
                op.overwrite = true;
                op.isMove = false;
                for (size_t i = 2; i < parts.size(); ++i) {
                    if (_wcsicmp(parts[i].c_str(), L"no overwrite") == 0) op.overwrite = false;
                    if (_wcsicmp(parts[i].c_str(), L"overwrite") == 0) op.overwrite = true;
                    if (_wcsicmp(parts[i].c_str(), L"move") == 0) op.isMove = true;
                }
                return op;
            }
        } else if (_wcsicmp(key.c_str(), L"attributes") == 0) {
            auto parts = split_string(value, delimiter);
            if (!parts.empty()) {
                AttributesOp op;
                op.path = parts[0];
                op.attributes = FILE_ATTRIBUTE_NORMAL;
                if (parts.size() > 1) {
                    op.attributes = 0;
                    auto attr_parts = split_string(parts[1], L",");
                    for (const auto& attr : attr_parts) {
                        if (_wcsicmp(attr.c_str(), L"hidden") == 0) op.attributes |= FILE_ATTRIBUTE_HIDDEN;
                        if (_wcsicmp(attr.c_str(), L"normal") == 0) op.attributes |= FILE_ATTRIBUTE_NORMAL;
                        if (_wcsicmp(attr.c_str(), L"readonly") == 0) op.attributes |= FILE_ATTRIBUTE_READONLY;
                        if (_wcsicmp(attr.c_str(), L"system") == 0) op.attributes |= FILE_ATTRIBUTE_SYSTEM;
                    }
                    if (op.attributes == 0) op.attributes = FILE_ATTRIBUTE_NORMAL;
                }
                return op;
            }
        }
        else if (_wcsicmp(key.c_str(), L"iniwrite") == 0) {
            auto parts = split_string(value, delimiter);
            if (parts.size() >= 2) {
                IniWriteOp op;
                op.path = parts[0];
                op.section = parts[1];

                if (op.section.rfind(L"--", 0) == 0) {
                    op.deleteSection = true;
                    op.section = op.section.substr(2);
                    op.key = L"";
                    op.value = L"";
                    return op;
                }

                if (parts.size() >= 3) {
                    op.deleteSection = false;
                    op.key = parts[2];
                    op.value = (parts.size() > 3) ? parts[3] : L"null";
                    return op;
                }
            }
        }
        else if (_wcsicmp(key.c_str(), L"replace") == 0) {
            auto parts = split_string(value, delimiter);
            if (parts.size() == 3) {
                return ReplaceOp{parts[0], parts[1], parts[2]};
            }
        } else if (_wcsicmp(key.c_str(), L"replaceline") == 0) {
            const std::wstring local_delimiter = L" :: ";
            size_t first_delim_pos = value.find(local_delimiter);
            if (first_delim_pos != std::wstring::npos) {
                size_t second_delim_pos = value.find(local_delimiter, first_delim_pos + local_delimiter.length());
                if (second_delim_pos != std::wstring::npos) {
                    std::wstring path = trim(value.substr(0, first_delim_pos));
                    std::wstring lineStart = value.substr(first_delim_pos + local_delimiter.length(), second_delim_pos - (first_delim_pos + local_delimiter.length()));
                    std::wstring replaceLine = value.substr(second_delim_pos + local_delimiter.length());
                    return ReplaceLineOp{path, lineStart, replaceLine};
                }
            }
        }
        else if (_wcsicmp(key.c_str(), L"envvar") == 0) {
            auto parts = split_string(value, delimiter);
            if (parts.size() == 2) {
                return EnvVarOp{parts[0], parts[1]};
            }
        }
        return std::nullopt;
    };


    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty() || line[0] == L';' || line[0] == L'#') continue;

        if (line[0] == L'[' && line.back() == L']') {
            if (_wcsicmp(line.c_str(), L"[General]") == 0) currentSection = Section::General;
            else if (_wcsicmp(line.c_str(), L"[Before]") == 0) currentSection = Section::Before;
            else if (_wcsicmp(line.c_str(), L"[After]") == 0) currentSection = Section::After;
            else currentSection = Section::None;
            continue;
        }

        size_t delimiterPos = line.find(L'=');
        if (delimiterPos == std::wstring::npos) continue;

        std::wstring key = trim(line.substr(0, delimiterPos));
        std::wstring value = line.substr(delimiterPos + 1);

        if (_wcsicmp(key.c_str(), L"uservar") == 0) {
            if (currentSection == Section::Before || currentSection == Section::After) {
                auto parts = split_string(value, delimiter);
                if (parts.size() == 2) {
                    variables[parts[0]] = ExpandVariables(parts[1], variables);
                }
            }
            continue;
        }

        if (_wcsicmp(key.c_str(), L"stringreplace") == 0) {
            if (currentSection == Section::Before || currentSection == Section::After) {
                auto parts = split_string(value, delimiter);
                if (parts.size() == 4) {
                    std::wstring result = ExpandVariables(parts[0], variables);
                    std::wstring toFind = parts[1];
                    std::wstring toReplace = (_wcsicmp(parts[2].c_str(), L"null") == 0) ? L"" : parts[2];
                    size_t pos = result.find(toFind);
                    while(pos != std::wstring::npos) {
                        result.replace(pos, toFind.size(), toReplace);
                        pos = result.find(toFind, pos + toReplace.size());
                    }
                    variables[parts[3]] = result;
                }
            }
            continue;
        }

        value = trim(value);

        if (currentSection == Section::Before) {
            BeforeOperation beforeOp;
            bool op_created = false;

            if (_wcsicmp(key.c_str(), L"hardlink") == 0 || _wcsicmp(key.c_str(), L"symlink") == 0) {
                LinkOp l_op;
                l_op.isHardlink = (_wcsicmp(key.c_str(), L"hardlink") == 0);
                auto parts = split_string(value, delimiter);
                if (parts.size() >= 2) {
                    l_op.linkPath = ResolveToAbsolutePath(ExpandVariables(parts[0], variables), variables);
                    l_op.targetPath = ResolveToAbsolutePath(ExpandVariables(parts[1], variables), variables);
                    if (parts.size() > 2) {
                        l_op.traversalMode = trim(parts[2]);
                    }
                    if (!l_op.traversalMode.empty()) {
                        l_op.isDirectory = true;
                    } else {
                        l_op.isDirectory = (parts[0].back() == L'\\' || parts[1].back() == L'\\');
                    }

                    if (l_op.isDirectory) {
                        if (l_op.linkPath.back() == L'\\') l_op.linkPath.pop_back();
                        if (l_op.targetPath.back() == L'\\') l_op.targetPath.pop_back();
                    }

                    l_op.backupPath = l_op.linkPath + L"_Backup";

                    if (l_op.isHardlink && l_op.traversalMode.empty()) {
                        if (!PathFileExistsW(l_op.targetPath.c_str())) {
                            l_op.performMoveOnCleanup = true;
                        }
                    }

                    beforeOp.data = l_op;
                    op_created = true;
                }
            } else if (_wcsicmp(key.c_str(), L"firewall") == 0) {
                auto parts = split_string(value, delimiter);
                if (parts.size() == 4) {
                    FirewallOp f_op;
                    f_op.ruleName = ExpandVariables(parts[0], variables);
                    if (_wcsicmp(parts[1].c_str(), L"in") == 0) f_op.direction = NET_FW_RULE_DIR_IN;
                    else if (_wcsicmp(parts[1].c_str(), L"out") == 0) f_op.direction = NET_FW_RULE_DIR_OUT;
                    else continue;
                    if (_wcsicmp(parts[2].c_str(), L"allow") == 0) f_op.action = NET_FW_ACTION_ALLOW;
                    else if (_wcsicmp(parts[2].c_str(), L"block") == 0) f_op.action = NET_FW_ACTION_BLOCK;
                    else continue;
                    f_op.appPath = ResolveToAbsolutePath(ExpandVariables(parts[3], variables), variables);
                    beforeOp.data = f_op; op_created = true;
                }
            } else if (_wcsicmp(key.c_str(), L"(regvalue)") == 0 || _wcsicmp(key.c_str(), L"(regkey)") == 0 || _wcsicmp(key.c_str(), L"regvalue") == 0 || _wcsicmp(key.c_str(), L"regkey") == 0) {
                RegistryOp r_op; r_op.isKey = (key.find(L"key") != std::wstring::npos); r_op.isSaveRestore = (key.front() != L'(');
                std::wstring regPathRaw = value;
                if (r_op.isSaveRestore) {
                    auto parts = split_string(value, delimiter);
                    if (!parts.empty()) {
                        regPathRaw = parts[0];
                        if (parts.size() > 1) r_op.filePath = ResolveToAbsolutePath(ExpandVariables(parts[1], variables), variables);
                    }
                }
                if (ParseRegistryPath(ExpandVariables(regPathRaw, variables), r_op.isKey, r_op.hRootKey, r_op.rootKeyStr, r_op.subKey, r_op.valueName)) {
                    r_op.backupName = (r_op.isKey ? r_op.subKey : r_op.valueName) + L"_Backup";
                    beforeOp.data = r_op; op_created = true;
                }
            } else if (_wcsicmp(key.c_str(), L"(file)") == 0 || _wcsicmp(key.c_str(), L"(dir)") == 0) {
                RestoreOnlyFileOp ro_op; ro_op.isDirectory = (_wcsicmp(key.c_str(), L"(dir)") == 0);
                ro_op.targetPath = ResolveToAbsolutePath(ExpandVariables(value, variables), variables);
                ro_op.backupPath = ro_op.targetPath + L"_Backup";
                beforeOp.data = ro_op; op_created = true;
            }
            else if (_wcsicmp(key.c_str(), L"file") == 0 || _wcsicmp(key.c_str(), L"dir") == 0) {
                FileOp f_op; f_op.isDirectory = (_wcsicmp(key.c_str(), L"dir") == 0);
                auto parts = split_string(value, delimiter);
                if (parts.size() == 2) {
                    f_op.destPath = ResolveToAbsolutePath(ExpandVariables(parts[0], variables), variables);
                    std::wstring sourceRaw = parts[1];
                    std::wstring expandedSource = ResolveToAbsolutePath(ExpandVariables(sourceRaw, variables), variables);
                    if (f_op.isDirectory) {
                        f_op.sourcePath = expandedSource;
                    } else {
                        if (sourceRaw.back() == L'\\') f_op.sourcePath = expandedSource + PathFindFileNameW(f_op.destPath.c_str());
                        else f_op.sourcePath = expandedSource;
                    }
                    f_op.destBackupPath = f_op.destPath + L"_Backup";
                    f_op.wasMoved = ArePathsOnSameVolume(f_op.sourcePath, f_op.destPath);
                    beforeOp.data = f_op; op_created = true;
                }
            } else if (_wcsicmp(key.c_str(), L"backupdir") == 0) {
                backupData.backupDirs.push_back(ParseBackupEntry(value, variables));
            } else if (_wcsicmp(key.c_str(), L"backupfile") == 0) {
                backupData.backupFiles.push_back(ParseBackupEntry(value, variables));
            } else {
                auto action_op = parse_action_op(key, value);
                if (action_op) {
                    beforeOp.data = *action_op;
                    op_created = true;
                }
            }

            if (op_created) {
                beforeOps.push_back(beforeOp);
            }
        }
        else if (currentSection == Section::After) {
            AfterOperation afterOp;
            bool op_created = false;
            if (_wcsicmp(key.c_str(), L"restore") == 0 && value == L"1") {
                afterOp.data = RestoreMarkerOp{};
                op_created = true;
            } else {
                auto action_op = parse_action_op(key, value);
                if (action_op) {
                    afterOp.data = ActionOperation{*action_op};
                    op_created = true;
                }
            }
            if (op_created) {
                afterOps.push_back(afterOp);
            }
        }
    }
}

void ExecuteActionOperation(const ActionOpData& opData, std::map<std::wstring, std::wstring>& variables, const std::set<DWORD>& trustedPids) {
    std::visit([&](const auto& arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, RunOp>) {
            std::wstring finalPath = ExpandVariables(arg.programPath, variables);
            std::wstring finalCmd = ExpandVariables(arg.commandLine, variables);
            std::wstring finalDir = ExpandVariables(arg.workDir, variables);
            ExecuteProcess(ResolveToAbsolutePath(finalPath, variables), finalCmd, ResolveToAbsolutePath(finalDir, variables), arg.wait, arg.hide);
        }
        else if constexpr (std::is_same_v<T, RegImportOp>) {
            std::wstring finalPath = ExpandVariables(arg.regPath, variables);
            ImportRegistryFile(ResolveToAbsolutePath(finalPath, variables));
        } else if constexpr (std::is_same_v<T, RegDllOp>) {
            std::wstring finalPath = ExpandVariables(arg.dllPath, variables);
            wchar_t systemPath[MAX_PATH];
            GetSystemDirectoryW(systemPath, MAX_PATH);
            std::wstring regsvrPath = std::wstring(systemPath) + L"\\regsvr32.exe";
            std::wstring args = L"/s \"" + ResolveToAbsolutePath(finalPath, variables) + L"\"";
            if (arg.unregister) {
                args = L"/u " + args;
            }
            ExecuteProcess(regsvrPath, args, L"", true, true);
        } else if constexpr (std::is_same_v<T, DeleteFileOp>) {
            std::wstring finalPath = ExpandVariables(arg.pathPattern, variables);
            ActionHelpers::HandleDeleteFile(ResolveToAbsolutePath(finalPath, variables));
        } else if constexpr (std::is_same_v<T, DeleteDirOp>) {
            std::wstring finalPath = ExpandVariables(arg.pathPattern, variables);
            ActionHelpers::HandleDeleteDir(ResolveToAbsolutePath(finalPath, variables), arg.ifEmpty);
        } else if constexpr (std::is_same_v<T, DeleteRegKeyOp>) {
            ActionHelpers::HandleDeleteRegKey(ExpandVariables(arg.keyPattern, variables), arg.ifEmpty);
        } else if constexpr (std::is_same_v<T, DeleteRegValueOp>) {
            ActionHelpers::HandleDeleteRegValue(ExpandVariables(arg.keyPattern, variables), ExpandVariables(arg.valuePattern, variables));
        } else if constexpr (std::is_same_v<T, CreateDirOp>) {
            std::wstring finalPath = ExpandVariables(arg.path, variables);
            SHCreateDirectoryExW(NULL, ResolveToAbsolutePath(finalPath, variables).c_str(), NULL);
        } else if constexpr (std::is_same_v<T, DelayOp>) {
            Sleep(arg.milliseconds);
        } else if constexpr (std::is_same_v<T, KillProcessOp>) {
            // <-- [修改] 在调用前展开和解析 KillProcessOp 中的路径
            // 创建一个可修改的副本
            KillProcessOp final_op = arg;
            // 仅当需要检查路径时 才展开变量
            if (final_op.checkProcessPath) {
                // 确保 basePath 被正确地展开和解析为绝对路径
                final_op.basePath = ResolveToAbsolutePath(ExpandVariables(final_op.basePath, variables), variables);
            }
            // 使用修正后的 final_op 调用处理函数
            ActionHelpers::HandleKillProcess(final_op, trustedPids);
        } else if constexpr (std::is_same_v<T, CreateFileOp>) {
            CreateFileOp mutable_op = arg;
            mutable_op.path = ResolveToAbsolutePath(ExpandVariables(arg.path, variables), variables);
            mutable_op.content = ExpandVariables(arg.content, variables);
            ActionHelpers::HandleCreateFile(mutable_op);
        } else if constexpr (std::is_same_v<T, CreateRegKeyOp>) {
            ActionHelpers::HandleCreateRegKey(ExpandVariables(arg.keyPath, variables));
        } else if constexpr (std::is_same_v<T, CreateRegValueOp>) {
            CreateRegValueOp mutable_op = arg;
            mutable_op.keyPath = ExpandVariables(arg.keyPath, variables);
            mutable_op.valueName = ExpandVariables(arg.valueName, variables);
            mutable_op.valueData = ExpandVariables(arg.valueData, variables);
            ActionHelpers::HandleCreateRegValue(mutable_op);
        }
        else if constexpr (std::is_same_v<T, CopyMoveOp>) {
            CopyMoveOp mutable_op = arg;
            mutable_op.sourcePath = ResolveToAbsolutePath(ExpandVariables(arg.sourcePath, variables), variables);
            mutable_op.destPath = ResolveToAbsolutePath(ExpandVariables(arg.destPath, variables), variables);
            ActionHelpers::HandleCopyMove(mutable_op);
        } else if constexpr (std::is_same_v<T, AttributesOp>) {
            AttributesOp mutable_op = arg;
            mutable_op.path = ResolveToAbsolutePath(ExpandVariables(arg.path, variables), variables);
            ActionHelpers::HandleAttributes(mutable_op);
        } else if constexpr (std::is_same_v<T, IniWriteOp>) {
            IniWriteOp mutable_op = arg;
            mutable_op.path = ResolveToAbsolutePath(ExpandVariables(arg.path, variables), variables);
            mutable_op.value = ExpandVariables(arg.value, variables);
            ActionHelpers::HandleIniWrite(mutable_op);
        } else if constexpr (std::is_same_v<T, ReplaceOp>) {
            ReplaceOp mutable_op = arg;
            mutable_op.path = ResolveToAbsolutePath(ExpandVariables(arg.path, variables), variables);
            mutable_op.findText = ExpandVariables(arg.findText, variables);
            mutable_op.replaceText = ExpandVariables(arg.replaceText, variables);
            ActionHelpers::HandleReplace(mutable_op);
        } else if constexpr (std::is_same_v<T, ReplaceLineOp>) {
            ReplaceLineOp mutable_op = arg;
            mutable_op.path = ResolveToAbsolutePath(ExpandVariables(arg.path, variables), variables);
            mutable_op.lineStart = ExpandVariables(arg.lineStart, variables);
            mutable_op.replaceLine = ExpandVariables(arg.replaceLine, variables);
            ActionHelpers::HandleReplaceLine(mutable_op);
        }
        else if constexpr (std::is_same_v<T, EnvVarOp>) {
            std::wstring finalName = ExpandVariables(arg.name, variables);
            std::wstring finalValue = ExpandVariables(arg.value, variables);

            // 检查变量名是否为 "Path"
            if (_wcsicmp(finalName.c_str(), L"Path") == 0) {
                // 特殊处理 Path 变量
                if (_wcsicmp(finalValue.c_str(), L"null") == 0) {
                    // 如果设置为 "null" 则恢复为程序启动时的原始 Path
                    SetEnvironmentVariableW(L"Path", g_originalPath.c_str());
                } else {
                    // 否则 将新值追加到原始 Path 后面
                    std::wstring newPath = g_originalPath;
                    if (!newPath.empty() && newPath.back() != L';') {
                        newPath += L';';
                    }
                    newPath += finalValue;
                    SetEnvironmentVariableW(L"Path", newPath.c_str());
                }
            } else {
                // 对所有其他环境变量 保持原始的覆盖行为
                if (_wcsicmp(finalValue.c_str(), L"null") == 0) {
                    SetEnvironmentVariableW(finalName.c_str(), NULL);
                } else {
                    SetEnvironmentVariableW(finalName.c_str(), finalValue.c_str());
                }
            }
        }
    }, opData);
}

void PerformFullCleanup(
    std::vector<AfterOperation>& afterOps,
    std::vector<StartupShutdownOperation>& shutdownOps,
    std::map<std::wstring, std::wstring>& variables,
    const std::set<DWORD>& trustedPids
) {
    bool restoreMarkerFound = false;
    for (const auto& op : afterOps) {
        if (std::holds_alternative<RestoreMarkerOp>(op.data)) {
            restoreMarkerFound = true;
            break;
        }
    }

    if (restoreMarkerFound) {
        for (auto& op : afterOps) {
            if (std::holds_alternative<RestoreMarkerOp>(op.data)) {
                for (auto it = shutdownOps.rbegin(); it != shutdownOps.rend(); ++it) {
                    PerformShutdownOperation(it->data);
                }
            } else {
                ActionOperation actionOp = std::get<ActionOperation>(op.data);
                // <-- [修改] 调用 ExecuteActionOperation 时传递 trustedPids
                ExecuteActionOperation(actionOp.data, variables, trustedPids);
            }
        }
    } else {
        for (auto it = shutdownOps.rbegin(); it != shutdownOps.rend(); ++it) {
            PerformShutdownOperation(it->data);
        }
        for (auto& op : afterOps) {
            ActionOperation actionOp = std::get<ActionOperation>(op.data);
            // <-- [修改] 调用 ExecuteActionOperation 时传递 trustedPids
            ExecuteActionOperation(actionOp.data, variables, trustedPids);
        }
    }
}


// --- Main Application Logic ---
void LaunchApplication(const std::wstring& iniContent, std::map<std::wstring, std::wstring>& variables) {
    std::wstring appPathRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"General", L"application"), variables);
    if (appPathRaw.empty()) return;

    std::wstring workDirRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"General", L"workdir"), variables);
    std::wstring commandLine = ExpandVariables(GetValueFromIniContent(iniContent, L"General", L"commandline"), variables);
    ExecuteProcess(ResolveToAbsolutePath(appPathRaw, variables), commandLine, ResolveToAbsolutePath(workDirRaw, variables), false, false);
}

DWORD WINAPI LauncherWorkerThread(LPVOID lpParam) {
    LauncherThreadData* data = static_cast<LauncherThreadData*>(lpParam);
    if (!data) {
        return 1;
    }

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    std::wstring commandLine = ExpandVariables(GetValueFromIniContent(data->iniContent, L"General", L"commandline"), data->variables);
    std::wstring fullCommandLine = L"\"" + data->absoluteAppPath + L"\" " + commandLine;
    wchar_t commandLineBuffer[4096];
    wcscpy_s(commandLineBuffer, fullCommandLine.c_str());

    // <-- [新增] 声明用于存储最终受信任PID列表的集合
    std::set<DWORD> finalTrustedPids;

    if (!CreateProcessW(NULL, commandLineBuffer, NULL, NULL, FALSE, 0, NULL, data->finalWorkDir.c_str(), &si, &pi)) {
        MessageBoxW(NULL, (L"启动程序失败: \n" + data->absoluteAppPath).c_str(), L"启动错误", MB_ICONERROR);
        // 即使启动失败 也要将启动器自身视为受信任进程以执行清理
        finalTrustedPids.insert(GetCurrentProcessId());
    } else {
        std::vector<std::wstring> waitProcesses;
        std::wstringstream waitStream(data->iniContent);
        std::wstring waitLine;
        std::wstring waitCurrentSection;
        bool waitInSettings = false;
        while (std::getline(waitStream, waitLine)) {
            waitLine = trim(waitLine);
            if (waitLine.empty() || waitLine[0] == L';' || waitLine[0] == L'#') continue;
            if (waitLine[0] == L'[' && waitLine.back() == L']') {
                waitCurrentSection = waitLine;
                waitInSettings = (_wcsicmp(waitCurrentSection.c_str(), L"[General]") == 0);
                continue;
            }
            if (!waitInSettings) continue;
            size_t delimiterPos = waitLine.find(L'=');
            if (delimiterPos != std::wstring::npos) {
                std::wstring key = trim(waitLine.substr(0, delimiterPos));
                if (_wcsicmp(key.c_str(), L"waitprocess") == 0) {
                    std::wstring value = trim(waitLine.substr(delimiterPos + 1));
                    waitProcesses.push_back(ExpandVariables(value, data->variables));
                }
            }
        }

        bool multiInstanceEnabled = (GetValueFromIniContent(data->iniContent, L"General", L"multiple") == L"1");

        if (multiInstanceEnabled) {
            WaitForSingleObject(pi.hProcess, INFINITE);

            const wchar_t* appFilename = PathFindFileNameW(data->absoluteAppPath.c_str());
            if (appFilename && wcslen(appFilename) > 0) {
                waitProcesses.push_back(appFilename);
            }

            if (!waitProcesses.empty()) {
                Sleep(3000);
                while (true) {
                    std::vector<HANDLE> handlesToWaitOn = ScanForWaitProcessHandles(waitProcesses);
                    if (handlesToWaitOn.empty()) {
                        break;
                    }
                    if (handlesToWaitOn.size() <= MAXIMUM_WAIT_OBJECTS) {
                        WaitForMultipleObjects((DWORD)handlesToWaitOn.size(), handlesToWaitOn.data(), TRUE, INFINITE);
                    } else {
                        for (size_t i = 0; i < handlesToWaitOn.size(); i += MAXIMUM_WAIT_OBJECTS) {
                            size_t count = min(MAXIMUM_WAIT_OBJECTS, handlesToWaitOn.size() - i);
                            WaitForMultipleObjects((DWORD)count, &handlesToWaitOn[i], TRUE, INFINITE);
                        }
                    }
                    for (HANDLE h : handlesToWaitOn) {
                        CloseHandle(h);
                    }
                    Sleep(3000);
                }
            }
            // <-- [新增] 为多实例模式填充受信任PID列表
            finalTrustedPids.insert(GetCurrentProcessId());
            finalTrustedPids.insert(pi.dwProcessId);

        } else { // 单实例逻辑
            if (waitProcesses.empty()) {
                WaitForSingleObject(pi.hProcess, INFINITE);
                // <-- [新增] 为单实例（无等待）模式填充受信任PID列表
                finalTrustedPids.insert(GetCurrentProcessId());
                finalTrustedPids.insert(pi.dwProcessId);
            } else {
                std::set<DWORD> trustedPids;
                std::set<DWORD> pidsWeHaveWaitedFor;
                std::vector<HANDLE> handlesToWaitOn;

                trustedPids.insert(GetCurrentProcessId());
                trustedPids.insert(pi.dwProcessId);
                handlesToWaitOn.push_back(pi.hProcess);

                while (!handlesToWaitOn.empty()) {
                    DWORD startTime = GetTickCount();
                    while (GetTickCount() - startTime < 3000) {
                         std::vector<HANDLE> foundHandles = FindNewDescendantsAndWaitTargets(trustedPids, waitProcesses, pidsWeHaveWaitedFor);
                        if (!foundHandles.empty()) {
                            handlesToWaitOn.insert(handlesToWaitOn.end(), foundHandles.begin(), foundHandles.end());
                        }
                        Sleep(50);
                    }

                    DWORD waitResult = WaitForMultipleObjects((DWORD)handlesToWaitOn.size(), handlesToWaitOn.data(), FALSE, INFINITE);

                    if (waitResult >= WAIT_OBJECT_0 && waitResult < WAIT_OBJECT_0 + handlesToWaitOn.size()) {
                        int index = waitResult - WAIT_OBJECT_0;

                        CloseHandle(handlesToWaitOn[index]);
                        handlesToWaitOn.erase(handlesToWaitOn.begin() + index);

                        if (handlesToWaitOn.empty()) {
                            startTime = GetTickCount();
                            while (GetTickCount() - startTime < 3000) {
                                std::vector<HANDLE> foundHandles = FindNewDescendantsAndWaitTargets(trustedPids, waitProcesses, pidsWeHaveWaitedFor);
                                if (!foundHandles.empty()) {
                                    handlesToWaitOn.insert(handlesToWaitOn.end(), foundHandles.begin(), foundHandles.end());
                                }
                                Sleep(50);
                            }
                            if (handlesToWaitOn.empty()) {
                                break;
                            }
                        }
                    } else {
                        for(HANDLE h : handlesToWaitOn) {
                            CloseHandle(h);
                        }
                        break;
                    }
                }
                // <-- [新增] 等待循环结束后 将其累积的PID列表赋给最终列表
                finalTrustedPids = trustedPids;
            }
        }

        if (pi.hProcess) CloseHandle(pi.hProcess);
        if (pi.hThread) CloseHandle(pi.hThread);
    }

    if (data->hMonitorThread) {
        if (data->hMonitorThreadId != 0) {
            PostThreadMessageW(data->hMonitorThreadId, WM_QUIT, 0, 0);
        }
        WaitForSingleObject(data->hMonitorThread, 2000);
        CloseHandle(data->hMonitorThread);
        SetAllProcessesState(data->monitorData->suspendProcesses, false);
    }
    if (data->hBackupThread) {
        *(data->stopMonitor) = true;
        while (*(data->isBackupWorking)) Sleep(100);
        WaitForSingleObject(data->hBackupThread, 1500);
        CloseHandle(data->hBackupThread);
    }

    // <-- [修改] 调用 PerformFullCleanup 时传递 finalTrustedPids
    PerformFullCleanup(data->afterOps, data->shutdownOps, data->variables, finalTrustedPids);

    DeleteFileW(data->tempFilePath.c_str());

    CoUninitialize();
    return 0;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    EnableAllPrivileges();

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        g_NtSuspendProcess = (pfnNtSuspendProcess)GetProcAddress(hNtdll, "NtSuspendProcess");
        g_NtResumeProcess = (pfnNtResumeProcess)GetProcAddress(hNtdll, "NtResumeProcess");
    }

    // <-- [新增] 在程序开始时获取并存储原始的Path环境变量
    DWORD pathSize = GetEnvironmentVariableW(L"Path", NULL, 0);
    if (pathSize > 0) {
        std::vector<wchar_t> pathBuffer(pathSize);
        if (GetEnvironmentVariableW(L"Path", pathBuffer.data(), pathSize) > 0) {
            g_originalPath = pathBuffer.data();
        }
    }

    wchar_t launcherFullPath[MAX_PATH];
    GetModuleFileNameW(NULL, launcherFullPath, MAX_PATH);
    std::wstring iniPath = launcherFullPath;
    size_t pos = iniPath.find_last_of(L".");
    if (pos != std::wstring::npos) iniPath.replace(pos, std::wstring::npos, L".ini");
    std::wstring iniContent;
    if (!ReadFileToWString(iniPath, iniContent)) {
        MessageBoxW(NULL, L"无法读取INI文件", L"错误", MB_ICONERROR);
        return 1;
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

    std::wstring appPathRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"General", L"application"), variables);

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
        CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

        if (appPathRaw.empty()) {
            MessageBoxW(NULL, L"INI配置文件中未找到或未设置 'application' 路径", L"配置错误", MB_ICONERROR);
            CloseHandle(hMutex);
            CoUninitialize();
            return 1;
        }

        std::wstring absoluteAppPath = ResolveToAbsolutePath(appPathRaw, variables);
        variables[L"APPEXE"] = absoluteAppPath;
        wchar_t appDir[MAX_PATH];
        wcscpy_s(appDir, absoluteAppPath.c_str());
        PathRemoveFileSpecW(appDir);
        variables[L"EXEPATH"] = appDir;

        const wchar_t* appFilename = PathFindFileNameW(absoluteAppPath.c_str());
        if (appFilename) {
            variables[L"EXENAME"] = appFilename;
			wchar_t appNameBuffer[MAX_PATH];
			wcscpy_s(appNameBuffer, MAX_PATH, appFilename);
			PathRemoveExtensionW(appNameBuffer);
			variables[L"APPNAME"] = appNameBuffer;
        }

        std::wstring workDirRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"General", L"workdir"), variables);
        std::wstring finalWorkDir = ResolveToAbsolutePath(workDirRaw, variables);
        if (finalWorkDir.empty() || !PathIsDirectoryW(finalWorkDir.c_str())) {
            finalWorkDir = appDir;
        }
        variables[L"WORKDIR"] = finalWorkDir;

        std::wstring tempFileName = std::wstring(launcherBaseName) + L"Temp.ini";
        std::wstring tempFileDirRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"General", L"tempfile"), variables);
        std::wstring tempFileDir = ResolveToAbsolutePath(tempFileDirRaw, variables);
        if (tempFileDirRaw.empty()) {
            tempFileDir = variables[L"YAPROOT"];
        }
        std::wstring tempFilePath = tempFileDir + L"\\" + tempFileName;

        std::vector<BeforeOperation> beforeOps;
        std::vector<AfterOperation> afterOps;
        BackupThreadData backupData;

        if (PathFileExistsW(tempFilePath.c_str())) {
            ParseIniSections(iniContent, variables, beforeOps, afterOps, backupData);

            std::vector<StartupShutdownOperation> shutdownOpsForCrash;
            for (auto& op : beforeOps) {
                std::visit([&](auto& arg) {
                    using T = std::decay_t<decltype(arg)>;
                    if constexpr (!std::is_same_v<T, ActionOpData>) {
                        StartupShutdownOperation ssOp{arg};
                        std::visit([&](auto& op_data) {
                            using OpType = std::decay_t<decltype(op_data)>;
                            if constexpr (std::is_same_v<OpType, FileOp>) {
                                op_data.destBackupCreated = true;
                            } else if constexpr (std::is_same_v<OpType, RestoreOnlyFileOp> ||
                                               std::is_same_v<OpType, RegistryOp>) {
                                op_data.backupCreated = true;
                            } else if constexpr (std::is_same_v<OpType, FirewallOp>) {
                                op_data.ruleCreated = true;
                            } else if constexpr (std::is_same_v<OpType, LinkOp>) {
                                op_data.backupCreated = true;
                                if (!op_data.traversalMode.empty()) {
                                    WIN32_FIND_DATAW findData;
                                    std::wstring searchPath = op_data.targetPath + L"\\*";
                                    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
                                    if (hFind != INVALID_HANDLE_VALUE) {
                                        do {
                                            std::wstring itemName = findData.cFileName;
                                            if (itemName == L"." || itemName == L"..") continue;
                                            bool isItemDirectory = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
                                            bool shouldHaveBeenLinked = false;
                                            if (_wcsicmp(op_data.traversalMode.c_str(), L"all") == 0) shouldHaveBeenLinked = true;
                                            else if (_wcsicmp(op_data.traversalMode.c_str(), L"dir") == 0) shouldHaveBeenLinked = isItemDirectory;
                                            else if (_wcsicmp(op_data.traversalMode.c_str(), L"file") == 0) shouldHaveBeenLinked = !isItemDirectory;
                                            if (op_data.isHardlink && isItemDirectory) shouldHaveBeenLinked = false;

                                            if (shouldHaveBeenLinked) {
                                                std::wstring destFullPath = op_data.linkPath + L"\\" + itemName;
                                                if (PathFileExistsW(destFullPath.c_str())) {
                                                    op_data.createdLinks.push_back({destFullPath, L""});
                                                }
                                                std::wstring backupPath = destFullPath + L"_Backup";
                                                if (PathFileExistsW(backupPath.c_str())) {
                                                    op_data.backedUpPaths.push_back({backupPath, destFullPath});
                                                }
                                            }
                                        } while (FindNextFileW(hFind, &findData));
                                        FindClose(hFind);
                                    }
                                } else {
                                     if (PathFileExistsW(op_data.backupPath.c_str())) {
                                        op_data.backedUpPaths.push_back({op_data.backupPath, op_data.linkPath});
                                     }
                                }
                            }
                        }, ssOp.data);
                        shutdownOpsForCrash.push_back(ssOp);
                    }
                }, op.data);
            }

            // <-- [新增] 为崩溃恢复场景定义受信任的PID（仅限启动器自身）
            std::set<DWORD> crashTrustedPids;
            crashTrustedPids.insert(GetCurrentProcessId());

            // <-- [修改] 调用 PerformFullCleanup 时传递 crashTrustedPids
            PerformFullCleanup(afterOps, shutdownOpsForCrash, variables, crashTrustedPids);

            std::wstring crashWaitStr = GetValueFromIniContent(iniContent, L"General", L"crashwait");
            int crashWaitTime = crashWaitStr.empty() ? 1000 : _wtoi(crashWaitStr.c_str());
            if (crashWaitTime > 0) {
                Sleep(crashWaitTime);
            }

            DeleteFileW(tempFilePath.c_str());

            beforeOps.clear();
            afterOps.clear();
            backupData = {};
        }

        ParseIniSections(iniContent, variables, beforeOps, afterOps, backupData);

        std::vector<StartupShutdownOperation> shutdownOps;

        {
            wchar_t dirPath[MAX_PATH];
            wcscpy_s(dirPath, MAX_PATH, tempFilePath.c_str());
            PathRemoveFileSpecW(dirPath);
            if (wcslen(dirPath) > 0) {
                SHCreateDirectoryExW(NULL, dirPath, NULL);
            }
            std::ofstream tempFile(tempFilePath);
            tempFile.close();
        }

        // <-- [新增] 为 [Before] 阶段的操作定义受信任的PID（仅限启动器自身）
        std::set<DWORD> beforeTrustedPids;
        beforeTrustedPids.insert(GetCurrentProcessId());

        for (auto& op : beforeOps) {
            std::visit([&](auto& arg) {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, ActionOpData>) {
                    // <-- [修改] 调用 ExecuteActionOperation 时传递 beforeTrustedPids
                    ExecuteActionOperation(arg, variables, beforeTrustedPids);
                } else {
                    StartupShutdownOperation ssOp{arg};
                    PerformStartupOperation(ssOp.data);
                    shutdownOps.push_back(ssOp);
                }
            }, op.data);
        }

        MonitorThreadData monitorData;
        std::atomic<bool> stopMonitor(false);
        std::atomic<bool> isBackupWorking(false);

        LauncherThreadData threadData;
        threadData.iniContent = iniContent;
        threadData.variables = variables;
        threadData.shutdownOps = shutdownOps;
        threadData.afterOps = afterOps;
        threadData.absoluteAppPath = absoluteAppPath;
        threadData.finalWorkDir = finalWorkDir;
        threadData.tempFilePath = tempFilePath;
        threadData.monitorData = &monitorData;
        threadData.backupData = &backupData;
        threadData.stopMonitor = &stopMonitor;
        threadData.isBackupWorking = &isBackupWorking;

        std::wstring foregroundAppName = ExpandVariables(GetValueFromIniContent(iniContent, L"General", L"foreground"), variables);
        if (!foregroundAppName.empty()) {
            monitorData.foregroundAppName = foregroundAppName;

            std::wstringstream stream(iniContent);
            std::wstring line;
            std::wstring currentSection_fg;
            bool inSettings_fg = false;
            while (std::getline(stream, line)) {
                line = trim(line);
                if (line.empty() || line[0] == L';' || line[0] == L'#') continue;
                if (line[0] == L'[' && line.back() == L']') {
                    currentSection_fg = line;
                    inSettings_fg = (_wcsicmp(currentSection_fg.c_str(), L"[General]") == 0);
                    continue;
                }
                if (!inSettings_fg) continue;
                size_t delimiterPos = line.find(L'=');
                if (delimiterPos != std::wstring::npos) {
                    std::wstring key = trim(line.substr(0, delimiterPos));
                    if (_wcsicmp(key.c_str(), L"suspend") == 0) {
                        std::wstring value = trim(line.substr(delimiterPos + 1));
                        monitorData.suspendProcesses.push_back(ExpandVariables(value, variables));
                    }
                }
            }

            if (!monitorData.suspendProcesses.empty()) {
                DWORD monitorThreadId = 0;
                threadData.hMonitorThread = CreateThread(NULL, 0, ForegroundMonitorThread, &monitorData, 0, &monitorThreadId);
                threadData.hMonitorThreadId = monitorThreadId;
            }
        }

        std::wstring backupTimeStr = GetValueFromIniContent(iniContent, L"General", L"backuptime");
        int backupTime = backupTimeStr.empty() ? 0 : _wtoi(backupTimeStr.c_str());
        if (backupTime > 0) {
            backupData.shouldStop = &stopMonitor;
            backupData.isWorking = &isBackupWorking;
            backupData.backupInterval = backupTime * 60 * 1000;
            if (!backupData.backupDirs.empty() || !backupData.backupFiles.empty()) {
                threadData.hBackupThread = CreateThread(NULL, 0, BackupWorkerThread, &backupData, 0, NULL);
            }
        }

        HANDLE hWorkerThread = CreateThread(NULL, 0, LauncherWorkerThread, &threadData, 0, NULL);

        if (hWorkerThread) {
            while (true) {
                DWORD dwResult = MsgWaitForMultipleObjects(1, &hWorkerThread, FALSE, INFINITE, QS_ALLINPUT);
                if (dwResult == WAIT_OBJECT_0) {
                    break;
                }
                else if (dwResult == WAIT_OBJECT_0 + 1) {
                    MSG msg;
                    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                        TranslateMessage(&msg);
                        DispatchMessage(&msg);
                    }
                } else {
                    break;
                }
            }
            CloseHandle(hWorkerThread);
        }

        CloseHandle(hMutex);
        CoUninitialize();

    } else {
        CloseHandle(hMutex);
        if (GetValueFromIniContent(iniContent, L"General", L"multiple") == L"1") {
            LaunchApplication(iniContent, variables);
        }
    }
    return 0;
}