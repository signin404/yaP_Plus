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
#include <filesystem>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "Psapi.lib")

// --- Function pointer types for NTDLL functions ---
typedef LONG (NTAPI *pfnNtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG (NTAPI *pfnNtResumeProcess)(IN HANDLE ProcessHandle);
pfnNtSuspendProcess g_NtSuspendProcess = nullptr;
pfnNtResumeProcess g_NtResumeProcess = nullptr;

// --- Data Structures ---

// Operations with startup and shutdown/cleanup logic
struct FileOp {
    std::filesystem::path sourcePath;
    std::filesystem::path destPath;
    std::filesystem::path destBackupPath;
    bool isDirectory;
    bool destBackupCreated = false;
    bool wasMoved = false;
};

struct RestoreOnlyFileOp {
    std::filesystem::path targetPath;
    std::filesystem::path backupPath;
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
    std::filesystem::path filePath;
    bool backupCreated = false;
};

struct LinkOp {
    std::filesystem::path linkPath;
    std::filesystem::path targetPath;
    std::filesystem::path backupPath;
    bool isDirectory;
    bool isHardlink;
    bool backupCreated = false;
    std::vector<std::pair<std::filesystem::path, std::filesystem::path>> createdLinks;
    std::vector<std::pair<std::filesystem::path, std::filesystem::path>> backedUpPaths;
    bool performMoveOnCleanup = false;
    std::wstring traversalMode; // "dir", "file", "all", or empty
};


struct FirewallOp {
    std::wstring ruleName;
    std::filesystem::path appPath;
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
    std::filesystem::path programPath;
    std::wstring commandLine;
    std::filesystem::path workDir;
    bool wait;
    bool hide;
};

struct RegImportOp {
    std::filesystem::path regPath;
};

struct RegDllOp {
    std::filesystem::path dllPath;
    bool unregister;
};

struct DeleteFileOp {
    std::filesystem::path pathPattern;
};

struct DeleteDirOp {
    std::filesystem::path pathPattern;
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
    std::filesystem::path path;
};

struct DelayOp {
    int milliseconds;
};

struct KillProcessOp {
    std::wstring processPattern;
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
    std::filesystem::path path;
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
    std::filesystem::path sourcePath;
    std::filesystem::path destPath;
    bool isDirectory;
    bool isMove;
    bool overwrite;
};

struct AttributesOp {
    std::filesystem::path path;
    DWORD attributes;
};

struct IniWriteOp {
    std::filesystem::path path;
    std::wstring section;
    std::wstring key;
    std::wstring value;
    bool deleteSection = false;
};

struct ReplaceOp {
    std::filesystem::path path;
    std::wstring findText;
    std::wstring replaceText;
};

struct ReplaceLineOp {
    std::filesystem::path path;
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
    std::filesystem::path absoluteAppPath;
    std::filesystem::path finalWorkDir;
    std::filesystem::path tempFilePath;
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

std::filesystem::path ResolveToAbsolutePath(const std::filesystem::path& path, const std::map<std::wstring, std::wstring>& variables) {
    if (path.empty()) {
        return {};
    }

    if (path.is_absolute()) {
        return std::filesystem::weakly_canonical(path);
    }

    auto it = variables.find(L"YAPROOT");
    if (it != variables.end()) {
        std::filesystem::path yapRoot(it->second);
        return std::filesystem::weakly_canonical(yapRoot / path);
    }

    return std::filesystem::absolute(path);
}

bool ArePathsOnSameVolume(const std::filesystem::path& path1, const std::filesystem::path& path2) {
    if (path1.empty() || path2.empty()) {
        return false;
    }

    wchar_t root1[MAX_PATH];
    if (GetVolumePathNameW(path1.c_str(), root1, MAX_PATH) == 0) {
        return false;
    }

    wchar_t root2[MAX_PATH];
    if (GetVolumePathNameW(path2.c_str(), root2, MAX_PATH) == 0) {
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

bool ReadFileToWString(const std::filesystem::path& path, std::wstring& out_content) {
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

bool ExecuteProcess(const std::filesystem::path& path, const std::wstring& args, const std::filesystem::path& workDir, bool wait, bool hide) {
    if (path.empty() || !std::filesystem::exists(path)) {
        return false;
    }

    std::filesystem::path finalWorkDir;
    if (!workDir.empty() && std::filesystem::is_directory(workDir)) {
        finalWorkDir = workDir;
    } else {
        finalWorkDir = path.parent_path();
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

// --- Registry Helpers ---

namespace ActionHelpers {
    // Forward declaration
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

LSTATUS RecursiveRegCopyKey(HKEY hKeySrc, HKEY hKeyDest) {
    DWORD dwValues, dwMaxValueNameLen, dwMaxValueDataLen;
    RegQueryInfoKeyW(hKeySrc, NULL, NULL, NULL, NULL, NULL, NULL, &dwValues, &dwMaxValueNameLen, &dwMaxValueDataLen, NULL, NULL);

    std::vector<wchar_t> valueNameBuffer(dwMaxValueNameLen + 1);
    std::vector<BYTE> dataBuffer(dwMaxValueDataLen);
    for (DWORD i = 0; i < dwValues; ++i) {
        DWORD valueNameLen = static_cast<DWORD>(valueNameBuffer.size());
        DWORD dataLen = static_cast<DWORD>(dataBuffer.size());
        DWORD type;
        LSTATUS res = RegEnumValueW(hKeySrc, i, valueNameBuffer.data(), &valueNameLen, NULL, &type, dataBuffer.data(), &dataLen);
        if (res == ERROR_SUCCESS) {
            RegSetValueExW(hKeyDest, valueNameBuffer.data(), 0, type, dataBuffer.data(), dataLen);
        }
    }

    DWORD dwSubKeys, dwMaxSubKeyLen;
    RegQueryInfoKeyW(hKeySrc, NULL, NULL, NULL, &dwSubKeys, &dwMaxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL);
    std::vector<wchar_t> subKeyNameBuffer(dwMaxSubKeyLen + 1);

    for (DWORD i = 0; i < dwSubKeys; ++i) {
        DWORD subKeyNameLen = static_cast<DWORD>(subKeyNameBuffer.size());
        LSTATUS res = RegEnumKeyExW(hKeySrc, i, subKeyNameBuffer.data(), &subKeyNameLen, NULL, NULL, NULL, NULL);
        if (res == ERROR_SUCCESS) {
            HKEY hSubKeySrc, hSubKeyDest;
            if (RegOpenKeyExW(hKeySrc, subKeyNameBuffer.data(), 0, KEY_READ, &hSubKeySrc) == ERROR_SUCCESS) {
                if (RegCreateKeyExW(hKeyDest, subKeyNameBuffer.data(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hSubKeyDest, NULL) == ERROR_SUCCESS) {
                    RecursiveRegCopyKey(hSubKeySrc, hSubKeyDest);
                    RegCloseKey(hSubKeyDest);
                }
                RegCloseKey(hSubKeySrc);
            }
        }
    }
    return ERROR_SUCCESS;
}

bool RenameRegistryKey(HKEY hRootKey, const std::wstring& subKey, const std::wstring& newSubKey) {
    HKEY hSrcKey, hDestKey;
    if (RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ, &hSrcKey) != ERROR_SUCCESS) {
        return false;
    }
    if (RegCreateKeyExW(hRootKey, newSubKey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hDestKey, NULL) != ERROR_SUCCESS) {
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

bool WriteRegValueToFile(HKEY hKey, const std::wstring& valueName, std::ofstream& regFile) {
    DWORD type, size = 0;
    if (RegQueryValueExW(hKey, valueName.c_str(), NULL, &type, NULL, &size) != ERROR_SUCCESS) {
        return false;
    }
    std::vector<BYTE> data(size);
    if (RegQueryValueExW(hKey, valueName.c_str(), NULL, &type, data.data(), &size) != ERROR_SUCCESS) {
        return false;
    }

    std::wstringstream wss;
    std::wstring displayName = valueName.empty() ? L"@" : L"\"" + valueName + L"\"";
    wss << displayName << L"=";

    if (type == REG_SZ || type == REG_EXPAND_SZ) {
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
        wss << L"hex(b):";
        const BYTE* qwordBytes = reinterpret_cast<const BYTE*>(&qwordValue);
        for (int i = 0; i < 8; ++i) {
            wss << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(qwordBytes[i]) << (i < 7 ? L"," : L"");
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
    wss << L"\r\n";
    std::wstring line = wss.str();
    regFile.write(reinterpret_cast<const char*>(line.c_str()), line.length() * sizeof(wchar_t));
    return true;
}

bool RecursiveRegExportKey(HKEY hKey, const std::wstring& currentPath, std::ofstream& regFile) {
    std::wstring header = L"\r\n[" + currentPath + L"]\r\n";
    regFile.write(reinterpret_cast<const char*>(header.c_str()), header.length() * sizeof(wchar_t));

    DWORD cValues, cchMaxValue, cbMaxValueData;
    RegQueryInfoKeyW(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &cValues, &cchMaxValue, &cbMaxValueData, NULL, NULL);
    
    std::vector<wchar_t> valueNameBuffer(cchMaxValue + 1);
    for (DWORD i = 0; i < cValues; i++) {
        DWORD cchValue = static_cast<DWORD>(valueNameBuffer.size());
        valueNameBuffer[0] = L'\0';
        if (RegEnumValueW(hKey, i, valueNameBuffer.data(), &cchValue, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            WriteRegValueToFile(hKey, valueNameBuffer.data(), regFile);
        }
    }

    DWORD cSubKeys, cchMaxSubKey;
    RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &cSubKeys, &cchMaxSubKey, NULL, NULL, NULL, NULL, NULL, NULL);
    std::vector<wchar_t> subKeyNameBuffer(cchMaxSubKey + 1);

    for (DWORD i = 0; i < cSubKeys; i++) {
        DWORD cchSubKey = static_cast<DWORD>(subKeyNameBuffer.size());
        if (RegEnumKeyExW(hKey, i, subKeyNameBuffer.data(), &cchSubKey, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY hSubKey;
            if (RegOpenKeyExW(hKey, subKeyNameBuffer.data(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                RecursiveRegExportKey(hSubKey, currentPath + L"\\" + subKeyNameBuffer.data(), regFile);
                RegCloseKey(hSubKey);
            }
        }
    }
    return true;
}

// 修复后的 ExportRegistryKey
bool ExportRegistryKey(const std::wstring& rootKeyStr, HKEY hRootKey, const std::wstring& subKey, const std::filesystem::path& filePath) {
    if (filePath.has_parent_path()) {
        std::filesystem::create_directories(filePath.parent_path());
    }

    std::ofstream regFile(filePath, std::ios::binary | std::ios::trunc); // 使用 ofstream
    if (!regFile.is_open()) return false;

    // 手动写入 UTF-16 LE BOM
    regFile.put((char)0xFF); 
    regFile.put((char)0xFE);

    std::wstring header = L"Windows Registry Editor Version 5.00\r\n";
    regFile.write(reinterpret_cast<const char*>(header.c_str()), header.length() * sizeof(wchar_t));

    HKEY hKey;
    if (RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RecursiveRegExportKey(hKey, rootKeyStr + L"\\" + subKey, regFile);
        RegCloseKey(hKey);
    }
    
    regFile.close();
    return true;
}

// 修复后的 ExportRegistryValue
bool ExportRegistryValue(HKEY hRootKey, const std::wstring& subKey, const std::wstring& valueName, const std::wstring& rootKeyStr, const std::filesystem::path& filePath) {
    if (filePath.has_parent_path()) {
        std::filesystem::create_directories(filePath.parent_path());
    }

    std::ofstream regFile(filePath, std::ios::binary | std::ios::trunc); // 使用 ofstream
    if (!regFile.is_open()) return false;
    
    // 手动写入 UTF-16 LE BOM
    regFile.put((char)0xFF); 
    regFile.put((char)0xFE);

    std::wstring header = L"Windows Registry Editor Version 5.00\r\n\r\n[" + rootKeyStr + L"\\" + subKey + L"]\r\n";
    regFile.write(reinterpret_cast<const char*>(header.c_str()), header.length() * sizeof(wchar_t));

    HKEY hKey;
    if (RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        WriteRegValueToFile(hKey, valueName, regFile);
        RegCloseKey(hKey);
    }

    regFile.close();
    return true;
}

bool ImportRegistryFile(const std::filesystem::path& filePath) {
    if (!std::filesystem::exists(filePath)) return true;

    wchar_t windir[MAX_PATH];
    GetWindowsDirectoryW(windir, MAX_PATH);
    std::filesystem::path regeditPath = std::filesystem::path(windir) / L"regedit.exe";
    std::wstring args = L"/s \"" + filePath.wstring() + L"\"";

    return ExecuteProcess(regeditPath, args, L"", true, true);
}


// Deletion and Action Helpers
namespace ActionHelpers {

    LSTATUS RecursiveRegDeleteKey_Internal(HKEY hKeyParent, const wchar_t* subKeyName, REGSAM samDesired) {
        HKEY hKey;
        LSTATUS res = RegOpenKeyExW(hKeyParent, subKeyName, 0, KEY_ENUMERATE_SUB_KEYS | samDesired, &hKey);
        if (res != ERROR_SUCCESS) {
            if (res == ERROR_FILE_NOT_FOUND) return ERROR_SUCCESS;
            return res;
        }

        wchar_t childKeyName[MAX_PATH];
        DWORD childKeyNameSize = MAX_PATH;
        while (RegEnumKeyExW(hKey, 0, childKeyName, &childKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            res = RecursiveRegDeleteKey_Internal(hKey, childKeyName, samDesired);
            if (res != ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return res;
            }
            childKeyNameSize = MAX_PATH;
        }

        RegCloseKey(hKey);
        return RegDeleteKeyExW(hKeyParent, subKeyName, samDesired, 0);
    }

    void DeleteRegistryKeyTree(HKEY hRootKey, const std::wstring& subKey) {
        if (hRootKey == HKEY_LOCAL_MACHINE) {
            RecursiveRegDeleteKey_Internal(hRootKey, subKey.c_str(), KEY_WOW64_64KEY);
            RecursiveRegDeleteKey_Internal(hRootKey, subKey.c_str(), KEY_WOW64_32KEY);
        } else {
            RecursiveRegDeleteKey_Internal(hRootKey, subKey.c_str(), 0);
        }
    }

    void HandleKillProcess(const std::wstring& processPattern) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (PathMatchSpecW(pe32.szExeFile, processPattern.c_str())) {
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

    void HandleDeleteFile(const std::filesystem::path& pathPattern) {
        std::filesystem::path dirPath = pathPattern.parent_path();
        std::wstring filePattern = pathPattern.filename().wstring();

        if (!std::filesystem::exists(dirPath)) return;

        for (const auto& entry : std::filesystem::directory_iterator(dirPath)) {
            if (entry.is_regular_file() && PathMatchSpecW(entry.path().filename().c_str(), filePattern.c_str())) {
                std::filesystem::remove(entry.path());
            }
        }
    }

    void HandleDeleteDir(const std::filesystem::path& pathPattern, bool ifEmpty) {
        std::filesystem::path dirPart = pathPattern.parent_path();
        std::wstring patternPart = pathPattern.filename().wstring();

        if (!std::filesystem::exists(dirPart)) return;

        for (const auto& entry : std::filesystem::directory_iterator(dirPart)) {
            if (entry.is_directory() && PathMatchSpecW(entry.path().filename().c_str(), patternPart.c_str())) {
                if (ifEmpty) {
                    if (std::filesystem::is_empty(entry.path())) {
                        std::filesystem::remove(entry.path());
                    }
                } else {
                    std::filesystem::remove_all(entry.path());
                }
            }
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
                        if (PathMatchSpecW(keyName, patternSegment.c_str())) {
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
                    wchar_t valName[16383];
                    DWORD valNameSize = 16383;
                    DWORD i = 0;
                    while (RegEnumValueW(hKey, i, valName, &valNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                        if (PathMatchSpecW(valName, valuePattern.c_str())) {
                            RegDeleteValueW(hKey, valName);
                            valNameSize = 16383;
                        } else {
                            i++;
                            valNameSize = 16383;
                        }
                    }
                    RegCloseKey(hKey);
                }
            }
        }
    }

    void HandleCreateFile(const CreateFileOp& op) {
        if (!op.overwrite && std::filesystem::exists(op.path)) {
            return;
        }

        if (op.path.has_parent_path()) {
            std::filesystem::create_directories(op.path.parent_path());
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
        if (!op.overwrite && std::filesystem::exists(op.destPath)) {
            return;
        }

        if (op.destPath.has_parent_path()) {
            std::filesystem::create_directories(op.destPath.parent_path());
        }

        if (op.overwrite && std::filesystem::exists(op.destPath)) {
            std::filesystem::path backupPath = op.destPath.wstring() + L"_Backup";
            std::filesystem::rename(op.destPath, backupPath);
            std::filesystem::remove_all(backupPath);
        }

        if (op.isMove) {
            std::filesystem::rename(op.sourcePath, op.destPath);
        } else {
            auto copyOptions = std::filesystem::copy_options::overwrite_existing;
            if (op.isDirectory) {
                copyOptions |= std::filesystem::copy_options::recursive;
            }
            std::filesystem::copy(op.sourcePath, op.destPath, copyOptions);
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

    bool ReadFileWithFormatDetection(const std::filesystem::path& path, FileContentInfo& info) {
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


    bool WriteFileWithFormat(const std::filesystem::path& path, const std::vector<std::wstring>& lines, const FileContentInfo& info) {
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
        if (!std::filesystem::exists(op.path)) {
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
        std::vector<wchar_t> buffer(MAX_PATH);
        while (true) {
            DWORD size = static_cast<DWORD>(buffer.size());
            if (QueryFullProcessImageNameW(hProcess, 0, buffer.data(), &size)) {
                CloseHandle(hProcess);
                return std::filesystem::path(buffer.data()).filename().wstring();
            }
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                buffer.resize(buffer.size() * 2);
            } else {
                break;
            }
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
                if (g_areProcessesSuspended) {
                    SetAllProcessesState(*g_suspendProcesses, false);
                    g_areProcessesSuspended = false;
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

    if (g_areProcessesSuspended) {
        SetAllProcessesState(*g_suspendProcesses, false);
        g_areProcessesSuspended = false;
    }

    return 0;
}

std::pair<std::filesystem::path, std::filesystem::path> ParseBackupEntry(const std::wstring& entry, const std::map<std::wstring, std::wstring>& variables) {
    const std::wstring delimiter = L" :: ";
    size_t separatorPos = entry.find(delimiter);
    if (separatorPos == std::wstring::npos) return {};
    auto src = ResolveToAbsolutePath(ExpandVariables(trim(entry.substr(0, separatorPos)), variables), variables);
    auto dest = ResolveToAbsolutePath(ExpandVariables(trim(entry.substr(separatorPos + delimiter.length())), variables), variables);
    if (dest.empty() || src.empty()) return {};
    return {dest, src};
}

void PerformDirectoryBackup(const std::filesystem::path& dest, const std::filesystem::path& src) {
    if (!std::filesystem::exists(src)) return;
    std::filesystem::path backupDest = dest.wstring() + L"_Backup";
    if (std::filesystem::exists(dest)) {
        std::filesystem::rename(dest, backupDest);
    }
    std::filesystem::copy(src, dest, std::filesystem::copy_options::recursive);
    if (std::filesystem::exists(backupDest)) {
        std::filesystem::remove_all(backupDest);
    }
}

void PerformFileBackup(const std::filesystem::path& dest, const std::filesystem::path& src) {
    if (!std::filesystem::exists(src)) return;
    std::filesystem::path backupDest = dest.wstring() + L"_Backup";
    if (std::filesystem::exists(dest)) {
        std::filesystem::rename(dest, backupDest);
    }
    std::filesystem::copy_file(src, dest);
    if (std::filesystem::exists(backupDest)) {
        std::filesystem::remove(backupDest);
    }
}

struct BackupThreadData {
    std::atomic<bool>* shouldStop;
    std::atomic<bool>* isWorking;
    int backupInterval;
    std::vector<std::pair<std::filesystem::path, std::filesystem::path>> backupDirs;
    std::vector<std::pair<std::filesystem::path, std::filesystem::path>> backupFiles;
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

void CreateHardLinksRecursive(const std::filesystem::path& srcDir, const std::filesystem::path& destDir, std::vector<std::pair<std::filesystem::path, std::filesystem::path>>& createdLinks) {
    for (const auto& entry : std::filesystem::directory_iterator(srcDir)) {
        const auto& srcPath = entry.path();
        const auto destPath = destDir / srcPath.filename();
        if (entry.is_directory()) {
            std::filesystem::create_directory(destPath);
            CreateHardLinksRecursive(srcPath, destPath, createdLinks);
        } else {
            if (CreateHardLinkW(destPath.c_str(), srcPath.c_str(), NULL)) {
                createdLinks.push_back({destPath, srcPath});
            }
        }
    }
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
            if (arg.destPath.has_parent_path()) {
                std::filesystem::create_directories(arg.destPath.parent_path());
            }

            if (std::filesystem::exists(arg.destPath)) {
                std::filesystem::rename(arg.destPath, arg.destBackupPath);
                arg.destBackupCreated = true;
            }
            if (std::filesystem::exists(arg.sourcePath)) {
                if (arg.wasMoved) {
                    std::filesystem::rename(arg.sourcePath, arg.destPath);
                } else {
                    auto opts = std::filesystem::copy_options::overwrite_existing;
                    if (arg.isDirectory) opts |= std::filesystem::copy_options::recursive;
                    std::filesystem::copy(arg.sourcePath, arg.destPath, opts);
                }
            }
        } else if constexpr (std::is_same_v<T, RestoreOnlyFileOp>) {
            if (std::filesystem::exists(arg.targetPath)) {
                std::filesystem::rename(arg.targetPath, arg.backupPath);
                arg.backupCreated = true;
            }
        } else if constexpr (std::is_same_v<T, RegistryOp>) {
            bool renamed = false;
            if (arg.isKey) {
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
                std::filesystem::create_directories(arg.linkPath);
                for(const auto& entry : std::filesystem::directory_iterator(arg.targetPath)) {
                    const auto& itemName = entry.path().filename();
                    bool isItemDirectory = entry.is_directory();
                    bool shouldLink = false;
                    if (_wcsicmp(arg.traversalMode.c_str(), L"all") == 0) shouldLink = true;
                    else if (_wcsicmp(arg.traversalMode.c_str(), L"dir") == 0) shouldLink = isItemDirectory;
                    else if (_wcsicmp(arg.traversalMode.c_str(), L"file") == 0) shouldLink = !isItemDirectory;
                    
                    if (arg.isHardlink && isItemDirectory) shouldLink = false;

                    if (shouldLink) {
                        auto srcFullPath = arg.targetPath / itemName;
                        auto destFullPath = arg.linkPath / itemName;
                        if (std::filesystem::exists(destFullPath)) {
                            auto backupDestPath = destFullPath.wstring() + L"_Backup";
                            std::filesystem::rename(destFullPath, backupDestPath);
                            arg.backedUpPaths.push_back({backupDestPath, destFullPath});
                            arg.backupCreated = true;
                        }
                        if (arg.isHardlink) {
                            std::filesystem::create_hard_link(srcFullPath, destFullPath);
                            arg.createdLinks.push_back({destFullPath, L""});
                        } else {
                            if (isItemDirectory) std::filesystem::create_directory_symlink(srcFullPath, destFullPath);
                            else std::filesystem::create_symlink(srcFullPath, destFullPath);
                            arg.createdLinks.push_back({destFullPath, L""});
                        }
                    }
                }
            } else {
                if (arg.linkPath.has_parent_path()) {
                    std::filesystem::create_directories(arg.linkPath.parent_path());
                }

                if (std::filesystem::exists(arg.linkPath)) {
                    std::filesystem::rename(arg.linkPath, arg.backupPath);
                    arg.backedUpPaths.push_back({arg.backupPath, arg.linkPath});
                    arg.backupCreated = true;
                }

                if (arg.performMoveOnCleanup) {
                    // DO NOTHING.
                } else {
                    if (arg.isHardlink) {
                        if (arg.isDirectory) {
                            std::filesystem::create_directory(arg.linkPath);
                            CreateHardLinksRecursive(arg.targetPath, arg.linkPath, arg.createdLinks);
                        } else {
                            std::filesystem::create_hard_link(arg.targetPath, arg.linkPath);
                        }
                    } else {
                        if (arg.isDirectory) std::filesystem::create_directory_symlink(arg.targetPath, arg.linkPath);
                        else std::filesystem::create_symlink(arg.targetPath, arg.linkPath);
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
                if (std::filesystem::exists(arg.destPath)) {
                    if (std::filesystem::exists(arg.sourcePath)) {
                         std::filesystem::remove_all(arg.sourcePath);
                    }
                    std::filesystem::rename(arg.destPath, arg.sourcePath);
                }
            } else {
                if (std::filesystem::exists(arg.destPath)) {
                    auto sourceBackupPath = arg.sourcePath.wstring() + L"_Backup";
                    if (std::filesystem::exists(arg.sourcePath)) std::filesystem::rename(arg.sourcePath, sourceBackupPath);
                    std::filesystem::copy(arg.destPath, arg.sourcePath, std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing);
                    if (std::filesystem::exists(sourceBackupPath)) {
                        std::filesystem::remove_all(sourceBackupPath);
                    }
                }
                std::filesystem::remove_all(arg.destPath);
            }
            if (arg.destBackupCreated && std::filesystem::exists(arg.destBackupPath)) {
                std::filesystem::rename(arg.destBackupPath, arg.destPath);
            }
        } else if constexpr (std::is_same_v<T, RestoreOnlyFileOp>) {
            if (std::filesystem::exists(arg.targetPath)) {
                std::filesystem::remove_all(arg.targetPath);
            }
            if (arg.backupCreated && std::filesystem::exists(arg.backupPath)) {
                std::filesystem::rename(arg.backupPath, arg.targetPath);
            }
        } else if constexpr (std::is_same_v<T, RegistryOp>) {
            if (arg.isSaveRestore) {
                if (arg.isKey) ExportRegistryKey(arg.rootKeyStr, arg.hRootKey, arg.subKey, arg.filePath);
                else ExportRegistryValue(arg.hRootKey, arg.subKey, arg.valueName, arg.rootKeyStr, arg.filePath);
            }
            if (arg.isKey) ActionHelpers::DeleteRegistryKeyTree(arg.hRootKey, arg.subKey);
            else {
                HKEY hKey;
                if (RegOpenKeyExW(arg.hRootKey, arg.subKey.c_str(), 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, arg.valueName.c_str());
                    RegCloseKey(hKey);
                }
            }
            if (arg.backupCreated) {
                if (arg.isKey) RenameRegistryKey(arg.hRootKey, arg.backupName, arg.subKey);
                else RenameRegistryValue(arg.hRootKey, arg.subKey, arg.backupName, arg.valueName);
            }
        } else if constexpr (std::is_same_v<T, LinkOp>) {
            if (arg.performMoveOnCleanup) {
                if (std::filesystem::exists(arg.linkPath)) {
                    if (arg.targetPath.has_parent_path()) {
                        std::filesystem::create_directories(arg.targetPath.parent_path());
                    }
                    std::filesystem::rename(arg.linkPath, arg.targetPath);
                }
            } else if (!arg.traversalMode.empty()) {
                for (const auto& linkPair : arg.createdLinks) {
                    std::filesystem::remove(linkPair.first);
                }
            } else {
                if (arg.isHardlink && arg.isDirectory) {
                    for (auto it = arg.createdLinks.rbegin(); it != arg.createdLinks.rend(); ++it) {
                        std::filesystem::remove(it->first);
                    }
                }
                std::filesystem::remove_all(arg.linkPath);
            }
            if (arg.backupCreated) {
                for (const auto& backupPair : arg.backedUpPaths) {
                    if (std::filesystem::exists(backupPair.first)) {
                        std::filesystem::rename(backupPair.first, backupPair.second);
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
            return KillProcessOp{value};
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
                    
                    l_op.backupPath = l_op.linkPath.wstring() + L"_Backup";

                    if (l_op.isHardlink && l_op.traversalMode.empty()) {
                        if (!std::filesystem::exists(l_op.targetPath)) {
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
                ro_op.backupPath = ro_op.targetPath.wstring() + L"_Backup";
                beforeOp.data = ro_op; op_created = true;
            } 
            else if (_wcsicmp(key.c_str(), L"file") == 0 || _wcsicmp(key.c_str(), L"dir") == 0) {
                FileOp f_op; f_op.isDirectory = (_wcsicmp(key.c_str(), L"dir") == 0);
                auto parts = split_string(value, delimiter);
                if (parts.size() == 2) {
                    f_op.destPath = ResolveToAbsolutePath(ExpandVariables(parts[0], variables), variables);
                    std::wstring sourceRaw = parts[1];
                    auto expandedSource = ResolveToAbsolutePath(ExpandVariables(sourceRaw, variables), variables);
                    if (f_op.isDirectory) {
                        f_op.sourcePath = expandedSource;
                    } else {
                        if (sourceRaw.back() == L'\\') f_op.sourcePath = expandedSource / f_op.destPath.filename();
                        else f_op.sourcePath = expandedSource;
                    }
                    f_op.destBackupPath = f_op.destPath.wstring() + L"_Backup";
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

void ExecuteActionOperation(const ActionOpData& opData, std::map<std::wstring, std::wstring>& variables) {
    std::visit([&](const auto& arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, RunOp>) {
            auto finalPath = ResolveToAbsolutePath(ExpandVariables(arg.programPath.wstring(), variables), variables);
            std::wstring finalCmd = ExpandVariables(arg.commandLine, variables);
            auto finalDir = ResolveToAbsolutePath(ExpandVariables(arg.workDir.wstring(), variables), variables);
            ExecuteProcess(finalPath, finalCmd, finalDir, arg.wait, arg.hide);
        }
        else if constexpr (std::is_same_v<T, RegImportOp>) {
            auto finalPath = ResolveToAbsolutePath(ExpandVariables(arg.regPath.wstring(), variables), variables);
            ImportRegistryFile(finalPath);
        } else if constexpr (std::is_same_v<T, RegDllOp>) {
            auto finalPath = ResolveToAbsolutePath(ExpandVariables(arg.dllPath.wstring(), variables), variables);
            wchar_t systemPath[MAX_PATH];
            GetSystemDirectoryW(systemPath, MAX_PATH);
            std::filesystem::path regsvrPath = std::filesystem::path(systemPath) / L"regsvr32.exe";
            std::wstring args = L"/s \"" + finalPath.wstring() + L"\"";
            if (arg.unregister) {
                args = L"/u " + args;
            }
            ExecuteProcess(regsvrPath, args, L"", true, true);
        } else if constexpr (std::is_same_v<T, DeleteFileOp>) {
            auto finalPath = ResolveToAbsolutePath(ExpandVariables(arg.pathPattern.wstring(), variables), variables);
            ActionHelpers::HandleDeleteFile(finalPath);
        } else if constexpr (std::is_same_v<T, DeleteDirOp>) {
            auto finalPath = ResolveToAbsolutePath(ExpandVariables(arg.pathPattern.wstring(), variables), variables);
            ActionHelpers::HandleDeleteDir(finalPath, arg.ifEmpty);
        } else if constexpr (std::is_same_v<T, DeleteRegKeyOp>) {
            ActionHelpers::HandleDeleteRegKey(ExpandVariables(arg.keyPattern, variables), arg.ifEmpty);
        } else if constexpr (std::is_same_v<T, DeleteRegValueOp>) {
            ActionHelpers::HandleDeleteRegValue(ExpandVariables(arg.keyPattern, variables), ExpandVariables(arg.valuePattern, variables));
        } else if constexpr (std::is_same_v<T, CreateDirOp>) {
            auto finalPath = ResolveToAbsolutePath(ExpandVariables(arg.path.wstring(), variables), variables);
            std::filesystem::create_directories(finalPath);
        } else if constexpr (std::is_same_v<T, DelayOp>) {
            Sleep(arg.milliseconds);
        } else if constexpr (std::is_same_v<T, KillProcessOp>) {
            ActionHelpers::HandleKillProcess(ExpandVariables(arg.processPattern, variables));
        } else if constexpr (std::is_same_v<T, CreateFileOp>) {
            CreateFileOp mutable_op = arg;
            mutable_op.path = ResolveToAbsolutePath(ExpandVariables(arg.path.wstring(), variables), variables);
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
            mutable_op.sourcePath = ResolveToAbsolutePath(ExpandVariables(arg.sourcePath.wstring(), variables), variables);
            mutable_op.destPath = ResolveToAbsolutePath(ExpandVariables(arg.destPath.wstring(), variables), variables);
            ActionHelpers::HandleCopyMove(mutable_op);
        } else if constexpr (std::is_same_v<T, AttributesOp>) {
            AttributesOp mutable_op = arg;
            mutable_op.path = ResolveToAbsolutePath(ExpandVariables(arg.path.wstring(), variables), variables);
            ActionHelpers::HandleAttributes(mutable_op);
        } else if constexpr (std::is_same_v<T, IniWriteOp>) {
            IniWriteOp mutable_op = arg;
            mutable_op.path = ResolveToAbsolutePath(ExpandVariables(arg.path.wstring(), variables), variables);
            mutable_op.value = ExpandVariables(arg.value, variables);
            ActionHelpers::HandleIniWrite(mutable_op);
        } else if constexpr (std::is_same_v<T, ReplaceOp>) {
            ReplaceOp mutable_op = arg;
            mutable_op.path = ResolveToAbsolutePath(ExpandVariables(arg.path.wstring(), variables), variables);
            mutable_op.findText = ExpandVariables(arg.findText, variables);
            mutable_op.replaceText = ExpandVariables(arg.replaceText, variables);
            ActionHelpers::HandleReplace(mutable_op);
        } else if constexpr (std::is_same_v<T, ReplaceLineOp>) {
            ReplaceLineOp mutable_op = arg;
            mutable_op.path = ResolveToAbsolutePath(ExpandVariables(arg.path.wstring(), variables), variables);
            mutable_op.lineStart = ExpandVariables(arg.lineStart, variables);
            mutable_op.replaceLine = ExpandVariables(arg.replaceLine, variables);
            ActionHelpers::HandleReplaceLine(mutable_op);
        }
        else if constexpr (std::is_same_v<T, EnvVarOp>) {
            std::wstring finalName = ExpandVariables(arg.name, variables);
            std::wstring finalValue = ExpandVariables(arg.value, variables);
            if (_wcsicmp(finalValue.c_str(), L"null") == 0) {
                SetEnvironmentVariableW(finalName.c_str(), NULL);
            } else {
                SetEnvironmentVariableW(finalName.c_str(), finalValue.c_str());
            }
        }
    }, opData);
}

void PerformFullCleanup(
    std::vector<AfterOperation>& afterOps,
    std::vector<StartupShutdownOperation>& shutdownOps,
    std::map<std::wstring, std::wstring>& variables
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
                ExecuteActionOperation(actionOp.data, variables);
            }
        }
    } else {
        for (auto it = shutdownOps.rbegin(); it != shutdownOps.rend(); ++it) {
            PerformShutdownOperation(it->data);
        }
        for (auto& op : afterOps) {
            ActionOperation actionOp = std::get<ActionOperation>(op.data);
            ExecuteActionOperation(actionOp.data, variables);
        }
    }
}


// --- Main Application Logic ---
void LaunchApplication(const std::wstring& iniContent, std::map<std::wstring, std::wstring>& variables) {
    std::filesystem::path appPathRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"General", L"application"), variables);
    if (appPathRaw.empty()) return;

    std::filesystem::path workDirRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"General", L"workdir"), variables);
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
    std::wstring fullCommandLineForDisplay = L"\"" + data->absoluteAppPath.wstring() + L"\" " + commandLine;
    std::vector<wchar_t> commandLineBuffer(fullCommandLineForDisplay.begin(), fullCommandLineForDisplay.end());
    commandLineBuffer.push_back(0);

    if (!CreateProcessW(NULL, commandLineBuffer.data(), NULL, NULL, FALSE, 0, NULL, data->finalWorkDir.c_str(), &si, &pi)) {
        MessageBoxW(NULL, (L"启动程序失败: \n" + data->absoluteAppPath.wstring()).c_str(), L"启动错误", MB_ICONERROR);
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

            if (data->absoluteAppPath.has_filename()) {
                waitProcesses.push_back(data->absoluteAppPath.filename().wstring());
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
        } else { // 单实例逻辑
            if (waitProcesses.empty()) {
                WaitForSingleObject(pi.hProcess, INFINITE);
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

    PerformFullCleanup(data->afterOps, data->shutdownOps, data->variables);

    std::filesystem::remove(data->tempFilePath);
    
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

    std::filesystem::path launcherFullPath;
    {
        std::vector<wchar_t> buffer(MAX_PATH);
        DWORD size = MAX_PATH;
        while (true) {
            size = GetModuleFileNameW(NULL, buffer.data(), static_cast<DWORD>(buffer.size()));
            if (size < buffer.size()) {
                launcherFullPath = buffer.data();
                break;
            }
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                buffer.resize(buffer.size() * 2);
            } else {
                MessageBoxW(NULL, L"无法获取启动器路径", L"致命错误", MB_ICONERROR);
                return 1;
            }
        }
    }
    
    std::filesystem::path iniPath = launcherFullPath;
    iniPath.replace_extension(L".ini");

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
    variables[L"DRIVE"] = launcherFullPath.root_name().wstring();
    variables[L"YAPROOT"] = launcherFullPath.parent_path().wstring();

    std::filesystem::path appPathRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"General", L"application"), variables);

    std::wstring launcherBaseName = launcherFullPath.stem().wstring();
    std::wstring appBaseName = appPathRaw.stem().wstring();
    std::wstring mutexName = L"Global\\" + launcherBaseName + L"_" + appBaseName;

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
        
        auto absoluteAppPath = ResolveToAbsolutePath(appPathRaw, variables);
        variables[L"APPEXE"] = absoluteAppPath.wstring();
        variables[L"EXEPATH"] = absoluteAppPath.parent_path().wstring();
        
        if (absoluteAppPath.has_filename()) {
            variables[L"EXENAME"] = absoluteAppPath.filename().wstring();
			variables[L"APPNAME"] = absoluteAppPath.stem().wstring();
        }

        std::filesystem::path workDirRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"General", L"workdir"), variables);
        auto finalWorkDir = ResolveToAbsolutePath(workDirRaw, variables);
        if (finalWorkDir.empty() || !std::filesystem::is_directory(finalWorkDir)) {
            finalWorkDir = absoluteAppPath.parent_path();
        }
        variables[L"WORKDIR"] = finalWorkDir.wstring();

        std::filesystem::path tempFileDir;
        std::filesystem::path tempFileDirRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"General", L"tempfile"), variables);
        if (tempFileDirRaw.empty()) {
            tempFileDir = variables[L"YAPROOT"];
        } else {
            tempFileDir = ResolveToAbsolutePath(tempFileDirRaw, variables);
        }
        std::filesystem::path tempFilePath = tempFileDir / (launcherBaseName + L"Temp.ini");

        std::vector<BeforeOperation> beforeOps;
        std::vector<AfterOperation> afterOps;
        BackupThreadData backupData;

        if (std::filesystem::exists(tempFilePath)) {
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
                                    for(const auto& entry : std::filesystem::directory_iterator(op_data.targetPath)) {
                                        const auto& itemName = entry.path().filename();
                                        bool isItemDirectory = entry.is_directory();
                                        bool shouldHaveBeenLinked = false;
                                        if (_wcsicmp(op_data.traversalMode.c_str(), L"all") == 0) shouldHaveBeenLinked = true;
                                        else if (_wcsicmp(op_data.traversalMode.c_str(), L"dir") == 0) shouldHaveBeenLinked = isItemDirectory;
                                        else if (_wcsicmp(op_data.traversalMode.c_str(), L"file") == 0) shouldHaveBeenLinked = !isItemDirectory;
                                        if (op_data.isHardlink && isItemDirectory) shouldHaveBeenLinked = false;

                                        if (shouldHaveBeenLinked) {
                                            auto destFullPath = op_data.linkPath / itemName;
                                            if (std::filesystem::exists(destFullPath)) {
                                                op_data.createdLinks.push_back({destFullPath, L""});
                                            }
                                            auto backupPath = destFullPath.wstring() + L"_Backup";
                                            if (std::filesystem::exists(backupPath)) {
                                                op_data.backedUpPaths.push_back({backupPath, destFullPath});
                                            }
                                        }
                                    }
                                } else {
                                     if (std::filesystem::exists(op_data.backupPath)) {
                                        op_data.backedUpPaths.push_back({op_data.backupPath, op_data.linkPath});
                                     }
                                }
                            }
                        }, ssOp.data);
                        shutdownOpsForCrash.push_back(ssOp);
                    }
                }, op.data);
            }

            PerformFullCleanup(afterOps, shutdownOpsForCrash, variables);

            std::wstring crashWaitStr = GetValueFromIniContent(iniContent, L"General", L"crashwait");
            int crashWaitTime = crashWaitStr.empty() ? 1000 : _wtoi(crashWaitStr.c_str());
            if (crashWaitTime > 0) {
                Sleep(crashWaitTime);
            }

            std::filesystem::remove(tempFilePath);

            beforeOps.clear();
            afterOps.clear();
            backupData = {};
        }

        ParseIniSections(iniContent, variables, beforeOps, afterOps, backupData);

        std::vector<StartupShutdownOperation> shutdownOps;

        {
            if (tempFilePath.has_parent_path()) {
                std::filesystem::create_directories(tempFilePath.parent_path());
            }
            std::ofstream tempFile(tempFilePath);
            tempFile.close();
        }

        for (auto& op : beforeOps) {
            std::visit([&](auto& arg) {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, ActionOpData>) {
                    ExecuteActionOperation(arg, variables);
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