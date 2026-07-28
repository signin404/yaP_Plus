#include <windows.h>
#include <winternl.h>
#include <aclapi.h>
#include <sddl.h>
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
#include <regex>
#include <functional>
#include <wincrypt.h>
#include "IpcCommon.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Gdi32.lib")
#pragma comment(lib, "Version.lib")

#define IDR_INI_FILE 101
#define IDR_HOOK_DLL_32 102
#define IDR_HOOK_DLL_64 103
#define IDR_INJECTOR32 104

#ifndef REG_OPTION_OPEN_LINK
#define REG_OPTION_OPEN_LINK (0x00000008L)
#endif

// --- Function pointer types for NTDLL functions ---
typedef LONG (NTAPI *pfnNtDeleteKey)(IN HANDLE KeyHandle);
typedef LONG (NTAPI *pfnNtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG (NTAPI *pfnNtResumeProcess)(IN HANDLE ProcessHandle);
typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pfnRtlCreateUserThread)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PVOID);

// [修改] 确保全局变量已声明
pfnNtDeleteKey g_NtDeleteKey = nullptr;
pfnNtSuspendProcess g_NtSuspendProcess = nullptr;
pfnNtResumeProcess g_NtResumeProcess = nullptr;
pfnNtQueryInformationProcess g_NtQueryInformationProcess = nullptr;
pfnRtlCreateUserThread g_RtlCreateUserThread = nullptr;

std::wstring g_originalPath;
std::wstring g_LauncherDir;
std::vector<std::wstring> g_TemporaryFonts;

// --- Data Structures ---

// Operations with startup and shutdown/cleanup logic
struct FileOp {
    std::wstring sourcePath;
    std::wstring destPath;
    std::wstring destBackupPath;
    bool isDirectory;
    bool destBackupCreated = false;
    bool wasMoved = false;
    bool isWildcard = false;
    std::wstring wildcardPattern;
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

struct RegDllOp {
    std::wstring dllPath;
};

// [新增] 注册表符号链接操作结构体
struct RegLinkOp {
    HKEY hRootKey;
    std::wstring rootKeyStr;
    std::wstring subKey;
    std::wstring targetWin32Path;
    std::wstring targetNtPath;
    std::wstring backupSubKey;
    bool backupCreated = false;
    bool isCreated = false;
};

// This variant is now only used for the shutdown stack
using StartupShutdownOperationData = std::variant<FileOp, RestoreOnlyFileOp, RegistryOp, LinkOp, FirewallOp, RegDllOp, RegLinkOp>;
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
    bool isWildcard = false;
    std::wstring wildcardPattern;
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
    bool useRegex = false;
    bool ignoreCase = false;
};

struct ReplaceLineOp {
    std::wstring path;
    std::wstring lineStart;
    std::wstring replaceLine;
};

enum class EnvVarType {
    Process, // 进程专用 (默认)
    User,    // 当前用户 (全局)
    System   // 系统 (全局)
};

struct EnvVarOp {
    std::wstring name;
    std::wstring value;
    EnvVarType type = EnvVarType::Process;
};


// A variant for one-shot actions, used by [Before] and [After] sections
using ActionOpData = std::variant<
    RunOp, RegImportOp, DeleteFileOp, DeleteDirOp, DeleteRegKeyOp, DeleteRegValueOp,
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
    FileOp, RestoreOnlyFileOp, RegistryOp, LinkOp, FirewallOp, RegDllOp, RegLinkOp, // Startup/Shutdown types
    ActionOpData // One-shot types (using the variant directly)
>;
struct BeforeOperation {
    BeforeOperationData data;
};

// Forward declarations for thread data structures
struct MonitorThreadData;
struct BackupThreadData;

// <-- [新增] 用于存储解析后的等待进程条目的结构体
struct WaitProcessInfo {
    std::wstring processName;
    bool checkPath = false;
    std::wstring basePath;
};

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
	DWORD launcherPid;
    std::wstring pipeName;
    std::wstring regMountName; // [新增] 传递挂载名称用于卸载
    std::wstring hivePath;     // [新增] 传递文件路径用于清理日志
};

// --- 提取嵌入资源的辅助函数 ---
bool ExtractResourceToFile(int resourceId, const std::wstring& outputPath) {
    // 1. 查找资源
    // NULL 表示查找当前模块(EXE)
    // MAKEINTRESOURCE(resourceId) 是资源的数字 ID
    // RT_RCDATA 是资源类型 (Raw Data)
    HRSRC hRes = FindResourceW(NULL, MAKEINTRESOURCEW(resourceId), RT_RCDATA);
    if (!hRes) return false; // 资源不存在

    // 2. 加载资源
    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) return false;

    // 3. 获取资源大小和指针
    DWORD dataSize = SizeofResource(NULL, hRes);
    void* pData = LockResource(hData);
    if (!pData || dataSize == 0) return false;

    // 4. 写入文件
    std::ofstream out(outputPath, std::ios::binary);
    if (!out.is_open()) return false;

    out.write(static_cast<const char*>(pData), dataSize);
    out.close();

    return true;
}

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

// [新增] 计算二进制数据的 SHA1 值
std::vector<uint8_t> CalculateSHA1(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(20, 0);
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
            if (CryptHashData(hHash, data.data(), static_cast<DWORD>(data.size()), 0)) {
                DWORD hashLen = 20;
                CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0);
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return hash;
}

// [新增] 模拟 .NET 独有的 ToBase32StringSuitableForDirName 编码算法
std::wstring ToBase32StringSuitableForDirName(const std::vector<uint8_t>& buff) {
    static const wchar_t s_Base32Char[] = {
        L'a', L'b', L'c', L'd', L'e', L'f', L'g', L'h',
        L'i', L'j', L'k', L'l', L'm', L'n', L'o', L'p',
        L'q', L'r', L's', L't', L'u', L'v', L'w', L'x',
        L'y', L'z', L'0', L'1', L'2', L'3', L'4', L'5'
    };

    std::wstring result;
    size_t l = buff.size();
    size_t i = 0;
    uint8_t b0, b1, b2, b3, b4;

    do {
        b0 = (i < l) ? buff[i++] : 0;
        b1 = (i < l) ? buff[i++] : 0;
        b2 = (i < l) ? buff[i++] : 0;
        b3 = (i < l) ? buff[i++] : 0;
        b4 = (i < l) ? buff[i++] : 0;

        // 获取每个字节的后 5 位进行 Base32 映射
        result += s_Base32Char[b0 & 0x1F];
        result += s_Base32Char[b1 & 0x1F];
        result += s_Base32Char[b2 & 0x1F];
        result += s_Base32Char[b3 & 0x1F];
        result += s_Base32Char[b4 & 0x1F];

        // 处理高位数据合并与移位
        result += s_Base32Char[((b0 & 0xE0) >> 5) | ((b3 & 0x60) >> 2)];
        result += s_Base32Char[((b1 & 0xE0) >> 5) | ((b4 & 0x60) >> 2)];

        b2 >>= 5;
        if ((b3 & 0x80) != 0) b2 |= 0x08;
        if ((b4 & 0x80) != 0) b2 |= 0x10;
        result += s_Base32Char[b2];
    } while (i < l);

    return result;
}

// [新增] 模拟 .NET 逻辑计算含有 Url 及 SHA1 校验码的文件名段
std::wstring CalculateNetPath(std::wstring absoluteAppPath, int mode) {
    if (mode < 0 || mode >= 1728) return L"";

    // 通过 mode 还原 8 个维度的配置 (0 ~ 1727)
    int m = mode;
    int prefix_ext_mode = m % 2; m /= 2;  // 0:无扩展名, 1:带扩展名
    int path_ext_mode   = m % 2; m /= 2;  // 0:无扩展名, 1:带扩展名
    int drive_mode      = m % 3; m /= 3;  // 0:原样, 1:大写, 2:小写
    int slash_mode      = m % 2; m /= 2;  // 0:反斜杠, 1:正斜杠
    int proto_mode      = m % 3; m /= 3;  // 0:无, 1:file:///, 2:FILE:///
    int case_mode       = m % 2; m /= 2;  // 0:原样, 1:全大写
    int salt_mode       = m % 3; m /= 3;  // 0:无, 1:后置(File:), 2:前置(File:)
    int enc_mode        = m % 4;          // 0:纯UTF8, 1:7bit+UTF8, 2:NRBF, 3:纯UTF16LE

    const wchar_t* appFilenameWithExt = PathFindFileNameW(absoluteAppPath.c_str());
    if (!appFilenameWithExt || wcslen(appFilenameWithExt) == 0) return L"";

    std::wstring prefixWithExt = appFilenameWithExt;
    std::wstring prefixNoExt = prefixWithExt;
    size_t dotPos = prefixNoExt.find_last_of(L".");
    if (dotPos != std::wstring::npos) prefixNoExt = prefixNoExt.substr(0, dotPos);

    std::wstring prefixName = (prefix_ext_mode == 0) ? prefixNoExt : prefixWithExt;

    std::wstring basePath = absoluteAppPath;
    dotPos = basePath.find_last_of(L".");
    size_t slashPos = basePath.find_last_of(L"\\/");
    if (dotPos != std::wstring::npos && (slashPos == std::wstring::npos || dotPos > slashPos)) {
        basePath = basePath.substr(0, dotPos);
    }

    std::wstring pathStr = (path_ext_mode == 0) ? basePath : absoluteAppPath;

    // 盘符大小写处理
    std::wstring pathCopy = pathStr;
    if (pathCopy.length() >= 2 && pathCopy[1] == L':') {
        if (drive_mode == 1) pathCopy[0] = towupper(pathCopy[0]);
        else if (drive_mode == 2) pathCopy[0] = towlower(pathCopy[0]);
    }

    // 斜杠处理
    wchar_t targetSlash = (slash_mode == 0) ? L'\\' : L'/';
    std::wstring modifiedPath = pathCopy;
    for (auto& ch : modifiedPath) {
        if (ch == L'\\' || ch == L'/') ch = targetSlash;
    }

    // 协议前缀
    std::wstring uri;
    if (proto_mode == 0) uri = modifiedPath;
    else if (proto_mode == 1) uri = L"file:///" + modifiedPath;
    else uri = L"FILE:///" + modifiedPath;

    // 全局大小写
    std::wstring finalUri = uri;
    if (case_mode == 1) {
        for (auto& ch : finalUri) {
            if (ch >= L'a' && ch <= L'z') ch -= 32;
        }
    }

    // 转换为 UTF-8 (如果需要)
    std::string utf8Uri;
    if (enc_mode < 3) {
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, finalUri.c_str(), (int)finalUri.length(), NULL, 0, NULL, NULL);
        utf8Uri.resize(size_needed);
        WideCharToMultiByte(CP_UTF8, 0, finalUri.c_str(), (int)finalUri.length(), &utf8Uri[0], size_needed, NULL, NULL);
    }

    std::string salt = "File:";
    std::vector<uint8_t> rawData;

    // NRBF 头部
    if (enc_mode == 2) {
        const uint8_t bfHeader[] = {
            0x00, 0x01, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };
        rawData.insert(rawData.end(), bfHeader, bfHeader + 17);
        rawData.push_back(0x06); // BinaryObjectString
        rawData.push_back(0x01); rawData.push_back(0x00); rawData.push_back(0x00); rawData.push_back(0x00); // ObjectId
    }

    // 7-bit 长度前缀
    if (enc_mode == 1 || enc_mode == 2) {
        size_t val = utf8Uri.length();
        while (val >= 0x80) {
            rawData.push_back(static_cast<uint8_t>((val & 0x7F) | 0x80));
            val >>= 7;
        }
        rawData.push_back(static_cast<uint8_t>(val & 0x7F));
    }

    // 拼接主体数据
    if (enc_mode < 3) { // UTF8 based
        if (salt_mode == 2) { // Prefix Salt
            rawData.insert(rawData.end(), salt.begin(), salt.end());
        }
        rawData.insert(rawData.end(), utf8Uri.begin(), utf8Uri.end());
        if (salt_mode == 1) { // Suffix Salt
            rawData.insert(rawData.end(), salt.begin(), salt.end());
        }
    } else { // enc_mode == 3: UTF16LE
        rawData.resize(finalUri.length() * 2);
        memcpy(rawData.data(), finalUri.c_str(), finalUri.length() * 2);
        if (salt_mode == 1) { // Suffix Salt
            rawData.insert(rawData.end(), salt.begin(), salt.end());
        } else if (salt_mode == 2) { // Prefix Salt
            rawData.insert(rawData.begin(), salt.begin(), salt.end());
        }
    }

    // NRBF 结束符
    if (enc_mode == 2) {
        rawData.push_back(0x0B);
    }

    // SHA1 & Base32
    std::vector<uint8_t> sha1Hash = CalculateSHA1(rawData);
    std::wstring base32Hash = ToBase32StringSuitableForDirName(sha1Hash);

    return prefixName + L"_Url_" + base32Hash;
}

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
    void GrantRegistryKeyPermission(HKEY hKeyParent, const std::wstring& subKey, REGSAM view = 0);
}

// [新增] 获取当前用户 SID 字符串的辅助函数
std::wstring GetCurrentUserSidString() {
    std::wstring sidStr;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
        if (dwSize > 0) {
            std::vector<BYTE> buffer(dwSize);
            if (GetTokenInformation(hToken, TokenUser, buffer.data(), dwSize, &dwSize)) {
                PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(buffer.data());
                wchar_t* szSid = NULL;
                if (ConvertSidToStringSidW(pTokenUser->User.Sid, &szSid)) {
                    sidStr = szSid;
                    LocalFree(szSid);
                }
            }
        }
        CloseHandle(hToken);
    }
    return sidStr;
}

// [新增] 将 Win32 注册表路径转换为 NT 内核绝对注册表路径 (注册表符号链接必须使用 NT 绝对路径)
std::wstring ConvertToNtRegistryPath(const std::wstring& win32RegPath) {
    HKEY hRootKey;
    std::wstring rootKeyStr, subKey, valueName;
    if (!ParseRegistryPath(win32RegPath, true, hRootKey, rootKeyStr, subKey, valueName)) {
        return L"";
    }

    std::wstring ntPath;
    if (hRootKey == HKEY_LOCAL_MACHINE) {
        ntPath = L"\\Registry\\Machine\\" + subKey;
    } else if (hRootKey == HKEY_CURRENT_USER) {
        std::wstring sid = GetCurrentUserSidString();
        if (!sid.empty()) {
            ntPath = L"\\Registry\\User\\" + sid + L"\\" + subKey;
        } else {
            ntPath = L"\\Registry\\User\\CurrentUser\\" + subKey;
        }
    } else if (hRootKey == HKEY_USERS) {
        ntPath = L"\\Registry\\User\\" + subKey;
    } else if (hRootKey == HKEY_CLASSES_ROOT) {
        ntPath = L"\\Registry\\Machine\\Software\\Classes\\" + subKey;
    }

    return ntPath;
}

// [新增] 创建注册表符号链接
bool CreateRegistrySymbolicLink(HKEY hRootKey, const std::wstring& subKey, const std::wstring& targetNtPath) {
    HKEY hKey = NULL;
    DWORD disposition = 0;
    LSTATUS status = RegCreateKeyExW(
        hRootKey,
        subKey.c_str(),
        0,
        NULL,
        REG_OPTION_CREATE_LINK,
        KEY_WRITE | KEY_CREATE_LINK,
        NULL,
        &hKey,
        &disposition
    );
    if (status != ERROR_SUCCESS) {
        return false;
    }

    // 写入 SymbolicLinkValue 目标值 (必须是 REG_LINK 类型且不包含空终止符)
    status = RegSetValueExW(
        hKey,
        L"SymbolicLinkValue",
        0,
        REG_LINK,
        reinterpret_cast<const BYTE*>(targetNtPath.c_str()),
        static_cast<DWORD>(targetNtPath.length() * sizeof(wchar_t))
    );

    RegCloseKey(hKey);
    return (status == ERROR_SUCCESS);
}

// [新增] 删除注册表符号链接 (必须指定 REG_OPTION_OPEN_LINK 并使用 NtDeleteKey)
bool DeleteRegistrySymbolicLink(HKEY hRootKey, const std::wstring& subKey) {
    if (!g_NtDeleteKey) return false;
    HKEY hKey = NULL;
    LSTATUS status = RegOpenKeyExW(hRootKey, subKey.c_str(), REG_OPTION_OPEN_LINK, KEY_WRITE | DELETE, &hKey);
    if (status == ERROR_SUCCESS) {
        LONG ntStatus = g_NtDeleteKey(hKey);
        RegCloseKey(hKey);
        return (ntStatus == 0);
    }
    return false;
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
    LSTATUS res = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ, &hSrcKey);

    // [新增] 如果源键拒绝访问 尝试提权后重试
    if (res == ERROR_ACCESS_DENIED) {
        ActionHelpers::GrantRegistryKeyPermission(hRootKey, subKey, 0);
        res = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ, &hSrcKey);
    }
    if (res != ERROR_SUCCESS) {
        return false;
    }

    LSTATUS createStatus = RegCreateKeyExW(hRootKey, newSubKey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hDestKey, NULL);

    // [新增] 如果创建备份键拒绝访问（通常是因为父键如 Enum\Root 没有写入权限） 对父键提权
    if (createStatus == ERROR_ACCESS_DENIED) {
        std::wstring parentKey;
        size_t lastSlash = newSubKey.find_last_of(L'\\');
        if (lastSlash != std::wstring::npos) {
            parentKey = newSubKey.substr(0, lastSlash);
            ActionHelpers::GrantRegistryKeyPermission(hRootKey, parentKey, 0);
        } else {
            ActionHelpers::GrantRegistryKeyPermission(hRootKey, L"", 0);
        }
        createStatus = RegCreateKeyExW(hRootKey, newSubKey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hDestKey, NULL);
    }

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
    LSTATUS res = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ | KEY_WRITE, &hKey);

    // [新增] 如果拒绝访问 尝试提权后重试
    if (res == ERROR_ACCESS_DENIED) {
        ActionHelpers::GrantRegistryKeyPermission(hRootKey, subKey, 0);
        res = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ | KEY_WRITE, &hKey);
    }
    if (res != ERROR_SUCCESS) return false;

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

            if (type == REG_SZ && (dataSize % sizeof(wchar_t) == 0)) {
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
            } else if (type == REG_DWORD && dataSize == sizeof(DWORD)) {
                DWORD dwordValue = *reinterpret_cast<DWORD*>(data.data());
                wss << L"dword:" << std::hex << std::setw(8) << std::setfill(L'0') << dwordValue;
            } else {
                wss << L"hex";
                if (type == REG_EXPAND_SZ) wss << L"(2)";
                else if (type == REG_MULTI_SZ) wss << L"(7)";
                else if (type == REG_QWORD) wss << L"(b)";
                else if (type == REG_SZ) wss << L"(1)"; // [新增] 畸形字符串会变成 hex(1):
                else if (type != REG_BINARY) wss << L"(" << std::hex << type << L")";
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
    LSTATUS res = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ, &hKeyToExport);

    // [新增] 如果导出时拒绝访问 尝试提权后重试
    if (res == ERROR_ACCESS_DENIED) {
        ActionHelpers::GrantRegistryKeyPermission(hRootKey, subKey, 0);
        res = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ, &hKeyToExport);
    }
    if (res != ERROR_SUCCESS) {
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
    LSTATUS res = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ, &hKey);

    // [新增] 如果导出时拒绝访问 尝试提权后重试
    if (res == ERROR_ACCESS_DENIED) {
        ActionHelpers::GrantRegistryKeyPermission(hRootKey, subKey, 0);
        res = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ, &hKey);
    }
    if (res != ERROR_SUCCESS) return false;

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

    // 1. 处理字符串 (REG_SZ)
    // 检查类型是否为 REG_SZ 且长度是否为偶数
    if (type == REG_SZ && (size % sizeof(wchar_t) == 0)) {
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
    }
    // 2. 处理 DWORD (REG_DWORD)
    // 检查类型是否为 REG_DWORD 且长度是否严格为 4 字节
    else if (type == REG_DWORD && size == sizeof(DWORD)) {
        DWORD dwordValue = *reinterpret_cast<DWORD*>(data.data());
        wss << L"dword:" << std::hex << std::setw(8) << std::setfill(L'0') << dwordValue;
    }
    // 3. 处理其他所有类型 (Hex 导出)
    else {
        wss << L"hex";
        if (type == REG_EXPAND_SZ) wss << L"(2)";
        else if (type == REG_MULTI_SZ) wss << L"(7)";
        else if (type == REG_QWORD) wss << L"(b)";
        else if (type == REG_SZ) wss << L"(1)"; // 畸形字符串
        // [修正] 强制使用十六进制输出类型值 (例如 hex(a) 而不是 hex(10))
        else if (type != REG_BINARY) wss << L"(" << std::hex << type << L")";

        wss << L":";

        // --- [核心修改] ---
        const size_t MAX_LINE_LEN = 80;
        size_t currentLineLength = wss.str().length();

        // [修正] 这里也使用 'size'
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

// <-- [新增] 用于一次性构建NT设备名到驱动器号映射缓存的函数
void BuildDeviceMapCache(std::map<std::wstring, std::wstring>& cache) {
    wchar_t driveStrings[MAX_PATH];
    if (GetLogicalDriveStringsW(MAX_PATH, driveStrings) == 0) {
        return;
    }

    wchar_t* pDrive = driveStrings;
    while (*pDrive) {
        std::wstring driveLetter = pDrive;
        driveLetter.pop_back(); // 移除 '\', 得到 "C:"

        wchar_t deviceName[MAX_PATH];
        if (QueryDosDeviceW(driveLetter.c_str(), deviceName, MAX_PATH) != 0) {
            // 存入缓存 键是NT设备名 值是驱动器号
            cache[deviceName] = driveLetter;
        }
        pDrive += wcslen(pDrive) + 1;
    }
}

// <-- [修改] 最终的、可靠的、且带缓存的路径转换函数
std::wstring ConvertDevicePathToDosPath(const std::wstring& path) {
    // 使用静态变量作为缓存 它只会被初始化一次
    static std::map<std::wstring, std::wstring> deviceMapCache;
    // 如果缓存为空（即第一次调用此函数时） 则构建缓存
    if (deviceMapCache.empty()) {
        BuildDeviceMapCache(deviceMapCache);
    }

    // 如果路径不是以 "\Device\" 开头 则直接返回
    if (path.rfind(L"\\Device\\", 0) != 0) {
        return path;
    }

    // 遍历缓存中的所有已知NT设备名
    for (const auto& entry : deviceMapCache) {
        const std::wstring& ntDeviceName = entry.first;
        const std::wstring& driveLetter = entry.second;

        // 检查输入路径是否以缓存中的NT设备名开头
        if (path.rfind(ntDeviceName, 0) == 0) {
            // 如果是 则用驱动器号替换掉NT设备名部分 构造出Win32路径
            return driveLetter + path.substr(ntDeviceName.length());
        }
    }

    // 如果找不到匹配项 则返回原始路径
    return path;
}

// <-- [新增] 获取进程完整路径的辅助函数 支持长路径
std::wstring GetProcessFullPathByPid(DWORD pid) {
    if (pid == 0) return L"";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        std::vector<wchar_t> buffer(MAX_PATH);
        DWORD size = (DWORD)buffer.size();
        while (true) {
            // --- [最终修正：恢复为最原始、兼容性最好的调用方式] ---
            if (QueryFullProcessImageNameW(hProcess, 0, buffer.data(), &size)) {
                CloseHandle(hProcess);
                return std::wstring(buffer.data());
            } else {
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    size *= 2;
                    buffer.resize(size);
                } else {
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

    // [新增] 辅助函数：获取注册表项权限 (提权)
    // 相当于 NSIS 中的 AccessControl::GrantOnRegKey ... "(BU)" "FullAccess"
    void GrantRegistryKeyPermission(HKEY hKeyParent, const std::wstring& subKey, REGSAM view) {
        PSECURITY_DESCRIPTOR pSD = nullptr;
        // O:BA (Owner: Built-in Admins) G:BA (Group: Built-in Admins) D:(A;OICI;KA;;;BU) (DACL: Allow Full Access to Built-in Users)
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:(A;OICI;KA;;;BU)", SDDL_REVISION_1, &pSD, nullptr)) {
            PACL pDacl = nullptr;
            PSID pOwner = nullptr;
            BOOL bDaclPresent = FALSE, bDaclDefaulted = FALSE;
            BOOL bOwnerDefaulted = FALSE;

            GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted);
            GetSecurityDescriptorOwner(pSD, &pOwner, &bOwnerDefaulted);

            HKEY hTemp;
            // 1. 尝试获取所有权 (需要 SeTakeOwnershipPrivilege)
            if (RegOpenKeyExW(hKeyParent, subKey.c_str(), 0, WRITE_OWNER | view, &hTemp) == ERROR_SUCCESS) {
                SetSecurityInfo(hTemp, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, pOwner, nullptr, nullptr, nullptr);
                RegCloseKey(hTemp);
            }

            // 2. 尝试修改 DACL 赋予完全控制权限 (获取所有权后通常拥有 WRITE_DAC 权限)
            if (RegOpenKeyExW(hKeyParent, subKey.c_str(), 0, WRITE_DAC | view, &hTemp) == ERROR_SUCCESS) {
                SetSecurityInfo(hTemp, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, nullptr, nullptr, pDacl, nullptr);
                RegCloseKey(hTemp);
            }

            LocalFree(pSD);
        }
    }

    // [新增] 辅助函数：判断字符串是否以指定后缀结尾
    bool EndsWith(const std::wstring& str, const std::wstring& suffix) {
        if (str.length() < suffix.length()) return false;
        return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
    }

    // 辅助函数：强制删除文件 即使它有只读属性
    void ForceDeleteFile(const std::wstring& path) {
        // 1. 获取文件属性
        DWORD attributes = GetFileAttributesW(path.c_str());

        // 2. 检查文件是否存在且为只读
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_READONLY)) {
            // 3. 移除只读属性 (保留其他属性)
            SetFileAttributesW(path.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY);
        }

        // 4. 现在可以安全地删除文件了
        DeleteFileW(path.c_str());
    }

    // [新增] 处理 CopyMoveOp 的通配符逻辑
    void ProcessWildcardCopyMove(const CopyMoveOp& op) {
        // 1. 确保目标父目录存在
        if (!PathFileExistsW(op.destPath.c_str())) {
            SHCreateDirectoryExW(NULL, op.destPath.c_str(), NULL);
        }

        std::wstring searchPath = op.sourcePath + L"\\*";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);

        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            // 过滤 . 和 ..
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

            // [关键] 根据指令类型过滤 文件 vs 目录
            bool isItemDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
            if (op.isDirectory && !isItemDir) continue; // <-dir 但遇到了文件 跳过
            if (!op.isDirectory && isItemDir) continue; // <-file 但遇到了目录 跳过

            // 匹配通配符
            if (::WildcardMatch(fd.cFileName, op.wildcardPattern.c_str())) {
                std::wstring srcFullPath = op.sourcePath + L"\\" + fd.cFileName;
                std::wstring destFullPath = op.destPath + L"\\" + fd.cFileName;

                // [关键] 处理 overwrite / no overwrite
                if (PathFileExistsW(destFullPath.c_str())) {
                    if (!op.overwrite) {
                        continue; // 不覆盖 跳过
                    }
                    // 如果需要覆盖 且是移动/复制目录 或者目标是只读文件 先尝试删除目标
                    // 注意：对于文件 CopyFile 有覆盖选项 但 MoveFile 没有 所以 Move 前最好清理
                    if (isItemDir) {
                        PerformFileSystemOperation(FO_DELETE, destFullPath);
                    } else {
                        ForceDeleteFile(destFullPath.c_str());
                    }
                }

                // 执行操作
                if (isItemDir) {
                    // --- 目录操作 ---
                    if (op.isMove) {
                        // 移动目录
                        if (!MoveFileW(srcFullPath.c_str(), destFullPath.c_str())) {
                            PerformFileSystemOperation(FO_MOVE, srcFullPath, destFullPath);
                        }
                    } else {
                        // 复制目录
                        PerformFileSystemOperation(FO_COPY, srcFullPath, destFullPath);
                    }
                } else {
                    // --- 文件操作 ---
                    if (op.isMove) {
                        MoveFileW(srcFullPath.c_str(), destFullPath.c_str());
                    } else {
                        // CopyFile 第三个参数: FALSE = 覆盖, TRUE = 不覆盖
                        // 但我们上面已经处理了 overwrite 逻辑 这里直接覆盖即可
                        CopyFileW(srcFullPath.c_str(), destFullPath.c_str(), FALSE);
                    }
                }
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }

    // [新增] 目录版：基于通配符批量传输 (Copy 或 Move)
    void TransferDirectoriesByPattern(const std::wstring& srcDir, const std::wstring& destDir, const std::wstring& pattern, bool isMove) {
        if (!PathFileExistsW(destDir.c_str())) {
            SHCreateDirectoryExW(NULL, destDir.c_str(), NULL);
        }

        std::wstring searchPath = srcDir + L"\\*";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);

        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            if (EndsWith(fd.cFileName, L"_Backup")) continue;

            if (::WildcardMatch(fd.cFileName, pattern.c_str())) {
                std::wstring srcPath = srcDir + L"\\" + fd.cFileName;
                std::wstring destPath = destDir + L"\\" + fd.cFileName;

                if (isMove) {
                    // --- 移动模式 (保持不变) ---
                    if (PathFileExistsW(destPath.c_str())) {
                        PerformFileSystemOperation(FO_DELETE, destPath);
                    }
                    if (!MoveFileW(srcPath.c_str(), destPath.c_str())) {
                        PerformFileSystemOperation(FO_MOVE, srcPath, destPath);
                    }
                } else {
                    // --- 复制模式 (修改为：重命名 -> 复制 -> 删除) ---

                    std::wstring tempBackupPath = destPath + L"_Backup";
                    bool needCleanup = false;

                    // 1. 如果目标已存在 先将其改名为 _Backup
                    if (PathFileExistsW(destPath.c_str())) {
                        // 如果之前残留了 _Backup 先删掉它
                        if (PathFileExistsW(tempBackupPath.c_str())) {
                            PerformFileSystemOperation(FO_DELETE, tempBackupPath);
                        }

                        // 尝试重命名 (相当于移动到 _Backup)
                        if (MoveFileW(destPath.c_str(), tempBackupPath.c_str())) {
                            needCleanup = true;
                        } else {
                            // 如果重命名失败（例如被占用） 则强制删除旧目录
                            PerformFileSystemOperation(FO_DELETE, destPath);
                        }
                    }

                    // 2. 执行复制 (此时 destPath 应该不存在了 或者是空的)
                    PerformFileSystemOperation(FO_COPY, srcPath, destPath);

                    // 3. 如果复制成功且之前进行了备份 删除 _Backup
                    if (needCleanup && PathFileExistsW(destPath.c_str())) {
                        PerformFileSystemOperation(FO_DELETE, tempBackupPath);
                    }
                }
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }

    // [新增] 目录版：原地备份
    void BackupDirectoriesInPlace(const std::wstring& dir, const std::wstring& pattern) {
        std::wstring searchPath = dir + L"\\" + pattern;
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);

        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            if (EndsWith(fd.cFileName, L"_Backup")) continue;

            if (::WildcardMatch(fd.cFileName, pattern.c_str())) {
                std::wstring srcPath = dir + L"\\" + fd.cFileName;
                std::wstring backupPath = srcPath + L"_Backup";

                if (PathFileExistsW(backupPath.c_str())) {
                    PerformFileSystemOperation(FO_DELETE, backupPath);
                }
                MoveFileW(srcPath.c_str(), backupPath.c_str());
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }

    // [新增] 目录版：安全删除 (跳过备份)
    void DeleteDirectoriesByPatternSafe(const std::wstring& dir, const std::wstring& pattern) {
        std::wstring searchPath = dir + L"\\" + pattern;
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);

        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

            // [关键] 跳过备份目录
            if (EndsWith(fd.cFileName, L"_Backup")) continue;

            if (::WildcardMatch(fd.cFileName, pattern.c_str())) {
                std::wstring fullPath = dir + L"\\" + fd.cFileName;
                // 删除非空目录
                PerformFileSystemOperation(FO_DELETE, fullPath);
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }

    // [新增] 目录版：原地恢复
    void RestoreDirectoryBackupsInPlace(const std::wstring& dir, const std::wstring& pattern) {
        std::wstring searchPath = dir + L"\\*";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);

        if (hFind == INVALID_HANDLE_VALUE) return;

        std::wstring backupSuffix = L"_Backup";

        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

            std::wstring dirName = fd.cFileName;

            if (EndsWith(dirName, backupSuffix)) {
                std::wstring originalName = dirName.substr(0, dirName.length() - backupSuffix.length());

                if (::WildcardMatch(originalName.c_str(), pattern.c_str())) {
                    std::wstring backupPath = dir + L"\\" + dirName;
                    std::wstring restorePath = dir + L"\\" + originalName;

                    if (PathFileExistsW(restorePath.c_str())) {
                        PerformFileSystemOperation(FO_DELETE, restorePath);
                    }

                    MoveFileW(backupPath.c_str(), restorePath.c_str());
                }
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }

    // [新增] 安全删除匹配文件：显式跳过备份文件
    void DeleteFilesByPatternSafe(const std::wstring& dir, const std::wstring& pattern) {
        std::wstring searchPath = dir + L"\\" + pattern;
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);

        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            // 跳过目录
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

            // [核心修复] 绝对不要删除备份文件！
            if (EndsWith(fd.cFileName, L"_Backup")) continue;

            // 再次确认匹配 (防止 FindFirstFile 的 8.3 短文件名误匹配)
            if (::WildcardMatch(fd.cFileName, pattern.c_str())) {
                std::wstring fullPath = dir + L"\\" + fd.cFileName;
                ForceDeleteFile(fullPath.c_str());
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }

    // [新增] 使用 WildcardMatch 筛选并批量传输文件
    void TransferFilesByPattern(const std::wstring& srcDir, const std::wstring& destDir, const std::wstring& pattern, bool isMove) {
        // 1. 确保目标目录存在
        if (!PathFileExistsW(destDir.c_str())) {
            SHCreateDirectoryExW(NULL, destDir.c_str(), NULL);
        }

        // 2. 遍历源目录下的所有文件
        std::wstring searchPath = srcDir + L"\\*";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);

        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            // 跳过目录和特殊标识
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

            // [新增] 关键修复：显式跳过以 _Backup 结尾的文件
            // 防止在回写同步时 将备份文件错误地复制回源目录
            if (EndsWith(fd.cFileName, L"_Backup")) continue;

            // 使用全局的 WildcardMatch 进行匹配
            if (::WildcardMatch(fd.cFileName, pattern.c_str())) {
                std::wstring srcFile = srcDir + L"\\" + fd.cFileName;
                std::wstring destFile = destDir + L"\\" + fd.cFileName;

                if (isMove) {
                    // 移动模式：如果目标存在先强制删除 (处理只读属性)
                    if (PathFileExistsW(destFile.c_str())) {
                        ActionHelpers::ForceDeleteFile(destFile);
                    }
                    MoveFileW(srcFile.c_str(), destFile.c_str());
                } else {
                    // 复制模式：覆盖目标
                    if (PathFileExistsW(destFile.c_str())) {
                        // 移除目标只读属性以确保覆盖成功
                        DWORD attrs = GetFileAttributesW(destFile.c_str());
                        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_READONLY)) {
                            SetFileAttributesW(destFile.c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);
                        }
                    }
                    CopyFileW(srcFile.c_str(), destFile.c_str(), FALSE);
                }
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }

    // [新增] 原地备份：将匹配的文件重命名为 filename_Backup
    void BackupWildcardInPlace(const std::wstring& dir, const std::wstring& pattern) {
        std::wstring searchPath = dir + L"\\" + pattern;
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);

        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

            // 严格匹配模式
            if (::WildcardMatch(fd.cFileName, pattern.c_str())) {
                std::wstring srcFile = dir + L"\\" + fd.cFileName;
                std::wstring backupFile = srcFile + L"_Backup";

                // 如果备份文件已存在 先删除 防止重命名失败
                if (PathFileExistsW(backupFile.c_str())) {
                    ForceDeleteFile(backupFile.c_str());
                }

                // 原地重命名
                MoveFileW(srcFile.c_str(), backupFile.c_str());
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }

    // [新增] 原地恢复：查找 *_Backup 文件 如果去掉后缀后匹配 pattern 则还原
    void RestoreBackupsInPlace(const std::wstring& dir, const std::wstring& pattern) {
        // 这里必须扫描所有文件 因为我们不知道具体的备份文件名
        std::wstring searchPath = dir + L"\\*";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);

        if (hFind == INVALID_HANDLE_VALUE) return;

        std::wstring backupSuffix = L"_Backup";

        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

            std::wstring fileName = fd.cFileName;

            // 检查是否以 _Backup 结尾
            if (EndsWith(fileName, backupSuffix)) {
                // 还原原始文件名
                std::wstring originalName = fileName.substr(0, fileName.length() - backupSuffix.length());

                // 检查原始文件名是否匹配我们的通配符模式
                if (::WildcardMatch(originalName.c_str(), pattern.c_str())) {
                    std::wstring backupPath = dir + L"\\" + fileName;
                    std::wstring restorePath = dir + L"\\" + originalName;

                    // 如果当前位置有文件（可能是运行时生成的） 先删除
                    if (PathFileExistsW(restorePath.c_str())) {
                        ForceDeleteFile(restorePath.c_str());
                    }

                    // 恢复文件名
                    MoveFileW(backupPath.c_str(), restorePath.c_str());
                }
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }

    // Helper to collect all 'path' values from the INI for a specific scope
    std::vector<std::wstring> CollectPathValuesFromIni(const std::wstring& iniContent, std::map<std::wstring, std::wstring>& variables, EnvVarType type) {
        std::vector<std::wstring> paths;
        std::wstringstream stream(iniContent);
        std::wstring line;
        enum class Section { None, Before, After };
        Section currentSection = Section::None;

        const std::wstring delimiter = L" :: ";

        while (std::getline(stream, line)) {
            line = trim(line);
            if (line.empty() || line[0] == L';' || line[0] == L'#') continue;

            if (line[0] == L'[' && line.back() == L']') {
                if (_wcsicmp(line.c_str(), L"[Before]") == 0) currentSection = Section::Before;
                else if (_wcsicmp(line.c_str(), L"[After]") == 0) currentSection = Section::After;
                else currentSection = Section::None;
                continue;
            }

            if (currentSection == Section::None) continue;

            size_t delimiterPos = line.find(L'=');
            if (delimiterPos == std::wstring::npos) continue;

            std::wstring key = trim(line.substr(0, delimiterPos));
            if (_wcsicmp(key.c_str(), L"envvar") != 0) continue;

            std::wstring value = trim(line.substr(delimiterPos + 1));
            auto parts = split_string(value, delimiter);

            if (parts.size() >= 2 && _wcsicmp(parts[0].c_str(), L"path") == 0) {
                EnvVarType currentType = EnvVarType::Process;
                if (parts.size() > 2) {
                    if (_wcsicmp(parts[2].c_str(), L"user") == 0) currentType = EnvVarType::User;
                    else if (_wcsicmp(parts[2].c_str(), L"system") == 0) currentType = EnvVarType::System;
                }

                if (currentType == type && _wcsicmp(parts[1].c_str(), L"null") != 0) {
                    paths.push_back(ExpandVariables(parts[1], variables));
                }
            }
        }
        return paths;
    }

    // Helper to split a path string into a vector of segments
    std::vector<std::wstring> SplitPathString(const std::wstring& path) {
        std::vector<std::wstring> segments;
        std::wstringstream ss(path);
        std::wstring segment;
        while (std::getline(ss, segment, L';')) {
            if (!segment.empty()) {
                segments.push_back(segment);
            }
        }
        return segments;
    }

    // Helper to join a vector of segments back into a path string
    std::wstring JoinPathSegments(const std::vector<std::wstring>& segments) {
        std::wstring result;
        for (size_t i = 0; i < segments.size(); ++i) {
            result += segments[i];
            if (i < segments.size() - 1) {
                result += L';';
            }
        }
        return result;
    }

    // 辅助函数：在修改注册表后 通知系统环境变量已更改
    void BroadcastEnvironmentUpdate() {
        SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment", SMTO_ABORTIFHUNG, 5000, NULL);
    }

    // 核心函数：处理所有环境变量的设置和删除
    void HandleEnvVar(const EnvVarOp& op, std::map<std::wstring, std::wstring>& variables, const std::wstring& iniContent) {
        std::wstring finalName = ExpandVariables(op.name, variables);
        std::wstring finalValue = ExpandVariables(op.value, variables);
        bool isNullValue = (_wcsicmp(finalValue.c_str(), L"null") == 0);

        // --- 步骤 1: 如果是全局变量 先修改注册表 ---
        if (op.type == EnvVarType::User || op.type == EnvVarType::System) {
            bool registryWasModified = false; // <-- [新增] 状态标志

            HKEY hRootKey = (op.type == EnvVarType::User) ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE;
            const wchar_t* subKey = (op.type == EnvVarType::User)
                ? L"Environment"
                : L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";

            HKEY hKey;
            if (RegOpenKeyExW(hRootKey, subKey, 0, KEY_SET_VALUE | KEY_READ, &hKey) == ERROR_SUCCESS) {
                if (_wcsicmp(finalName.c_str(), L"Path") == 0) {
                    // --- 高级 Path 变量处理 ---
                    std::wstring currentRegPath;
                    DWORD bufferSize = 0;
                    if (RegQueryValueExW(hKey, finalName.c_str(), NULL, NULL, NULL, &bufferSize) == ERROR_SUCCESS && bufferSize > 0) {
                        std::vector<wchar_t> buffer(bufferSize / sizeof(wchar_t));
                        RegQueryValueExW(hKey, finalName.c_str(), NULL, NULL, (LPBYTE)buffer.data(), &bufferSize);
                        currentRegPath = buffer.data();
                    }

                    auto pathSegments = SplitPathString(currentRegPath);

                    if (isNullValue) {
                        // --- 删除逻辑 ---
                        auto pathsToRemove = CollectPathValuesFromIni(iniContent, variables, op.type);
                        size_t originalSize = pathSegments.size();
                        pathSegments.erase(std::remove_if(pathSegments.begin(), pathSegments.end(),
                            [&](const std::wstring& segment) {
                                for (const auto& toRemove : pathsToRemove) {
                                    if (_wcsicmp(segment.c_str(), toRemove.c_str()) == 0) return true;
                                }
                                return false;
                            }), pathSegments.end());

                        if (pathSegments.size() != originalSize) {
                            registryWasModified = true; // <-- [修改] 仅当删除了内容时才设置标志
                        }
                    } else {
                        // --- 添加逻辑 ---
                        bool alreadyExists = false;
                        for (const auto& segment : pathSegments) {
                            if (_wcsicmp(segment.c_str(), finalValue.c_str()) == 0) {
                                alreadyExists = true;
                                break;
                            }
                        }
                        if (!alreadyExists) {
                            pathSegments.push_back(finalValue);
                            registryWasModified = true; // <-- [修改] 仅当添加了新内容时才设置标志
                        }
                    }

                    if (registryWasModified) {
                        std::wstring newRegPath = JoinPathSegments(pathSegments);
                        RegSetValueExW(hKey, finalName.c_str(), 0, REG_EXPAND_SZ,
                                       (const BYTE*)newRegPath.c_str(),
                                       (DWORD)(newRegPath.length() + 1) * sizeof(wchar_t));
                    }
                } else {
                    // --- 其他所有变量的简单处理 ---
                    if (isNullValue) {
                        if (RegDeleteValueW(hKey, finalName.c_str()) == ERROR_SUCCESS) {
                            registryWasModified = true;
                        }
                    } else {
                        if (RegSetValueExW(hKey, finalName.c_str(), 0, REG_SZ,
                                           (const BYTE*)finalValue.c_str(),
                                           (DWORD)(finalValue.length() + 1) * sizeof(wchar_t)) == ERROR_SUCCESS) {
                            registryWasModified = true;
                        }
                    }
                }

                RegCloseKey(hKey);

                // --- [核心修改] 仅在注册表实际被修改后才发送通知 ---
                if (registryWasModified) {
                    BroadcastEnvironmentUpdate();
                }
            }
        }

        // --- 步骤 2: 总是将变更同步到当前进程的环境变量 (这部分逻辑不变) ---
        if (_wcsicmp(finalName.c_str(), L"Path") == 0) {
            if (isNullValue) {
                SetEnvironmentVariableW(L"Path", g_originalPath.c_str());
            } else {
                std::wstring newProcessPath = g_originalPath;
                if (!newProcessPath.empty() && newProcessPath.back() != L';') {
                    newProcessPath += L';';
                }
                newProcessPath += finalValue;
                SetEnvironmentVariableW(L"Path", newProcessPath.c_str());
            }
        } else {
            SetEnvironmentVariableW(finalName.c_str(), isNullValue ? NULL : finalValue.c_str());
        }
    }

    void HandleKillProcess(const KillProcessOp& op, const std::set<DWORD>& trustedPids, DWORD launcherPid) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return;

        std::wstring win32BasePath;
        bool isBasePathDirectory = false;

        if (op.checkProcessPath && !op.basePath.empty()) {
            win32BasePath = op.basePath;
            DWORD attrs = GetFileAttributesW(win32BasePath.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                isBasePathDirectory = true;
            }
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                 if (pe32.th32ProcessID == launcherPid) {
                    continue;
                }

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
                    if (win32BasePath.empty()) {
                        shouldTerminate = false;
                    } else {
                        // --- [最终修正：使用万能转换器确保路径格式统一] ---
                        std::wstring rawProcessPath = GetProcessFullPathByPid(pe32.th32ProcessID);
                        std::wstring processWin32Path = ConvertDevicePathToDosPath(rawProcessPath);

                        if (processWin32Path.empty()) {
                            shouldTerminate = false;
                        }
                        else if (isBasePathDirectory) {
                            std::wstring normalizedBasePath = win32BasePath;
                            if (normalizedBasePath.back() != L'\\') {
                                normalizedBasePath += L'\\';
                            }
                            if (processWin32Path.length() < normalizedBasePath.length() ||
                                _wcsnicmp(processWin32Path.c_str(), normalizedBasePath.c_str(), normalizedBasePath.length()) != 0) {
                                shouldTerminate = false;
                            }
                        } else {
                            if (_wcsicmp(processWin32Path.c_str(), win32BasePath.c_str()) != 0) {
                                shouldTerminate = false;
                            }
                        }
                    }
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

    // [新增] 递归遍历目录并删除匹配文件的辅助函数
    void DeleteFilesRecursive(const std::wstring& dirPath, const std::wstring& filePattern) {
        std::wstring searchPath = dirPath + L"\\*";
        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            const std::wstring fileName = findData.cFileName;
            if (fileName == L"." || fileName == L"..") continue;

            std::wstring fullPath = dirPath + L"\\" + fileName;

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                // 如果是目录 递归进入
                DeleteFilesRecursive(fullPath, filePattern);
            } else {
                // 如果是文件 检查是否匹配模式
                if (WildcardMatch(fileName.c_str(), filePattern.c_str())) {
                    // 使用之前定义的强制删除函数（处理只读属性）
                    ForceDeleteFile(fullPath);
                }
            }
        } while (FindNextFileW(hFind, &findData));

        FindClose(hFind);
    }

    // [新增] 路径通配符展开辅助函数
    // 将包含通配符的路径模式 (如 "Data\CLR_*") 展开为实际存在的目录列表
    std::vector<std::wstring> ExpandDirectoryPattern(const std::wstring& pathPattern) {
        std::vector<std::wstring> currentPaths;
        if (pathPattern.empty() || pathPattern == L".") {
            currentPaths.push_back(L".");
            return currentPaths;
        }

        std::vector<std::wstring> segments;
        std::wstringstream ss(pathPattern);
        std::wstring segment;

        // 分割路径
        while (std::getline(ss, segment, L'\\')) {
            segments.push_back(segment);
        }

        if (segments.empty()) return {};

        size_t startIndex = 0;

        // 初始化起始路径
        if (segments[0].size() == 2 && segments[0][1] == L':') {
            // 绝对路径 (C:\...)
            currentPaths.push_back(segments[0] + L"\\");
            startIndex = 1;
        }
        else if (segments[0].empty()) {
            // 根路径 (\...)
            currentPaths.push_back(L"\\");
            startIndex = 1;
        }
        else {
            // 相对路径
            currentPaths.push_back(L".");
            startIndex = 0;
        }

        // 逐层遍历
        for (size_t i = startIndex; i < segments.size(); ++i) {
            std::wstring part = segments[i];
            if (part.empty()) continue;

            std::vector<std::wstring> nextPaths;
            bool hasWildcard = (part.find(L'*') != std::wstring::npos || part.find(L'?') != std::wstring::npos);

            for (const auto& basePath : currentPaths) {
                std::wstring searchPath;

                // 构建搜索路径
                if (basePath == L".") searchPath = part;
                else if (basePath.back() == L'\\') searchPath = basePath + part;
                else searchPath = basePath + L"\\" + part;

                if (hasWildcard) {
                    // 如果当前层级包含通配符 则查找匹配的目录
                    WIN32_FIND_DATAW findData;
                    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
                    if (hFind != INVALID_HANDLE_VALUE) {
                        do {
                            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                                wcscmp(findData.cFileName, L".") != 0 &&
                                wcscmp(findData.cFileName, L"..") != 0) {

                                // [核心修正] 使用严格的 WildcardMatch 再次校验
                                // FindFirstFile 的 ? 匹配规则比较宽松（可能匹配空字符） 这里强制要求 ? 必须匹配一个字符
                                if (::WildcardMatch(findData.cFileName, part.c_str())) {
                                    std::wstring foundName = findData.cFileName;
                                    std::wstring newPath;
                                    if (basePath == L".") newPath = foundName;
                                    else if (basePath.back() == L'\\') newPath = basePath + foundName;
                                    else newPath = basePath + L"\\" + foundName;

                                    nextPaths.push_back(newPath);
                                }
                            }
                        } while (FindNextFileW(hFind, &findData));
                        FindClose(hFind);
                    }
                } else {
                    // 如果是普通名称 检查是否存在
                    DWORD attrs = GetFileAttributesW(searchPath.c_str());
                    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                        nextPaths.push_back(searchPath);
                    }
                }
            }
            currentPaths = nextPaths;
            if (currentPaths.empty()) return {}; // 路径中断 无匹配
        }
        return currentPaths;
    }

     // [完全替换] 支持递归遍历的删除文件函数
    void HandleDeleteFile(const std::wstring& pathPattern) {
        // 检查是否存在递归标记 "\*\"
        const std::wstring recursiveToken = L"\\*\\";
        size_t tokenPos = pathPattern.find(recursiveToken);

        if (tokenPos != std::wstring::npos) {
            // --- 递归模式 (例如: Data\CLR_*\*\*.txt) ---
            // 提取目录模式: "Data\CLR_*"
            std::wstring rootDirPattern = pathPattern.substr(0, tokenPos);
            // 提取文件模式: "*.txt"
            std::wstring filePattern = pathPattern.substr(tokenPos + recursiveToken.length());

            if (rootDirPattern.empty()) rootDirPattern = L".";

            // 1. 展开目录通配符 获取所有匹配的根目录
            std::vector<std::wstring> directories = ExpandDirectoryPattern(rootDirPattern);

            // 2. 对每个匹配的目录执行递归删除
            for (const auto& dir : directories) {
                DeleteFilesRecursive(dir, filePattern);
            }
        } else {
            // --- 扁平模式 (例如: Data\CLR_*\*.txt) ---
            // 分离目录部分和文件模式部分

            size_t lastSlash = pathPattern.find_last_of(L'\\');
            std::wstring dirPattern;
            std::wstring filePattern;

            if (lastSlash == std::wstring::npos) {
                dirPattern = L".";
                filePattern = pathPattern;
            } else {
                dirPattern = pathPattern.substr(0, lastSlash);
                filePattern = pathPattern.substr(lastSlash + 1);
            }

            // 1. 展开目录通配符
            std::vector<std::wstring> directories = ExpandDirectoryPattern(dirPattern);

            // 2. 在每个匹配的目录中删除文件 (非递归)
            for (const auto& dir : directories) {
                std::wstring searchPattern = dir + L"\\" + filePattern;
                WIN32_FIND_DATAW findData;
                HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &findData);
                if (hFind == INVALID_HANDLE_VALUE) {
                    continue;
                }

                do {
                    if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        // [核心修正] 同样对文件名进行严格匹配校验
                        if (::WildcardMatch(findData.cFileName, filePattern.c_str())) {
                            std::wstring fullPathToDelete = dir + L"\\" + findData.cFileName;
                            ForceDeleteFile(fullPathToDelete);
                        }
                    }
                } while (FindNextFileW(hFind, &findData));

                FindClose(hFind);
            }
        }
    }

    // [新增] 递归遍历并删除匹配目录的辅助函数
    void DeleteDirsRecursive(const std::wstring& dirPath, const std::wstring& dirPattern, bool ifEmpty) {
        std::wstring searchPath = dirPath + L"\\*";
        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            const std::wstring fileName = findData.cFileName;
            if (fileName == L"." || fileName == L"..") continue;

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                std::wstring fullPath = dirPath + L"\\" + fileName;
                bool matched = WildcardMatch(fileName.c_str(), dirPattern.c_str());

                if (matched) {
                    if (ifEmpty) {
                        // --- 空目录模式 (后序遍历) ---
                        // 先递归处理子目录 这样如果子目录被删空了 父目录也有机会被删除
                        DeleteDirsRecursive(fullPath, dirPattern, ifEmpty);

                        // 子目录处理完后 检查当前目录是否为空并删除
                        if (PathIsDirectoryEmptyW(fullPath.c_str())) {
                            RemoveDirectoryW(fullPath.c_str());
                        }
                    } else {
                        // --- 强制删除模式 ---
                        // 匹配到了直接删除整个树 无需再进入子目录
                        PerformFileSystemOperation(FO_DELETE, fullPath);
                    }
                } else {
                    // --- 不匹配 ---
                    // 继续深入递归查找
                    DeleteDirsRecursive(fullPath, dirPattern, ifEmpty);
                }
            }
        } while (FindNextFileW(hFind, &findData));

        FindClose(hFind);
    }

    // [完全替换] 支持递归遍历的删除目录函数
    void HandleDeleteDir(const std::wstring& pathPattern, bool ifEmpty) {
        // 检查是否存在递归标记 "\*\"
        const std::wstring recursiveToken = L"\\*\\";
        size_t tokenPos = pathPattern.find(recursiveToken);

        if (tokenPos != std::wstring::npos) {
            // --- 递归模式 (例如: Data*\*\NEW-*) ---
            // 提取根目录模式: "Data*" (支持通配符)
            std::wstring rootDirPattern = pathPattern.substr(0, tokenPos);
            // 提取目标目录模式: "NEW-*"
            std::wstring targetDirPattern = pathPattern.substr(tokenPos + recursiveToken.length());

            if (rootDirPattern.empty()) rootDirPattern = L".";

            // 1. 展开根目录通配符 获取所有匹配的起始目录
            std::vector<std::wstring> roots = ExpandDirectoryPattern(rootDirPattern);

            // 2. 在每个起始目录下递归查找并删除
            for (const auto& root : roots) {
                DeleteDirsRecursive(root, targetDirPattern, ifEmpty);
            }
        } else {
            // --- 扁平模式 (例如: Data*\NEW-*) ---
            size_t lastSlash = pathPattern.find_last_of(L'\\');
            std::wstring parentDirPattern;
            std::wstring targetDirPattern;

            if (lastSlash == std::wstring::npos) {
                parentDirPattern = L".";
                targetDirPattern = pathPattern;
            } else {
                parentDirPattern = pathPattern.substr(0, lastSlash);
                targetDirPattern = pathPattern.substr(lastSlash + 1);
            }

            // 1. 展开父目录通配符
            std::vector<std::wstring> parents = ExpandDirectoryPattern(parentDirPattern);

            // 2. 在每个父目录下查找匹配的子目录
            for (const auto& parent : parents) {
                std::wstring searchPattern = parent + L"\\" + targetDirPattern;
                WIN32_FIND_DATAW findData;
                HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &findData);
                if (hFind == INVALID_HANDLE_VALUE) {
                    continue;
                }

                do {
                    if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                        wcscmp(findData.cFileName, L".") != 0 &&
                        wcscmp(findData.cFileName, L"..") != 0) {

                        // [核心修正] 使用严格的 WildcardMatch 进行二次校验
                        // 确保 ? 不会匹配空字符
                        if (::WildcardMatch(findData.cFileName, targetDirPattern.c_str())) {
                            std::wstring fullPath = parent + L"\\" + findData.cFileName;

                            if (ifEmpty) {
                                // 如果指定了 ifEmpty 仅当目录为空时删除
                                if (PathIsDirectoryEmptyW(fullPath.c_str())) {
                                    RemoveDirectoryW(fullPath.c_str());
                                }
                            } else {
                                // 否则强制删除整个目录树
                                PerformFileSystemOperation(FO_DELETE, fullPath);
                            }
                        }
                    }
                } while (FindNextFileW(hFind, &findData));
                FindClose(hFind);
            }
        }
    }

    LSTATUS RecursiveRegDeleteKey_Internal(HKEY hKeyParent, const std::wstring& subKey, REGSAM samAccess) {
        HKEY hKey;
        LSTATUS res = RegOpenKeyExW(hKeyParent, subKey.c_str(), 0, KEY_ENUMERATE_SUB_KEYS | samAccess, &hKey);

        // [新增] 如果拒绝访问 尝试提权后重试
        if (res == ERROR_ACCESS_DENIED) {
            GrantRegistryKeyPermission(hKeyParent, subKey, samAccess);
            res = RegOpenKeyExW(hKeyParent, subKey.c_str(), 0, KEY_ENUMERATE_SUB_KEYS | samAccess, &hKey);
        }

        if (res != ERROR_SUCCESS) {
            // [新增] 如果仍然打不开（可能没有子项但有权限问题） 尝试直接提权并删除
            LSTATUS delRes = RegDeleteKeyExW(hKeyParent, subKey.c_str(), samAccess, 0);
            if (delRes == ERROR_ACCESS_DENIED) {
                GrantRegistryKeyPermission(hKeyParent, subKey, samAccess);
                delRes = RegDeleteKeyExW(hKeyParent, subKey.c_str(), samAccess, 0);
            }
            return delRes == ERROR_SUCCESS ? ERROR_SUCCESS : res;
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

        res = RegDeleteKeyExW(hKeyParent, subKey.c_str(), samAccess, 0);
        // [新增] 删除时如果拒绝访问 尝试提权后重试
        if (res == ERROR_ACCESS_DENIED) {
            GrantRegistryKeyPermission(hKeyParent, subKey, samAccess);
            res = RegDeleteKeyExW(hKeyParent, subKey.c_str(), samAccess, 0);
        }
        return res;
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
                        // [修改] 增加提权重试
                        if (RegDeleteKeyExW(hRootKey, key.c_str(), KEY_WOW64_64KEY, 0) == ERROR_ACCESS_DENIED) {
                            GrantRegistryKeyPermission(hRootKey, key, KEY_WOW64_64KEY);
                            RegDeleteKeyExW(hRootKey, key.c_str(), KEY_WOW64_64KEY, 0);
                        }
                    }
                    if (IsKeyEmptyInView(hRootKey, key, KEY_WOW64_32KEY)) {
                        // [修改] 增加提权重试
                        if (RegDeleteKeyExW(hRootKey, key.c_str(), KEY_WOW64_32KEY, 0) == ERROR_ACCESS_DENIED) {
                            GrantRegistryKeyPermission(hRootKey, key, KEY_WOW64_32KEY);
                            RegDeleteKeyExW(hRootKey, key.c_str(), KEY_WOW64_32KEY, 0);
                        }
                    }
                } else {
                    if (IsKeyEmptyInView(hRootKey, key, 0)) {
                        // [修改] 增加提权重试
                        if (RegDeleteKeyW(hRootKey, key.c_str()) == ERROR_ACCESS_DENIED) {
                            GrantRegistryKeyPermission(hRootKey, key, 0);
                            RegDeleteKeyW(hRootKey, key.c_str());
                        }
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
                LSTATUS res = RegOpenKeyExW(hRootKey, keyPath.c_str(), 0, KEY_READ | KEY_SET_VALUE | view, &hKey);

                // [新增] 如果拒绝访问 尝试提权后重试
                if (res == ERROR_ACCESS_DENIED) {
                    GrantRegistryKeyPermission(hRootKey, keyPath, view);
                    res = RegOpenKeyExW(hRootKey, keyPath.c_str(), 0, KEY_READ | KEY_SET_VALUE | view, &hKey);
                }

                if (res == ERROR_SUCCESS) {
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

        // [新增] 覆盖模式下 如果目标存在 使用强制删除以处理只读属性
        // 这避免了 std::ofstream 无法打开只读文件进行截断写入的问题
        if (op.overwrite && PathFileExistsW(op.path.c_str())) {
            ForceDeleteFile(op.path.c_str());
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

        // [新增] 通配符分支
        if (op.isWildcard) {
            ProcessWildcardCopyMove(op);
            return;
        }

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

            // [修改] 如果备份路径已存在 先强制删除
            if (PathFileExistsW(backupPath.c_str())) {
                if (PathIsDirectoryW(backupPath.c_str())) {
                     PerformFileSystemOperation(FO_DELETE, backupPath);
                } else {
                    ForceDeleteFile(backupPath.c_str());
                }
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
                // [修改] 使用强制删除清理备份 防止因只读属性导致残留
                ForceDeleteFile(backupPath.c_str());
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
        // [修改] 获取原始属性
        DWORD originalAttrs = GetFileAttributesW(path.c_str());

        // [修改] 移除只读、隐藏、系统属性以确保 std::ofstream 可以打开并截断文件
        if (originalAttrs != INVALID_FILE_ATTRIBUTES) {
            DWORD attrsToRemove = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
            if (originalAttrs & attrsToRemove) {
                SetFileAttributesW(path.c_str(), originalAttrs & ~attrsToRemove);
            }
        }

        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            // 打开失败 尝试恢复属性
            if (originalAttrs != INVALID_FILE_ATTRIBUTES) {
                SetFileAttributesW(path.c_str(), originalAttrs);
            }
            return false;
        }

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

        // [新增] 恢复隐藏和系统属性 (不恢复只读 因为文件内容已被修改)
        if (originalAttrs != INVALID_FILE_ATTRIBUTES) {
            DWORD attrsToRestore = originalAttrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
            if (attrsToRestore != 0) {
                DWORD currentAttrs = GetFileAttributesW(path.c_str());
                if (currentAttrs != INVALID_FILE_ATTRIBUTES) {
                    SetFileAttributesW(path.c_str(), currentAttrs | attrsToRestore);
                }
            }
        }

        return true;
    }

    void HandleIniWrite(const IniWriteOp& op) {
        if (!PathFileExistsW(op.path.c_str())) {
            return;
        }

        FileContentInfo formatInfo;
        if (!ReadFileWithFormatDetection(op.path, formatInfo)) return;

        std::vector<std::wstring> lines = GetLinesFromFile(formatInfo);
        bool contentChanged = false; // [新增] 变更标记

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
                } else {
                    // 如果我们在删除部分 说明内容发生了变化（有行被跳过）
                    contentChanged = true;
                }
            }

            // 如果内容没有变化（例如要删除的节根本不存在） 则直接返回
            if (!contentChanged) return;

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
                            // 构建新的行内容
                            std::wstring new_line_content;
                            size_t original_eq_pos = l.find(L'=');
                            size_t value_start_pos = l.find_first_not_of(L" \t", original_eq_pos + 1);
                            if (value_start_pos == std::wstring::npos) { // key=
                                new_line_content = l.substr(0, original_eq_pos + 1) + op.value;
                            } else {
                                new_line_content = l.substr(0, value_start_pos) + op.value;
                            }

                            // 只有当新内容与旧内容不同时 才进行修改并标记变更
                            if (l != new_line_content) {
                                l = new_line_content;
                                contentChanged = true;
                            }
                        } else { // Delete
                            lines.erase(lines.begin() + i);
                            --i;
                            contentChanged = true;
                        }
                        key_found_and_handled = true;
                        if (is_null_section) break;
                    }
                }
            }
        }

        if (!key_found_and_handled && _wcsicmp(op.value.c_str(), L"null") != 0) {
            // 需要插入新键值对
            contentChanged = true;
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

        // 如果内容没有变化 则不写入文件
        if (!contentChanged) {
            return;
        }

        WriteFileWithFormat(op.path, lines, formatInfo);
    }

    // [完全替换] 使用新的双模式（正则/字面量）重写 HandleReplace 函数
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

        // --- [核心修改] 处理 {DELETE} 标记 ---
        if (finalReplaceText == L"{DELETE}") {
            finalReplaceText = L"";
        } else {
            // 只有不是删除标记时 才需要处理换行符
            size_t lb_pos_replace = 0;
            while ((lb_pos_replace = finalReplaceText.find(toFindToken, lb_pos_replace)) != std::wstring::npos) {
                finalReplaceText.replace(lb_pos_replace, toFindToken.length(), normalizedNewline);
                lb_pos_replace += normalizedNewline.length();
            }
        }

        std::wstring new_content;

        if (op.useRegex) {
            // --- 正则表达式替换模式 ---
            try {
                auto flags = std::regex_constants::ECMAScript;
                if (op.ignoreCase) {
                    flags |= std::regex_constants::icase;
                }
                std::wregex re(finalFindText, flags);
                new_content = std::regex_replace(content, re, finalReplaceText);
            } catch (const std::regex_error& e) {
                new_content = content;
            }
        } else {
            // --- 字面量（精确）替换模式 ---
            new_content = content;
            size_t pos = 0;
            while ((pos = new_content.find(finalFindText, pos)) != std::wstring::npos) {
                new_content.replace(pos, finalFindText.length(), finalReplaceText);
                // 如果是删除操作(finalReplaceText为空) pos 不需要前进
                // 但为了避免死循环（例如查找空字符串） 标准做法是前进替换后的长度
                // 如果替换为空 长度为0 下一次查找会从同一位置开始
                // 但由于 find 找到了内容 下一次 find 应该从 pos 开始（如果内容被删除了 pos现在指向原来内容的下一个字符）
                // 修正：std::wstring::replace 删除后 后面的字符会前移
                // 下一次查找应该从当前 pos 开始
                pos += finalReplaceText.length();
            }
        }

        // --- [新增] 如果内容没有变化 则不写入文件 ---
        if (new_content == content) {
            return;
        }

        // 将新内容写回文件
        std::vector<std::wstring> new_lines;
        std::wstringstream ss(new_content);
        std::wstring line;
        while (std::getline(ss, line, L'\n')) {
            new_lines.push_back(line);
        }
        if (new_content.empty() && !lines.empty()) new_lines.clear();

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
        bool contentChanged = false; // [新增] 变更标记

        for (const auto& l : lines) {
            // 检查行是否以 lineStart 开头
            if (l.rfind(op.lineStart, 0) == 0) {
                // 只有当新行内容与旧行不同时 才标记为已变更
                if (l != finalReplaceLine) {
                    new_lines.push_back(finalReplaceLine);
                    contentChanged = true;
                } else {
                    // 如果内容完全一致 则保留原样
                    new_lines.push_back(l);
                }
            } else {
                new_lines.push_back(l);
            }
        }

        // [新增] 如果内容没有发生任何实质性变化 直接返回 不写入文件
        if (!contentChanged) {
            return;
        }

        WriteFileWithFormat(op.path, new_lines, formatInfo);
    }

} // namespace ActionHelpers


// --- [新增] 字体批量加载与卸载逻辑 ---
// 检查文件是否为支持的字体格式
bool IsFontFile(const std::wstring& fileName) {
    const wchar_t* ext = PathFindExtensionW(fileName.c_str());
    if (!ext) return false;
    return (_wcsicmp(ext, L".ttf") == 0 ||
            _wcsicmp(ext, L".otf") == 0 ||
            _wcsicmp(ext, L".ttc") == 0 ||
            _wcsicmp(ext, L".fon") == 0);
}

void LoadFontsFromDirectory(const std::wstring& dirPath) {
    std::wstring searchPath = dirPath + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            // 跳过目录 只处理文件
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                if (IsFontFile(fd.cFileName)) {
                    std::wstring fullPath = dirPath + L"\\" + fd.cFileName;

                    // 注册字体：
                    // 0: 表示系统全局可见 且会出现在 EnumFontFamilies 的枚举列表中（下拉框可见）
                    if (AddFontResourceExW(fullPath.c_str(), 0, 0) > 0) {
                        g_TemporaryFonts.push_back(fullPath);
                    }
                }
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
}

void ProcessLoadFontConfig(const std::wstring& iniContent, std::map<std::wstring, std::wstring>& variables) {
    std::wstringstream stream(iniContent);
    std::wstring line;
    bool inTargetSection = false;

    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty() || line[0] == L';' || line[0] == L'#') continue;
        if (line[0] == L'[' && line.back() == L']') {
            inTargetSection = (_wcsicmp(line.c_str(), L"[Before]") == 0);
            continue;
        }

        if (inTargetSection) {
            size_t delimiterPos = line.find(L'=');
            if (delimiterPos != std::wstring::npos) {
                std::wstring key = trim(line.substr(0, delimiterPos));
                std::wstring val = trim(line.substr(delimiterPos + 1));

                if (_wcsicmp(key.c_str(), L"loadfont") == 0 && !val.empty()) {
                    // 展开路径并转为绝对路径
                    std::wstring fullPath = ResolveToAbsolutePath(ExpandVariables(val, variables), variables);

                    if (PathIsDirectoryW(fullPath.c_str())) {
                        LoadFontsFromDirectory(fullPath);
                    }
                }
            }
        }
    }

    if (!g_TemporaryFonts.empty()) {
        PostMessage(HWND_BROADCAST, WM_FONTCHANGE, 0, 0);
    }
}

void UnloadTemporaryFonts() {
    if (g_TemporaryFonts.empty()) return;

    for (const auto& fontPath : g_TemporaryFonts) {
        RemoveFontResourceExW(fontPath.c_str(), 0, 0);
    }
    g_TemporaryFonts.clear();

    // 卸载后再次通知系统
    PostMessage(HWND_BROADCAST, WM_FONTCHANGE, 0, 0);
}

// --- [新增] 注册表 Hive 管理辅助函数 ---
// 计算 Hive 挂载名称 (基于启动器名称)
std::wstring GetHiveMountName(const std::wstring& launcherName) {
    return L"YapHookReg_" + launcherName;
}

// 确保 Hive 文件存在且有效 (如果不存在则创建并初始化)
bool EnsureHiveFileExists(const std::wstring& hivePath) {
    if (PathFileExistsW(hivePath.c_str())) return true;

    // 创建一个临时 Key 用于构建 Hive 结构
    HKEY hTempKey;
    std::wstring tempKeyName = L"YapHookTempHive_" + std::to_wstring(GetCurrentProcessId());

    if (RegCreateKeyExW(HKEY_CURRENT_USER, tempKeyName.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hTempKey, NULL) != ERROR_SUCCESS) {
        return false;
    }

    // [修改] 预创建基础 COM 键和核心骨架
    // 移植自 Sandboxie Key_CreateBaseKeys 确保 COM 和 Explorer 相关的深层路径存在
    // 这样可以避免惰性 CoW 在首次打开深层子键时因为父键不存在而失败
    const wchar_t* baseKeys[] = {
        // HKLM 基础骨架
        L"Machine\\System",
        L"Machine\\Software\\Classes", // COM 核心
        L"Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",

        // HKCU 基础骨架
        L"User\\Software\\Classes",    // COM 核心 (用户层)
        L"User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",

        // HKU 根
        L"Users"
    };

    HKEY hSub;
    for (const wchar_t* keyPath : baseKeys) {
        // RegCreateKeyW 会递归创建不存在的父键
        if (RegCreateKeyW(hTempKey, keyPath, &hSub) == ERROR_SUCCESS) {
            RegCloseKey(hSub);
        }
    }

    // 保存到文件 (需要 SeBackupPrivilege 已在 EnableAllPrivileges 中启用)
    // 注意：RegSaveKey 要求目标文件不存在
    LSTATUS status = RegSaveKeyW(hTempKey, hivePath.c_str(), NULL);

    RegCloseKey(hTempKey);
    SHDeleteKeyW(HKEY_CURRENT_USER, tempKeyName.c_str());

    return (status == ERROR_SUCCESS);
}

// --- Process Management Functions ---

// Helper for single-instance wait
std::vector<HANDLE> FindNewDescendantsAndWaitTargets(
    std::set<DWORD>& trustedPids,
    const std::vector<WaitProcessInfo>& processInfos,
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
            if (pe32.th32ProcessID == GetCurrentProcessId()) {
                continue;
            }

            // --- [最终核心修正：实现按规则区分的PPID检查] ---
            bool parentIsTrusted = trustedPids.count(pe32.th32ParentProcessID) > 0;

            // 步骤1: 无论如何 只要是子进程 就追踪它 以建立完整的进程树
            if (parentIsTrusted) {
                newlyTrustedPids.insert(pe32.th32ProcessID);
            }

            // 步骤2: 如果这个进程我们已经等待过了 就跳过匹配逻辑
            if (pidsToIgnore.count(pe32.th32ProcessID)) {
                continue;
            }

            // 步骤3: 遍历所有等待规则 为当前进程寻找匹配项
            for (const auto& info : processInfos) {
                // 首先 名字必须匹配
                if (!WildcardMatch(pe32.szExeFile, info.processName.c_str())) {
                    continue; // 名字不符 看下一条规则
                }

                bool match = false;
                if (info.checkPath) {
                    // 规则A: 按路径等待 - 不检查PPID 只检查路径
                    std::wstring processWin32Path = ConvertDevicePathToDosPath(GetProcessFullPathByPid(pe32.th32ProcessID));
                    if (!processWin32Path.empty() && !info.basePath.empty()) {
                        DWORD attrs = GetFileAttributesW(info.basePath.c_str());
                        bool isBasePathDirectory = (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY));

                        if (isBasePathDirectory) {
                            std::wstring normalizedBasePath = info.basePath;
                            if (normalizedBasePath.back() != L'\\') normalizedBasePath += L'\\';
                            if (processWin32Path.length() >= normalizedBasePath.length() &&
                                _wcsnicmp(processWin32Path.c_str(), normalizedBasePath.c_str(), normalizedBasePath.length()) == 0) {
                                match = true;
                            }
                        } else {
                            if (_wcsicmp(processWin32Path.c_str(), info.basePath.c_str()) == 0) {
                                match = true;
                            }
                        }
                    }
                } else {
                    // 规则B: 按名称等待 - 必须检查PPID
                    if (parentIsTrusted) {
                        match = true;
                    }
                }

                if (match) {
                    HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        handlesToWaitOn.push_back(hProcess);
                        pidsToIgnore.insert(pe32.th32ProcessID);
                    }
                    break; // 已找到匹配规则 无需再检查此进程
                }
            }
            // --- [修正结束] ---
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    trustedPids.insert(newlyTrustedPids.begin(), newlyTrustedPids.end());
    return handlesToWaitOn;
}

// Helper for multi-instance wait: Scans and returns handles for all matching processes
std::vector<HANDLE> ScanForWaitProcessHandles(const std::vector<WaitProcessInfo>& processInfos) {
    std::vector<HANDLE> handles;
    if (processInfos.empty()) return handles;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return handles;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == GetCurrentProcessId()) {
                continue;
            }

            for (const auto& info : processInfos) {
                if (WildcardMatch(pe32.szExeFile, info.processName.c_str())) {
                    bool match = false;
                    if (!info.checkPath) {
                        // 模式1：仅按名称匹配
                        match = true;
                    } else {
                        // 模式2：名称和路径双重匹配
                        std::wstring processWin32Path = ConvertDevicePathToDosPath(GetProcessFullPathByPid(pe32.th32ProcessID));
                        if (!processWin32Path.empty() && !info.basePath.empty()) {
                            DWORD attrs = GetFileAttributesW(info.basePath.c_str());
                            bool isBasePathDirectory = (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY));

                            if (isBasePathDirectory) {
                                std::wstring normalizedBasePath = info.basePath;
                                if (normalizedBasePath.back() != L'\\') normalizedBasePath += L'\\';
                                if (processWin32Path.length() >= normalizedBasePath.length() &&
                                    _wcsnicmp(processWin32Path.c_str(), normalizedBasePath.c_str(), normalizedBasePath.length()) == 0) {
                                    match = true;
                                }
                            } else {
                                if (_wcsicmp(processWin32Path.c_str(), info.basePath.c_str()) == 0) {
                                    match = true;
                                }
                            }
                        }
                    }

                    if (match) {
                        HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, pe32.th32ProcessID);
                        if (hProcess) {
                            handles.push_back(hProcess);
                        }
                        break; // 已找到匹配项 无需再检查此进程的其他规则
                    }
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

// <-- [新增] 获取文件最后修改时间的辅助函数
bool GetFileLastWriteTime(const std::wstring& path, FILETIME& ft) {
    WIN32_FILE_ATTRIBUTE_DATA data;
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) {
        ft = data.ftLastWriteTime;
        return true;
    }
    return false;
}

// <-- [新增] 递归增量同步目录 (源 -> 目标)
void SyncDirectoryRecursive(const std::wstring& srcDir, const std::wstring& destDir) {
    // 1. 确保目标目录存在
    if (!PathFileExistsW(destDir.c_str())) {
        SHCreateDirectoryExW(NULL, destDir.c_str(), NULL);
    }

    // 2. 索引目标目录中的所有项 (用于后续判断删除)
    // Map: 文件名 -> 是否为目录
    std::map<std::wstring, bool> destItems;
    WIN32_FIND_DATAW fdDest;
    std::wstring searchDest = destDir + L"\\*";
    HANDLE hFindDest = FindFirstFileW(searchDest.c_str(), &fdDest);
    if (hFindDest != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fdDest.cFileName, L".") == 0 || wcscmp(fdDest.cFileName, L"..") == 0) continue;
            destItems[fdDest.cFileName] = (fdDest.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
        } while (FindNextFileW(hFindDest, &fdDest));
        FindClose(hFindDest);
    }

    // 3. 遍历源目录 执行复制或覆盖
    WIN32_FIND_DATAW fdSrc;
    std::wstring searchSrc = srcDir + L"\\*";
    HANDLE hFindSrc = FindFirstFileW(searchSrc.c_str(), &fdSrc);

    if (hFindSrc != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fdSrc.cFileName, L".") == 0 || wcscmp(fdSrc.cFileName, L"..") == 0) continue;

            std::wstring fileName = fdSrc.cFileName;
            std::wstring srcPath = srcDir + L"\\" + fileName;
            std::wstring destPath = destDir + L"\\" + fileName;
            bool isSrcDir = (fdSrc.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);

            // 检查目标是否存在同名项
            auto it = destItems.find(fileName);
            bool existsInDest = (it != destItems.end());

            if (existsInDest) {
                bool isDestDir = it->second;
                // 从待删除列表中移除 (因为源中存在)
                destItems.erase(it);

                // 如果类型不匹配 (一个是文件 一个是目录) 先删除目标
                if (isSrcDir != isDestDir) {
                    if (isDestDir) PerformFileSystemOperation(FO_DELETE, destPath);
                    else ActionHelpers::ForceDeleteFile(destPath.c_str());
                    existsInDest = false;
                }
            }

            if (isSrcDir) {
                // 递归处理子目录
                SyncDirectoryRecursive(srcPath, destPath);
            } else {
                // 处理文件
                bool needCopy = true;
                if (existsInDest) {
                    FILETIME ftDest;
                    // 对比修改时间
                    if (GetFileLastWriteTime(destPath, ftDest)) {
                        if (CompareFileTime(&fdSrc.ftLastWriteTime, &ftDest) == 0) {
                            needCopy = false; // 时间一致 跳过
                        }
                    }
                }

                if (needCopy) {
                    // 如果目标存在且只读 CopyFile 可能会失败 所以先尝试移除只读属性
                    if (existsInDest) {
                        DWORD attrs = GetFileAttributesW(destPath.c_str());
                        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_READONLY)) {
                            SetFileAttributesW(destPath.c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);
                        }
                    }
                    CopyFileW(srcPath.c_str(), destPath.c_str(), FALSE);
                }
            }

        } while (FindNextFileW(hFindSrc, &fdSrc));
        FindClose(hFindSrc);
    }

    // 4. 删除目标中有但源中没有的项 (清理旧文件)
    for (const auto& item : destItems) {
        std::wstring pathToDelete = destDir + L"\\" + item.first;
        if (item.second) {
            // 删除目录
            PerformFileSystemOperation(FO_DELETE, pathToDelete);
        } else {
            // 删除文件
            ActionHelpers::ForceDeleteFile(pathToDelete.c_str());
        }
    }
}

// <-- [修改] 目录备份函数 以处理新的 "no overwrite" 逻辑 和 "overwrite" 的增量同步逻辑
void PerformDirectoryBackup(const BackupEntry& entry) {
    if (!PathFileExistsW(entry.source.c_str())) return;

    if (entry.overwrite) {
        // [修改] 增量备份模式 (Sync)
        // 不再暴力删除重建 而是对比时间戳同步
        SyncDirectoryRecursive(entry.source, entry.destination);
    } else {
        // 新的、已修正的时间戳备份逻辑 (保持不变)
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

// <-- [修改] 文件备份函数 以处理新的 "no overwrite" 逻辑 和 "overwrite" 的增量同步逻辑
void PerformFileBackup(const BackupEntry& entry) {
    if (!PathFileExistsW(entry.source.c_str())) return;

    // 1. [新增] 自动创建目标父目录
    // 无论是覆盖模式还是时间戳模式 都需要确保目标文件夹存在
    wchar_t destDir[MAX_PATH];
    wcscpy_s(destDir, MAX_PATH, entry.destination.c_str());
    PathRemoveFileSpecW(destDir);
    if (wcslen(destDir) > 0) {
        // SHCreateDirectoryExW 会自动创建多级目录 如果目录已存在则忽略
        SHCreateDirectoryExW(NULL, destDir, NULL);
    }

    if (entry.overwrite) {
        // [修改] 增量备份模式 (仅对比时间)
        bool needCopy = true;

        if (PathFileExistsW(entry.destination.c_str())) {
            FILETIME ftSrc, ftDest;
            if (GetFileLastWriteTime(entry.source.c_str(), ftSrc) &&
                GetFileLastWriteTime(entry.destination.c_str(), ftDest)) {
                // 只要时间不一致就覆盖
                if (CompareFileTime(&ftSrc, &ftDest) == 0) {
                    needCopy = false;
                }
            }

            // 如果需要覆盖 且目标只读 先处理属性
            if (needCopy) {
                DWORD attrs = GetFileAttributesW(entry.destination.c_str());
                if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_READONLY)) {
                    SetFileAttributesW(entry.destination.c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);
                }
            }
        }

        if (needCopy) {
            CopyFileW(entry.source.c_str(), entry.destination.c_str(), FALSE);
        }
    } else {
        // 新的、已修正的时间戳备份逻辑 (保持不变)
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

            // [新增] 处理通配符模式
            if (arg.isWildcard) {
                SHCreateDirectoryExW(NULL, arg.destPath.c_str(), NULL);

                if (arg.isDirectory) {
                    // [新增] 目录通配符处理逻辑
                    // 1. 备份目录
                    ActionHelpers::BackupDirectoriesInPlace(arg.destPath, arg.wildcardPattern);
                    arg.destBackupCreated = true;
                    // 2. 传输目录
                    if (PathFileExistsW(arg.sourcePath.c_str())) {
                        ActionHelpers::TransferDirectoriesByPattern(arg.sourcePath, arg.destPath, arg.wildcardPattern, arg.wasMoved);
                    }
                } else {
                    // [原有] 文件通配符处理逻辑
                    ActionHelpers::BackupWildcardInPlace(arg.destPath, arg.wildcardPattern);
                    arg.destBackupCreated = true;
                    if (PathFileExistsW(arg.sourcePath.c_str())) {
                        ActionHelpers::TransferFilesByPattern(arg.sourcePath, arg.destPath, arg.wildcardPattern, arg.wasMoved);
                    }
                }
                return;
            }

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
        } else if constexpr (std::is_same_v<T, RegLinkOp>) {
            // 1. 自动创建链接的目标键 (如果不存在)
            HKEY hTargetRoot;
            std::wstring targetRootStr, targetSubKey, targetValName;
            if (ParseRegistryPath(arg.targetWin32Path, true, hTargetRoot, targetRootStr, targetSubKey, targetValName)) {
                HKEY hTargetKey;
                // RegCreateKeyExW 会自动递归创建所有不存在的父级键
                if (RegCreateKeyExW(hTargetRoot, targetSubKey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hTargetKey, NULL) == ERROR_SUCCESS) {
                    RegCloseKey(hTargetKey);
                }
            }

            // 2. 将已存在的注册表项重命名为 _Backup
            HKEY hTemp;
            if (RegOpenKeyExW(arg.hRootKey, arg.subKey.c_str(), 0, KEY_READ, &hTemp) == ERROR_SUCCESS) {
                RegCloseKey(hTemp);
                if (RenameRegistryKey(arg.hRootKey, arg.subKey, arg.backupSubKey)) {
                    arg.backupCreated = true;
                }
            }

            // 3. 创建注册表符号链接指向目标
            if (CreateRegistrySymbolicLink(arg.hRootKey, arg.subKey, arg.targetNtPath)) {
                arg.isCreated = true;
            }
        }
        // [新增] 处理 DLL 注册
        else if constexpr (std::is_same_v<T, RegDllOp>) {
            wchar_t systemPath[MAX_PATH];
            GetSystemDirectoryW(systemPath, MAX_PATH);
            std::wstring regsvrPath = std::wstring(systemPath) + L"\\regsvr32.exe";
            std::wstring args = L"/s \"" + arg.dllPath + L"\"";
            ExecuteProcess(regsvrPath, args, L"", true, true);
        }
    }, opData);
}

void PerformShutdownOperation(StartupShutdownOperationData& opData) {
    std::visit([&](auto& arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, FileOp>) {

            // [新增] 处理通配符模式
            if (arg.isWildcard) {
                if (PathFileExistsW(arg.destPath.c_str())) {
                    SHCreateDirectoryExW(NULL, arg.sourcePath.c_str(), NULL);

                    if (arg.isDirectory) {
                        // [新增] 目录通配符恢复逻辑
                        if (arg.wasMoved) {
                            // 同分区 Move Back
                            ActionHelpers::TransferDirectoriesByPattern(arg.destPath, arg.sourcePath, arg.wildcardPattern, true);
                        } else {
                            // 异分区 Copy Back + Delete Safe
                            ActionHelpers::TransferDirectoriesByPattern(arg.destPath, arg.sourcePath, arg.wildcardPattern, false);
                            ActionHelpers::DeleteDirectoriesByPatternSafe(arg.destPath, arg.wildcardPattern);
                        }
                    } else {
                        // [原有] 文件通配符恢复逻辑
                        if (arg.wasMoved) {
                            ActionHelpers::TransferFilesByPattern(arg.destPath, arg.sourcePath, arg.wildcardPattern, true);
                        } else {
                            ActionHelpers::TransferFilesByPattern(arg.destPath, arg.sourcePath, arg.wildcardPattern, false);
                            ActionHelpers::DeleteFilesByPatternSafe(arg.destPath, arg.wildcardPattern);
                        }
                    }
                }

                // 恢复备份
                if (arg.destBackupCreated) {
                    if (arg.isDirectory) {
                        // [新增] 恢复目录备份
                        ActionHelpers::RestoreDirectoryBackupsInPlace(arg.destPath, arg.wildcardPattern);
                    } else {
                        // [原有] 恢复文件备份
                        ActionHelpers::RestoreBackupsInPlace(arg.destPath, arg.wildcardPattern);
                    }
                }
                return;
            }

            if (arg.wasMoved) {
                if (PathFileExistsW(arg.destPath.c_str())) {
                    if (PathFileExistsW(arg.sourcePath.c_str())) {
                         if (arg.isDirectory) PerformFileSystemOperation(FO_DELETE, arg.sourcePath);
                         else ActionHelpers::ForceDeleteFile(arg.sourcePath.c_str());
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
                        else ActionHelpers::ForceDeleteFile(sourceBackupPath.c_str());
                    }
                }
                if (arg.isDirectory) PerformFileSystemOperation(FO_DELETE, arg.destPath);
                else ActionHelpers::ForceDeleteFile(arg.destPath.c_str());
            }
            if (arg.destBackupCreated && PathFileExistsW(arg.destBackupPath.c_str())) {
                MoveFileW(arg.destBackupPath.c_str(), arg.destPath.c_str());
            }
        } else if constexpr (std::is_same_v<T, RestoreOnlyFileOp>) {
            if (PathFileExistsW(arg.targetPath.c_str())) {
                if (arg.isDirectory) PerformFileSystemOperation(FO_DELETE, arg.targetPath);
                else ActionHelpers::ForceDeleteFile(arg.targetPath.c_str());
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
                LSTATUS res = RegOpenKeyExW(arg.hRootKey, arg.subKey.c_str(), 0, KEY_WRITE, &hKey);

                //[新增] 如果删除值时拒绝访问 尝试提权后重试
                if (res == ERROR_ACCESS_DENIED) {
                    ActionHelpers::GrantRegistryKeyPermission(arg.hRootKey, arg.subKey, 0);
                    res = RegOpenKeyExW(arg.hRootKey, arg.subKey.c_str(), 0, KEY_WRITE, &hKey);
                }

                if (res == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, arg.valueName.c_str());
                    RegCloseKey(hKey);
                }
            }
            if (arg.backupCreated) {
                if (arg.isKey) {
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
                        ActionHelpers::ForceDeleteFile(pathToDelete.c_str());
                    }
                }
            } else {
                if (arg.isHardlink && arg.isDirectory) {
                    for (auto it = arg.createdLinks.rbegin(); it != arg.createdLinks.rend(); ++it) {
                        ActionHelpers::ForceDeleteFile(it->first.c_str());
                    }
                    PerformFileSystemOperation(FO_DELETE, arg.linkPath);
                } else {
                    if (arg.isDirectory) {
                        PerformFileSystemOperation(FO_DELETE, arg.linkPath);
                    }
                    else {
                        ActionHelpers::ForceDeleteFile(arg.linkPath.c_str());
                    }
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
        } else if constexpr (std::is_same_v<T, RegLinkOp>) {
            // 退出后:
            // 1. 删除注册表符号链接键本身
            if (arg.isCreated) {
                DeleteRegistrySymbolicLink(arg.hRootKey, arg.subKey);
            }
            // 2. 将备份重命名恢复
            if (arg.backupCreated) {
                RenameRegistryKey(arg.hRootKey, arg.backupSubKey, arg.subKey);
            }
        }
        // [新增] 处理 DLL 反注册 (自动清理)
        else if constexpr (std::is_same_v<T, RegDllOp>) {
            wchar_t systemPath[MAX_PATH];
            GetSystemDirectoryW(systemPath, MAX_PATH);
            std::wstring regsvrPath = std::wstring(systemPath) + L"\\regsvr32.exe";
            std::wstring args = L"/s /u \"" + arg.dllPath + L"\"";
            ExecuteProcess(regsvrPath, args, L"", true, true);
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
                    std::wstring rawPath;
                    if (parts.size() > 2 && !parts[2].empty()) {
                        rawPath = parts[2];
                    } else {
                        rawPath = L"{YAPROOT}";
                    }
                    // --- [最终修正：在解析时立即展开变量] ---
                    op.basePath = ExpandVariables(rawPath, variables);
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

                // 原始源路径和目标路径字符串
                std::wstring rawSrc = is_reversed ? parts[0] : parts[1];
                std::wstring rawDest = is_reversed ? parts[1] : parts[0];

                // 预先展开变量
                rawSrc = ExpandVariables(rawSrc, variables);
                rawDest = ExpandVariables(rawDest, variables);

                // [新增] 检测源路径是否包含通配符
                if (rawSrc.find(L'*') != std::wstring::npos || rawSrc.find(L'?') != std::wstring::npos) {
                    op.isWildcard = true;

                    // 分离源路径的目录和模式
                    // 例如: Other\#New*  ->  Dir: Other, Pattern: #New*
                    size_t lastSlash = rawSrc.find_last_of(L'\\');
                    if (lastSlash != std::wstring::npos) {
                        op.sourcePath = ResolveToAbsolutePath(rawSrc.substr(0, lastSlash), variables);
                        op.wildcardPattern = rawSrc.substr(lastSlash + 1);
                    } else {
                        op.sourcePath = ResolveToAbsolutePath(L".", variables);
                        op.wildcardPattern = rawSrc;
                    }

                    // 目标路径处理 (通配符模式下 目标必须是目录)
                    // 如果 rawDest 是 "Data\" ResolveToAbsolutePath 会处理好
                    op.destPath = ResolveToAbsolutePath(rawDest, variables);
                    // 移除末尾反斜杠以保持一致性
                    if (!op.destPath.empty() && op.destPath.back() == L'\\') op.destPath.pop_back();

                } else {
                    // [原有] 常规逻辑
                    op.isWildcard = false;
                    op.sourcePath = ResolveToAbsolutePath(rawSrc, variables);
                    op.destPath = ResolveToAbsolutePath(rawDest, variables);
                }

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
            const std::wstring local_delimiter = L" :: ";
            size_t first_delim = value.find(local_delimiter);
            if (first_delim != std::wstring::npos) {
                size_t second_delim = value.find(local_delimiter, first_delim + local_delimiter.length());
                if (second_delim != std::wstring::npos) {
                    ReplaceOp op;
                    op.path = trim(value.substr(0, first_delim));

                    size_t third_delim = value.find(local_delimiter, second_delim + local_delimiter.length());

                    if (third_delim != std::wstring::npos) {
                        // 找到4个部分 (路径 :: 查找 :: 替换 :: 模式)
                        op.findText = value.substr(first_delim + local_delimiter.length(), second_delim - (first_delim + local_delimiter.length()));
                        op.replaceText = value.substr(second_delim + local_delimiter.length(), third_delim - (second_delim + local_delimiter.length()));

                        // --- [核心修改] 解析 "regex/i" 格式 ---
                        std::wstring modeStr = trim(value.substr(third_delim + local_delimiter.length()));

                        // 查找标志分隔符 '/'
                        size_t slash_pos = modeStr.find(L'/');
                        // 提取基础模式 (例如 "regex")
                        std::wstring base_mode = (slash_pos == std::wstring::npos) ? modeStr : modeStr.substr(0, slash_pos);

                        if (_wcsicmp(base_mode.c_str(), L"regex") == 0) {
                            op.useRegex = true;
                            // 如果是正则模式 并且找到了'/' 则检查后面的标志
                            if (slash_pos != std::wstring::npos) {
                                std::wstring flags_str = modeStr.substr(slash_pos + 1);
                                // 检查是否存在 'i' 标志
                                if (flags_str.find(L'i') != std::wstring::npos) {
                                    op.ignoreCase = true;
                                }
                            }
                        }
                        // --- [修改结束] ---

                    } else {
                        // 只找到3个部分 (路径 :: 查找 :: 替换) 默认为字面量替换
                        op.findText = value.substr(first_delim + local_delimiter.length(), second_delim - (first_delim + local_delimiter.length()));
                        op.replaceText = value.substr(second_delim + local_delimiter.length());
                    }
                    return op;
                }
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
            if (parts.size() >= 2) { // 至少需要 变量名 和 变量值
                EnvVarOp op;
                op.name = parts[0];
                op.value = parts[1];

                // 检查是否指定了类型
                if (parts.size() > 2) {
                    if (_wcsicmp(parts[2].c_str(), L"user") == 0) {
                        op.type = EnvVarType::User;
                    } else if (_wcsicmp(parts[2].c_str(), L"system") == 0) {
                        op.type = EnvVarType::System;
                    }
                    // 如果是其他无法识别的类型 则保持默认的 EnvVarType::Process
                }
                return op;
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

        // --- [修改] 在 General 部分处理 backupdir 和 backupfile ---
        if (currentSection == Section::General) {
            if (_wcsicmp(key.c_str(), L"backupdir") == 0) {
                backupData.backupDirs.push_back(ParseBackupEntry(value, variables));
                continue;
            } else if (_wcsicmp(key.c_str(), L"backupfile") == 0) {
                backupData.backupFiles.push_back(ParseBackupEntry(value, variables));
                continue;
            }
        }

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
            } else if (_wcsicmp(key.c_str(), L"regdll") == 0) {
                auto parts = split_string(value, delimiter);
                if (!parts.empty() && !parts[0].empty()) {
                    RegDllOp op;
                    op.dllPath = ResolveToAbsolutePath(ExpandVariables(parts[0], variables), variables);
                    beforeOp.data = op;
                    op_created = true;
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
                FileOp f_op;
                // [关键] 记录原始意图：是操作文件还是目录
                bool isDirOp = (_wcsicmp(key.c_str(), L"dir") == 0);
                f_op.isDirectory = isDirOp;

                auto parts = split_string(value, delimiter);
                if (parts.size() == 2) {
                    // [修改] 预先展开变量以检测通配符
                    std::wstring rawDest = ExpandVariables(parts[0], variables);

                    // 检测是否包含通配符 (* 或 ?)
                    if (rawDest.find(L'*') != std::wstring::npos || rawDest.find(L'?') != std::wstring::npos) {
                        f_op.isWildcard = true;

                        // 分离目录和文件名模式
                        // 例如: {LocalLow}\HG_*  ->  Path: ...\LocalLow, Pattern: HG_*
                        size_t lastSlash = rawDest.find_last_of(L'\\');
                        if (lastSlash != std::wstring::npos) {
                            f_op.destPath = ResolveToAbsolutePath(rawDest.substr(0, lastSlash), variables);
                            f_op.wildcardPattern = rawDest.substr(lastSlash + 1);
                        } else {
                            // 如果没有反斜杠 假设是当前工作目录
                            f_op.destPath = ResolveToAbsolutePath(L".", variables);
                            f_op.wildcardPattern = rawDest;
                        }

                        // 解析源路径 (通常是目录)
                        f_op.sourcePath = ResolveToAbsolutePath(ExpandVariables(parts[1], variables), variables);
                        // 移除源路径末尾的反斜杠以保持一致性
                        if (!f_op.sourcePath.empty() && f_op.sourcePath.back() == L'\\') f_op.sourcePath.pop_back();

                        // 设置备份路径 (目录)
                        f_op.destBackupPath = f_op.destPath + L"_Backup";

                        // [新增] 关键修改：检测是否在同一分区
                        f_op.wasMoved = ArePathsOnSameVolume(f_op.sourcePath, f_op.destPath);
                    }
                    else {
                        // --- 原有的常规逻辑 ---
                        f_op.destPath = ResolveToAbsolutePath(rawDest, variables);
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
                    }

                    beforeOp.data = f_op;
                    op_created = true;
                }
            }
            else if (_wcsicmp(key.c_str(), L"reglink") == 0) {
                auto parts = split_string(value, delimiter);
                if (parts.size() == 2) {
                    RegLinkOp rl_op;
                    std::wstring srcPath = ExpandVariables(parts[0], variables);
                    std::wstring destPath = ExpandVariables(parts[1], variables);
                    std::wstring dummyValName;

                    if (ParseRegistryPath(srcPath, true, rl_op.hRootKey, rl_op.rootKeyStr, rl_op.subKey, dummyValName)) {
                        rl_op.targetWin32Path = destPath;
                        rl_op.targetNtPath = ConvertToNtRegistryPath(destPath);
                        rl_op.backupSubKey = rl_op.subKey + L"_Backup";
                        beforeOp.data = rl_op;
                        op_created = true;
                    }
                }
            }
            else {
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

void ExecuteActionOperation(const ActionOpData& opData, std::map<std::wstring, std::wstring>& variables, const std::set<DWORD>& trustedPids, DWORD launcherPid, const std::wstring& iniContent) {
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
            // 变量已在解析时展开完毕 此处只需确保路径是绝对路径
            KillProcessOp final_op = arg;
            if (final_op.checkProcessPath) {
                final_op.basePath = ResolveToAbsolutePath(final_op.basePath, variables);
            }
            ActionHelpers::HandleKillProcess(final_op, trustedPids, launcherPid);
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
            ActionHelpers::HandleEnvVar(arg, variables, iniContent);
        }
    }, opData);
}

void PerformFullCleanup(
    std::vector<AfterOperation>& afterOps,
    std::vector<StartupShutdownOperation>& shutdownOps,
    std::map<std::wstring, std::wstring>& variables,
    const std::set<DWORD>& trustedPids,
    DWORD launcherPid,
    const std::wstring& iniContent
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
                // <-- [修改] 将 launcherPid 传递给下一层函数
                ExecuteActionOperation(actionOp.data, variables, trustedPids, launcherPid, iniContent);
            }
        }
    } else {
        for (auto it = shutdownOps.rbegin(); it != shutdownOps.rend(); ++it) {
            PerformShutdownOperation(it->data);
        }
        for (auto& op : afterOps) {
            ActionOperation actionOp = std::get<ActionOperation>(op.data);
            // <-- [修改] 将 launcherPid 传递给下一层函数
            ExecuteActionOperation(actionOp.data, variables, trustedPids, launcherPid, iniContent);
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

// --- [新增] 在此处添加 PerformFullCleanup 的前向声明 ---
void PerformFullCleanup(
    std::vector<AfterOperation>& afterOps,
    std::vector<StartupShutdownOperation>& shutdownOps,
    std::map<std::wstring, std::wstring>& variables,
    const std::set<DWORD>& trustedPids,
    DWORD launcherPid,
    const std::wstring& iniContent
);

// --- [新增] 进程注入与架构检测相关函数 ---
// 检查 PE 文件的架构 (32位 或 64位)
// 返回: 32, 64, 或 0 (未知/错误)
int GetPeArchitecture(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    int arch = 0;
    DWORD bytesRead;
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS32 ntHeaders32;

    if (ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, NULL) && bytesRead == sizeof(dosHeader)) {
        if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
            if (SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
                // 读取 NT 头签名和文件头
                if (ReadFile(hFile, &ntHeaders32, sizeof(ntHeaders32), &bytesRead, NULL) && bytesRead == sizeof(ntHeaders32)) {
                    if (ntHeaders32.Signature == IMAGE_NT_SIGNATURE) {
                        if (ntHeaders32.FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
                            arch = 32;
                        } else if (ntHeaders32.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
                            arch = 64;
                        }
                    }
                }
            }
        }
    }
    CloseHandle(hFile);
    return arch;
}

// --- [新增] 关键修复：获取远程进程入口点 ---
LPVOID GetEntryPoint(HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG len;
    if (!g_NtQueryInformationProcess) return NULL;
    // 使用 ProcessBasicInformation (0)
    if (g_NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &len) != 0) return NULL;

    BOOL isWow64 = FALSE;
    IsWow64Process(hProcess, &isWow64);

    if (isWow64) {
        // 32-bit process (WOW64)
        ULONG_PTR peb32 = 0;
        // ProcessWow64Information = 26
        if (g_NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)26, &peb32, sizeof(peb32), &len) != 0) return NULL;

        if (peb32 == 0) return NULL;

        DWORD imageBase32 = 0;
        // [修复] 显式转换 peb32 + 8 为 PVOID
        if (!ReadProcessMemory(hProcess, (PVOID)(peb32 + 8), &imageBase32, sizeof(imageBase32), NULL)) return NULL;

        IMAGE_DOS_HEADER dosHeader;
        // [修复] imageBase32 是 DWORD 在 x64 下需先转 ULONG_PTR 再转 PVOID
        if (!ReadProcessMemory(hProcess, (PVOID)(ULONG_PTR)imageBase32, &dosHeader, sizeof(dosHeader), NULL)) return NULL;

        IMAGE_NT_HEADERS32 ntHeaders32;
        // [修复] 指针算术运算修正
        if (!ReadProcessMemory(hProcess, (PVOID)((ULONG_PTR)imageBase32 + dosHeader.e_lfanew), &ntHeaders32, sizeof(ntHeaders32), NULL)) return NULL;

        return (LPVOID)((ULONG_PTR)imageBase32 + ntHeaders32.OptionalHeader.AddressOfEntryPoint);
    } else {
        // 64-bit process
        PVOID imageBase = 0;
        // PEB + 0x10 is ImageBaseAddress in x64
        if (!ReadProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, &imageBase, sizeof(imageBase), NULL)) return NULL;

        IMAGE_DOS_HEADER dosHeader;
        if (!ReadProcessMemory(hProcess, imageBase, &dosHeader, sizeof(dosHeader), NULL)) return NULL;

        IMAGE_NT_HEADERS64 ntHeaders64;
        if (!ReadProcessMemory(hProcess, (PBYTE)imageBase + dosHeader.e_lfanew, &ntHeaders64, sizeof(ntHeaders64), NULL)) return NULL;

        return (LPVOID)((PBYTE)imageBase + ntHeaders64.OptionalHeader.AddressOfEntryPoint);
    }
}

// --- [修改] 获取 LoadLibraryW 地址 ---
LPVOID GetLoadLibraryAddress(HANDLE hProcess, bool targetIs32Bit) {
    // 如果目标是 32 位 Launcher (x64) 无法直接获取其地址
    // 但我们现在使用 YapInjector32 所以这里直接返回 NULL 即可
    if (targetIs32Bit) return NULL;

    // 如果目标是 64 位 Kernel32 在所有 64 位进程中的加载地址通常是相同的
    // 直接返回当前进程的 LoadLibraryW 地址即可
    return (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
}

// --- [修改] 核心注入函数 ---
bool InjectDll(HANDLE hProcess, HANDLE hThread, const std::wstring& dllPath, const std::wstring& injectorPath) {
    if (dllPath.empty()) return false;

    BOOL isWow64 = FALSE;
    IsWow64Process(hProcess, &isWow64);
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    bool targetIs32Bit = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 && isWow64) ||
                         (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL);

    // 1. 确保 Kernel32 已加载 (自旋锁逻辑)
    LPVOID pLoadLibrary = GetLoadLibraryAddress(hProcess, targetIs32Bit);
    LPVOID pEntryPoint = GetEntryPoint(hProcess);

    if (pEntryPoint) {
        if (!pLoadLibrary) {
            BYTE originalBytes[2];
            BYTE loopBytes[2] = { 0xEB, 0xFE }; // JMP $

            if (ReadProcessMemory(hProcess, pEntryPoint, originalBytes, 2, NULL)) {
                if (WriteProcessMemory(hProcess, pEntryPoint, loopBytes, 2, NULL)) {
                    FlushInstructionCache(hProcess, pEntryPoint, 2);

                    if (g_NtResumeProcess) g_NtResumeProcess(hProcess);
                    else ResumeThread(hThread);

                    if (targetIs32Bit) {
                        Sleep(1000);
                    } else {
                        for (int i = 0; i < 300; ++i) {
                            Sleep(10);
                            pLoadLibrary = GetLoadLibraryAddress(hProcess, targetIs32Bit);
                            if (pLoadLibrary) break;
                        }
                    }

                    if (g_NtSuspendProcess) g_NtSuspendProcess(hProcess);
                    else SuspendThread(hThread);

                    WriteProcessMemory(hProcess, pEntryPoint, originalBytes, 2, NULL);
                    FlushInstructionCache(hProcess, pEntryPoint, 2);
                }
            }
        }
    }

    if (!pLoadLibrary && !targetIs32Bit) return false;

    // 2. 分支处理
    if (targetIs32Bit) {
        // --- 方案：调用外部 32位 Injector ---

        // [修改] 使用传入的 injectorPath 不再自行推导
        if (injectorPath.empty() || !PathFileExistsW(injectorPath.c_str())) {
            return false;
        }

        // C. 构造命令行: YapInjector32 <PID> <DLLPath>
        DWORD pid = GetProcessId(hProcess);
        std::wstring cmdLine = L"\"" + injectorPath + L"\" " + std::to_wstring(pid) + L" \"" + dllPath + L"\"";

        STARTUPINFOW si_inj = { 0 };
        si_inj.cb = sizeof(si_inj);
        si_inj.dwFlags = STARTF_USESHOWWINDOW;
        si_inj.wShowWindow = SW_HIDE; // 隐藏窗口

        PROCESS_INFORMATION pi_inj = { 0 };

        if (CreateProcessW(NULL, &cmdLine[0], NULL, NULL, FALSE, 0, NULL, NULL, &si_inj, &pi_inj)) {
            WaitForSingleObject(pi_inj.hProcess, 5000);

            DWORD exitCode = 1;
            GetExitCodeProcess(pi_inj.hProcess, &exitCode);

            CloseHandle(pi_inj.hProcess);
            CloseHandle(pi_inj.hThread);

            return (exitCode == 0);
        }
        return false;

    } else {
        // --- x64 原生注入 ---
        // 必须确保 pLoadLibrary 有效
        if (!pLoadLibrary) return false;

        LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, MAX_PATH * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
        if (!pRemoteMem) return false;

        if (!WriteProcessMemory(hProcess, pRemoteMem, dllPath.c_str(), (dllPath.length() + 1) * sizeof(wchar_t), NULL)) {
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            return false;
        }

        HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMem, 0, NULL);
        if (hRemoteThread) {
            WaitForSingleObject(hRemoteThread, INFINITE);
            CloseHandle(hRemoteThread);
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            return true;
        }
        return false;
    }
}

// --- IPC 服务端逻辑 ---

// --- [新增] Launcher 日志 ---
void LauncherLog(const std::wstring& msg) {
    // 日志功能已禁用
    return;
}

// --- [修改] 注入并智能等待 ---
bool InjectAndWait(HANDLE hProcess, HANDLE hThread, DWORD pid, const std::wstring& dllPath, const std::wstring& hookPath, const std::wstring& pipeName, const std::wstring& injectorPath) {
    std::wstring eventName = GetReadyEventName(pid);
    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, eventName.c_str());

    std::wstring mapName = GetConfigMapName(pid);
    HANDLE hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(HookConfig), mapName.c_str());
    if (hMap) {
        void* pBuf = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(HookConfig));
        if (pBuf) {
            HookConfig* config = (HookConfig*)pBuf;
            wcscpy_s(config->hookPath, MAX_PATH, hookPath.c_str());
            wcscpy_s(config->pipeName, MAX_PATH, pipeName.c_str());
            wcscpy_s(config->launcherDir, MAX_PATH, g_LauncherDir.c_str());
            UnmapViewOfFile(pBuf);
        }
    }

    // 传递 hThread
    if (!InjectDll(hProcess, hThread, dllPath, injectorPath)) {
        if (hMap) CloseHandle(hMap);
        CloseHandle(hEvent);
        return false;
    }

    // 此时 无论是 32位还是 64位 DLL 都应该已经加载并运行了 DllMain
    // 我们可以放心地等待 Event 信号 确认 Hook 初始化完成
    HANDLE handles[] = { hEvent, hProcess };
    DWORD waitResult = WaitForMultipleObjects(2, handles, FALSE, 3000);

    bool success = (waitResult == WAIT_OBJECT_0);

    if (hMap) CloseHandle(hMap);
    CloseHandle(hEvent);
    return success;
}

// --- [新增] IPC 服务端线程参数 ---
struct IpcThreadParam {
    std::wstring pipeName;
    std::wstring dll32Path;
    std::wstring dll64Path;
    std::wstring hookPath;
    std::atomic<bool>* shouldStop;
    std::vector<std::wstring> extraDlls;
    std::wstring injectorPath;
};

// [新增] IPC 工作线程参数
struct IpcWorkerParam {
    HANDLE hPipe;
    IpcThreadParam* mainParam;
};

// [新增] 处理单个 IPC 连接的工作线程
DWORD WINAPI IpcWorkerThread(LPVOID lpParam) {
    IpcWorkerParam* workerParam = (IpcWorkerParam*)lpParam;
    HANDLE hPipe = workerParam->hPipe;
    IpcThreadParam* param = workerParam->mainParam;

    // 释放参数内存
    delete workerParam;

    IpcMessage msg;
    DWORD bytesRead;
    if (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL)) {
        // LauncherLog(L"IPC Worker: Processing PID " + std::to_wstring(msg.targetPid));

        bool success = false;
        HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, msg.targetPid);
        if (hTarget) {
            BOOL isWow64 = FALSE;
            IsWow64Process(hTarget, &isWow64);
            SYSTEM_INFO si;
            GetNativeSystemInfo(&si);
            bool systemIs64 = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
            bool targetIs32Bit = systemIs64 ? (isWow64 == TRUE) : true;

            std::wstring targetDll = targetIs32Bit ? param->dll32Path : param->dll64Path;

            // 1. 注入主 Hook DLL
            success = InjectAndWait(hTarget, NULL, msg.targetPid, targetDll, param->hookPath, param->pipeName, param->injectorPath);

            // 2. 注入第三方 DLL
            if (success) {
                int targetArch = targetIs32Bit ? 32 : 64;
                for (const auto& dllPath : param->extraDlls) {
                    int dllArch = GetPeArchitecture(dllPath);
                    if (dllArch != 0 && dllArch != targetArch) continue;
                    InjectDll(hTarget, NULL, dllPath, param->injectorPath);
                }
            }
            CloseHandle(hTarget);
        }

        IpcResponse resp = { success, 0 };
        DWORD bytesWritten;
        WriteFile(hPipe, &resp, sizeof(resp), &bytesWritten, NULL);
    }

    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    return 0;
}

// [修改] IPC 服务端主线程 (改为并发模式)
DWORD WINAPI IpcServerThread(LPVOID lpParam) {
    IpcThreadParam* param = (IpcThreadParam*)lpParam;
    // LauncherLog(L"IPC Server started: " + param->pipeName);

    while (!*(param->shouldStop)) {
        // 注意：PIPE_UNLIMITED_INSTANCES 允许创建多个管道实例
        HANDLE hPipe = CreateNamedPipeW(
            param->pipeName.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, // 允许无限实例
            512, 512, 0, NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(100);
            continue;
        }

        // 等待客户端连接
        bool connected = ConnectNamedPipe(hPipe, NULL) ? true : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (connected) {
            // 连接成功 创建一个新线程去处理这个管道实例
            IpcWorkerParam* workerParam = new IpcWorkerParam;
            workerParam->hPipe = hPipe;
            workerParam->mainParam = param;

            HANDLE hThread = CreateThread(NULL, 0, IpcWorkerThread, workerParam, 0, NULL);
            if (hThread) {
                CloseHandle(hThread); // 不需要等待它结束
            } else {
                // 创建线程失败 清理资源
                delete workerParam;
                DisconnectNamedPipe(hPipe);
                CloseHandle(hPipe);
            }
        } else {
            // 连接失败
            CloseHandle(hPipe);
        }
    }
    return 0;
}

DWORD WINAPI LauncherWorkerThread(LPVOID lpParam) {
    LauncherThreadData* data = static_cast<LauncherThreadData*>(lpParam);
    if (!data) return 1;

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // --- 1. 准备启动参数 ---
    std::wstring commandLine = ExpandVariables(GetValueFromIniContent(data->iniContent, L"General", L"commandline"), data->variables);
    std::wstring fullCommandLine = L"\"" + data->absoluteAppPath + L"\" " + commandLine;
    wchar_t commandLineBuffer[4096];
    wcscpy_s(commandLineBuffer, fullCommandLine.c_str());

    // --- 2. 解析 Hook 配置 ---
    std::wstring hookFileVal = GetValueFromIniContent(data->iniContent, L"Hook", L"hookfile");
    int hookMode = _wtoi(hookFileVal.c_str());

    // [新增] 解析网络拦截配置
    std::wstring netBlockVal = GetValueFromIniContent(data->iniContent, L"Hook", L"hooknet");
    int netBlockMode = _wtoi(netBlockVal.c_str());
    bool blockNetwork = (netBlockMode > 0); // 只要大于0就启用网络挂钩

    // 2. 解析 hookchild (提前)
    std::wstring hookChildVal = GetValueFromIniContent(data->iniContent, L"Hook", L"hookchild");
    if (hookChildVal.empty()) hookChildVal = L"1";
    bool hookChild = (_wtoi(hookChildVal.c_str()) != 0);

    // --- [修改] 解析 Injector 和 hookchildname 配置 (从 [Hook] 章节) ---
    std::vector<std::wstring> thirdPartyDlls;
    std::wstring childHookNamesVar; // 用于存储 hookchildname 列表
    {
        std::wstringstream stream(data->iniContent);
        std::wstring line;
        bool inHookSection = false; // [修改] 标志位改为 inHookSection
        while (std::getline(stream, line)) {
            line = trim(line);
            if (line.empty() || line[0] == L';' || line[0] == L'#') continue;
            if (line[0] == L'[' && line.back() == L']') {
                // [修改] 检查是否进入 [Hook] 章节
                inHookSection = (_wcsicmp(line.c_str(), L"[Hook]") == 0);
                continue;
            }
            if (inHookSection) {
                size_t delimiterPos = line.find(L'=');
                if (delimiterPos != std::wstring::npos) {
                    std::wstring key = trim(line.substr(0, delimiterPos));
                    std::wstring val = trim(line.substr(delimiterPos + 1));

                    if (_wcsicmp(key.c_str(), L"Injector") == 0) {
                        std::wstring expanded = ResolveToAbsolutePath(ExpandVariables(val, data->variables), data->variables);
                        if (!expanded.empty()) {
                            thirdPartyDlls.push_back(expanded);
                        }
                    } else if (_wcsicmp(key.c_str(), L"hookchildname") == 0) {
                        if (!val.empty()) {
                            childHookNamesVar += val + L";";
                        }
                    }
                }
            }
        }
    }

    // [新增] 解析 hookcopysize 配置 (单位: MB)
    std::wstring hookCopySizeVal = GetValueFromIniContent(data->iniContent, L"Hook", L"hookcopysize");
    if (hookMode > 0 && !hookCopySizeVal.empty()) {
        SetEnvironmentVariableW(L"YAP_HOOK_COPY_SIZE", hookCopySizeVal.c_str());
    } else {
        SetEnvironmentVariableW(L"YAP_HOOK_COPY_SIZE", NULL);
    }

    // [新增] 解析 hookvolumeid 配置 (格式: XXXX-XXXX)
    std::wstring hookVolumeIdVal = GetValueFromIniContent(data->iniContent, L"Hook", L"hookvolumeid");
    if (!hookVolumeIdVal.empty()) {
        SetEnvironmentVariableW(L"YAP_HOOK_VOLUME_ID", hookVolumeIdVal.c_str());
    }

    // [新增] 解析 hookcd 配置 (指定伪装成光驱的目录)
    std::wstring hookCdVal = GetValueFromIniContent(data->iniContent, L"Hook", L"hookcd");
    if (!hookCdVal.empty()) {
        // 展开变量并转换为绝对路径
        std::wstring finalCdPath = ResolveToAbsolutePath(ExpandVariables(hookCdVal, data->variables), data->variables);
        SetEnvironmentVariableW(L"YAP_HOOK_CD", finalCdPath.c_str());
    }

    // [新增] 解析 hookfont 配置
    std::wstring hookFontVal = GetValueFromIniContent(data->iniContent, L"Hook", L"hookfont");
    if (!hookFontVal.empty()) {
        // 1. 展开变量 (如 {YAPROOT})
        std::wstring expandedVal = ExpandVariables(hookFontVal, data->variables);

        // 2. 解析为绝对路径 (相对于启动器目录)
        std::wstring resolvedFontPath = ResolveToAbsolutePath(expandedVal, data->variables);

        // 3. 检查文件是否存在
        // 如果作为文件存在 传递绝对路径；否则传递原始值（可能是系统字体名 如 "Arial"）
        if (PathFileExistsW(resolvedFontPath.c_str())) {
            SetEnvironmentVariableW(L"YAP_HOOK_FONT", resolvedFontPath.c_str());
        } else {
            SetEnvironmentVariableW(L"YAP_HOOK_FONT", hookFontVal.c_str());
        }
    }

    // --- [新增] 解析 hooklocale (语言区域伪造) ---
    std::wstring hookLocaleVal = GetValueFromIniContent(data->iniContent, L"Hook", L"hooklocale");
    if (!hookLocaleVal.empty()) {
        SetEnvironmentVariableW(L"YAP_HOOK_LOCALE", hookLocaleVal.c_str());
    }

    // [新增] 解析 hooktime 配置
    std::wstring hookTimeVal = GetValueFromIniContent(data->iniContent, L"Hook", L"hooktime");
    if (!hookTimeVal.empty()) {
        SetEnvironmentVariableW(L"YAP_HOOK_TIME", hookTimeVal.c_str());
    }

    // --- [新增] 解析 hookreg 配置 (注册表重定向) ---
    std::wstring hookRegVal = GetValueFromIniContent(data->iniContent, L"Hook", L"hookreg");

    // [新增] 将第三方 DLL 列表拼接并设置环境变量 (供 HookDll 直接注入使用)
    std::wstring extraDllsEnv;
    for (const auto& dll : thirdPartyDlls) {
        if (!extraDllsEnv.empty()) extraDllsEnv += L"|";
        extraDllsEnv += dll;
    }
    if (!extraDllsEnv.empty()) {
        SetEnvironmentVariableW(L"YAP_EXTRA_DLL", extraDllsEnv.c_str());
    } else {
        SetEnvironmentVariableW(L"YAP_EXTRA_DLL", NULL);
    }

    // [修改] 启用 Hook 的条件 (针对当前进程)
    // 只有当需要文件重定向、网络拦截、伪装等核心功能时 才认为当前进程需要 "Hook"
    bool enableHook = (hookMode > 0 || blockNetwork || !hookVolumeIdVal.empty() || !hookCdVal.empty() || !hookFontVal.empty() || !hookLocaleVal.empty() || !hookTimeVal.empty() || !hookRegVal.empty() || (hookChild && !thirdPartyDlls.empty()));

    // [新增] 解析 multiple 配置
    std::wstring multipleVal = GetValueFromIniContent(data->iniContent, L"General", L"multiple");
    bool allowMultiple = (multipleVal == L"1");

    // [关键修改] 决定是否启动 IPC 服务端
    // 条件 A: 当前进程需要 Hook (必须启动 IPC 以支持子进程注入)
    // 条件 B: 允许多实例 且 配置了第三方 DLL (即使当前进程不需要 Hook 也启动 IPC 为后续实例服务)
    bool startIpcServer = enableHook || (allowMultiple && !thirdPartyDlls.empty());

    std::wstring hookPathRaw = GetValueFromIniContent(data->iniContent, L"Hook", L"hookpath");
    std::wstring finalHookPath = ResolveToAbsolutePath(ExpandVariables(hookPathRaw, data->variables), data->variables);

    // --- 3. 准备 IPC 与 DLL (如果启用 Hook) ---
    std::atomic<bool> stopIpc(false);
    HANDLE hIpcThread = NULL;
    IpcThreadParam ipcParam;

    // [修改] 是否需要释放辅助文件 (只要启动 IPC 或 有第三方DLL 就需要)
    bool needHelpers = startIpcServer || !thirdPartyDlls.empty();

    // 将 DLL 路径变量移到函数作用域顶部 以便最后删除
    std::wstring dll32Path;
    std::wstring dll64Path;
    std::wstring injectorPath;

    // [修改] 提取资源逻辑移出 enableHook 判断 改用 needHelpers
    if (needHelpers) {
        // A. 确定 DLL 释放路径 (改为 tempfile 路径)
        wchar_t dllDir[MAX_PATH];
        wcscpy_s(dllDir, MAX_PATH, data->tempFilePath.c_str());
        PathRemoveFileSpecW(dllDir);

        dll32Path = std::wstring(dllDir) + L"\\YapHook32.dll";
        dll64Path = std::wstring(dllDir) + L"\\YapHook64.dll";
        injectorPath = std::wstring(dllDir) + L"\\YapInjector32.exe";

        // B. 释放资源到磁盘
        ExtractResourceToFile(IDR_HOOK_DLL_32, dll32Path);
        ExtractResourceToFile(IDR_HOOK_DLL_64, dll64Path);
        ExtractResourceToFile(IDR_INJECTOR32, injectorPath);
    }

    // [修改] 使用 startIpcServer 控制 IPC 启动
    if (startIpcServer) {
        // C. 配置 IPC 参数
        ipcParam.dll32Path = dll32Path;
        ipcParam.dll64Path = dll64Path;
        ipcParam.hookPath = finalHookPath;
        ipcParam.shouldStop = &stopIpc;
        ipcParam.pipeName = data->pipeName;
        ipcParam.extraDlls = thirdPartyDlls;
        ipcParam.injectorPath = injectorPath;

        // D. 设置环境变量 (供 Hook DLL 读取)
        SetEnvironmentVariableW(L"YAP_IPC_PIPE", ipcParam.pipeName.c_str());
        if (!finalHookPath.empty()) {
            SetEnvironmentVariableW(L"YAP_HOOK_PATH", finalHookPath.c_str());
        }
        SetEnvironmentVariableW(L"YAP_LAUNCHER_DIR", g_LauncherDir.c_str());
        SetEnvironmentVariableW(L"YAP_HOOK_FILE", std::to_wstring(hookMode).c_str());
        SetEnvironmentVariableW(L"YAP_HOOK_NET", std::to_wstring(netBlockMode).c_str());

        SetEnvironmentVariableW(L"YAP_HOOK_CHILD", hookChildVal.c_str());
        if (!childHookNamesVar.empty()) {
            SetEnvironmentVariableW(L"YAP_HOOK_CHILD_NAME", childHookNamesVar.c_str());
        } else {
            SetEnvironmentVariableW(L"YAP_HOOK_CHILD_NAME", NULL); // 不设置或清除
        }

        // E. 启动 IPC 服务端线程
        hIpcThread = CreateThread(NULL, 0, IpcServerThread, &ipcParam, 0, NULL);
    }

    std::set<DWORD> finalTrustedPids;

    // --- 4. 创建进程 (始终挂起) ---
    if (!CreateProcessW(NULL, commandLineBuffer, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, data->finalWorkDir.c_str(), &si, &pi)) {
        MessageBoxW(NULL, (L"启动程序失败: \n" + data->absoluteAppPath).c_str(), L"启动错误", MB_ICONERROR);
        finalTrustedPids.insert(GetCurrentProcessId());
    } else {
        // --- 5. 主进程注入逻辑 ---

        // 情况 A: 启用 Hook
        if (enableHook) {
            // 检测目标架构
            int arch = GetPeArchitecture(data->absoluteAppPath);
            std::wstring targetDll;

            if (arch == 32) targetDll = ipcParam.dll32Path;
            else if (arch == 64) targetDll = ipcParam.dll64Path;

            // 1. 注入主 Hook DLL (带等待)
            if (!targetDll.empty()) {
                InjectAndWait(pi.hProcess, pi.hThread, pi.dwProcessId, targetDll, finalHookPath, ipcParam.pipeName, injectorPath);
            }

            // 2. [修改] 注入第三方 DLL (增加架构检查)
            for (const auto& dllPath : thirdPartyDlls) {
                // 获取 DLL 架构
                int dllArch = GetPeArchitecture(dllPath);

                // arch 是之前通过 GetPeArchitecture(data->absoluteAppPath) 获取的主程序架构
                if (dllArch != 0 && dllArch != arch) {
                    continue; // 架构不匹配 跳过
                }

                InjectDll(pi.hProcess, pi.hThread, dllPath, injectorPath);
            }
        }
        // 情况 B: 禁用 Hook (hookfile=0)
        else {
            // [修改] 仅注入第三方 DLL (增加架构检查)

            // 1. 获取主程序架构
            int arch = GetPeArchitecture(data->absoluteAppPath);

            for (const auto& dllPath : thirdPartyDlls) {
                // 2. 获取 DLL 架构
                int dllArch = GetPeArchitecture(dllPath);

                // 3. 架构不匹配则跳过
                if (dllArch != 0 && dllArch != arch) {
                    continue;
                }

                InjectDll(pi.hProcess, pi.hThread, dllPath, injectorPath);
            }
        }

        ResumeThread(pi.hThread);

        // --- 7. 等待逻辑 (WaitProcess) ---
        // 解析 waitprocess 配置
        std::vector<WaitProcessInfo> waitProcesses;
        bool isPathBasedWait = false; // 新标志：只要有一个条目使用路径检查 就为true

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
                    auto parts = split_string(value, L" :: ");

                    WaitProcessInfo info;
                    info.processName = parts[0];

                    if (parts.size() > 1 && _wcsicmp(parts[1].c_str(), L"path") == 0) {
                        info.checkPath = true;
                        isPathBasedWait = true; // 激活路径等待模式
                        std::wstring rawPath;
                        if (parts.size() > 2 && !parts[2].empty()) {
                            rawPath = parts[2];
                        } else {
                            rawPath = L"{YAPROOT}"; // 默认路径
                        }
                        // 在解析时立即展开变量并转换为绝对路径
                        info.basePath = ResolveToAbsolutePath(ExpandVariables(rawPath, data->variables), data->variables);
                    }
                    waitProcesses.push_back(info);
                }
            }
        }

        bool multiInstanceEnabled = (GetValueFromIniContent(data->iniContent, L"General", L"multiple") == L"1");

        if (multiInstanceEnabled) {
            // --- 多实例模式等待 ---
            WaitForSingleObject(pi.hProcess, INFINITE);

            // 添加主程序自身的等待规则
            const wchar_t* appFilename = PathFindFileNameW(data->absoluteAppPath.c_str());
            if (appFilename && wcslen(appFilename) > 0) {
                WaitProcessInfo mainAppInfo;
                mainAppInfo.processName = appFilename;
                mainAppInfo.checkPath = true;
                mainAppInfo.basePath = data->absoluteAppPath;
                waitProcesses.push_back(mainAppInfo);
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
                        // 处理超过 64 个句柄的情况
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
            finalTrustedPids.insert(GetCurrentProcessId());
            finalTrustedPids.insert(pi.dwProcessId);

        } else {
            // --- 单实例模式等待 ---
            if (waitProcesses.empty()) {
                WaitForSingleObject(pi.hProcess, INFINITE);
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
                    // 动态扫描新产生的子进程
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
                            // 最后一个进程退出后 再多等一会看有没有孙进程产生
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
                finalTrustedPids = trustedPids;
            }
        }

        if (pi.hProcess) CloseHandle(pi.hProcess);
        if (pi.hThread) CloseHandle(pi.hThread);
    }

    // --- 8. 停止 IPC 服务 ---
    if (hIpcThread) {
        stopIpc = true;
        // 尝试连接管道以解除 ConnectNamedPipe 的阻塞状态
        HANDLE hPipe = CreateFileW(ipcParam.pipeName.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) CloseHandle(hPipe);

        WaitForSingleObject(hIpcThread, 1000);
        CloseHandle(hIpcThread);

    }

    // --- 9. 停止监控线程 ---
    if (data->hMonitorThread) {
        if (data->hMonitorThreadId != 0) {
            PostThreadMessageW(data->hMonitorThreadId, WM_QUIT, 0, 0);
        }
        WaitForSingleObject(data->hMonitorThread, 2000);
        CloseHandle(data->hMonitorThread);
        SetAllProcessesState(data->monitorData->suspendProcesses, false);
    }

    // --- 10. 停止备份线程 ---
    if (data->hBackupThread) {
        *(data->stopMonitor) = true;
        while (*(data->isBackupWorking)) Sleep(100);
        WaitForSingleObject(data->hBackupThread, 1500);
        CloseHandle(data->hBackupThread);
    }

    // --- 11. 执行清理 ---
    // 传入 iniContent 以支持智能 Path 变量清理
    PerformFullCleanup(data->afterOps, data->shutdownOps, data->variables, finalTrustedPids, data->launcherPid, data->iniContent);

    // [新增] 卸载注册表 Hive
    if (!data->regMountName.empty()) {
        // 尝试卸载 Hive
        // 注意：如果子进程尚未完全退出或有句柄泄露 RegUnLoadKeyW 可能会失败
        // 这是正常的系统行为 (Lazy Unload) 系统会在所有句柄关闭后最终卸载它

        // [修改] 添加重试机制：如果卸载失败 每隔1秒重试1次 总共重试10次
        for (int retry = 0; retry <= 10; ++retry) {
            LSTATUS status = RegUnLoadKeyW(HKEY_USERS, data->regMountName.c_str());
            if (status == ERROR_SUCCESS) {
                break; // 卸载成功 跳出重试循环
            }

            if (retry < 10) {
                Sleep(1000); // 卸载失败 等待 1 秒后重试
            }
            // 如果 retry == 10 依然失败 循环将自然结束 放弃卸载并继续执行后续操作
        }

        // [新增] 卸载后使用通配符删除日志文件 (避免误删 YapHookReg.dat 本身)
        if (!data->hivePath.empty()) {
            wchar_t hiveDir[MAX_PATH];
            wcscpy_s(hiveDir, MAX_PATH, data->hivePath.c_str());
            PathRemoveFileSpecW(hiveDir);
            ActionHelpers::DeleteFilesByPatternSafe(hiveDir, L"YapHookReg.dat.*");
            ActionHelpers::DeleteFilesByPatternSafe(hiveDir, L"YapHookReg.dat{*");
        }
    }

    DeleteFileW(data->tempFilePath.c_str());

    // [修改] 删除已释放的 DLL 文件
    if (needHelpers) {
        DeleteFileW(dll32Path.c_str());
        DeleteFileW(dll64Path.c_str());
        DeleteFileW(injectorPath.c_str());
    }

    CoUninitialize();
    return 0;
}

// --- [修改] 获取确定性的管道名称 (基于启动器名称) ---
std::wstring GetDeterministicPipeName(const std::wstring& launcherName) {
    return L"\\\\.\\pipe\\YapLauncherPipe_" + launcherName;
}

// [新增] 用于检测 INI 文件的 [Before] 区域是否配置了注册表符号链接
bool HasRegLinkInBefore(const std::wstring& iniContent) {
    std::wstringstream stream(iniContent);
    std::wstring line;
    bool inBefore = false;
    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty() || line[0] == L';' || line[0] == L'#') continue;
        if (line[0] == L'[' && line.back() == L']') {
            inBefore = (_wcsicmp(line.c_str(), L"[Before]") == 0);
            continue;
        }
        if (inBefore) {
            size_t delimiterPos = line.find(L'=');
            if (delimiterPos != std::wstring::npos) {
                std::wstring key = trim(line.substr(0, delimiterPos));
                if (_wcsicmp(key.c_str(), L"reglink") == 0) {
                    return true;
                }
            }
        }
    }
    return false;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    EnableAllPrivileges();
	DWORD launcherPid = GetCurrentProcessId();

    // [新增] 获取启动器目录
    wchar_t pathBuffer[MAX_PATH];
    GetModuleFileNameW(NULL, pathBuffer, MAX_PATH);
    PathRemoveFileSpecW(pathBuffer);
    g_LauncherDir = pathBuffer;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        g_NtDeleteKey = (pfnNtDeleteKey)GetProcAddress(hNtdll, "NtDeleteKey");
        g_NtSuspendProcess = (pfnNtSuspendProcess)GetProcAddress(hNtdll, "NtSuspendProcess");
        g_NtResumeProcess = (pfnNtResumeProcess)GetProcAddress(hNtdll, "NtResumeProcess");
        // [新增] 初始化这两个关键函数
        g_NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        g_RtlCreateUserThread = (pfnRtlCreateUserThread)GetProcAddress(hNtdll, "RtlCreateUserThread");
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

    // --- 检查 INI 是否存在 如果不存在则尝试从资源释放 ---
    if (!PathFileExistsW(iniPath.c_str())) {
        if (ExtractResourceToFile(IDR_INI_FILE, iniPath)) {
        } else {
        }
    }

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

    // --- 预解析 ---
    // 预解析 [Before] 中的 uservar 以便在 application 路径中使用
    {
        std::wstringstream stream(iniContent);
        std::wstring line;
        std::wstring currentSection;
        const std::wstring delimiter = L" :: ";

        while (std::getline(stream, line)) {
            line = trim(line);
            if (line.empty() || line[0] == L';' || line[0] == L'#') continue;

            if (line[0] == L'[' && line.back() == L']') {
                currentSection = line;
                continue;
            }

            // 仅预加载 [Before] 区域的变量
            if (_wcsicmp(currentSection.c_str(), L"[Before]") == 0) {
                size_t delimiterPos = line.find(L'=');
                if (delimiterPos != std::wstring::npos) {
                    std::wstring key = trim(line.substr(0, delimiterPos));

                    if (_wcsicmp(key.c_str(), L"uservar") == 0) {
                        std::wstring value = trim(line.substr(delimiterPos + 1));
                        auto parts = split_string(value, delimiter);
                        if (parts.size() == 2) {
                            // 解析变量并立即加入 map 支持变量嵌套 (如 Z: 依赖于其他变量)
                            variables[parts[0]] = ExpandVariables(parts[1], variables);
                        }
                    }
                }
            }
        }
    }

    std::wstring appPathRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"General", L"application"), variables);

    wchar_t launcherBaseName[MAX_PATH];
    wcscpy_s(launcherBaseName, PathFindFileNameW(launcherFullPath));
    PathRemoveExtensionW(launcherBaseName);
    variables[L"LAUNCHERNAME"] = launcherBaseName; // 新增：保存启动器名称供后续使用
    variables[L"YAPNAME"] = launcherBaseName;      // [新增] 启动器名称 (不含 .exe)

    wchar_t appBaseName[MAX_PATH] = L"";
    if (!appPathRaw.empty()) {
        wcscpy_s(appBaseName, PathFindFileNameW(appPathRaw.c_str()));
        PathRemoveExtensionW(appBaseName);
    }
    std::wstring mutexName = L"Global\\" + std::wstring(launcherBaseName) + L"_" + std::wstring(appBaseName);

    // [修改] 计算确定性的管道名称 供所有实例使用 (基于启动器名称)
    std::wstring sharedPipeName = GetDeterministicPipeName(launcherBaseName);

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
        variables[L"NETHASH0"] = CalculateNetPathEx(absoluteAppPath, 0);
        variables[L"NETHASH1"] = CalculateNetPathEx(absoluteAppPath, 1);
        variables[L"NETHASH2"] = CalculateNetPathEx(absoluteAppPath, 2);
        variables[L"NETHASH3"] = CalculateNetPathEx(absoluteAppPath, 3);
        variables[L"NETHASH4"] = CalculateNetPathEx(absoluteAppPath, 4);
        variables[L"NETHASH5"] = CalculateNetPathEx(absoluteAppPath, 5);
        variables[L"NETHASH6"] = CalculateNetPathEx(absoluteAppPath, 6);
        variables[L"NETHASH7"] = CalculateNetPathEx(absoluteAppPath, 7);
        variables[L"NETHASH8"] = CalculateNetPathEx(absoluteAppPath, 8);
        variables[L"NETHASH9"] = CalculateNetPathEx(absoluteAppPath, 9);
        variables[L"NETHASH10"] = CalculateNetPathEx(absoluteAppPath, 10);
        variables[L"NETHASH11"] = CalculateNetPathEx(absoluteAppPath, 11);
        variables[L"NETHASH12"] = CalculateNetPathEx(absoluteAppPath, 12);
        variables[L"NETHASH13"] = CalculateNetPathEx(absoluteAppPath, 13);
        variables[L"NETHASH14"] = CalculateNetPathEx(absoluteAppPath, 14);
        variables[L"NETHASH15"] = CalculateNetPathEx(absoluteAppPath, 15);
        variables[L"NETHASH16"] = CalculateNetPathEx(absoluteAppPath, 16);
        variables[L"NETHASH17"] = CalculateNetPathEx(absoluteAppPath, 17);
        variables[L"NETHASH18"] = CalculateNetPathEx(absoluteAppPath, 18);
        variables[L"NETHASH19"] = CalculateNetPathEx(absoluteAppPath, 19);
        variables[L"NETHASH20"] = CalculateNetPathEx(absoluteAppPath, 20);
        variables[L"NETHASH21"] = CalculateNetPathEx(absoluteAppPath, 21);
        variables[L"NETHASH22"] = CalculateNetPathEx(absoluteAppPath, 22);
        variables[L"NETHASH23"] = CalculateNetPathEx(absoluteAppPath, 23);
        variables[L"NETHASH24"] = CalculateNetPathEx(absoluteAppPath, 24);
        variables[L"NETHASH25"] = CalculateNetPathEx(absoluteAppPath, 25);
        variables[L"NETHASH26"] = CalculateNetPathEx(absoluteAppPath, 26);
        variables[L"NETHASH27"] = CalculateNetPathEx(absoluteAppPath, 27);
        variables[L"NETHASH28"] = CalculateNetPathEx(absoluteAppPath, 28);
        variables[L"NETHASH29"] = CalculateNetPathEx(absoluteAppPath, 29);
        variables[L"NETHASH30"] = CalculateNetPathEx(absoluteAppPath, 30);
        variables[L"NETHASH31"] = CalculateNetPathEx(absoluteAppPath, 31);
        variables[L"NETHASH32"] = CalculateNetPathEx(absoluteAppPath, 32);
        variables[L"NETHASH33"] = CalculateNetPathEx(absoluteAppPath, 33);
        variables[L"NETHASH34"] = CalculateNetPathEx(absoluteAppPath, 34);
        variables[L"NETHASH35"] = CalculateNetPathEx(absoluteAppPath, 35);
        variables[L"NETHASH36"] = CalculateNetPathEx(absoluteAppPath, 36);
        variables[L"NETHASH37"] = CalculateNetPathEx(absoluteAppPath, 37);
        variables[L"NETHASH38"] = CalculateNetPathEx(absoluteAppPath, 38);
        variables[L"NETHASH39"] = CalculateNetPathEx(absoluteAppPath, 39);
        variables[L"NETHASH40"] = CalculateNetPathEx(absoluteAppPath, 40);
        variables[L"NETHASH41"] = CalculateNetPathEx(absoluteAppPath, 41);
        variables[L"NETHASH42"] = CalculateNetPathEx(absoluteAppPath, 42);
        variables[L"NETHASH43"] = CalculateNetPathEx(absoluteAppPath, 43);
        variables[L"NETHASH44"] = CalculateNetPathEx(absoluteAppPath, 44);
        variables[L"NETHASH45"] = CalculateNetPathEx(absoluteAppPath, 45);
        variables[L"NETHASH46"] = CalculateNetPathEx(absoluteAppPath, 46);
        variables[L"NETHASH47"] = CalculateNetPathEx(absoluteAppPath, 47);
        variables[L"NETHASH48"] = CalculateNetPathEx(absoluteAppPath, 48);
        variables[L"NETHASH49"] = CalculateNetPathEx(absoluteAppPath, 49);
        variables[L"NETHASH50"] = CalculateNetPathEx(absoluteAppPath, 50);
        variables[L"NETHASH51"] = CalculateNetPathEx(absoluteAppPath, 51);
        variables[L"NETHASH52"] = CalculateNetPathEx(absoluteAppPath, 52);
        variables[L"NETHASH53"] = CalculateNetPathEx(absoluteAppPath, 53);
        variables[L"NETHASH54"] = CalculateNetPathEx(absoluteAppPath, 54);
        variables[L"NETHASH55"] = CalculateNetPathEx(absoluteAppPath, 55);
        variables[L"NETHASH56"] = CalculateNetPathEx(absoluteAppPath, 56);
        variables[L"NETHASH57"] = CalculateNetPathEx(absoluteAppPath, 57);
        variables[L"NETHASH58"] = CalculateNetPathEx(absoluteAppPath, 58);
        variables[L"NETHASH59"] = CalculateNetPathEx(absoluteAppPath, 59);
        variables[L"NETHASH60"] = CalculateNetPathEx(absoluteAppPath, 60);
        variables[L"NETHASH61"] = CalculateNetPathEx(absoluteAppPath, 61);
        variables[L"NETHASH62"] = CalculateNetPathEx(absoluteAppPath, 62);
        variables[L"NETHASH63"] = CalculateNetPathEx(absoluteAppPath, 63);
        variables[L"NETHASH64"] = CalculateNetPathEx(absoluteAppPath, 64);
        variables[L"NETHASH65"] = CalculateNetPathEx(absoluteAppPath, 65);
        variables[L"NETHASH66"] = CalculateNetPathEx(absoluteAppPath, 66);
        variables[L"NETHASH67"] = CalculateNetPathEx(absoluteAppPath, 67);
        variables[L"NETHASH68"] = CalculateNetPathEx(absoluteAppPath, 68);
        variables[L"NETHASH69"] = CalculateNetPathEx(absoluteAppPath, 69);
        variables[L"NETHASH70"] = CalculateNetPathEx(absoluteAppPath, 70);
        variables[L"NETHASH71"] = CalculateNetPathEx(absoluteAppPath, 71);
        variables[L"NETHASH72"] = CalculateNetPathEx(absoluteAppPath, 72);
        variables[L"NETHASH73"] = CalculateNetPathEx(absoluteAppPath, 73);
        variables[L"NETHASH74"] = CalculateNetPathEx(absoluteAppPath, 74);
        variables[L"NETHASH75"] = CalculateNetPathEx(absoluteAppPath, 75);
        variables[L"NETHASH76"] = CalculateNetPathEx(absoluteAppPath, 76);
        variables[L"NETHASH77"] = CalculateNetPathEx(absoluteAppPath, 77);
        variables[L"NETHASH78"] = CalculateNetPathEx(absoluteAppPath, 78);
        variables[L"NETHASH79"] = CalculateNetPathEx(absoluteAppPath, 79);
        variables[L"NETHASH80"] = CalculateNetPathEx(absoluteAppPath, 80);
        variables[L"NETHASH81"] = CalculateNetPathEx(absoluteAppPath, 81);
        variables[L"NETHASH82"] = CalculateNetPathEx(absoluteAppPath, 82);
        variables[L"NETHASH83"] = CalculateNetPathEx(absoluteAppPath, 83);
        variables[L"NETHASH84"] = CalculateNetPathEx(absoluteAppPath, 84);
        variables[L"NETHASH85"] = CalculateNetPathEx(absoluteAppPath, 85);
        variables[L"NETHASH86"] = CalculateNetPathEx(absoluteAppPath, 86);
        variables[L"NETHASH87"] = CalculateNetPathEx(absoluteAppPath, 87);
        variables[L"NETHASH88"] = CalculateNetPathEx(absoluteAppPath, 88);
        variables[L"NETHASH89"] = CalculateNetPathEx(absoluteAppPath, 89);
        variables[L"NETHASH90"] = CalculateNetPathEx(absoluteAppPath, 90);
        variables[L"NETHASH91"] = CalculateNetPathEx(absoluteAppPath, 91);
        variables[L"NETHASH92"] = CalculateNetPathEx(absoluteAppPath, 92);
        variables[L"NETHASH93"] = CalculateNetPathEx(absoluteAppPath, 93);
        variables[L"NETHASH94"] = CalculateNetPathEx(absoluteAppPath, 94);
        variables[L"NETHASH95"] = CalculateNetPathEx(absoluteAppPath, 95);
        variables[L"NETHASH96"] = CalculateNetPathEx(absoluteAppPath, 96);
        variables[L"NETHASH97"] = CalculateNetPathEx(absoluteAppPath, 97);
        variables[L"NETHASH98"] = CalculateNetPathEx(absoluteAppPath, 98);
        variables[L"NETHASH99"] = CalculateNetPathEx(absoluteAppPath, 99);
        variables[L"NETHASH100"] = CalculateNetPathEx(absoluteAppPath, 100);
        variables[L"NETHASH101"] = CalculateNetPathEx(absoluteAppPath, 101);
        variables[L"NETHASH102"] = CalculateNetPathEx(absoluteAppPath, 102);
        variables[L"NETHASH103"] = CalculateNetPathEx(absoluteAppPath, 103);
        variables[L"NETHASH104"] = CalculateNetPathEx(absoluteAppPath, 104);
        variables[L"NETHASH105"] = CalculateNetPathEx(absoluteAppPath, 105);
        variables[L"NETHASH106"] = CalculateNetPathEx(absoluteAppPath, 106);
        variables[L"NETHASH107"] = CalculateNetPathEx(absoluteAppPath, 107);
        variables[L"NETHASH108"] = CalculateNetPathEx(absoluteAppPath, 108);
        variables[L"NETHASH109"] = CalculateNetPathEx(absoluteAppPath, 109);
        variables[L"NETHASH110"] = CalculateNetPathEx(absoluteAppPath, 110);
        variables[L"NETHASH111"] = CalculateNetPathEx(absoluteAppPath, 111);
        variables[L"NETHASH112"] = CalculateNetPathEx(absoluteAppPath, 112);
        variables[L"NETHASH113"] = CalculateNetPathEx(absoluteAppPath, 113);
        variables[L"NETHASH114"] = CalculateNetPathEx(absoluteAppPath, 114);
        variables[L"NETHASH115"] = CalculateNetPathEx(absoluteAppPath, 115);
        variables[L"NETHASH116"] = CalculateNetPathEx(absoluteAppPath, 116);
        variables[L"NETHASH117"] = CalculateNetPathEx(absoluteAppPath, 117);
        variables[L"NETHASH118"] = CalculateNetPathEx(absoluteAppPath, 118);
        variables[L"NETHASH119"] = CalculateNetPathEx(absoluteAppPath, 119);
        variables[L"NETHASH120"] = CalculateNetPathEx(absoluteAppPath, 120);
        variables[L"NETHASH121"] = CalculateNetPathEx(absoluteAppPath, 121);
        variables[L"NETHASH122"] = CalculateNetPathEx(absoluteAppPath, 122);
        variables[L"NETHASH123"] = CalculateNetPathEx(absoluteAppPath, 123);
        variables[L"NETHASH124"] = CalculateNetPathEx(absoluteAppPath, 124);
        variables[L"NETHASH125"] = CalculateNetPathEx(absoluteAppPath, 125);
        variables[L"NETHASH126"] = CalculateNetPathEx(absoluteAppPath, 126);
        variables[L"NETHASH127"] = CalculateNetPathEx(absoluteAppPath, 127);
        variables[L"NETHASH128"] = CalculateNetPathEx(absoluteAppPath, 128);
        variables[L"NETHASH129"] = CalculateNetPathEx(absoluteAppPath, 129);
        variables[L"NETHASH130"] = CalculateNetPathEx(absoluteAppPath, 130);
        variables[L"NETHASH131"] = CalculateNetPathEx(absoluteAppPath, 131);
        variables[L"NETHASH132"] = CalculateNetPathEx(absoluteAppPath, 132);
        variables[L"NETHASH133"] = CalculateNetPathEx(absoluteAppPath, 133);
        variables[L"NETHASH134"] = CalculateNetPathEx(absoluteAppPath, 134);
        variables[L"NETHASH135"] = CalculateNetPathEx(absoluteAppPath, 135);
        variables[L"NETHASH136"] = CalculateNetPathEx(absoluteAppPath, 136);
        variables[L"NETHASH137"] = CalculateNetPathEx(absoluteAppPath, 137);
        variables[L"NETHASH138"] = CalculateNetPathEx(absoluteAppPath, 138);
        variables[L"NETHASH139"] = CalculateNetPathEx(absoluteAppPath, 139);
        variables[L"NETHASH140"] = CalculateNetPathEx(absoluteAppPath, 140);
        variables[L"NETHASH141"] = CalculateNetPathEx(absoluteAppPath, 141);
        variables[L"NETHASH142"] = CalculateNetPathEx(absoluteAppPath, 142);
        variables[L"NETHASH143"] = CalculateNetPathEx(absoluteAppPath, 143);
        variables[L"NETHASH144"] = CalculateNetPathEx(absoluteAppPath, 144);
        variables[L"NETHASH145"] = CalculateNetPathEx(absoluteAppPath, 145);
        variables[L"NETHASH146"] = CalculateNetPathEx(absoluteAppPath, 146);
        variables[L"NETHASH147"] = CalculateNetPathEx(absoluteAppPath, 147);
        variables[L"NETHASH148"] = CalculateNetPathEx(absoluteAppPath, 148);
        variables[L"NETHASH149"] = CalculateNetPathEx(absoluteAppPath, 149);
        variables[L"NETHASH150"] = CalculateNetPathEx(absoluteAppPath, 150);
        variables[L"NETHASH151"] = CalculateNetPathEx(absoluteAppPath, 151);
        variables[L"NETHASH152"] = CalculateNetPathEx(absoluteAppPath, 152);
        variables[L"NETHASH153"] = CalculateNetPathEx(absoluteAppPath, 153);
        variables[L"NETHASH154"] = CalculateNetPathEx(absoluteAppPath, 154);
        variables[L"NETHASH155"] = CalculateNetPathEx(absoluteAppPath, 155);
        variables[L"NETHASH156"] = CalculateNetPathEx(absoluteAppPath, 156);
        variables[L"NETHASH157"] = CalculateNetPathEx(absoluteAppPath, 157);
        variables[L"NETHASH158"] = CalculateNetPathEx(absoluteAppPath, 158);
        variables[L"NETHASH159"] = CalculateNetPathEx(absoluteAppPath, 159);
        variables[L"NETHASH160"] = CalculateNetPathEx(absoluteAppPath, 160);
        variables[L"NETHASH161"] = CalculateNetPathEx(absoluteAppPath, 161);
        variables[L"NETHASH162"] = CalculateNetPathEx(absoluteAppPath, 162);
        variables[L"NETHASH163"] = CalculateNetPathEx(absoluteAppPath, 163);
        variables[L"NETHASH164"] = CalculateNetPathEx(absoluteAppPath, 164);
        variables[L"NETHASH165"] = CalculateNetPathEx(absoluteAppPath, 165);
        variables[L"NETHASH166"] = CalculateNetPathEx(absoluteAppPath, 166);
        variables[L"NETHASH167"] = CalculateNetPathEx(absoluteAppPath, 167);
        variables[L"NETHASH168"] = CalculateNetPathEx(absoluteAppPath, 168);
        variables[L"NETHASH169"] = CalculateNetPathEx(absoluteAppPath, 169);
        variables[L"NETHASH170"] = CalculateNetPathEx(absoluteAppPath, 170);
        variables[L"NETHASH171"] = CalculateNetPathEx(absoluteAppPath, 171);
        variables[L"NETHASH172"] = CalculateNetPathEx(absoluteAppPath, 172);
        variables[L"NETHASH173"] = CalculateNetPathEx(absoluteAppPath, 173);
        variables[L"NETHASH174"] = CalculateNetPathEx(absoluteAppPath, 174);
        variables[L"NETHASH175"] = CalculateNetPathEx(absoluteAppPath, 175);
        variables[L"NETHASH176"] = CalculateNetPathEx(absoluteAppPath, 176);
        variables[L"NETHASH177"] = CalculateNetPathEx(absoluteAppPath, 177);
        variables[L"NETHASH178"] = CalculateNetPathEx(absoluteAppPath, 178);
        variables[L"NETHASH179"] = CalculateNetPathEx(absoluteAppPath, 179);
        variables[L"NETHASH180"] = CalculateNetPathEx(absoluteAppPath, 180);
        variables[L"NETHASH181"] = CalculateNetPathEx(absoluteAppPath, 181);
        variables[L"NETHASH182"] = CalculateNetPathEx(absoluteAppPath, 182);
        variables[L"NETHASH183"] = CalculateNetPathEx(absoluteAppPath, 183);
        variables[L"NETHASH184"] = CalculateNetPathEx(absoluteAppPath, 184);
        variables[L"NETHASH185"] = CalculateNetPathEx(absoluteAppPath, 185);
        variables[L"NETHASH186"] = CalculateNetPathEx(absoluteAppPath, 186);
        variables[L"NETHASH187"] = CalculateNetPathEx(absoluteAppPath, 187);
        variables[L"NETHASH188"] = CalculateNetPathEx(absoluteAppPath, 188);
        variables[L"NETHASH189"] = CalculateNetPathEx(absoluteAppPath, 189);
        variables[L"NETHASH190"] = CalculateNetPathEx(absoluteAppPath, 190);
        variables[L"NETHASH191"] = CalculateNetPathEx(absoluteAppPath, 191);
        variables[L"NETHASH192"] = CalculateNetPathEx(absoluteAppPath, 192);
        variables[L"NETHASH193"] = CalculateNetPathEx(absoluteAppPath, 193);
        variables[L"NETHASH194"] = CalculateNetPathEx(absoluteAppPath, 194);
        variables[L"NETHASH195"] = CalculateNetPathEx(absoluteAppPath, 195);
        variables[L"NETHASH196"] = CalculateNetPathEx(absoluteAppPath, 196);
        variables[L"NETHASH197"] = CalculateNetPathEx(absoluteAppPath, 197);
        variables[L"NETHASH198"] = CalculateNetPathEx(absoluteAppPath, 198);
        variables[L"NETHASH199"] = CalculateNetPathEx(absoluteAppPath, 199);
        variables[L"NETHASH200"] = CalculateNetPathEx(absoluteAppPath, 200);
        variables[L"NETHASH201"] = CalculateNetPathEx(absoluteAppPath, 201);
        variables[L"NETHASH202"] = CalculateNetPathEx(absoluteAppPath, 202);
        variables[L"NETHASH203"] = CalculateNetPathEx(absoluteAppPath, 203);
        variables[L"NETHASH204"] = CalculateNetPathEx(absoluteAppPath, 204);
        variables[L"NETHASH205"] = CalculateNetPathEx(absoluteAppPath, 205);
        variables[L"NETHASH206"] = CalculateNetPathEx(absoluteAppPath, 206);
        variables[L"NETHASH207"] = CalculateNetPathEx(absoluteAppPath, 207);
        variables[L"NETHASH208"] = CalculateNetPathEx(absoluteAppPath, 208);
        variables[L"NETHASH209"] = CalculateNetPathEx(absoluteAppPath, 209);
        variables[L"NETHASH210"] = CalculateNetPathEx(absoluteAppPath, 210);
        variables[L"NETHASH211"] = CalculateNetPathEx(absoluteAppPath, 211);
        variables[L"NETHASH212"] = CalculateNetPathEx(absoluteAppPath, 212);
        variables[L"NETHASH213"] = CalculateNetPathEx(absoluteAppPath, 213);
        variables[L"NETHASH214"] = CalculateNetPathEx(absoluteAppPath, 214);
        variables[L"NETHASH215"] = CalculateNetPathEx(absoluteAppPath, 215);
        variables[L"NETHASH216"] = CalculateNetPathEx(absoluteAppPath, 216);
        variables[L"NETHASH217"] = CalculateNetPathEx(absoluteAppPath, 217);
        variables[L"NETHASH218"] = CalculateNetPathEx(absoluteAppPath, 218);
        variables[L"NETHASH219"] = CalculateNetPathEx(absoluteAppPath, 219);
        variables[L"NETHASH220"] = CalculateNetPathEx(absoluteAppPath, 220);
        variables[L"NETHASH221"] = CalculateNetPathEx(absoluteAppPath, 221);
        variables[L"NETHASH222"] = CalculateNetPathEx(absoluteAppPath, 222);
        variables[L"NETHASH223"] = CalculateNetPathEx(absoluteAppPath, 223);
        variables[L"NETHASH224"] = CalculateNetPathEx(absoluteAppPath, 224);
        variables[L"NETHASH225"] = CalculateNetPathEx(absoluteAppPath, 225);
        variables[L"NETHASH226"] = CalculateNetPathEx(absoluteAppPath, 226);
        variables[L"NETHASH227"] = CalculateNetPathEx(absoluteAppPath, 227);
        variables[L"NETHASH228"] = CalculateNetPathEx(absoluteAppPath, 228);
        variables[L"NETHASH229"] = CalculateNetPathEx(absoluteAppPath, 229);
        variables[L"NETHASH230"] = CalculateNetPathEx(absoluteAppPath, 230);
        variables[L"NETHASH231"] = CalculateNetPathEx(absoluteAppPath, 231);
        variables[L"NETHASH232"] = CalculateNetPathEx(absoluteAppPath, 232);
        variables[L"NETHASH233"] = CalculateNetPathEx(absoluteAppPath, 233);
        variables[L"NETHASH234"] = CalculateNetPathEx(absoluteAppPath, 234);
        variables[L"NETHASH235"] = CalculateNetPathEx(absoluteAppPath, 235);
        variables[L"NETHASH236"] = CalculateNetPathEx(absoluteAppPath, 236);
        variables[L"NETHASH237"] = CalculateNetPathEx(absoluteAppPath, 237);
        variables[L"NETHASH238"] = CalculateNetPathEx(absoluteAppPath, 238);
        variables[L"NETHASH239"] = CalculateNetPathEx(absoluteAppPath, 239);
        variables[L"NETHASH240"] = CalculateNetPathEx(absoluteAppPath, 240);
        variables[L"NETHASH241"] = CalculateNetPathEx(absoluteAppPath, 241);
        variables[L"NETHASH242"] = CalculateNetPathEx(absoluteAppPath, 242);
        variables[L"NETHASH243"] = CalculateNetPathEx(absoluteAppPath, 243);
        variables[L"NETHASH244"] = CalculateNetPathEx(absoluteAppPath, 244);
        variables[L"NETHASH245"] = CalculateNetPathEx(absoluteAppPath, 245);
        variables[L"NETHASH246"] = CalculateNetPathEx(absoluteAppPath, 246);
        variables[L"NETHASH247"] = CalculateNetPathEx(absoluteAppPath, 247);
        variables[L"NETHASH248"] = CalculateNetPathEx(absoluteAppPath, 248);
        variables[L"NETHASH249"] = CalculateNetPathEx(absoluteAppPath, 249);
        variables[L"NETHASH250"] = CalculateNetPathEx(absoluteAppPath, 250);
        variables[L"NETHASH251"] = CalculateNetPathEx(absoluteAppPath, 251);
        variables[L"NETHASH252"] = CalculateNetPathEx(absoluteAppPath, 252);
        variables[L"NETHASH253"] = CalculateNetPathEx(absoluteAppPath, 253);
        variables[L"NETHASH254"] = CalculateNetPathEx(absoluteAppPath, 254);
        variables[L"NETHASH255"] = CalculateNetPathEx(absoluteAppPath, 255);
        variables[L"NETHASH256"] = CalculateNetPathEx(absoluteAppPath, 256);
        variables[L"NETHASH257"] = CalculateNetPathEx(absoluteAppPath, 257);
        variables[L"NETHASH258"] = CalculateNetPathEx(absoluteAppPath, 258);
        variables[L"NETHASH259"] = CalculateNetPathEx(absoluteAppPath, 259);
        variables[L"NETHASH260"] = CalculateNetPathEx(absoluteAppPath, 260);
        variables[L"NETHASH261"] = CalculateNetPathEx(absoluteAppPath, 261);
        variables[L"NETHASH262"] = CalculateNetPathEx(absoluteAppPath, 262);
        variables[L"NETHASH263"] = CalculateNetPathEx(absoluteAppPath, 263);
        variables[L"NETHASH264"] = CalculateNetPathEx(absoluteAppPath, 264);
        variables[L"NETHASH265"] = CalculateNetPathEx(absoluteAppPath, 265);
        variables[L"NETHASH266"] = CalculateNetPathEx(absoluteAppPath, 266);
        variables[L"NETHASH267"] = CalculateNetPathEx(absoluteAppPath, 267);
        variables[L"NETHASH268"] = CalculateNetPathEx(absoluteAppPath, 268);
        variables[L"NETHASH269"] = CalculateNetPathEx(absoluteAppPath, 269);
        variables[L"NETHASH270"] = CalculateNetPathEx(absoluteAppPath, 270);
        variables[L"NETHASH271"] = CalculateNetPathEx(absoluteAppPath, 271);
        variables[L"NETHASH272"] = CalculateNetPathEx(absoluteAppPath, 272);
        variables[L"NETHASH273"] = CalculateNetPathEx(absoluteAppPath, 273);
        variables[L"NETHASH274"] = CalculateNetPathEx(absoluteAppPath, 274);
        variables[L"NETHASH275"] = CalculateNetPathEx(absoluteAppPath, 275);
        variables[L"NETHASH276"] = CalculateNetPathEx(absoluteAppPath, 276);
        variables[L"NETHASH277"] = CalculateNetPathEx(absoluteAppPath, 277);
        variables[L"NETHASH278"] = CalculateNetPathEx(absoluteAppPath, 278);
        variables[L"NETHASH279"] = CalculateNetPathEx(absoluteAppPath, 279);
        variables[L"NETHASH280"] = CalculateNetPathEx(absoluteAppPath, 280);
        variables[L"NETHASH281"] = CalculateNetPathEx(absoluteAppPath, 281);
        variables[L"NETHASH282"] = CalculateNetPathEx(absoluteAppPath, 282);
        variables[L"NETHASH283"] = CalculateNetPathEx(absoluteAppPath, 283);
        variables[L"NETHASH284"] = CalculateNetPathEx(absoluteAppPath, 284);
        variables[L"NETHASH285"] = CalculateNetPathEx(absoluteAppPath, 285);
        variables[L"NETHASH286"] = CalculateNetPathEx(absoluteAppPath, 286);
        variables[L"NETHASH287"] = CalculateNetPathEx(absoluteAppPath, 287);
        variables[L"NETHASH288"] = CalculateNetPathEx(absoluteAppPath, 288);
        variables[L"NETHASH289"] = CalculateNetPathEx(absoluteAppPath, 289);
        variables[L"NETHASH290"] = CalculateNetPathEx(absoluteAppPath, 290);
        variables[L"NETHASH291"] = CalculateNetPathEx(absoluteAppPath, 291);
        variables[L"NETHASH292"] = CalculateNetPathEx(absoluteAppPath, 292);
        variables[L"NETHASH293"] = CalculateNetPathEx(absoluteAppPath, 293);
        variables[L"NETHASH294"] = CalculateNetPathEx(absoluteAppPath, 294);
        variables[L"NETHASH295"] = CalculateNetPathEx(absoluteAppPath, 295);
        variables[L"NETHASH296"] = CalculateNetPathEx(absoluteAppPath, 296);
        variables[L"NETHASH297"] = CalculateNetPathEx(absoluteAppPath, 297);
        variables[L"NETHASH298"] = CalculateNetPathEx(absoluteAppPath, 298);
        variables[L"NETHASH299"] = CalculateNetPathEx(absoluteAppPath, 299);
        variables[L"NETHASH300"] = CalculateNetPathEx(absoluteAppPath, 300);
        variables[L"NETHASH301"] = CalculateNetPathEx(absoluteAppPath, 301);
        variables[L"NETHASH302"] = CalculateNetPathEx(absoluteAppPath, 302);
        variables[L"NETHASH303"] = CalculateNetPathEx(absoluteAppPath, 303);
        variables[L"NETHASH304"] = CalculateNetPathEx(absoluteAppPath, 304);
        variables[L"NETHASH305"] = CalculateNetPathEx(absoluteAppPath, 305);
        variables[L"NETHASH306"] = CalculateNetPathEx(absoluteAppPath, 306);
        variables[L"NETHASH307"] = CalculateNetPathEx(absoluteAppPath, 307);
        variables[L"NETHASH308"] = CalculateNetPathEx(absoluteAppPath, 308);
        variables[L"NETHASH309"] = CalculateNetPathEx(absoluteAppPath, 309);
        variables[L"NETHASH310"] = CalculateNetPathEx(absoluteAppPath, 310);
        variables[L"NETHASH311"] = CalculateNetPathEx(absoluteAppPath, 311);
        variables[L"NETHASH312"] = CalculateNetPathEx(absoluteAppPath, 312);
        variables[L"NETHASH313"] = CalculateNetPathEx(absoluteAppPath, 313);
        variables[L"NETHASH314"] = CalculateNetPathEx(absoluteAppPath, 314);
        variables[L"NETHASH315"] = CalculateNetPathEx(absoluteAppPath, 315);
        variables[L"NETHASH316"] = CalculateNetPathEx(absoluteAppPath, 316);
        variables[L"NETHASH317"] = CalculateNetPathEx(absoluteAppPath, 317);
        variables[L"NETHASH318"] = CalculateNetPathEx(absoluteAppPath, 318);
        variables[L"NETHASH319"] = CalculateNetPathEx(absoluteAppPath, 319);
        variables[L"NETHASH320"] = CalculateNetPathEx(absoluteAppPath, 320);
        variables[L"NETHASH321"] = CalculateNetPathEx(absoluteAppPath, 321);
        variables[L"NETHASH322"] = CalculateNetPathEx(absoluteAppPath, 322);
        variables[L"NETHASH323"] = CalculateNetPathEx(absoluteAppPath, 323);
        variables[L"NETHASH324"] = CalculateNetPathEx(absoluteAppPath, 324);
        variables[L"NETHASH325"] = CalculateNetPathEx(absoluteAppPath, 325);
        variables[L"NETHASH326"] = CalculateNetPathEx(absoluteAppPath, 326);
        variables[L"NETHASH327"] = CalculateNetPathEx(absoluteAppPath, 327);
        variables[L"NETHASH328"] = CalculateNetPathEx(absoluteAppPath, 328);
        variables[L"NETHASH329"] = CalculateNetPathEx(absoluteAppPath, 329);
        variables[L"NETHASH330"] = CalculateNetPathEx(absoluteAppPath, 330);
        variables[L"NETHASH331"] = CalculateNetPathEx(absoluteAppPath, 331);
        variables[L"NETHASH332"] = CalculateNetPathEx(absoluteAppPath, 332);
        variables[L"NETHASH333"] = CalculateNetPathEx(absoluteAppPath, 333);
        variables[L"NETHASH334"] = CalculateNetPathEx(absoluteAppPath, 334);
        variables[L"NETHASH335"] = CalculateNetPathEx(absoluteAppPath, 335);
        variables[L"NETHASH336"] = CalculateNetPathEx(absoluteAppPath, 336);
        variables[L"NETHASH337"] = CalculateNetPathEx(absoluteAppPath, 337);
        variables[L"NETHASH338"] = CalculateNetPathEx(absoluteAppPath, 338);
        variables[L"NETHASH339"] = CalculateNetPathEx(absoluteAppPath, 339);
        variables[L"NETHASH340"] = CalculateNetPathEx(absoluteAppPath, 340);
        variables[L"NETHASH341"] = CalculateNetPathEx(absoluteAppPath, 341);
        variables[L"NETHASH342"] = CalculateNetPathEx(absoluteAppPath, 342);
        variables[L"NETHASH343"] = CalculateNetPathEx(absoluteAppPath, 343);
        variables[L"NETHASH344"] = CalculateNetPathEx(absoluteAppPath, 344);
        variables[L"NETHASH345"] = CalculateNetPathEx(absoluteAppPath, 345);
        variables[L"NETHASH346"] = CalculateNetPathEx(absoluteAppPath, 346);
        variables[L"NETHASH347"] = CalculateNetPathEx(absoluteAppPath, 347);
        variables[L"NETHASH348"] = CalculateNetPathEx(absoluteAppPath, 348);
        variables[L"NETHASH349"] = CalculateNetPathEx(absoluteAppPath, 349);
        variables[L"NETHASH350"] = CalculateNetPathEx(absoluteAppPath, 350);
        variables[L"NETHASH351"] = CalculateNetPathEx(absoluteAppPath, 351);
        variables[L"NETHASH352"] = CalculateNetPathEx(absoluteAppPath, 352);
        variables[L"NETHASH353"] = CalculateNetPathEx(absoluteAppPath, 353);
        variables[L"NETHASH354"] = CalculateNetPathEx(absoluteAppPath, 354);
        variables[L"NETHASH355"] = CalculateNetPathEx(absoluteAppPath, 355);
        variables[L"NETHASH356"] = CalculateNetPathEx(absoluteAppPath, 356);
        variables[L"NETHASH357"] = CalculateNetPathEx(absoluteAppPath, 357);
        variables[L"NETHASH358"] = CalculateNetPathEx(absoluteAppPath, 358);
        variables[L"NETHASH359"] = CalculateNetPathEx(absoluteAppPath, 359);
        variables[L"NETHASH360"] = CalculateNetPathEx(absoluteAppPath, 360);
        variables[L"NETHASH361"] = CalculateNetPathEx(absoluteAppPath, 361);
        variables[L"NETHASH362"] = CalculateNetPathEx(absoluteAppPath, 362);
        variables[L"NETHASH363"] = CalculateNetPathEx(absoluteAppPath, 363);
        variables[L"NETHASH364"] = CalculateNetPathEx(absoluteAppPath, 364);
        variables[L"NETHASH365"] = CalculateNetPathEx(absoluteAppPath, 365);
        variables[L"NETHASH366"] = CalculateNetPathEx(absoluteAppPath, 366);
        variables[L"NETHASH367"] = CalculateNetPathEx(absoluteAppPath, 367);
        variables[L"NETHASH368"] = CalculateNetPathEx(absoluteAppPath, 368);
        variables[L"NETHASH369"] = CalculateNetPathEx(absoluteAppPath, 369);
        variables[L"NETHASH370"] = CalculateNetPathEx(absoluteAppPath, 370);
        variables[L"NETHASH371"] = CalculateNetPathEx(absoluteAppPath, 371);
        variables[L"NETHASH372"] = CalculateNetPathEx(absoluteAppPath, 372);
        variables[L"NETHASH373"] = CalculateNetPathEx(absoluteAppPath, 373);
        variables[L"NETHASH374"] = CalculateNetPathEx(absoluteAppPath, 374);
        variables[L"NETHASH375"] = CalculateNetPathEx(absoluteAppPath, 375);
        variables[L"NETHASH376"] = CalculateNetPathEx(absoluteAppPath, 376);
        variables[L"NETHASH377"] = CalculateNetPathEx(absoluteAppPath, 377);
        variables[L"NETHASH378"] = CalculateNetPathEx(absoluteAppPath, 378);
        variables[L"NETHASH379"] = CalculateNetPathEx(absoluteAppPath, 379);
        variables[L"NETHASH380"] = CalculateNetPathEx(absoluteAppPath, 380);
        variables[L"NETHASH381"] = CalculateNetPathEx(absoluteAppPath, 381);
        variables[L"NETHASH382"] = CalculateNetPathEx(absoluteAppPath, 382);
        variables[L"NETHASH383"] = CalculateNetPathEx(absoluteAppPath, 383);
        variables[L"NETHASH384"] = CalculateNetPathEx(absoluteAppPath, 384);
        variables[L"NETHASH385"] = CalculateNetPathEx(absoluteAppPath, 385);
        variables[L"NETHASH386"] = CalculateNetPathEx(absoluteAppPath, 386);
        variables[L"NETHASH387"] = CalculateNetPathEx(absoluteAppPath, 387);
        variables[L"NETHASH388"] = CalculateNetPathEx(absoluteAppPath, 388);
        variables[L"NETHASH389"] = CalculateNetPathEx(absoluteAppPath, 389);
        variables[L"NETHASH390"] = CalculateNetPathEx(absoluteAppPath, 390);
        variables[L"NETHASH391"] = CalculateNetPathEx(absoluteAppPath, 391);
        variables[L"NETHASH392"] = CalculateNetPathEx(absoluteAppPath, 392);
        variables[L"NETHASH393"] = CalculateNetPathEx(absoluteAppPath, 393);
        variables[L"NETHASH394"] = CalculateNetPathEx(absoluteAppPath, 394);
        variables[L"NETHASH395"] = CalculateNetPathEx(absoluteAppPath, 395);
        variables[L"NETHASH396"] = CalculateNetPathEx(absoluteAppPath, 396);
        variables[L"NETHASH397"] = CalculateNetPathEx(absoluteAppPath, 397);
        variables[L"NETHASH398"] = CalculateNetPathEx(absoluteAppPath, 398);
        variables[L"NETHASH399"] = CalculateNetPathEx(absoluteAppPath, 399);
        variables[L"NETHASH400"] = CalculateNetPathEx(absoluteAppPath, 400);
        variables[L"NETHASH401"] = CalculateNetPathEx(absoluteAppPath, 401);
        variables[L"NETHASH402"] = CalculateNetPathEx(absoluteAppPath, 402);
        variables[L"NETHASH403"] = CalculateNetPathEx(absoluteAppPath, 403);
        variables[L"NETHASH404"] = CalculateNetPathEx(absoluteAppPath, 404);
        variables[L"NETHASH405"] = CalculateNetPathEx(absoluteAppPath, 405);
        variables[L"NETHASH406"] = CalculateNetPathEx(absoluteAppPath, 406);
        variables[L"NETHASH407"] = CalculateNetPathEx(absoluteAppPath, 407);
        variables[L"NETHASH408"] = CalculateNetPathEx(absoluteAppPath, 408);
        variables[L"NETHASH409"] = CalculateNetPathEx(absoluteAppPath, 409);
        variables[L"NETHASH410"] = CalculateNetPathEx(absoluteAppPath, 410);
        variables[L"NETHASH411"] = CalculateNetPathEx(absoluteAppPath, 411);
        variables[L"NETHASH412"] = CalculateNetPathEx(absoluteAppPath, 412);
        variables[L"NETHASH413"] = CalculateNetPathEx(absoluteAppPath, 413);
        variables[L"NETHASH414"] = CalculateNetPathEx(absoluteAppPath, 414);
        variables[L"NETHASH415"] = CalculateNetPathEx(absoluteAppPath, 415);
        variables[L"NETHASH416"] = CalculateNetPathEx(absoluteAppPath, 416);
        variables[L"NETHASH417"] = CalculateNetPathEx(absoluteAppPath, 417);
        variables[L"NETHASH418"] = CalculateNetPathEx(absoluteAppPath, 418);
        variables[L"NETHASH419"] = CalculateNetPathEx(absoluteAppPath, 419);
        variables[L"NETHASH420"] = CalculateNetPathEx(absoluteAppPath, 420);
        variables[L"NETHASH421"] = CalculateNetPathEx(absoluteAppPath, 421);
        variables[L"NETHASH422"] = CalculateNetPathEx(absoluteAppPath, 422);
        variables[L"NETHASH423"] = CalculateNetPathEx(absoluteAppPath, 423);
        variables[L"NETHASH424"] = CalculateNetPathEx(absoluteAppPath, 424);
        variables[L"NETHASH425"] = CalculateNetPathEx(absoluteAppPath, 425);
        variables[L"NETHASH426"] = CalculateNetPathEx(absoluteAppPath, 426);
        variables[L"NETHASH427"] = CalculateNetPathEx(absoluteAppPath, 427);
        variables[L"NETHASH428"] = CalculateNetPathEx(absoluteAppPath, 428);
        variables[L"NETHASH429"] = CalculateNetPathEx(absoluteAppPath, 429);
        variables[L"NETHASH430"] = CalculateNetPathEx(absoluteAppPath, 430);
        variables[L"NETHASH431"] = CalculateNetPathEx(absoluteAppPath, 431);
        variables[L"NETHASH432"] = CalculateNetPathEx(absoluteAppPath, 432);
        variables[L"NETHASH433"] = CalculateNetPathEx(absoluteAppPath, 433);
        variables[L"NETHASH434"] = CalculateNetPathEx(absoluteAppPath, 434);
        variables[L"NETHASH435"] = CalculateNetPathEx(absoluteAppPath, 435);
        variables[L"NETHASH436"] = CalculateNetPathEx(absoluteAppPath, 436);
        variables[L"NETHASH437"] = CalculateNetPathEx(absoluteAppPath, 437);
        variables[L"NETHASH438"] = CalculateNetPathEx(absoluteAppPath, 438);
        variables[L"NETHASH439"] = CalculateNetPathEx(absoluteAppPath, 439);
        variables[L"NETHASH440"] = CalculateNetPathEx(absoluteAppPath, 440);
        variables[L"NETHASH441"] = CalculateNetPathEx(absoluteAppPath, 441);
        variables[L"NETHASH442"] = CalculateNetPathEx(absoluteAppPath, 442);
        variables[L"NETHASH443"] = CalculateNetPathEx(absoluteAppPath, 443);
        variables[L"NETHASH444"] = CalculateNetPathEx(absoluteAppPath, 444);
        variables[L"NETHASH445"] = CalculateNetPathEx(absoluteAppPath, 445);
        variables[L"NETHASH446"] = CalculateNetPathEx(absoluteAppPath, 446);
        variables[L"NETHASH447"] = CalculateNetPathEx(absoluteAppPath, 447);
        variables[L"NETHASH448"] = CalculateNetPathEx(absoluteAppPath, 448);
        variables[L"NETHASH449"] = CalculateNetPathEx(absoluteAppPath, 449);
        variables[L"NETHASH450"] = CalculateNetPathEx(absoluteAppPath, 450);
        variables[L"NETHASH451"] = CalculateNetPathEx(absoluteAppPath, 451);
        variables[L"NETHASH452"] = CalculateNetPathEx(absoluteAppPath, 452);
        variables[L"NETHASH453"] = CalculateNetPathEx(absoluteAppPath, 453);
        variables[L"NETHASH454"] = CalculateNetPathEx(absoluteAppPath, 454);
        variables[L"NETHASH455"] = CalculateNetPathEx(absoluteAppPath, 455);
        variables[L"NETHASH456"] = CalculateNetPathEx(absoluteAppPath, 456);
        variables[L"NETHASH457"] = CalculateNetPathEx(absoluteAppPath, 457);
        variables[L"NETHASH458"] = CalculateNetPathEx(absoluteAppPath, 458);
        variables[L"NETHASH459"] = CalculateNetPathEx(absoluteAppPath, 459);
        variables[L"NETHASH460"] = CalculateNetPathEx(absoluteAppPath, 460);
        variables[L"NETHASH461"] = CalculateNetPathEx(absoluteAppPath, 461);
        variables[L"NETHASH462"] = CalculateNetPathEx(absoluteAppPath, 462);
        variables[L"NETHASH463"] = CalculateNetPathEx(absoluteAppPath, 463);
        variables[L"NETHASH464"] = CalculateNetPathEx(absoluteAppPath, 464);
        variables[L"NETHASH465"] = CalculateNetPathEx(absoluteAppPath, 465);
        variables[L"NETHASH466"] = CalculateNetPathEx(absoluteAppPath, 466);
        variables[L"NETHASH467"] = CalculateNetPathEx(absoluteAppPath, 467);
        variables[L"NETHASH468"] = CalculateNetPathEx(absoluteAppPath, 468);
        variables[L"NETHASH469"] = CalculateNetPathEx(absoluteAppPath, 469);
        variables[L"NETHASH470"] = CalculateNetPathEx(absoluteAppPath, 470);
        variables[L"NETHASH471"] = CalculateNetPathEx(absoluteAppPath, 471);
        variables[L"NETHASH472"] = CalculateNetPathEx(absoluteAppPath, 472);
        variables[L"NETHASH473"] = CalculateNetPathEx(absoluteAppPath, 473);
        variables[L"NETHASH474"] = CalculateNetPathEx(absoluteAppPath, 474);
        variables[L"NETHASH475"] = CalculateNetPathEx(absoluteAppPath, 475);
        variables[L"NETHASH476"] = CalculateNetPathEx(absoluteAppPath, 476);
        variables[L"NETHASH477"] = CalculateNetPathEx(absoluteAppPath, 477);
        variables[L"NETHASH478"] = CalculateNetPathEx(absoluteAppPath, 478);
        variables[L"NETHASH479"] = CalculateNetPathEx(absoluteAppPath, 479);
        variables[L"NETHASH480"] = CalculateNetPathEx(absoluteAppPath, 480);
        variables[L"NETHASH481"] = CalculateNetPathEx(absoluteAppPath, 481);
        variables[L"NETHASH482"] = CalculateNetPathEx(absoluteAppPath, 482);
        variables[L"NETHASH483"] = CalculateNetPathEx(absoluteAppPath, 483);
        variables[L"NETHASH484"] = CalculateNetPathEx(absoluteAppPath, 484);
        variables[L"NETHASH485"] = CalculateNetPathEx(absoluteAppPath, 485);
        variables[L"NETHASH486"] = CalculateNetPathEx(absoluteAppPath, 486);
        variables[L"NETHASH487"] = CalculateNetPathEx(absoluteAppPath, 487);
        variables[L"NETHASH488"] = CalculateNetPathEx(absoluteAppPath, 488);
        variables[L"NETHASH489"] = CalculateNetPathEx(absoluteAppPath, 489);
        variables[L"NETHASH490"] = CalculateNetPathEx(absoluteAppPath, 490);
        variables[L"NETHASH491"] = CalculateNetPathEx(absoluteAppPath, 491);
        variables[L"NETHASH492"] = CalculateNetPathEx(absoluteAppPath, 492);
        variables[L"NETHASH493"] = CalculateNetPathEx(absoluteAppPath, 493);
        variables[L"NETHASH494"] = CalculateNetPathEx(absoluteAppPath, 494);
        variables[L"NETHASH495"] = CalculateNetPathEx(absoluteAppPath, 495);
        variables[L"NETHASH496"] = CalculateNetPathEx(absoluteAppPath, 496);
        variables[L"NETHASH497"] = CalculateNetPathEx(absoluteAppPath, 497);
        variables[L"NETHASH498"] = CalculateNetPathEx(absoluteAppPath, 498);
        variables[L"NETHASH499"] = CalculateNetPathEx(absoluteAppPath, 499);
        variables[L"NETHASH500"] = CalculateNetPathEx(absoluteAppPath, 500);
        variables[L"NETHASH501"] = CalculateNetPathEx(absoluteAppPath, 501);
        variables[L"NETHASH502"] = CalculateNetPathEx(absoluteAppPath, 502);
        variables[L"NETHASH503"] = CalculateNetPathEx(absoluteAppPath, 503);
        variables[L"NETHASH504"] = CalculateNetPathEx(absoluteAppPath, 504);
        variables[L"NETHASH505"] = CalculateNetPathEx(absoluteAppPath, 505);
        variables[L"NETHASH506"] = CalculateNetPathEx(absoluteAppPath, 506);
        variables[L"NETHASH507"] = CalculateNetPathEx(absoluteAppPath, 507);
        variables[L"NETHASH508"] = CalculateNetPathEx(absoluteAppPath, 508);
        variables[L"NETHASH509"] = CalculateNetPathEx(absoluteAppPath, 509);
        variables[L"NETHASH510"] = CalculateNetPathEx(absoluteAppPath, 510);
        variables[L"NETHASH511"] = CalculateNetPathEx(absoluteAppPath, 511);
        variables[L"NETHASH512"] = CalculateNetPathEx(absoluteAppPath, 512);
        variables[L"NETHASH513"] = CalculateNetPathEx(absoluteAppPath, 513);
        variables[L"NETHASH514"] = CalculateNetPathEx(absoluteAppPath, 514);
        variables[L"NETHASH515"] = CalculateNetPathEx(absoluteAppPath, 515);
        variables[L"NETHASH516"] = CalculateNetPathEx(absoluteAppPath, 516);
        variables[L"NETHASH517"] = CalculateNetPathEx(absoluteAppPath, 517);
        variables[L"NETHASH518"] = CalculateNetPathEx(absoluteAppPath, 518);
        variables[L"NETHASH519"] = CalculateNetPathEx(absoluteAppPath, 519);
        variables[L"NETHASH520"] = CalculateNetPathEx(absoluteAppPath, 520);
        variables[L"NETHASH521"] = CalculateNetPathEx(absoluteAppPath, 521);
        variables[L"NETHASH522"] = CalculateNetPathEx(absoluteAppPath, 522);
        variables[L"NETHASH523"] = CalculateNetPathEx(absoluteAppPath, 523);
        variables[L"NETHASH524"] = CalculateNetPathEx(absoluteAppPath, 524);
        variables[L"NETHASH525"] = CalculateNetPathEx(absoluteAppPath, 525);
        variables[L"NETHASH526"] = CalculateNetPathEx(absoluteAppPath, 526);
        variables[L"NETHASH527"] = CalculateNetPathEx(absoluteAppPath, 527);
        variables[L"NETHASH528"] = CalculateNetPathEx(absoluteAppPath, 528);
        variables[L"NETHASH529"] = CalculateNetPathEx(absoluteAppPath, 529);
        variables[L"NETHASH530"] = CalculateNetPathEx(absoluteAppPath, 530);
        variables[L"NETHASH531"] = CalculateNetPathEx(absoluteAppPath, 531);
        variables[L"NETHASH532"] = CalculateNetPathEx(absoluteAppPath, 532);
        variables[L"NETHASH533"] = CalculateNetPathEx(absoluteAppPath, 533);
        variables[L"NETHASH534"] = CalculateNetPathEx(absoluteAppPath, 534);
        variables[L"NETHASH535"] = CalculateNetPathEx(absoluteAppPath, 535);
        variables[L"NETHASH536"] = CalculateNetPathEx(absoluteAppPath, 536);
        variables[L"NETHASH537"] = CalculateNetPathEx(absoluteAppPath, 537);
        variables[L"NETHASH538"] = CalculateNetPathEx(absoluteAppPath, 538);
        variables[L"NETHASH539"] = CalculateNetPathEx(absoluteAppPath, 539);
        variables[L"NETHASH540"] = CalculateNetPathEx(absoluteAppPath, 540);
        variables[L"NETHASH541"] = CalculateNetPathEx(absoluteAppPath, 541);
        variables[L"NETHASH542"] = CalculateNetPathEx(absoluteAppPath, 542);
        variables[L"NETHASH543"] = CalculateNetPathEx(absoluteAppPath, 543);
        variables[L"NETHASH544"] = CalculateNetPathEx(absoluteAppPath, 544);
        variables[L"NETHASH545"] = CalculateNetPathEx(absoluteAppPath, 545);
        variables[L"NETHASH546"] = CalculateNetPathEx(absoluteAppPath, 546);
        variables[L"NETHASH547"] = CalculateNetPathEx(absoluteAppPath, 547);
        variables[L"NETHASH548"] = CalculateNetPathEx(absoluteAppPath, 548);
        variables[L"NETHASH549"] = CalculateNetPathEx(absoluteAppPath, 549);
        variables[L"NETHASH550"] = CalculateNetPathEx(absoluteAppPath, 550);
        variables[L"NETHASH551"] = CalculateNetPathEx(absoluteAppPath, 551);
        variables[L"NETHASH552"] = CalculateNetPathEx(absoluteAppPath, 552);
        variables[L"NETHASH553"] = CalculateNetPathEx(absoluteAppPath, 553);
        variables[L"NETHASH554"] = CalculateNetPathEx(absoluteAppPath, 554);
        variables[L"NETHASH555"] = CalculateNetPathEx(absoluteAppPath, 555);
        variables[L"NETHASH556"] = CalculateNetPathEx(absoluteAppPath, 556);
        variables[L"NETHASH557"] = CalculateNetPathEx(absoluteAppPath, 557);
        variables[L"NETHASH558"] = CalculateNetPathEx(absoluteAppPath, 558);
        variables[L"NETHASH559"] = CalculateNetPathEx(absoluteAppPath, 559);
        variables[L"NETHASH560"] = CalculateNetPathEx(absoluteAppPath, 560);
        variables[L"NETHASH561"] = CalculateNetPathEx(absoluteAppPath, 561);
        variables[L"NETHASH562"] = CalculateNetPathEx(absoluteAppPath, 562);
        variables[L"NETHASH563"] = CalculateNetPathEx(absoluteAppPath, 563);
        variables[L"NETHASH564"] = CalculateNetPathEx(absoluteAppPath, 564);
        variables[L"NETHASH565"] = CalculateNetPathEx(absoluteAppPath, 565);
        variables[L"NETHASH566"] = CalculateNetPathEx(absoluteAppPath, 566);
        variables[L"NETHASH567"] = CalculateNetPathEx(absoluteAppPath, 567);
        variables[L"NETHASH568"] = CalculateNetPathEx(absoluteAppPath, 568);
        variables[L"NETHASH569"] = CalculateNetPathEx(absoluteAppPath, 569);
        variables[L"NETHASH570"] = CalculateNetPathEx(absoluteAppPath, 570);
        variables[L"NETHASH571"] = CalculateNetPathEx(absoluteAppPath, 571);
        variables[L"NETHASH572"] = CalculateNetPathEx(absoluteAppPath, 572);
        variables[L"NETHASH573"] = CalculateNetPathEx(absoluteAppPath, 573);
        variables[L"NETHASH574"] = CalculateNetPathEx(absoluteAppPath, 574);
        variables[L"NETHASH575"] = CalculateNetPathEx(absoluteAppPath, 575);
        variables[L"NETHASH576"] = CalculateNetPathEx(absoluteAppPath, 576);
        variables[L"NETHASH577"] = CalculateNetPathEx(absoluteAppPath, 577);
        variables[L"NETHASH578"] = CalculateNetPathEx(absoluteAppPath, 578);
        variables[L"NETHASH579"] = CalculateNetPathEx(absoluteAppPath, 579);
        variables[L"NETHASH580"] = CalculateNetPathEx(absoluteAppPath, 580);
        variables[L"NETHASH581"] = CalculateNetPathEx(absoluteAppPath, 581);
        variables[L"NETHASH582"] = CalculateNetPathEx(absoluteAppPath, 582);
        variables[L"NETHASH583"] = CalculateNetPathEx(absoluteAppPath, 583);
        variables[L"NETHASH584"] = CalculateNetPathEx(absoluteAppPath, 584);
        variables[L"NETHASH585"] = CalculateNetPathEx(absoluteAppPath, 585);
        variables[L"NETHASH586"] = CalculateNetPathEx(absoluteAppPath, 586);
        variables[L"NETHASH587"] = CalculateNetPathEx(absoluteAppPath, 587);
        variables[L"NETHASH588"] = CalculateNetPathEx(absoluteAppPath, 588);
        variables[L"NETHASH589"] = CalculateNetPathEx(absoluteAppPath, 589);
        variables[L"NETHASH590"] = CalculateNetPathEx(absoluteAppPath, 590);
        variables[L"NETHASH591"] = CalculateNetPathEx(absoluteAppPath, 591);
        variables[L"NETHASH592"] = CalculateNetPathEx(absoluteAppPath, 592);
        variables[L"NETHASH593"] = CalculateNetPathEx(absoluteAppPath, 593);
        variables[L"NETHASH594"] = CalculateNetPathEx(absoluteAppPath, 594);
        variables[L"NETHASH595"] = CalculateNetPathEx(absoluteAppPath, 595);
        variables[L"NETHASH596"] = CalculateNetPathEx(absoluteAppPath, 596);
        variables[L"NETHASH597"] = CalculateNetPathEx(absoluteAppPath, 597);
        variables[L"NETHASH598"] = CalculateNetPathEx(absoluteAppPath, 598);
        variables[L"NETHASH599"] = CalculateNetPathEx(absoluteAppPath, 599);
        variables[L"NETHASH600"] = CalculateNetPathEx(absoluteAppPath, 600);
        variables[L"NETHASH601"] = CalculateNetPathEx(absoluteAppPath, 601);
        variables[L"NETHASH602"] = CalculateNetPathEx(absoluteAppPath, 602);
        variables[L"NETHASH603"] = CalculateNetPathEx(absoluteAppPath, 603);
        variables[L"NETHASH604"] = CalculateNetPathEx(absoluteAppPath, 604);
        variables[L"NETHASH605"] = CalculateNetPathEx(absoluteAppPath, 605);
        variables[L"NETHASH606"] = CalculateNetPathEx(absoluteAppPath, 606);
        variables[L"NETHASH607"] = CalculateNetPathEx(absoluteAppPath, 607);
        variables[L"NETHASH608"] = CalculateNetPathEx(absoluteAppPath, 608);
        variables[L"NETHASH609"] = CalculateNetPathEx(absoluteAppPath, 609);
        variables[L"NETHASH610"] = CalculateNetPathEx(absoluteAppPath, 610);
        variables[L"NETHASH611"] = CalculateNetPathEx(absoluteAppPath, 611);
        variables[L"NETHASH612"] = CalculateNetPathEx(absoluteAppPath, 612);
        variables[L"NETHASH613"] = CalculateNetPathEx(absoluteAppPath, 613);
        variables[L"NETHASH614"] = CalculateNetPathEx(absoluteAppPath, 614);
        variables[L"NETHASH615"] = CalculateNetPathEx(absoluteAppPath, 615);
        variables[L"NETHASH616"] = CalculateNetPathEx(absoluteAppPath, 616);
        variables[L"NETHASH617"] = CalculateNetPathEx(absoluteAppPath, 617);
        variables[L"NETHASH618"] = CalculateNetPathEx(absoluteAppPath, 618);
        variables[L"NETHASH619"] = CalculateNetPathEx(absoluteAppPath, 619);
        variables[L"NETHASH620"] = CalculateNetPathEx(absoluteAppPath, 620);
        variables[L"NETHASH621"] = CalculateNetPathEx(absoluteAppPath, 621);
        variables[L"NETHASH622"] = CalculateNetPathEx(absoluteAppPath, 622);
        variables[L"NETHASH623"] = CalculateNetPathEx(absoluteAppPath, 623);
        variables[L"NETHASH624"] = CalculateNetPathEx(absoluteAppPath, 624);
        variables[L"NETHASH625"] = CalculateNetPathEx(absoluteAppPath, 625);
        variables[L"NETHASH626"] = CalculateNetPathEx(absoluteAppPath, 626);
        variables[L"NETHASH627"] = CalculateNetPathEx(absoluteAppPath, 627);
        variables[L"NETHASH628"] = CalculateNetPathEx(absoluteAppPath, 628);
        variables[L"NETHASH629"] = CalculateNetPathEx(absoluteAppPath, 629);
        variables[L"NETHASH630"] = CalculateNetPathEx(absoluteAppPath, 630);
        variables[L"NETHASH631"] = CalculateNetPathEx(absoluteAppPath, 631);
        variables[L"NETHASH632"] = CalculateNetPathEx(absoluteAppPath, 632);
        variables[L"NETHASH633"] = CalculateNetPathEx(absoluteAppPath, 633);
        variables[L"NETHASH634"] = CalculateNetPathEx(absoluteAppPath, 634);
        variables[L"NETHASH635"] = CalculateNetPathEx(absoluteAppPath, 635);
        variables[L"NETHASH636"] = CalculateNetPathEx(absoluteAppPath, 636);
        variables[L"NETHASH637"] = CalculateNetPathEx(absoluteAppPath, 637);
        variables[L"NETHASH638"] = CalculateNetPathEx(absoluteAppPath, 638);
        variables[L"NETHASH639"] = CalculateNetPathEx(absoluteAppPath, 639);
        variables[L"NETHASH640"] = CalculateNetPathEx(absoluteAppPath, 640);
        variables[L"NETHASH641"] = CalculateNetPathEx(absoluteAppPath, 641);
        variables[L"NETHASH642"] = CalculateNetPathEx(absoluteAppPath, 642);
        variables[L"NETHASH643"] = CalculateNetPathEx(absoluteAppPath, 643);
        variables[L"NETHASH644"] = CalculateNetPathEx(absoluteAppPath, 644);
        variables[L"NETHASH645"] = CalculateNetPathEx(absoluteAppPath, 645);
        variables[L"NETHASH646"] = CalculateNetPathEx(absoluteAppPath, 646);
        variables[L"NETHASH647"] = CalculateNetPathEx(absoluteAppPath, 647);
        variables[L"NETHASH648"] = CalculateNetPathEx(absoluteAppPath, 648);
        variables[L"NETHASH649"] = CalculateNetPathEx(absoluteAppPath, 649);
        variables[L"NETHASH650"] = CalculateNetPathEx(absoluteAppPath, 650);
        variables[L"NETHASH651"] = CalculateNetPathEx(absoluteAppPath, 651);
        variables[L"NETHASH652"] = CalculateNetPathEx(absoluteAppPath, 652);
        variables[L"NETHASH653"] = CalculateNetPathEx(absoluteAppPath, 653);
        variables[L"NETHASH654"] = CalculateNetPathEx(absoluteAppPath, 654);
        variables[L"NETHASH655"] = CalculateNetPathEx(absoluteAppPath, 655);
        variables[L"NETHASH656"] = CalculateNetPathEx(absoluteAppPath, 656);
        variables[L"NETHASH657"] = CalculateNetPathEx(absoluteAppPath, 657);
        variables[L"NETHASH658"] = CalculateNetPathEx(absoluteAppPath, 658);
        variables[L"NETHASH659"] = CalculateNetPathEx(absoluteAppPath, 659);
        variables[L"NETHASH660"] = CalculateNetPathEx(absoluteAppPath, 660);
        variables[L"NETHASH661"] = CalculateNetPathEx(absoluteAppPath, 661);
        variables[L"NETHASH662"] = CalculateNetPathEx(absoluteAppPath, 662);
        variables[L"NETHASH663"] = CalculateNetPathEx(absoluteAppPath, 663);
        variables[L"NETHASH664"] = CalculateNetPathEx(absoluteAppPath, 664);
        variables[L"NETHASH665"] = CalculateNetPathEx(absoluteAppPath, 665);
        variables[L"NETHASH666"] = CalculateNetPathEx(absoluteAppPath, 666);
        variables[L"NETHASH667"] = CalculateNetPathEx(absoluteAppPath, 667);
        variables[L"NETHASH668"] = CalculateNetPathEx(absoluteAppPath, 668);
        variables[L"NETHASH669"] = CalculateNetPathEx(absoluteAppPath, 669);
        variables[L"NETHASH670"] = CalculateNetPathEx(absoluteAppPath, 670);
        variables[L"NETHASH671"] = CalculateNetPathEx(absoluteAppPath, 671);
        variables[L"NETHASH672"] = CalculateNetPathEx(absoluteAppPath, 672);
        variables[L"NETHASH673"] = CalculateNetPathEx(absoluteAppPath, 673);
        variables[L"NETHASH674"] = CalculateNetPathEx(absoluteAppPath, 674);
        variables[L"NETHASH675"] = CalculateNetPathEx(absoluteAppPath, 675);
        variables[L"NETHASH676"] = CalculateNetPathEx(absoluteAppPath, 676);
        variables[L"NETHASH677"] = CalculateNetPathEx(absoluteAppPath, 677);
        variables[L"NETHASH678"] = CalculateNetPathEx(absoluteAppPath, 678);
        variables[L"NETHASH679"] = CalculateNetPathEx(absoluteAppPath, 679);
        variables[L"NETHASH680"] = CalculateNetPathEx(absoluteAppPath, 680);
        variables[L"NETHASH681"] = CalculateNetPathEx(absoluteAppPath, 681);
        variables[L"NETHASH682"] = CalculateNetPathEx(absoluteAppPath, 682);
        variables[L"NETHASH683"] = CalculateNetPathEx(absoluteAppPath, 683);
        variables[L"NETHASH684"] = CalculateNetPathEx(absoluteAppPath, 684);
        variables[L"NETHASH685"] = CalculateNetPathEx(absoluteAppPath, 685);
        variables[L"NETHASH686"] = CalculateNetPathEx(absoluteAppPath, 686);
        variables[L"NETHASH687"] = CalculateNetPathEx(absoluteAppPath, 687);
        variables[L"NETHASH688"] = CalculateNetPathEx(absoluteAppPath, 688);
        variables[L"NETHASH689"] = CalculateNetPathEx(absoluteAppPath, 689);
        variables[L"NETHASH690"] = CalculateNetPathEx(absoluteAppPath, 690);
        variables[L"NETHASH691"] = CalculateNetPathEx(absoluteAppPath, 691);
        variables[L"NETHASH692"] = CalculateNetPathEx(absoluteAppPath, 692);
        variables[L"NETHASH693"] = CalculateNetPathEx(absoluteAppPath, 693);
        variables[L"NETHASH694"] = CalculateNetPathEx(absoluteAppPath, 694);
        variables[L"NETHASH695"] = CalculateNetPathEx(absoluteAppPath, 695);
        variables[L"NETHASH696"] = CalculateNetPathEx(absoluteAppPath, 696);
        variables[L"NETHASH697"] = CalculateNetPathEx(absoluteAppPath, 697);
        variables[L"NETHASH698"] = CalculateNetPathEx(absoluteAppPath, 698);
        variables[L"NETHASH699"] = CalculateNetPathEx(absoluteAppPath, 699);
        variables[L"NETHASH700"] = CalculateNetPathEx(absoluteAppPath, 700);
        variables[L"NETHASH701"] = CalculateNetPathEx(absoluteAppPath, 701);
        variables[L"NETHASH702"] = CalculateNetPathEx(absoluteAppPath, 702);
        variables[L"NETHASH703"] = CalculateNetPathEx(absoluteAppPath, 703);
        variables[L"NETHASH704"] = CalculateNetPathEx(absoluteAppPath, 704);
        variables[L"NETHASH705"] = CalculateNetPathEx(absoluteAppPath, 705);
        variables[L"NETHASH706"] = CalculateNetPathEx(absoluteAppPath, 706);
        variables[L"NETHASH707"] = CalculateNetPathEx(absoluteAppPath, 707);
        variables[L"NETHASH708"] = CalculateNetPathEx(absoluteAppPath, 708);
        variables[L"NETHASH709"] = CalculateNetPathEx(absoluteAppPath, 709);
        variables[L"NETHASH710"] = CalculateNetPathEx(absoluteAppPath, 710);
        variables[L"NETHASH711"] = CalculateNetPathEx(absoluteAppPath, 711);
        variables[L"NETHASH712"] = CalculateNetPathEx(absoluteAppPath, 712);
        variables[L"NETHASH713"] = CalculateNetPathEx(absoluteAppPath, 713);
        variables[L"NETHASH714"] = CalculateNetPathEx(absoluteAppPath, 714);
        variables[L"NETHASH715"] = CalculateNetPathEx(absoluteAppPath, 715);
        variables[L"NETHASH716"] = CalculateNetPathEx(absoluteAppPath, 716);
        variables[L"NETHASH717"] = CalculateNetPathEx(absoluteAppPath, 717);
        variables[L"NETHASH718"] = CalculateNetPathEx(absoluteAppPath, 718);
        variables[L"NETHASH719"] = CalculateNetPathEx(absoluteAppPath, 719);
        variables[L"NETHASH720"] = CalculateNetPathEx(absoluteAppPath, 720);
        variables[L"NETHASH721"] = CalculateNetPathEx(absoluteAppPath, 721);
        variables[L"NETHASH722"] = CalculateNetPathEx(absoluteAppPath, 722);
        variables[L"NETHASH723"] = CalculateNetPathEx(absoluteAppPath, 723);
        variables[L"NETHASH724"] = CalculateNetPathEx(absoluteAppPath, 724);
        variables[L"NETHASH725"] = CalculateNetPathEx(absoluteAppPath, 725);
        variables[L"NETHASH726"] = CalculateNetPathEx(absoluteAppPath, 726);
        variables[L"NETHASH727"] = CalculateNetPathEx(absoluteAppPath, 727);
        variables[L"NETHASH728"] = CalculateNetPathEx(absoluteAppPath, 728);
        variables[L"NETHASH729"] = CalculateNetPathEx(absoluteAppPath, 729);
        variables[L"NETHASH730"] = CalculateNetPathEx(absoluteAppPath, 730);
        variables[L"NETHASH731"] = CalculateNetPathEx(absoluteAppPath, 731);
        variables[L"NETHASH732"] = CalculateNetPathEx(absoluteAppPath, 732);
        variables[L"NETHASH733"] = CalculateNetPathEx(absoluteAppPath, 733);
        variables[L"NETHASH734"] = CalculateNetPathEx(absoluteAppPath, 734);
        variables[L"NETHASH735"] = CalculateNetPathEx(absoluteAppPath, 735);
        variables[L"NETHASH736"] = CalculateNetPathEx(absoluteAppPath, 736);
        variables[L"NETHASH737"] = CalculateNetPathEx(absoluteAppPath, 737);
        variables[L"NETHASH738"] = CalculateNetPathEx(absoluteAppPath, 738);
        variables[L"NETHASH739"] = CalculateNetPathEx(absoluteAppPath, 739);
        variables[L"NETHASH740"] = CalculateNetPathEx(absoluteAppPath, 740);
        variables[L"NETHASH741"] = CalculateNetPathEx(absoluteAppPath, 741);
        variables[L"NETHASH742"] = CalculateNetPathEx(absoluteAppPath, 742);
        variables[L"NETHASH743"] = CalculateNetPathEx(absoluteAppPath, 743);
        variables[L"NETHASH744"] = CalculateNetPathEx(absoluteAppPath, 744);
        variables[L"NETHASH745"] = CalculateNetPathEx(absoluteAppPath, 745);
        variables[L"NETHASH746"] = CalculateNetPathEx(absoluteAppPath, 746);
        variables[L"NETHASH747"] = CalculateNetPathEx(absoluteAppPath, 747);
        variables[L"NETHASH748"] = CalculateNetPathEx(absoluteAppPath, 748);
        variables[L"NETHASH749"] = CalculateNetPathEx(absoluteAppPath, 749);
        variables[L"NETHASH750"] = CalculateNetPathEx(absoluteAppPath, 750);
        variables[L"NETHASH751"] = CalculateNetPathEx(absoluteAppPath, 751);
        variables[L"NETHASH752"] = CalculateNetPathEx(absoluteAppPath, 752);
        variables[L"NETHASH753"] = CalculateNetPathEx(absoluteAppPath, 753);
        variables[L"NETHASH754"] = CalculateNetPathEx(absoluteAppPath, 754);
        variables[L"NETHASH755"] = CalculateNetPathEx(absoluteAppPath, 755);
        variables[L"NETHASH756"] = CalculateNetPathEx(absoluteAppPath, 756);
        variables[L"NETHASH757"] = CalculateNetPathEx(absoluteAppPath, 757);
        variables[L"NETHASH758"] = CalculateNetPathEx(absoluteAppPath, 758);
        variables[L"NETHASH759"] = CalculateNetPathEx(absoluteAppPath, 759);
        variables[L"NETHASH760"] = CalculateNetPathEx(absoluteAppPath, 760);
        variables[L"NETHASH761"] = CalculateNetPathEx(absoluteAppPath, 761);
        variables[L"NETHASH762"] = CalculateNetPathEx(absoluteAppPath, 762);
        variables[L"NETHASH763"] = CalculateNetPathEx(absoluteAppPath, 763);
        variables[L"NETHASH764"] = CalculateNetPathEx(absoluteAppPath, 764);
        variables[L"NETHASH765"] = CalculateNetPathEx(absoluteAppPath, 765);
        variables[L"NETHASH766"] = CalculateNetPathEx(absoluteAppPath, 766);
        variables[L"NETHASH767"] = CalculateNetPathEx(absoluteAppPath, 767);
        variables[L"NETHASH768"] = CalculateNetPathEx(absoluteAppPath, 768);
        variables[L"NETHASH769"] = CalculateNetPathEx(absoluteAppPath, 769);
        variables[L"NETHASH770"] = CalculateNetPathEx(absoluteAppPath, 770);
        variables[L"NETHASH771"] = CalculateNetPathEx(absoluteAppPath, 771);
        variables[L"NETHASH772"] = CalculateNetPathEx(absoluteAppPath, 772);
        variables[L"NETHASH773"] = CalculateNetPathEx(absoluteAppPath, 773);
        variables[L"NETHASH774"] = CalculateNetPathEx(absoluteAppPath, 774);
        variables[L"NETHASH775"] = CalculateNetPathEx(absoluteAppPath, 775);
        variables[L"NETHASH776"] = CalculateNetPathEx(absoluteAppPath, 776);
        variables[L"NETHASH777"] = CalculateNetPathEx(absoluteAppPath, 777);
        variables[L"NETHASH778"] = CalculateNetPathEx(absoluteAppPath, 778);
        variables[L"NETHASH779"] = CalculateNetPathEx(absoluteAppPath, 779);
        variables[L"NETHASH780"] = CalculateNetPathEx(absoluteAppPath, 780);
        variables[L"NETHASH781"] = CalculateNetPathEx(absoluteAppPath, 781);
        variables[L"NETHASH782"] = CalculateNetPathEx(absoluteAppPath, 782);
        variables[L"NETHASH783"] = CalculateNetPathEx(absoluteAppPath, 783);
        variables[L"NETHASH784"] = CalculateNetPathEx(absoluteAppPath, 784);
        variables[L"NETHASH785"] = CalculateNetPathEx(absoluteAppPath, 785);
        variables[L"NETHASH786"] = CalculateNetPathEx(absoluteAppPath, 786);
        variables[L"NETHASH787"] = CalculateNetPathEx(absoluteAppPath, 787);
        variables[L"NETHASH788"] = CalculateNetPathEx(absoluteAppPath, 788);
        variables[L"NETHASH789"] = CalculateNetPathEx(absoluteAppPath, 789);
        variables[L"NETHASH790"] = CalculateNetPathEx(absoluteAppPath, 790);
        variables[L"NETHASH791"] = CalculateNetPathEx(absoluteAppPath, 791);
        variables[L"NETHASH792"] = CalculateNetPathEx(absoluteAppPath, 792);
        variables[L"NETHASH793"] = CalculateNetPathEx(absoluteAppPath, 793);
        variables[L"NETHASH794"] = CalculateNetPathEx(absoluteAppPath, 794);
        variables[L"NETHASH795"] = CalculateNetPathEx(absoluteAppPath, 795);
        variables[L"NETHASH796"] = CalculateNetPathEx(absoluteAppPath, 796);
        variables[L"NETHASH797"] = CalculateNetPathEx(absoluteAppPath, 797);
        variables[L"NETHASH798"] = CalculateNetPathEx(absoluteAppPath, 798);
        variables[L"NETHASH799"] = CalculateNetPathEx(absoluteAppPath, 799);
        variables[L"NETHASH800"] = CalculateNetPathEx(absoluteAppPath, 800);
        variables[L"NETHASH801"] = CalculateNetPathEx(absoluteAppPath, 801);
        variables[L"NETHASH802"] = CalculateNetPathEx(absoluteAppPath, 802);
        variables[L"NETHASH803"] = CalculateNetPathEx(absoluteAppPath, 803);
        variables[L"NETHASH804"] = CalculateNetPathEx(absoluteAppPath, 804);
        variables[L"NETHASH805"] = CalculateNetPathEx(absoluteAppPath, 805);
        variables[L"NETHASH806"] = CalculateNetPathEx(absoluteAppPath, 806);
        variables[L"NETHASH807"] = CalculateNetPathEx(absoluteAppPath, 807);
        variables[L"NETHASH808"] = CalculateNetPathEx(absoluteAppPath, 808);
        variables[L"NETHASH809"] = CalculateNetPathEx(absoluteAppPath, 809);
        variables[L"NETHASH810"] = CalculateNetPathEx(absoluteAppPath, 810);
        variables[L"NETHASH811"] = CalculateNetPathEx(absoluteAppPath, 811);
        variables[L"NETHASH812"] = CalculateNetPathEx(absoluteAppPath, 812);
        variables[L"NETHASH813"] = CalculateNetPathEx(absoluteAppPath, 813);
        variables[L"NETHASH814"] = CalculateNetPathEx(absoluteAppPath, 814);
        variables[L"NETHASH815"] = CalculateNetPathEx(absoluteAppPath, 815);
        variables[L"NETHASH816"] = CalculateNetPathEx(absoluteAppPath, 816);
        variables[L"NETHASH817"] = CalculateNetPathEx(absoluteAppPath, 817);
        variables[L"NETHASH818"] = CalculateNetPathEx(absoluteAppPath, 818);
        variables[L"NETHASH819"] = CalculateNetPathEx(absoluteAppPath, 819);
        variables[L"NETHASH820"] = CalculateNetPathEx(absoluteAppPath, 820);
        variables[L"NETHASH821"] = CalculateNetPathEx(absoluteAppPath, 821);
        variables[L"NETHASH822"] = CalculateNetPathEx(absoluteAppPath, 822);
        variables[L"NETHASH823"] = CalculateNetPathEx(absoluteAppPath, 823);
        variables[L"NETHASH824"] = CalculateNetPathEx(absoluteAppPath, 824);
        variables[L"NETHASH825"] = CalculateNetPathEx(absoluteAppPath, 825);
        variables[L"NETHASH826"] = CalculateNetPathEx(absoluteAppPath, 826);
        variables[L"NETHASH827"] = CalculateNetPathEx(absoluteAppPath, 827);
        variables[L"NETHASH828"] = CalculateNetPathEx(absoluteAppPath, 828);
        variables[L"NETHASH829"] = CalculateNetPathEx(absoluteAppPath, 829);
        variables[L"NETHASH830"] = CalculateNetPathEx(absoluteAppPath, 830);
        variables[L"NETHASH831"] = CalculateNetPathEx(absoluteAppPath, 831);
        variables[L"NETHASH832"] = CalculateNetPathEx(absoluteAppPath, 832);
        variables[L"NETHASH833"] = CalculateNetPathEx(absoluteAppPath, 833);
        variables[L"NETHASH834"] = CalculateNetPathEx(absoluteAppPath, 834);
        variables[L"NETHASH835"] = CalculateNetPathEx(absoluteAppPath, 835);
        variables[L"NETHASH836"] = CalculateNetPathEx(absoluteAppPath, 836);
        variables[L"NETHASH837"] = CalculateNetPathEx(absoluteAppPath, 837);
        variables[L"NETHASH838"] = CalculateNetPathEx(absoluteAppPath, 838);
        variables[L"NETHASH839"] = CalculateNetPathEx(absoluteAppPath, 839);
        variables[L"NETHASH840"] = CalculateNetPathEx(absoluteAppPath, 840);
        variables[L"NETHASH841"] = CalculateNetPathEx(absoluteAppPath, 841);
        variables[L"NETHASH842"] = CalculateNetPathEx(absoluteAppPath, 842);
        variables[L"NETHASH843"] = CalculateNetPathEx(absoluteAppPath, 843);
        variables[L"NETHASH844"] = CalculateNetPathEx(absoluteAppPath, 844);
        variables[L"NETHASH845"] = CalculateNetPathEx(absoluteAppPath, 845);
        variables[L"NETHASH846"] = CalculateNetPathEx(absoluteAppPath, 846);
        variables[L"NETHASH847"] = CalculateNetPathEx(absoluteAppPath, 847);
        variables[L"NETHASH848"] = CalculateNetPathEx(absoluteAppPath, 848);
        variables[L"NETHASH849"] = CalculateNetPathEx(absoluteAppPath, 849);
        variables[L"NETHASH850"] = CalculateNetPathEx(absoluteAppPath, 850);
        variables[L"NETHASH851"] = CalculateNetPathEx(absoluteAppPath, 851);
        variables[L"NETHASH852"] = CalculateNetPathEx(absoluteAppPath, 852);
        variables[L"NETHASH853"] = CalculateNetPathEx(absoluteAppPath, 853);
        variables[L"NETHASH854"] = CalculateNetPathEx(absoluteAppPath, 854);
        variables[L"NETHASH855"] = CalculateNetPathEx(absoluteAppPath, 855);
        variables[L"NETHASH856"] = CalculateNetPathEx(absoluteAppPath, 856);
        variables[L"NETHASH857"] = CalculateNetPathEx(absoluteAppPath, 857);
        variables[L"NETHASH858"] = CalculateNetPathEx(absoluteAppPath, 858);
        variables[L"NETHASH859"] = CalculateNetPathEx(absoluteAppPath, 859);
        variables[L"NETHASH860"] = CalculateNetPathEx(absoluteAppPath, 860);
        variables[L"NETHASH861"] = CalculateNetPathEx(absoluteAppPath, 861);
        variables[L"NETHASH862"] = CalculateNetPathEx(absoluteAppPath, 862);
        variables[L"NETHASH863"] = CalculateNetPathEx(absoluteAppPath, 863);
        variables[L"NETHASH864"] = CalculateNetPathEx(absoluteAppPath, 864);
        variables[L"NETHASH865"] = CalculateNetPathEx(absoluteAppPath, 865);
        variables[L"NETHASH866"] = CalculateNetPathEx(absoluteAppPath, 866);
        variables[L"NETHASH867"] = CalculateNetPathEx(absoluteAppPath, 867);
        variables[L"NETHASH868"] = CalculateNetPathEx(absoluteAppPath, 868);
        variables[L"NETHASH869"] = CalculateNetPathEx(absoluteAppPath, 869);
        variables[L"NETHASH870"] = CalculateNetPathEx(absoluteAppPath, 870);
        variables[L"NETHASH871"] = CalculateNetPathEx(absoluteAppPath, 871);
        variables[L"NETHASH872"] = CalculateNetPathEx(absoluteAppPath, 872);
        variables[L"NETHASH873"] = CalculateNetPathEx(absoluteAppPath, 873);
        variables[L"NETHASH874"] = CalculateNetPathEx(absoluteAppPath, 874);
        variables[L"NETHASH875"] = CalculateNetPathEx(absoluteAppPath, 875);
        variables[L"NETHASH876"] = CalculateNetPathEx(absoluteAppPath, 876);
        variables[L"NETHASH877"] = CalculateNetPathEx(absoluteAppPath, 877);
        variables[L"NETHASH878"] = CalculateNetPathEx(absoluteAppPath, 878);
        variables[L"NETHASH879"] = CalculateNetPathEx(absoluteAppPath, 879);
        variables[L"NETHASH880"] = CalculateNetPathEx(absoluteAppPath, 880);
        variables[L"NETHASH881"] = CalculateNetPathEx(absoluteAppPath, 881);
        variables[L"NETHASH882"] = CalculateNetPathEx(absoluteAppPath, 882);
        variables[L"NETHASH883"] = CalculateNetPathEx(absoluteAppPath, 883);
        variables[L"NETHASH884"] = CalculateNetPathEx(absoluteAppPath, 884);
        variables[L"NETHASH885"] = CalculateNetPathEx(absoluteAppPath, 885);
        variables[L"NETHASH886"] = CalculateNetPathEx(absoluteAppPath, 886);
        variables[L"NETHASH887"] = CalculateNetPathEx(absoluteAppPath, 887);
        variables[L"NETHASH888"] = CalculateNetPathEx(absoluteAppPath, 888);
        variables[L"NETHASH889"] = CalculateNetPathEx(absoluteAppPath, 889);
        variables[L"NETHASH890"] = CalculateNetPathEx(absoluteAppPath, 890);
        variables[L"NETHASH891"] = CalculateNetPathEx(absoluteAppPath, 891);
        variables[L"NETHASH892"] = CalculateNetPathEx(absoluteAppPath, 892);
        variables[L"NETHASH893"] = CalculateNetPathEx(absoluteAppPath, 893);
        variables[L"NETHASH894"] = CalculateNetPathEx(absoluteAppPath, 894);
        variables[L"NETHASH895"] = CalculateNetPathEx(absoluteAppPath, 895);
        variables[L"NETHASH896"] = CalculateNetPathEx(absoluteAppPath, 896);
        variables[L"NETHASH897"] = CalculateNetPathEx(absoluteAppPath, 897);
        variables[L"NETHASH898"] = CalculateNetPathEx(absoluteAppPath, 898);
        variables[L"NETHASH899"] = CalculateNetPathEx(absoluteAppPath, 899);
        variables[L"NETHASH900"] = CalculateNetPathEx(absoluteAppPath, 900);
        variables[L"NETHASH901"] = CalculateNetPathEx(absoluteAppPath, 901);
        variables[L"NETHASH902"] = CalculateNetPathEx(absoluteAppPath, 902);
        variables[L"NETHASH903"] = CalculateNetPathEx(absoluteAppPath, 903);
        variables[L"NETHASH904"] = CalculateNetPathEx(absoluteAppPath, 904);
        variables[L"NETHASH905"] = CalculateNetPathEx(absoluteAppPath, 905);
        variables[L"NETHASH906"] = CalculateNetPathEx(absoluteAppPath, 906);
        variables[L"NETHASH907"] = CalculateNetPathEx(absoluteAppPath, 907);
        variables[L"NETHASH908"] = CalculateNetPathEx(absoluteAppPath, 908);
        variables[L"NETHASH909"] = CalculateNetPathEx(absoluteAppPath, 909);
        variables[L"NETHASH910"] = CalculateNetPathEx(absoluteAppPath, 910);
        variables[L"NETHASH911"] = CalculateNetPathEx(absoluteAppPath, 911);
        variables[L"NETHASH912"] = CalculateNetPathEx(absoluteAppPath, 912);
        variables[L"NETHASH913"] = CalculateNetPathEx(absoluteAppPath, 913);
        variables[L"NETHASH914"] = CalculateNetPathEx(absoluteAppPath, 914);
        variables[L"NETHASH915"] = CalculateNetPathEx(absoluteAppPath, 915);
        variables[L"NETHASH916"] = CalculateNetPathEx(absoluteAppPath, 916);
        variables[L"NETHASH917"] = CalculateNetPathEx(absoluteAppPath, 917);
        variables[L"NETHASH918"] = CalculateNetPathEx(absoluteAppPath, 918);
        variables[L"NETHASH919"] = CalculateNetPathEx(absoluteAppPath, 919);
        variables[L"NETHASH920"] = CalculateNetPathEx(absoluteAppPath, 920);
        variables[L"NETHASH921"] = CalculateNetPathEx(absoluteAppPath, 921);
        variables[L"NETHASH922"] = CalculateNetPathEx(absoluteAppPath, 922);
        variables[L"NETHASH923"] = CalculateNetPathEx(absoluteAppPath, 923);
        variables[L"NETHASH924"] = CalculateNetPathEx(absoluteAppPath, 924);
        variables[L"NETHASH925"] = CalculateNetPathEx(absoluteAppPath, 925);
        variables[L"NETHASH926"] = CalculateNetPathEx(absoluteAppPath, 926);
        variables[L"NETHASH927"] = CalculateNetPathEx(absoluteAppPath, 927);
        variables[L"NETHASH928"] = CalculateNetPathEx(absoluteAppPath, 928);
        variables[L"NETHASH929"] = CalculateNetPathEx(absoluteAppPath, 929);
        variables[L"NETHASH930"] = CalculateNetPathEx(absoluteAppPath, 930);
        variables[L"NETHASH931"] = CalculateNetPathEx(absoluteAppPath, 931);
        variables[L"NETHASH932"] = CalculateNetPathEx(absoluteAppPath, 932);
        variables[L"NETHASH933"] = CalculateNetPathEx(absoluteAppPath, 933);
        variables[L"NETHASH934"] = CalculateNetPathEx(absoluteAppPath, 934);
        variables[L"NETHASH935"] = CalculateNetPathEx(absoluteAppPath, 935);
        variables[L"NETHASH936"] = CalculateNetPathEx(absoluteAppPath, 936);
        variables[L"NETHASH937"] = CalculateNetPathEx(absoluteAppPath, 937);
        variables[L"NETHASH938"] = CalculateNetPathEx(absoluteAppPath, 938);
        variables[L"NETHASH939"] = CalculateNetPathEx(absoluteAppPath, 939);
        variables[L"NETHASH940"] = CalculateNetPathEx(absoluteAppPath, 940);
        variables[L"NETHASH941"] = CalculateNetPathEx(absoluteAppPath, 941);
        variables[L"NETHASH942"] = CalculateNetPathEx(absoluteAppPath, 942);
        variables[L"NETHASH943"] = CalculateNetPathEx(absoluteAppPath, 943);
        variables[L"NETHASH944"] = CalculateNetPathEx(absoluteAppPath, 944);
        variables[L"NETHASH945"] = CalculateNetPathEx(absoluteAppPath, 945);
        variables[L"NETHASH946"] = CalculateNetPathEx(absoluteAppPath, 946);
        variables[L"NETHASH947"] = CalculateNetPathEx(absoluteAppPath, 947);
        variables[L"NETHASH948"] = CalculateNetPathEx(absoluteAppPath, 948);
        variables[L"NETHASH949"] = CalculateNetPathEx(absoluteAppPath, 949);
        variables[L"NETHASH950"] = CalculateNetPathEx(absoluteAppPath, 950);
        variables[L"NETHASH951"] = CalculateNetPathEx(absoluteAppPath, 951);
        variables[L"NETHASH952"] = CalculateNetPathEx(absoluteAppPath, 952);
        variables[L"NETHASH953"] = CalculateNetPathEx(absoluteAppPath, 953);
        variables[L"NETHASH954"] = CalculateNetPathEx(absoluteAppPath, 954);
        variables[L"NETHASH955"] = CalculateNetPathEx(absoluteAppPath, 955);
        variables[L"NETHASH956"] = CalculateNetPathEx(absoluteAppPath, 956);
        variables[L"NETHASH957"] = CalculateNetPathEx(absoluteAppPath, 957);
        variables[L"NETHASH958"] = CalculateNetPathEx(absoluteAppPath, 958);
        variables[L"NETHASH959"] = CalculateNetPathEx(absoluteAppPath, 959);
        variables[L"NETHASH960"] = CalculateNetPathEx(absoluteAppPath, 960);
        variables[L"NETHASH961"] = CalculateNetPathEx(absoluteAppPath, 961);
        variables[L"NETHASH962"] = CalculateNetPathEx(absoluteAppPath, 962);
        variables[L"NETHASH963"] = CalculateNetPathEx(absoluteAppPath, 963);
        variables[L"NETHASH964"] = CalculateNetPathEx(absoluteAppPath, 964);
        variables[L"NETHASH965"] = CalculateNetPathEx(absoluteAppPath, 965);
        variables[L"NETHASH966"] = CalculateNetPathEx(absoluteAppPath, 966);
        variables[L"NETHASH967"] = CalculateNetPathEx(absoluteAppPath, 967);
        variables[L"NETHASH968"] = CalculateNetPathEx(absoluteAppPath, 968);
        variables[L"NETHASH969"] = CalculateNetPathEx(absoluteAppPath, 969);
        variables[L"NETHASH970"] = CalculateNetPathEx(absoluteAppPath, 970);
        variables[L"NETHASH971"] = CalculateNetPathEx(absoluteAppPath, 971);
        variables[L"NETHASH972"] = CalculateNetPathEx(absoluteAppPath, 972);
        variables[L"NETHASH973"] = CalculateNetPathEx(absoluteAppPath, 973);
        variables[L"NETHASH974"] = CalculateNetPathEx(absoluteAppPath, 974);
        variables[L"NETHASH975"] = CalculateNetPathEx(absoluteAppPath, 975);
        variables[L"NETHASH976"] = CalculateNetPathEx(absoluteAppPath, 976);
        variables[L"NETHASH977"] = CalculateNetPathEx(absoluteAppPath, 977);
        variables[L"NETHASH978"] = CalculateNetPathEx(absoluteAppPath, 978);
        variables[L"NETHASH979"] = CalculateNetPathEx(absoluteAppPath, 979);
        variables[L"NETHASH980"] = CalculateNetPathEx(absoluteAppPath, 980);
        variables[L"NETHASH981"] = CalculateNetPathEx(absoluteAppPath, 981);
        variables[L"NETHASH982"] = CalculateNetPathEx(absoluteAppPath, 982);
        variables[L"NETHASH983"] = CalculateNetPathEx(absoluteAppPath, 983);
        variables[L"NETHASH984"] = CalculateNetPathEx(absoluteAppPath, 984);
        variables[L"NETHASH985"] = CalculateNetPathEx(absoluteAppPath, 985);
        variables[L"NETHASH986"] = CalculateNetPathEx(absoluteAppPath, 986);
        variables[L"NETHASH987"] = CalculateNetPathEx(absoluteAppPath, 987);
        variables[L"NETHASH988"] = CalculateNetPathEx(absoluteAppPath, 988);
        variables[L"NETHASH989"] = CalculateNetPathEx(absoluteAppPath, 989);
        variables[L"NETHASH990"] = CalculateNetPathEx(absoluteAppPath, 990);
        variables[L"NETHASH991"] = CalculateNetPathEx(absoluteAppPath, 991);
        variables[L"NETHASH992"] = CalculateNetPathEx(absoluteAppPath, 992);
        variables[L"NETHASH993"] = CalculateNetPathEx(absoluteAppPath, 993);
        variables[L"NETHASH994"] = CalculateNetPathEx(absoluteAppPath, 994);
        variables[L"NETHASH995"] = CalculateNetPathEx(absoluteAppPath, 995);
        variables[L"NETHASH996"] = CalculateNetPathEx(absoluteAppPath, 996);
        variables[L"NETHASH997"] = CalculateNetPathEx(absoluteAppPath, 997);
        variables[L"NETHASH998"] = CalculateNetPathEx(absoluteAppPath, 998);
        variables[L"NETHASH999"] = CalculateNetPathEx(absoluteAppPath, 999);
        variables[L"NETHASH1000"] = CalculateNetPathEx(absoluteAppPath, 1000);
        variables[L"NETHASH1001"] = CalculateNetPathEx(absoluteAppPath, 1001);
        variables[L"NETHASH1002"] = CalculateNetPathEx(absoluteAppPath, 1002);
        variables[L"NETHASH1003"] = CalculateNetPathEx(absoluteAppPath, 1003);
        variables[L"NETHASH1004"] = CalculateNetPathEx(absoluteAppPath, 1004);
        variables[L"NETHASH1005"] = CalculateNetPathEx(absoluteAppPath, 1005);
        variables[L"NETHASH1006"] = CalculateNetPathEx(absoluteAppPath, 1006);
        variables[L"NETHASH1007"] = CalculateNetPathEx(absoluteAppPath, 1007);
        variables[L"NETHASH1008"] = CalculateNetPathEx(absoluteAppPath, 1008);
        variables[L"NETHASH1009"] = CalculateNetPathEx(absoluteAppPath, 1009);
        variables[L"NETHASH1010"] = CalculateNetPathEx(absoluteAppPath, 1010);
        variables[L"NETHASH1011"] = CalculateNetPathEx(absoluteAppPath, 1011);
        variables[L"NETHASH1012"] = CalculateNetPathEx(absoluteAppPath, 1012);
        variables[L"NETHASH1013"] = CalculateNetPathEx(absoluteAppPath, 1013);
        variables[L"NETHASH1014"] = CalculateNetPathEx(absoluteAppPath, 1014);
        variables[L"NETHASH1015"] = CalculateNetPathEx(absoluteAppPath, 1015);
        variables[L"NETHASH1016"] = CalculateNetPathEx(absoluteAppPath, 1016);
        variables[L"NETHASH1017"] = CalculateNetPathEx(absoluteAppPath, 1017);
        variables[L"NETHASH1018"] = CalculateNetPathEx(absoluteAppPath, 1018);
        variables[L"NETHASH1019"] = CalculateNetPathEx(absoluteAppPath, 1019);
        variables[L"NETHASH1020"] = CalculateNetPathEx(absoluteAppPath, 1020);
        variables[L"NETHASH1021"] = CalculateNetPathEx(absoluteAppPath, 1021);
        variables[L"NETHASH1022"] = CalculateNetPathEx(absoluteAppPath, 1022);
        variables[L"NETHASH1023"] = CalculateNetPathEx(absoluteAppPath, 1023);
        variables[L"NETHASH1024"] = CalculateNetPathEx(absoluteAppPath, 1024);
        variables[L"NETHASH1025"] = CalculateNetPathEx(absoluteAppPath, 1025);
        variables[L"NETHASH1026"] = CalculateNetPathEx(absoluteAppPath, 1026);
        variables[L"NETHASH1027"] = CalculateNetPathEx(absoluteAppPath, 1027);
        variables[L"NETHASH1028"] = CalculateNetPathEx(absoluteAppPath, 1028);
        variables[L"NETHASH1029"] = CalculateNetPathEx(absoluteAppPath, 1029);
        variables[L"NETHASH1030"] = CalculateNetPathEx(absoluteAppPath, 1030);
        variables[L"NETHASH1031"] = CalculateNetPathEx(absoluteAppPath, 1031);
        variables[L"NETHASH1032"] = CalculateNetPathEx(absoluteAppPath, 1032);
        variables[L"NETHASH1033"] = CalculateNetPathEx(absoluteAppPath, 1033);
        variables[L"NETHASH1034"] = CalculateNetPathEx(absoluteAppPath, 1034);
        variables[L"NETHASH1035"] = CalculateNetPathEx(absoluteAppPath, 1035);
        variables[L"NETHASH1036"] = CalculateNetPathEx(absoluteAppPath, 1036);
        variables[L"NETHASH1037"] = CalculateNetPathEx(absoluteAppPath, 1037);
        variables[L"NETHASH1038"] = CalculateNetPathEx(absoluteAppPath, 1038);
        variables[L"NETHASH1039"] = CalculateNetPathEx(absoluteAppPath, 1039);
        variables[L"NETHASH1040"] = CalculateNetPathEx(absoluteAppPath, 1040);
        variables[L"NETHASH1041"] = CalculateNetPathEx(absoluteAppPath, 1041);
        variables[L"NETHASH1042"] = CalculateNetPathEx(absoluteAppPath, 1042);
        variables[L"NETHASH1043"] = CalculateNetPathEx(absoluteAppPath, 1043);
        variables[L"NETHASH1044"] = CalculateNetPathEx(absoluteAppPath, 1044);
        variables[L"NETHASH1045"] = CalculateNetPathEx(absoluteAppPath, 1045);
        variables[L"NETHASH1046"] = CalculateNetPathEx(absoluteAppPath, 1046);
        variables[L"NETHASH1047"] = CalculateNetPathEx(absoluteAppPath, 1047);
        variables[L"NETHASH1048"] = CalculateNetPathEx(absoluteAppPath, 1048);
        variables[L"NETHASH1049"] = CalculateNetPathEx(absoluteAppPath, 1049);
        variables[L"NETHASH1050"] = CalculateNetPathEx(absoluteAppPath, 1050);
        variables[L"NETHASH1051"] = CalculateNetPathEx(absoluteAppPath, 1051);
        variables[L"NETHASH1052"] = CalculateNetPathEx(absoluteAppPath, 1052);
        variables[L"NETHASH1053"] = CalculateNetPathEx(absoluteAppPath, 1053);
        variables[L"NETHASH1054"] = CalculateNetPathEx(absoluteAppPath, 1054);
        variables[L"NETHASH1055"] = CalculateNetPathEx(absoluteAppPath, 1055);
        variables[L"NETHASH1056"] = CalculateNetPathEx(absoluteAppPath, 1056);
        variables[L"NETHASH1057"] = CalculateNetPathEx(absoluteAppPath, 1057);
        variables[L"NETHASH1058"] = CalculateNetPathEx(absoluteAppPath, 1058);
        variables[L"NETHASH1059"] = CalculateNetPathEx(absoluteAppPath, 1059);
        variables[L"NETHASH1060"] = CalculateNetPathEx(absoluteAppPath, 1060);
        variables[L"NETHASH1061"] = CalculateNetPathEx(absoluteAppPath, 1061);
        variables[L"NETHASH1062"] = CalculateNetPathEx(absoluteAppPath, 1062);
        variables[L"NETHASH1063"] = CalculateNetPathEx(absoluteAppPath, 1063);
        variables[L"NETHASH1064"] = CalculateNetPathEx(absoluteAppPath, 1064);
        variables[L"NETHASH1065"] = CalculateNetPathEx(absoluteAppPath, 1065);
        variables[L"NETHASH1066"] = CalculateNetPathEx(absoluteAppPath, 1066);
        variables[L"NETHASH1067"] = CalculateNetPathEx(absoluteAppPath, 1067);
        variables[L"NETHASH1068"] = CalculateNetPathEx(absoluteAppPath, 1068);
        variables[L"NETHASH1069"] = CalculateNetPathEx(absoluteAppPath, 1069);
        variables[L"NETHASH1070"] = CalculateNetPathEx(absoluteAppPath, 1070);
        variables[L"NETHASH1071"] = CalculateNetPathEx(absoluteAppPath, 1071);
        variables[L"NETHASH1072"] = CalculateNetPathEx(absoluteAppPath, 1072);
        variables[L"NETHASH1073"] = CalculateNetPathEx(absoluteAppPath, 1073);
        variables[L"NETHASH1074"] = CalculateNetPathEx(absoluteAppPath, 1074);
        variables[L"NETHASH1075"] = CalculateNetPathEx(absoluteAppPath, 1075);
        variables[L"NETHASH1076"] = CalculateNetPathEx(absoluteAppPath, 1076);
        variables[L"NETHASH1077"] = CalculateNetPathEx(absoluteAppPath, 1077);
        variables[L"NETHASH1078"] = CalculateNetPathEx(absoluteAppPath, 1078);
        variables[L"NETHASH1079"] = CalculateNetPathEx(absoluteAppPath, 1079);
        variables[L"NETHASH1080"] = CalculateNetPathEx(absoluteAppPath, 1080);
        variables[L"NETHASH1081"] = CalculateNetPathEx(absoluteAppPath, 1081);
        variables[L"NETHASH1082"] = CalculateNetPathEx(absoluteAppPath, 1082);
        variables[L"NETHASH1083"] = CalculateNetPathEx(absoluteAppPath, 1083);
        variables[L"NETHASH1084"] = CalculateNetPathEx(absoluteAppPath, 1084);
        variables[L"NETHASH1085"] = CalculateNetPathEx(absoluteAppPath, 1085);
        variables[L"NETHASH1086"] = CalculateNetPathEx(absoluteAppPath, 1086);
        variables[L"NETHASH1087"] = CalculateNetPathEx(absoluteAppPath, 1087);
        variables[L"NETHASH1088"] = CalculateNetPathEx(absoluteAppPath, 1088);
        variables[L"NETHASH1089"] = CalculateNetPathEx(absoluteAppPath, 1089);
        variables[L"NETHASH1090"] = CalculateNetPathEx(absoluteAppPath, 1090);
        variables[L"NETHASH1091"] = CalculateNetPathEx(absoluteAppPath, 1091);
        variables[L"NETHASH1092"] = CalculateNetPathEx(absoluteAppPath, 1092);
        variables[L"NETHASH1093"] = CalculateNetPathEx(absoluteAppPath, 1093);
        variables[L"NETHASH1094"] = CalculateNetPathEx(absoluteAppPath, 1094);
        variables[L"NETHASH1095"] = CalculateNetPathEx(absoluteAppPath, 1095);
        variables[L"NETHASH1096"] = CalculateNetPathEx(absoluteAppPath, 1096);
        variables[L"NETHASH1097"] = CalculateNetPathEx(absoluteAppPath, 1097);
        variables[L"NETHASH1098"] = CalculateNetPathEx(absoluteAppPath, 1098);
        variables[L"NETHASH1099"] = CalculateNetPathEx(absoluteAppPath, 1099);
        variables[L"NETHASH1100"] = CalculateNetPathEx(absoluteAppPath, 1100);
        variables[L"NETHASH1101"] = CalculateNetPathEx(absoluteAppPath, 1101);
        variables[L"NETHASH1102"] = CalculateNetPathEx(absoluteAppPath, 1102);
        variables[L"NETHASH1103"] = CalculateNetPathEx(absoluteAppPath, 1103);
        variables[L"NETHASH1104"] = CalculateNetPathEx(absoluteAppPath, 1104);
        variables[L"NETHASH1105"] = CalculateNetPathEx(absoluteAppPath, 1105);
        variables[L"NETHASH1106"] = CalculateNetPathEx(absoluteAppPath, 1106);
        variables[L"NETHASH1107"] = CalculateNetPathEx(absoluteAppPath, 1107);
        variables[L"NETHASH1108"] = CalculateNetPathEx(absoluteAppPath, 1108);
        variables[L"NETHASH1109"] = CalculateNetPathEx(absoluteAppPath, 1109);
        variables[L"NETHASH1110"] = CalculateNetPathEx(absoluteAppPath, 1110);
        variables[L"NETHASH1111"] = CalculateNetPathEx(absoluteAppPath, 1111);
        variables[L"NETHASH1112"] = CalculateNetPathEx(absoluteAppPath, 1112);
        variables[L"NETHASH1113"] = CalculateNetPathEx(absoluteAppPath, 1113);
        variables[L"NETHASH1114"] = CalculateNetPathEx(absoluteAppPath, 1114);
        variables[L"NETHASH1115"] = CalculateNetPathEx(absoluteAppPath, 1115);
        variables[L"NETHASH1116"] = CalculateNetPathEx(absoluteAppPath, 1116);
        variables[L"NETHASH1117"] = CalculateNetPathEx(absoluteAppPath, 1117);
        variables[L"NETHASH1118"] = CalculateNetPathEx(absoluteAppPath, 1118);
        variables[L"NETHASH1119"] = CalculateNetPathEx(absoluteAppPath, 1119);
        variables[L"NETHASH1120"] = CalculateNetPathEx(absoluteAppPath, 1120);
        variables[L"NETHASH1121"] = CalculateNetPathEx(absoluteAppPath, 1121);
        variables[L"NETHASH1122"] = CalculateNetPathEx(absoluteAppPath, 1122);
        variables[L"NETHASH1123"] = CalculateNetPathEx(absoluteAppPath, 1123);
        variables[L"NETHASH1124"] = CalculateNetPathEx(absoluteAppPath, 1124);
        variables[L"NETHASH1125"] = CalculateNetPathEx(absoluteAppPath, 1125);
        variables[L"NETHASH1126"] = CalculateNetPathEx(absoluteAppPath, 1126);
        variables[L"NETHASH1127"] = CalculateNetPathEx(absoluteAppPath, 1127);
        variables[L"NETHASH1128"] = CalculateNetPathEx(absoluteAppPath, 1128);
        variables[L"NETHASH1129"] = CalculateNetPathEx(absoluteAppPath, 1129);
        variables[L"NETHASH1130"] = CalculateNetPathEx(absoluteAppPath, 1130);
        variables[L"NETHASH1131"] = CalculateNetPathEx(absoluteAppPath, 1131);
        variables[L"NETHASH1132"] = CalculateNetPathEx(absoluteAppPath, 1132);
        variables[L"NETHASH1133"] = CalculateNetPathEx(absoluteAppPath, 1133);
        variables[L"NETHASH1134"] = CalculateNetPathEx(absoluteAppPath, 1134);
        variables[L"NETHASH1135"] = CalculateNetPathEx(absoluteAppPath, 1135);
        variables[L"NETHASH1136"] = CalculateNetPathEx(absoluteAppPath, 1136);
        variables[L"NETHASH1137"] = CalculateNetPathEx(absoluteAppPath, 1137);
        variables[L"NETHASH1138"] = CalculateNetPathEx(absoluteAppPath, 1138);
        variables[L"NETHASH1139"] = CalculateNetPathEx(absoluteAppPath, 1139);
        variables[L"NETHASH1140"] = CalculateNetPathEx(absoluteAppPath, 1140);
        variables[L"NETHASH1141"] = CalculateNetPathEx(absoluteAppPath, 1141);
        variables[L"NETHASH1142"] = CalculateNetPathEx(absoluteAppPath, 1142);
        variables[L"NETHASH1143"] = CalculateNetPathEx(absoluteAppPath, 1143);
        variables[L"NETHASH1144"] = CalculateNetPathEx(absoluteAppPath, 1144);
        variables[L"NETHASH1145"] = CalculateNetPathEx(absoluteAppPath, 1145);
        variables[L"NETHASH1146"] = CalculateNetPathEx(absoluteAppPath, 1146);
        variables[L"NETHASH1147"] = CalculateNetPathEx(absoluteAppPath, 1147);
        variables[L"NETHASH1148"] = CalculateNetPathEx(absoluteAppPath, 1148);
        variables[L"NETHASH1149"] = CalculateNetPathEx(absoluteAppPath, 1149);
        variables[L"NETHASH1150"] = CalculateNetPathEx(absoluteAppPath, 1150);
        variables[L"NETHASH1151"] = CalculateNetPathEx(absoluteAppPath, 1151);
        variables[L"NETHASH1152"] = CalculateNetPathEx(absoluteAppPath, 1152);
        variables[L"NETHASH1153"] = CalculateNetPathEx(absoluteAppPath, 1153);
        variables[L"NETHASH1154"] = CalculateNetPathEx(absoluteAppPath, 1154);
        variables[L"NETHASH1155"] = CalculateNetPathEx(absoluteAppPath, 1155);
        variables[L"NETHASH1156"] = CalculateNetPathEx(absoluteAppPath, 1156);
        variables[L"NETHASH1157"] = CalculateNetPathEx(absoluteAppPath, 1157);
        variables[L"NETHASH1158"] = CalculateNetPathEx(absoluteAppPath, 1158);
        variables[L"NETHASH1159"] = CalculateNetPathEx(absoluteAppPath, 1159);
        variables[L"NETHASH1160"] = CalculateNetPathEx(absoluteAppPath, 1160);
        variables[L"NETHASH1161"] = CalculateNetPathEx(absoluteAppPath, 1161);
        variables[L"NETHASH1162"] = CalculateNetPathEx(absoluteAppPath, 1162);
        variables[L"NETHASH1163"] = CalculateNetPathEx(absoluteAppPath, 1163);
        variables[L"NETHASH1164"] = CalculateNetPathEx(absoluteAppPath, 1164);
        variables[L"NETHASH1165"] = CalculateNetPathEx(absoluteAppPath, 1165);
        variables[L"NETHASH1166"] = CalculateNetPathEx(absoluteAppPath, 1166);
        variables[L"NETHASH1167"] = CalculateNetPathEx(absoluteAppPath, 1167);
        variables[L"NETHASH1168"] = CalculateNetPathEx(absoluteAppPath, 1168);
        variables[L"NETHASH1169"] = CalculateNetPathEx(absoluteAppPath, 1169);
        variables[L"NETHASH1170"] = CalculateNetPathEx(absoluteAppPath, 1170);
        variables[L"NETHASH1171"] = CalculateNetPathEx(absoluteAppPath, 1171);
        variables[L"NETHASH1172"] = CalculateNetPathEx(absoluteAppPath, 1172);
        variables[L"NETHASH1173"] = CalculateNetPathEx(absoluteAppPath, 1173);
        variables[L"NETHASH1174"] = CalculateNetPathEx(absoluteAppPath, 1174);
        variables[L"NETHASH1175"] = CalculateNetPathEx(absoluteAppPath, 1175);
        variables[L"NETHASH1176"] = CalculateNetPathEx(absoluteAppPath, 1176);
        variables[L"NETHASH1177"] = CalculateNetPathEx(absoluteAppPath, 1177);
        variables[L"NETHASH1178"] = CalculateNetPathEx(absoluteAppPath, 1178);
        variables[L"NETHASH1179"] = CalculateNetPathEx(absoluteAppPath, 1179);
        variables[L"NETHASH1180"] = CalculateNetPathEx(absoluteAppPath, 1180);
        variables[L"NETHASH1181"] = CalculateNetPathEx(absoluteAppPath, 1181);
        variables[L"NETHASH1182"] = CalculateNetPathEx(absoluteAppPath, 1182);
        variables[L"NETHASH1183"] = CalculateNetPathEx(absoluteAppPath, 1183);
        variables[L"NETHASH1184"] = CalculateNetPathEx(absoluteAppPath, 1184);
        variables[L"NETHASH1185"] = CalculateNetPathEx(absoluteAppPath, 1185);
        variables[L"NETHASH1186"] = CalculateNetPathEx(absoluteAppPath, 1186);
        variables[L"NETHASH1187"] = CalculateNetPathEx(absoluteAppPath, 1187);
        variables[L"NETHASH1188"] = CalculateNetPathEx(absoluteAppPath, 1188);
        variables[L"NETHASH1189"] = CalculateNetPathEx(absoluteAppPath, 1189);
        variables[L"NETHASH1190"] = CalculateNetPathEx(absoluteAppPath, 1190);
        variables[L"NETHASH1191"] = CalculateNetPathEx(absoluteAppPath, 1191);
        variables[L"NETHASH1192"] = CalculateNetPathEx(absoluteAppPath, 1192);
        variables[L"NETHASH1193"] = CalculateNetPathEx(absoluteAppPath, 1193);
        variables[L"NETHASH1194"] = CalculateNetPathEx(absoluteAppPath, 1194);
        variables[L"NETHASH1195"] = CalculateNetPathEx(absoluteAppPath, 1195);
        variables[L"NETHASH1196"] = CalculateNetPathEx(absoluteAppPath, 1196);
        variables[L"NETHASH1197"] = CalculateNetPathEx(absoluteAppPath, 1197);
        variables[L"NETHASH1198"] = CalculateNetPathEx(absoluteAppPath, 1198);
        variables[L"NETHASH1199"] = CalculateNetPathEx(absoluteAppPath, 1199);
        variables[L"NETHASH1200"] = CalculateNetPathEx(absoluteAppPath, 1200);
        variables[L"NETHASH1201"] = CalculateNetPathEx(absoluteAppPath, 1201);
        variables[L"NETHASH1202"] = CalculateNetPathEx(absoluteAppPath, 1202);
        variables[L"NETHASH1203"] = CalculateNetPathEx(absoluteAppPath, 1203);
        variables[L"NETHASH1204"] = CalculateNetPathEx(absoluteAppPath, 1204);
        variables[L"NETHASH1205"] = CalculateNetPathEx(absoluteAppPath, 1205);
        variables[L"NETHASH1206"] = CalculateNetPathEx(absoluteAppPath, 1206);
        variables[L"NETHASH1207"] = CalculateNetPathEx(absoluteAppPath, 1207);
        variables[L"NETHASH1208"] = CalculateNetPathEx(absoluteAppPath, 1208);
        variables[L"NETHASH1209"] = CalculateNetPathEx(absoluteAppPath, 1209);
        variables[L"NETHASH1210"] = CalculateNetPathEx(absoluteAppPath, 1210);
        variables[L"NETHASH1211"] = CalculateNetPathEx(absoluteAppPath, 1211);
        variables[L"NETHASH1212"] = CalculateNetPathEx(absoluteAppPath, 1212);
        variables[L"NETHASH1213"] = CalculateNetPathEx(absoluteAppPath, 1213);
        variables[L"NETHASH1214"] = CalculateNetPathEx(absoluteAppPath, 1214);
        variables[L"NETHASH1215"] = CalculateNetPathEx(absoluteAppPath, 1215);
        variables[L"NETHASH1216"] = CalculateNetPathEx(absoluteAppPath, 1216);
        variables[L"NETHASH1217"] = CalculateNetPathEx(absoluteAppPath, 1217);
        variables[L"NETHASH1218"] = CalculateNetPathEx(absoluteAppPath, 1218);
        variables[L"NETHASH1219"] = CalculateNetPathEx(absoluteAppPath, 1219);
        variables[L"NETHASH1220"] = CalculateNetPathEx(absoluteAppPath, 1220);
        variables[L"NETHASH1221"] = CalculateNetPathEx(absoluteAppPath, 1221);
        variables[L"NETHASH1222"] = CalculateNetPathEx(absoluteAppPath, 1222);
        variables[L"NETHASH1223"] = CalculateNetPathEx(absoluteAppPath, 1223);
        variables[L"NETHASH1224"] = CalculateNetPathEx(absoluteAppPath, 1224);
        variables[L"NETHASH1225"] = CalculateNetPathEx(absoluteAppPath, 1225);
        variables[L"NETHASH1226"] = CalculateNetPathEx(absoluteAppPath, 1226);
        variables[L"NETHASH1227"] = CalculateNetPathEx(absoluteAppPath, 1227);
        variables[L"NETHASH1228"] = CalculateNetPathEx(absoluteAppPath, 1228);
        variables[L"NETHASH1229"] = CalculateNetPathEx(absoluteAppPath, 1229);
        variables[L"NETHASH1230"] = CalculateNetPathEx(absoluteAppPath, 1230);
        variables[L"NETHASH1231"] = CalculateNetPathEx(absoluteAppPath, 1231);
        variables[L"NETHASH1232"] = CalculateNetPathEx(absoluteAppPath, 1232);
        variables[L"NETHASH1233"] = CalculateNetPathEx(absoluteAppPath, 1233);
        variables[L"NETHASH1234"] = CalculateNetPathEx(absoluteAppPath, 1234);
        variables[L"NETHASH1235"] = CalculateNetPathEx(absoluteAppPath, 1235);
        variables[L"NETHASH1236"] = CalculateNetPathEx(absoluteAppPath, 1236);
        variables[L"NETHASH1237"] = CalculateNetPathEx(absoluteAppPath, 1237);
        variables[L"NETHASH1238"] = CalculateNetPathEx(absoluteAppPath, 1238);
        variables[L"NETHASH1239"] = CalculateNetPathEx(absoluteAppPath, 1239);
        variables[L"NETHASH1240"] = CalculateNetPathEx(absoluteAppPath, 1240);
        variables[L"NETHASH1241"] = CalculateNetPathEx(absoluteAppPath, 1241);
        variables[L"NETHASH1242"] = CalculateNetPathEx(absoluteAppPath, 1242);
        variables[L"NETHASH1243"] = CalculateNetPathEx(absoluteAppPath, 1243);
        variables[L"NETHASH1244"] = CalculateNetPathEx(absoluteAppPath, 1244);
        variables[L"NETHASH1245"] = CalculateNetPathEx(absoluteAppPath, 1245);
        variables[L"NETHASH1246"] = CalculateNetPathEx(absoluteAppPath, 1246);
        variables[L"NETHASH1247"] = CalculateNetPathEx(absoluteAppPath, 1247);
        variables[L"NETHASH1248"] = CalculateNetPathEx(absoluteAppPath, 1248);
        variables[L"NETHASH1249"] = CalculateNetPathEx(absoluteAppPath, 1249);
        variables[L"NETHASH1250"] = CalculateNetPathEx(absoluteAppPath, 1250);
        variables[L"NETHASH1251"] = CalculateNetPathEx(absoluteAppPath, 1251);
        variables[L"NETHASH1252"] = CalculateNetPathEx(absoluteAppPath, 1252);
        variables[L"NETHASH1253"] = CalculateNetPathEx(absoluteAppPath, 1253);
        variables[L"NETHASH1254"] = CalculateNetPathEx(absoluteAppPath, 1254);
        variables[L"NETHASH1255"] = CalculateNetPathEx(absoluteAppPath, 1255);
        variables[L"NETHASH1256"] = CalculateNetPathEx(absoluteAppPath, 1256);
        variables[L"NETHASH1257"] = CalculateNetPathEx(absoluteAppPath, 1257);
        variables[L"NETHASH1258"] = CalculateNetPathEx(absoluteAppPath, 1258);
        variables[L"NETHASH1259"] = CalculateNetPathEx(absoluteAppPath, 1259);
        variables[L"NETHASH1260"] = CalculateNetPathEx(absoluteAppPath, 1260);
        variables[L"NETHASH1261"] = CalculateNetPathEx(absoluteAppPath, 1261);
        variables[L"NETHASH1262"] = CalculateNetPathEx(absoluteAppPath, 1262);
        variables[L"NETHASH1263"] = CalculateNetPathEx(absoluteAppPath, 1263);
        variables[L"NETHASH1264"] = CalculateNetPathEx(absoluteAppPath, 1264);
        variables[L"NETHASH1265"] = CalculateNetPathEx(absoluteAppPath, 1265);
        variables[L"NETHASH1266"] = CalculateNetPathEx(absoluteAppPath, 1266);
        variables[L"NETHASH1267"] = CalculateNetPathEx(absoluteAppPath, 1267);
        variables[L"NETHASH1268"] = CalculateNetPathEx(absoluteAppPath, 1268);
        variables[L"NETHASH1269"] = CalculateNetPathEx(absoluteAppPath, 1269);
        variables[L"NETHASH1270"] = CalculateNetPathEx(absoluteAppPath, 1270);
        variables[L"NETHASH1271"] = CalculateNetPathEx(absoluteAppPath, 1271);
        variables[L"NETHASH1272"] = CalculateNetPathEx(absoluteAppPath, 1272);
        variables[L"NETHASH1273"] = CalculateNetPathEx(absoluteAppPath, 1273);
        variables[L"NETHASH1274"] = CalculateNetPathEx(absoluteAppPath, 1274);
        variables[L"NETHASH1275"] = CalculateNetPathEx(absoluteAppPath, 1275);
        variables[L"NETHASH1276"] = CalculateNetPathEx(absoluteAppPath, 1276);
        variables[L"NETHASH1277"] = CalculateNetPathEx(absoluteAppPath, 1277);
        variables[L"NETHASH1278"] = CalculateNetPathEx(absoluteAppPath, 1278);
        variables[L"NETHASH1279"] = CalculateNetPathEx(absoluteAppPath, 1279);
        variables[L"NETHASH1280"] = CalculateNetPathEx(absoluteAppPath, 1280);
        variables[L"NETHASH1281"] = CalculateNetPathEx(absoluteAppPath, 1281);
        variables[L"NETHASH1282"] = CalculateNetPathEx(absoluteAppPath, 1282);
        variables[L"NETHASH1283"] = CalculateNetPathEx(absoluteAppPath, 1283);
        variables[L"NETHASH1284"] = CalculateNetPathEx(absoluteAppPath, 1284);
        variables[L"NETHASH1285"] = CalculateNetPathEx(absoluteAppPath, 1285);
        variables[L"NETHASH1286"] = CalculateNetPathEx(absoluteAppPath, 1286);
        variables[L"NETHASH1287"] = CalculateNetPathEx(absoluteAppPath, 1287);
        variables[L"NETHASH1288"] = CalculateNetPathEx(absoluteAppPath, 1288);
        variables[L"NETHASH1289"] = CalculateNetPathEx(absoluteAppPath, 1289);
        variables[L"NETHASH1290"] = CalculateNetPathEx(absoluteAppPath, 1290);
        variables[L"NETHASH1291"] = CalculateNetPathEx(absoluteAppPath, 1291);
        variables[L"NETHASH1292"] = CalculateNetPathEx(absoluteAppPath, 1292);
        variables[L"NETHASH1293"] = CalculateNetPathEx(absoluteAppPath, 1293);
        variables[L"NETHASH1294"] = CalculateNetPathEx(absoluteAppPath, 1294);
        variables[L"NETHASH1295"] = CalculateNetPathEx(absoluteAppPath, 1295);
        variables[L"NETHASH1296"] = CalculateNetPathEx(absoluteAppPath, 1296);
        variables[L"NETHASH1297"] = CalculateNetPathEx(absoluteAppPath, 1297);
        variables[L"NETHASH1298"] = CalculateNetPathEx(absoluteAppPath, 1298);
        variables[L"NETHASH1299"] = CalculateNetPathEx(absoluteAppPath, 1299);
        variables[L"NETHASH1300"] = CalculateNetPathEx(absoluteAppPath, 1300);
        variables[L"NETHASH1301"] = CalculateNetPathEx(absoluteAppPath, 1301);
        variables[L"NETHASH1302"] = CalculateNetPathEx(absoluteAppPath, 1302);
        variables[L"NETHASH1303"] = CalculateNetPathEx(absoluteAppPath, 1303);
        variables[L"NETHASH1304"] = CalculateNetPathEx(absoluteAppPath, 1304);
        variables[L"NETHASH1305"] = CalculateNetPathEx(absoluteAppPath, 1305);
        variables[L"NETHASH1306"] = CalculateNetPathEx(absoluteAppPath, 1306);
        variables[L"NETHASH1307"] = CalculateNetPathEx(absoluteAppPath, 1307);
        variables[L"NETHASH1308"] = CalculateNetPathEx(absoluteAppPath, 1308);
        variables[L"NETHASH1309"] = CalculateNetPathEx(absoluteAppPath, 1309);
        variables[L"NETHASH1310"] = CalculateNetPathEx(absoluteAppPath, 1310);
        variables[L"NETHASH1311"] = CalculateNetPathEx(absoluteAppPath, 1311);
        variables[L"NETHASH1312"] = CalculateNetPathEx(absoluteAppPath, 1312);
        variables[L"NETHASH1313"] = CalculateNetPathEx(absoluteAppPath, 1313);
        variables[L"NETHASH1314"] = CalculateNetPathEx(absoluteAppPath, 1314);
        variables[L"NETHASH1315"] = CalculateNetPathEx(absoluteAppPath, 1315);
        variables[L"NETHASH1316"] = CalculateNetPathEx(absoluteAppPath, 1316);
        variables[L"NETHASH1317"] = CalculateNetPathEx(absoluteAppPath, 1317);
        variables[L"NETHASH1318"] = CalculateNetPathEx(absoluteAppPath, 1318);
        variables[L"NETHASH1319"] = CalculateNetPathEx(absoluteAppPath, 1319);
        variables[L"NETHASH1320"] = CalculateNetPathEx(absoluteAppPath, 1320);
        variables[L"NETHASH1321"] = CalculateNetPathEx(absoluteAppPath, 1321);
        variables[L"NETHASH1322"] = CalculateNetPathEx(absoluteAppPath, 1322);
        variables[L"NETHASH1323"] = CalculateNetPathEx(absoluteAppPath, 1323);
        variables[L"NETHASH1324"] = CalculateNetPathEx(absoluteAppPath, 1324);
        variables[L"NETHASH1325"] = CalculateNetPathEx(absoluteAppPath, 1325);
        variables[L"NETHASH1326"] = CalculateNetPathEx(absoluteAppPath, 1326);
        variables[L"NETHASH1327"] = CalculateNetPathEx(absoluteAppPath, 1327);
        variables[L"NETHASH1328"] = CalculateNetPathEx(absoluteAppPath, 1328);
        variables[L"NETHASH1329"] = CalculateNetPathEx(absoluteAppPath, 1329);
        variables[L"NETHASH1330"] = CalculateNetPathEx(absoluteAppPath, 1330);
        variables[L"NETHASH1331"] = CalculateNetPathEx(absoluteAppPath, 1331);
        variables[L"NETHASH1332"] = CalculateNetPathEx(absoluteAppPath, 1332);
        variables[L"NETHASH1333"] = CalculateNetPathEx(absoluteAppPath, 1333);
        variables[L"NETHASH1334"] = CalculateNetPathEx(absoluteAppPath, 1334);
        variables[L"NETHASH1335"] = CalculateNetPathEx(absoluteAppPath, 1335);
        variables[L"NETHASH1336"] = CalculateNetPathEx(absoluteAppPath, 1336);
        variables[L"NETHASH1337"] = CalculateNetPathEx(absoluteAppPath, 1337);
        variables[L"NETHASH1338"] = CalculateNetPathEx(absoluteAppPath, 1338);
        variables[L"NETHASH1339"] = CalculateNetPathEx(absoluteAppPath, 1339);
        variables[L"NETHASH1340"] = CalculateNetPathEx(absoluteAppPath, 1340);
        variables[L"NETHASH1341"] = CalculateNetPathEx(absoluteAppPath, 1341);
        variables[L"NETHASH1342"] = CalculateNetPathEx(absoluteAppPath, 1342);
        variables[L"NETHASH1343"] = CalculateNetPathEx(absoluteAppPath, 1343);
        variables[L"NETHASH1344"] = CalculateNetPathEx(absoluteAppPath, 1344);
        variables[L"NETHASH1345"] = CalculateNetPathEx(absoluteAppPath, 1345);
        variables[L"NETHASH1346"] = CalculateNetPathEx(absoluteAppPath, 1346);
        variables[L"NETHASH1347"] = CalculateNetPathEx(absoluteAppPath, 1347);
        variables[L"NETHASH1348"] = CalculateNetPathEx(absoluteAppPath, 1348);
        variables[L"NETHASH1349"] = CalculateNetPathEx(absoluteAppPath, 1349);
        variables[L"NETHASH1350"] = CalculateNetPathEx(absoluteAppPath, 1350);
        variables[L"NETHASH1351"] = CalculateNetPathEx(absoluteAppPath, 1351);
        variables[L"NETHASH1352"] = CalculateNetPathEx(absoluteAppPath, 1352);
        variables[L"NETHASH1353"] = CalculateNetPathEx(absoluteAppPath, 1353);
        variables[L"NETHASH1354"] = CalculateNetPathEx(absoluteAppPath, 1354);
        variables[L"NETHASH1355"] = CalculateNetPathEx(absoluteAppPath, 1355);
        variables[L"NETHASH1356"] = CalculateNetPathEx(absoluteAppPath, 1356);
        variables[L"NETHASH1357"] = CalculateNetPathEx(absoluteAppPath, 1357);
        variables[L"NETHASH1358"] = CalculateNetPathEx(absoluteAppPath, 1358);
        variables[L"NETHASH1359"] = CalculateNetPathEx(absoluteAppPath, 1359);
        variables[L"NETHASH1360"] = CalculateNetPathEx(absoluteAppPath, 1360);
        variables[L"NETHASH1361"] = CalculateNetPathEx(absoluteAppPath, 1361);
        variables[L"NETHASH1362"] = CalculateNetPathEx(absoluteAppPath, 1362);
        variables[L"NETHASH1363"] = CalculateNetPathEx(absoluteAppPath, 1363);
        variables[L"NETHASH1364"] = CalculateNetPathEx(absoluteAppPath, 1364);
        variables[L"NETHASH1365"] = CalculateNetPathEx(absoluteAppPath, 1365);
        variables[L"NETHASH1366"] = CalculateNetPathEx(absoluteAppPath, 1366);
        variables[L"NETHASH1367"] = CalculateNetPathEx(absoluteAppPath, 1367);
        variables[L"NETHASH1368"] = CalculateNetPathEx(absoluteAppPath, 1368);
        variables[L"NETHASH1369"] = CalculateNetPathEx(absoluteAppPath, 1369);
        variables[L"NETHASH1370"] = CalculateNetPathEx(absoluteAppPath, 1370);
        variables[L"NETHASH1371"] = CalculateNetPathEx(absoluteAppPath, 1371);
        variables[L"NETHASH1372"] = CalculateNetPathEx(absoluteAppPath, 1372);
        variables[L"NETHASH1373"] = CalculateNetPathEx(absoluteAppPath, 1373);
        variables[L"NETHASH1374"] = CalculateNetPathEx(absoluteAppPath, 1374);
        variables[L"NETHASH1375"] = CalculateNetPathEx(absoluteAppPath, 1375);
        variables[L"NETHASH1376"] = CalculateNetPathEx(absoluteAppPath, 1376);
        variables[L"NETHASH1377"] = CalculateNetPathEx(absoluteAppPath, 1377);
        variables[L"NETHASH1378"] = CalculateNetPathEx(absoluteAppPath, 1378);
        variables[L"NETHASH1379"] = CalculateNetPathEx(absoluteAppPath, 1379);
        variables[L"NETHASH1380"] = CalculateNetPathEx(absoluteAppPath, 1380);
        variables[L"NETHASH1381"] = CalculateNetPathEx(absoluteAppPath, 1381);
        variables[L"NETHASH1382"] = CalculateNetPathEx(absoluteAppPath, 1382);
        variables[L"NETHASH1383"] = CalculateNetPathEx(absoluteAppPath, 1383);
        variables[L"NETHASH1384"] = CalculateNetPathEx(absoluteAppPath, 1384);
        variables[L"NETHASH1385"] = CalculateNetPathEx(absoluteAppPath, 1385);
        variables[L"NETHASH1386"] = CalculateNetPathEx(absoluteAppPath, 1386);
        variables[L"NETHASH1387"] = CalculateNetPathEx(absoluteAppPath, 1387);
        variables[L"NETHASH1388"] = CalculateNetPathEx(absoluteAppPath, 1388);
        variables[L"NETHASH1389"] = CalculateNetPathEx(absoluteAppPath, 1389);
        variables[L"NETHASH1390"] = CalculateNetPathEx(absoluteAppPath, 1390);
        variables[L"NETHASH1391"] = CalculateNetPathEx(absoluteAppPath, 1391);
        variables[L"NETHASH1392"] = CalculateNetPathEx(absoluteAppPath, 1392);
        variables[L"NETHASH1393"] = CalculateNetPathEx(absoluteAppPath, 1393);
        variables[L"NETHASH1394"] = CalculateNetPathEx(absoluteAppPath, 1394);
        variables[L"NETHASH1395"] = CalculateNetPathEx(absoluteAppPath, 1395);
        variables[L"NETHASH1396"] = CalculateNetPathEx(absoluteAppPath, 1396);
        variables[L"NETHASH1397"] = CalculateNetPathEx(absoluteAppPath, 1397);
        variables[L"NETHASH1398"] = CalculateNetPathEx(absoluteAppPath, 1398);
        variables[L"NETHASH1399"] = CalculateNetPathEx(absoluteAppPath, 1399);
        variables[L"NETHASH1400"] = CalculateNetPathEx(absoluteAppPath, 1400);
        variables[L"NETHASH1401"] = CalculateNetPathEx(absoluteAppPath, 1401);
        variables[L"NETHASH1402"] = CalculateNetPathEx(absoluteAppPath, 1402);
        variables[L"NETHASH1403"] = CalculateNetPathEx(absoluteAppPath, 1403);
        variables[L"NETHASH1404"] = CalculateNetPathEx(absoluteAppPath, 1404);
        variables[L"NETHASH1405"] = CalculateNetPathEx(absoluteAppPath, 1405);
        variables[L"NETHASH1406"] = CalculateNetPathEx(absoluteAppPath, 1406);
        variables[L"NETHASH1407"] = CalculateNetPathEx(absoluteAppPath, 1407);
        variables[L"NETHASH1408"] = CalculateNetPathEx(absoluteAppPath, 1408);
        variables[L"NETHASH1409"] = CalculateNetPathEx(absoluteAppPath, 1409);
        variables[L"NETHASH1410"] = CalculateNetPathEx(absoluteAppPath, 1410);
        variables[L"NETHASH1411"] = CalculateNetPathEx(absoluteAppPath, 1411);
        variables[L"NETHASH1412"] = CalculateNetPathEx(absoluteAppPath, 1412);
        variables[L"NETHASH1413"] = CalculateNetPathEx(absoluteAppPath, 1413);
        variables[L"NETHASH1414"] = CalculateNetPathEx(absoluteAppPath, 1414);
        variables[L"NETHASH1415"] = CalculateNetPathEx(absoluteAppPath, 1415);
        variables[L"NETHASH1416"] = CalculateNetPathEx(absoluteAppPath, 1416);
        variables[L"NETHASH1417"] = CalculateNetPathEx(absoluteAppPath, 1417);
        variables[L"NETHASH1418"] = CalculateNetPathEx(absoluteAppPath, 1418);
        variables[L"NETHASH1419"] = CalculateNetPathEx(absoluteAppPath, 1419);
        variables[L"NETHASH1420"] = CalculateNetPathEx(absoluteAppPath, 1420);
        variables[L"NETHASH1421"] = CalculateNetPathEx(absoluteAppPath, 1421);
        variables[L"NETHASH1422"] = CalculateNetPathEx(absoluteAppPath, 1422);
        variables[L"NETHASH1423"] = CalculateNetPathEx(absoluteAppPath, 1423);
        variables[L"NETHASH1424"] = CalculateNetPathEx(absoluteAppPath, 1424);
        variables[L"NETHASH1425"] = CalculateNetPathEx(absoluteAppPath, 1425);
        variables[L"NETHASH1426"] = CalculateNetPathEx(absoluteAppPath, 1426);
        variables[L"NETHASH1427"] = CalculateNetPathEx(absoluteAppPath, 1427);
        variables[L"NETHASH1428"] = CalculateNetPathEx(absoluteAppPath, 1428);
        variables[L"NETHASH1429"] = CalculateNetPathEx(absoluteAppPath, 1429);
        variables[L"NETHASH1430"] = CalculateNetPathEx(absoluteAppPath, 1430);
        variables[L"NETHASH1431"] = CalculateNetPathEx(absoluteAppPath, 1431);
        variables[L"NETHASH1432"] = CalculateNetPathEx(absoluteAppPath, 1432);
        variables[L"NETHASH1433"] = CalculateNetPathEx(absoluteAppPath, 1433);
        variables[L"NETHASH1434"] = CalculateNetPathEx(absoluteAppPath, 1434);
        variables[L"NETHASH1435"] = CalculateNetPathEx(absoluteAppPath, 1435);
        variables[L"NETHASH1436"] = CalculateNetPathEx(absoluteAppPath, 1436);
        variables[L"NETHASH1437"] = CalculateNetPathEx(absoluteAppPath, 1437);
        variables[L"NETHASH1438"] = CalculateNetPathEx(absoluteAppPath, 1438);
        variables[L"NETHASH1439"] = CalculateNetPathEx(absoluteAppPath, 1439);
        variables[L"NETHASH1440"] = CalculateNetPathEx(absoluteAppPath, 1440);
        variables[L"NETHASH1441"] = CalculateNetPathEx(absoluteAppPath, 1441);
        variables[L"NETHASH1442"] = CalculateNetPathEx(absoluteAppPath, 1442);
        variables[L"NETHASH1443"] = CalculateNetPathEx(absoluteAppPath, 1443);
        variables[L"NETHASH1444"] = CalculateNetPathEx(absoluteAppPath, 1444);
        variables[L"NETHASH1445"] = CalculateNetPathEx(absoluteAppPath, 1445);
        variables[L"NETHASH1446"] = CalculateNetPathEx(absoluteAppPath, 1446);
        variables[L"NETHASH1447"] = CalculateNetPathEx(absoluteAppPath, 1447);
        variables[L"NETHASH1448"] = CalculateNetPathEx(absoluteAppPath, 1448);
        variables[L"NETHASH1449"] = CalculateNetPathEx(absoluteAppPath, 1449);
        variables[L"NETHASH1450"] = CalculateNetPathEx(absoluteAppPath, 1450);
        variables[L"NETHASH1451"] = CalculateNetPathEx(absoluteAppPath, 1451);
        variables[L"NETHASH1452"] = CalculateNetPathEx(absoluteAppPath, 1452);
        variables[L"NETHASH1453"] = CalculateNetPathEx(absoluteAppPath, 1453);
        variables[L"NETHASH1454"] = CalculateNetPathEx(absoluteAppPath, 1454);
        variables[L"NETHASH1455"] = CalculateNetPathEx(absoluteAppPath, 1455);
        variables[L"NETHASH1456"] = CalculateNetPathEx(absoluteAppPath, 1456);
        variables[L"NETHASH1457"] = CalculateNetPathEx(absoluteAppPath, 1457);
        variables[L"NETHASH1458"] = CalculateNetPathEx(absoluteAppPath, 1458);
        variables[L"NETHASH1459"] = CalculateNetPathEx(absoluteAppPath, 1459);
        variables[L"NETHASH1460"] = CalculateNetPathEx(absoluteAppPath, 1460);
        variables[L"NETHASH1461"] = CalculateNetPathEx(absoluteAppPath, 1461);
        variables[L"NETHASH1462"] = CalculateNetPathEx(absoluteAppPath, 1462);
        variables[L"NETHASH1463"] = CalculateNetPathEx(absoluteAppPath, 1463);
        variables[L"NETHASH1464"] = CalculateNetPathEx(absoluteAppPath, 1464);
        variables[L"NETHASH1465"] = CalculateNetPathEx(absoluteAppPath, 1465);
        variables[L"NETHASH1466"] = CalculateNetPathEx(absoluteAppPath, 1466);
        variables[L"NETHASH1467"] = CalculateNetPathEx(absoluteAppPath, 1467);
        variables[L"NETHASH1468"] = CalculateNetPathEx(absoluteAppPath, 1468);
        variables[L"NETHASH1469"] = CalculateNetPathEx(absoluteAppPath, 1469);
        variables[L"NETHASH1470"] = CalculateNetPathEx(absoluteAppPath, 1470);
        variables[L"NETHASH1471"] = CalculateNetPathEx(absoluteAppPath, 1471);
        variables[L"NETHASH1472"] = CalculateNetPathEx(absoluteAppPath, 1472);
        variables[L"NETHASH1473"] = CalculateNetPathEx(absoluteAppPath, 1473);
        variables[L"NETHASH1474"] = CalculateNetPathEx(absoluteAppPath, 1474);
        variables[L"NETHASH1475"] = CalculateNetPathEx(absoluteAppPath, 1475);
        variables[L"NETHASH1476"] = CalculateNetPathEx(absoluteAppPath, 1476);
        variables[L"NETHASH1477"] = CalculateNetPathEx(absoluteAppPath, 1477);
        variables[L"NETHASH1478"] = CalculateNetPathEx(absoluteAppPath, 1478);
        variables[L"NETHASH1479"] = CalculateNetPathEx(absoluteAppPath, 1479);
        variables[L"NETHASH1480"] = CalculateNetPathEx(absoluteAppPath, 1480);
        variables[L"NETHASH1481"] = CalculateNetPathEx(absoluteAppPath, 1481);
        variables[L"NETHASH1482"] = CalculateNetPathEx(absoluteAppPath, 1482);
        variables[L"NETHASH1483"] = CalculateNetPathEx(absoluteAppPath, 1483);
        variables[L"NETHASH1484"] = CalculateNetPathEx(absoluteAppPath, 1484);
        variables[L"NETHASH1485"] = CalculateNetPathEx(absoluteAppPath, 1485);
        variables[L"NETHASH1486"] = CalculateNetPathEx(absoluteAppPath, 1486);
        variables[L"NETHASH1487"] = CalculateNetPathEx(absoluteAppPath, 1487);
        variables[L"NETHASH1488"] = CalculateNetPathEx(absoluteAppPath, 1488);
        variables[L"NETHASH1489"] = CalculateNetPathEx(absoluteAppPath, 1489);
        variables[L"NETHASH1490"] = CalculateNetPathEx(absoluteAppPath, 1490);
        variables[L"NETHASH1491"] = CalculateNetPathEx(absoluteAppPath, 1491);
        variables[L"NETHASH1492"] = CalculateNetPathEx(absoluteAppPath, 1492);
        variables[L"NETHASH1493"] = CalculateNetPathEx(absoluteAppPath, 1493);
        variables[L"NETHASH1494"] = CalculateNetPathEx(absoluteAppPath, 1494);
        variables[L"NETHASH1495"] = CalculateNetPathEx(absoluteAppPath, 1495);
        variables[L"NETHASH1496"] = CalculateNetPathEx(absoluteAppPath, 1496);
        variables[L"NETHASH1497"] = CalculateNetPathEx(absoluteAppPath, 1497);
        variables[L"NETHASH1498"] = CalculateNetPathEx(absoluteAppPath, 1498);
        variables[L"NETHASH1499"] = CalculateNetPathEx(absoluteAppPath, 1499);
        variables[L"NETHASH1500"] = CalculateNetPathEx(absoluteAppPath, 1500);
        variables[L"NETHASH1501"] = CalculateNetPathEx(absoluteAppPath, 1501);
        variables[L"NETHASH1502"] = CalculateNetPathEx(absoluteAppPath, 1502);
        variables[L"NETHASH1503"] = CalculateNetPathEx(absoluteAppPath, 1503);
        variables[L"NETHASH1504"] = CalculateNetPathEx(absoluteAppPath, 1504);
        variables[L"NETHASH1505"] = CalculateNetPathEx(absoluteAppPath, 1505);
        variables[L"NETHASH1506"] = CalculateNetPathEx(absoluteAppPath, 1506);
        variables[L"NETHASH1507"] = CalculateNetPathEx(absoluteAppPath, 1507);
        variables[L"NETHASH1508"] = CalculateNetPathEx(absoluteAppPath, 1508);
        variables[L"NETHASH1509"] = CalculateNetPathEx(absoluteAppPath, 1509);
        variables[L"NETHASH1510"] = CalculateNetPathEx(absoluteAppPath, 1510);
        variables[L"NETHASH1511"] = CalculateNetPathEx(absoluteAppPath, 1511);
        variables[L"NETHASH1512"] = CalculateNetPathEx(absoluteAppPath, 1512);
        variables[L"NETHASH1513"] = CalculateNetPathEx(absoluteAppPath, 1513);
        variables[L"NETHASH1514"] = CalculateNetPathEx(absoluteAppPath, 1514);
        variables[L"NETHASH1515"] = CalculateNetPathEx(absoluteAppPath, 1515);
        variables[L"NETHASH1516"] = CalculateNetPathEx(absoluteAppPath, 1516);
        variables[L"NETHASH1517"] = CalculateNetPathEx(absoluteAppPath, 1517);
        variables[L"NETHASH1518"] = CalculateNetPathEx(absoluteAppPath, 1518);
        variables[L"NETHASH1519"] = CalculateNetPathEx(absoluteAppPath, 1519);
        variables[L"NETHASH1520"] = CalculateNetPathEx(absoluteAppPath, 1520);
        variables[L"NETHASH1521"] = CalculateNetPathEx(absoluteAppPath, 1521);
        variables[L"NETHASH1522"] = CalculateNetPathEx(absoluteAppPath, 1522);
        variables[L"NETHASH1523"] = CalculateNetPathEx(absoluteAppPath, 1523);
        variables[L"NETHASH1524"] = CalculateNetPathEx(absoluteAppPath, 1524);
        variables[L"NETHASH1525"] = CalculateNetPathEx(absoluteAppPath, 1525);
        variables[L"NETHASH1526"] = CalculateNetPathEx(absoluteAppPath, 1526);
        variables[L"NETHASH1527"] = CalculateNetPathEx(absoluteAppPath, 1527);
        variables[L"NETHASH1528"] = CalculateNetPathEx(absoluteAppPath, 1528);
        variables[L"NETHASH1529"] = CalculateNetPathEx(absoluteAppPath, 1529);
        variables[L"NETHASH1530"] = CalculateNetPathEx(absoluteAppPath, 1530);
        variables[L"NETHASH1531"] = CalculateNetPathEx(absoluteAppPath, 1531);
        variables[L"NETHASH1532"] = CalculateNetPathEx(absoluteAppPath, 1532);
        variables[L"NETHASH1533"] = CalculateNetPathEx(absoluteAppPath, 1533);
        variables[L"NETHASH1534"] = CalculateNetPathEx(absoluteAppPath, 1534);
        variables[L"NETHASH1535"] = CalculateNetPathEx(absoluteAppPath, 1535);
        variables[L"NETHASH1536"] = CalculateNetPathEx(absoluteAppPath, 1536);
        variables[L"NETHASH1537"] = CalculateNetPathEx(absoluteAppPath, 1537);
        variables[L"NETHASH1538"] = CalculateNetPathEx(absoluteAppPath, 1538);
        variables[L"NETHASH1539"] = CalculateNetPathEx(absoluteAppPath, 1539);
        variables[L"NETHASH1540"] = CalculateNetPathEx(absoluteAppPath, 1540);
        variables[L"NETHASH1541"] = CalculateNetPathEx(absoluteAppPath, 1541);
        variables[L"NETHASH1542"] = CalculateNetPathEx(absoluteAppPath, 1542);
        variables[L"NETHASH1543"] = CalculateNetPathEx(absoluteAppPath, 1543);
        variables[L"NETHASH1544"] = CalculateNetPathEx(absoluteAppPath, 1544);
        variables[L"NETHASH1545"] = CalculateNetPathEx(absoluteAppPath, 1545);
        variables[L"NETHASH1546"] = CalculateNetPathEx(absoluteAppPath, 1546);
        variables[L"NETHASH1547"] = CalculateNetPathEx(absoluteAppPath, 1547);
        variables[L"NETHASH1548"] = CalculateNetPathEx(absoluteAppPath, 1548);
        variables[L"NETHASH1549"] = CalculateNetPathEx(absoluteAppPath, 1549);
        variables[L"NETHASH1550"] = CalculateNetPathEx(absoluteAppPath, 1550);
        variables[L"NETHASH1551"] = CalculateNetPathEx(absoluteAppPath, 1551);
        variables[L"NETHASH1552"] = CalculateNetPathEx(absoluteAppPath, 1552);
        variables[L"NETHASH1553"] = CalculateNetPathEx(absoluteAppPath, 1553);
        variables[L"NETHASH1554"] = CalculateNetPathEx(absoluteAppPath, 1554);
        variables[L"NETHASH1555"] = CalculateNetPathEx(absoluteAppPath, 1555);
        variables[L"NETHASH1556"] = CalculateNetPathEx(absoluteAppPath, 1556);
        variables[L"NETHASH1557"] = CalculateNetPathEx(absoluteAppPath, 1557);
        variables[L"NETHASH1558"] = CalculateNetPathEx(absoluteAppPath, 1558);
        variables[L"NETHASH1559"] = CalculateNetPathEx(absoluteAppPath, 1559);
        variables[L"NETHASH1560"] = CalculateNetPathEx(absoluteAppPath, 1560);
        variables[L"NETHASH1561"] = CalculateNetPathEx(absoluteAppPath, 1561);
        variables[L"NETHASH1562"] = CalculateNetPathEx(absoluteAppPath, 1562);
        variables[L"NETHASH1563"] = CalculateNetPathEx(absoluteAppPath, 1563);
        variables[L"NETHASH1564"] = CalculateNetPathEx(absoluteAppPath, 1564);
        variables[L"NETHASH1565"] = CalculateNetPathEx(absoluteAppPath, 1565);
        variables[L"NETHASH1566"] = CalculateNetPathEx(absoluteAppPath, 1566);
        variables[L"NETHASH1567"] = CalculateNetPathEx(absoluteAppPath, 1567);
        variables[L"NETHASH1568"] = CalculateNetPathEx(absoluteAppPath, 1568);
        variables[L"NETHASH1569"] = CalculateNetPathEx(absoluteAppPath, 1569);
        variables[L"NETHASH1570"] = CalculateNetPathEx(absoluteAppPath, 1570);
        variables[L"NETHASH1571"] = CalculateNetPathEx(absoluteAppPath, 1571);
        variables[L"NETHASH1572"] = CalculateNetPathEx(absoluteAppPath, 1572);
        variables[L"NETHASH1573"] = CalculateNetPathEx(absoluteAppPath, 1573);
        variables[L"NETHASH1574"] = CalculateNetPathEx(absoluteAppPath, 1574);
        variables[L"NETHASH1575"] = CalculateNetPathEx(absoluteAppPath, 1575);
        variables[L"NETHASH1576"] = CalculateNetPathEx(absoluteAppPath, 1576);
        variables[L"NETHASH1577"] = CalculateNetPathEx(absoluteAppPath, 1577);
        variables[L"NETHASH1578"] = CalculateNetPathEx(absoluteAppPath, 1578);
        variables[L"NETHASH1579"] = CalculateNetPathEx(absoluteAppPath, 1579);
        variables[L"NETHASH1580"] = CalculateNetPathEx(absoluteAppPath, 1580);
        variables[L"NETHASH1581"] = CalculateNetPathEx(absoluteAppPath, 1581);
        variables[L"NETHASH1582"] = CalculateNetPathEx(absoluteAppPath, 1582);
        variables[L"NETHASH1583"] = CalculateNetPathEx(absoluteAppPath, 1583);
        variables[L"NETHASH1584"] = CalculateNetPathEx(absoluteAppPath, 1584);
        variables[L"NETHASH1585"] = CalculateNetPathEx(absoluteAppPath, 1585);
        variables[L"NETHASH1586"] = CalculateNetPathEx(absoluteAppPath, 1586);
        variables[L"NETHASH1587"] = CalculateNetPathEx(absoluteAppPath, 1587);
        variables[L"NETHASH1588"] = CalculateNetPathEx(absoluteAppPath, 1588);
        variables[L"NETHASH1589"] = CalculateNetPathEx(absoluteAppPath, 1589);
        variables[L"NETHASH1590"] = CalculateNetPathEx(absoluteAppPath, 1590);
        variables[L"NETHASH1591"] = CalculateNetPathEx(absoluteAppPath, 1591);
        variables[L"NETHASH1592"] = CalculateNetPathEx(absoluteAppPath, 1592);
        variables[L"NETHASH1593"] = CalculateNetPathEx(absoluteAppPath, 1593);
        variables[L"NETHASH1594"] = CalculateNetPathEx(absoluteAppPath, 1594);
        variables[L"NETHASH1595"] = CalculateNetPathEx(absoluteAppPath, 1595);
        variables[L"NETHASH1596"] = CalculateNetPathEx(absoluteAppPath, 1596);
        variables[L"NETHASH1597"] = CalculateNetPathEx(absoluteAppPath, 1597);
        variables[L"NETHASH1598"] = CalculateNetPathEx(absoluteAppPath, 1598);
        variables[L"NETHASH1599"] = CalculateNetPathEx(absoluteAppPath, 1599);
        variables[L"NETHASH1600"] = CalculateNetPathEx(absoluteAppPath, 1600);
        variables[L"NETHASH1601"] = CalculateNetPathEx(absoluteAppPath, 1601);
        variables[L"NETHASH1602"] = CalculateNetPathEx(absoluteAppPath, 1602);
        variables[L"NETHASH1603"] = CalculateNetPathEx(absoluteAppPath, 1603);
        variables[L"NETHASH1604"] = CalculateNetPathEx(absoluteAppPath, 1604);
        variables[L"NETHASH1605"] = CalculateNetPathEx(absoluteAppPath, 1605);
        variables[L"NETHASH1606"] = CalculateNetPathEx(absoluteAppPath, 1606);
        variables[L"NETHASH1607"] = CalculateNetPathEx(absoluteAppPath, 1607);
        variables[L"NETHASH1608"] = CalculateNetPathEx(absoluteAppPath, 1608);
        variables[L"NETHASH1609"] = CalculateNetPathEx(absoluteAppPath, 1609);
        variables[L"NETHASH1610"] = CalculateNetPathEx(absoluteAppPath, 1610);
        variables[L"NETHASH1611"] = CalculateNetPathEx(absoluteAppPath, 1611);
        variables[L"NETHASH1612"] = CalculateNetPathEx(absoluteAppPath, 1612);
        variables[L"NETHASH1613"] = CalculateNetPathEx(absoluteAppPath, 1613);
        variables[L"NETHASH1614"] = CalculateNetPathEx(absoluteAppPath, 1614);
        variables[L"NETHASH1615"] = CalculateNetPathEx(absoluteAppPath, 1615);
        variables[L"NETHASH1616"] = CalculateNetPathEx(absoluteAppPath, 1616);
        variables[L"NETHASH1617"] = CalculateNetPathEx(absoluteAppPath, 1617);
        variables[L"NETHASH1618"] = CalculateNetPathEx(absoluteAppPath, 1618);
        variables[L"NETHASH1619"] = CalculateNetPathEx(absoluteAppPath, 1619);
        variables[L"NETHASH1620"] = CalculateNetPathEx(absoluteAppPath, 1620);
        variables[L"NETHASH1621"] = CalculateNetPathEx(absoluteAppPath, 1621);
        variables[L"NETHASH1622"] = CalculateNetPathEx(absoluteAppPath, 1622);
        variables[L"NETHASH1623"] = CalculateNetPathEx(absoluteAppPath, 1623);
        variables[L"NETHASH1624"] = CalculateNetPathEx(absoluteAppPath, 1624);
        variables[L"NETHASH1625"] = CalculateNetPathEx(absoluteAppPath, 1625);
        variables[L"NETHASH1626"] = CalculateNetPathEx(absoluteAppPath, 1626);
        variables[L"NETHASH1627"] = CalculateNetPathEx(absoluteAppPath, 1627);
        variables[L"NETHASH1628"] = CalculateNetPathEx(absoluteAppPath, 1628);
        variables[L"NETHASH1629"] = CalculateNetPathEx(absoluteAppPath, 1629);
        variables[L"NETHASH1630"] = CalculateNetPathEx(absoluteAppPath, 1630);
        variables[L"NETHASH1631"] = CalculateNetPathEx(absoluteAppPath, 1631);
        variables[L"NETHASH1632"] = CalculateNetPathEx(absoluteAppPath, 1632);
        variables[L"NETHASH1633"] = CalculateNetPathEx(absoluteAppPath, 1633);
        variables[L"NETHASH1634"] = CalculateNetPathEx(absoluteAppPath, 1634);
        variables[L"NETHASH1635"] = CalculateNetPathEx(absoluteAppPath, 1635);
        variables[L"NETHASH1636"] = CalculateNetPathEx(absoluteAppPath, 1636);
        variables[L"NETHASH1637"] = CalculateNetPathEx(absoluteAppPath, 1637);
        variables[L"NETHASH1638"] = CalculateNetPathEx(absoluteAppPath, 1638);
        variables[L"NETHASH1639"] = CalculateNetPathEx(absoluteAppPath, 1639);
        variables[L"NETHASH1640"] = CalculateNetPathEx(absoluteAppPath, 1640);
        variables[L"NETHASH1641"] = CalculateNetPathEx(absoluteAppPath, 1641);
        variables[L"NETHASH1642"] = CalculateNetPathEx(absoluteAppPath, 1642);
        variables[L"NETHASH1643"] = CalculateNetPathEx(absoluteAppPath, 1643);
        variables[L"NETHASH1644"] = CalculateNetPathEx(absoluteAppPath, 1644);
        variables[L"NETHASH1645"] = CalculateNetPathEx(absoluteAppPath, 1645);
        variables[L"NETHASH1646"] = CalculateNetPathEx(absoluteAppPath, 1646);
        variables[L"NETHASH1647"] = CalculateNetPathEx(absoluteAppPath, 1647);
        variables[L"NETHASH1648"] = CalculateNetPathEx(absoluteAppPath, 1648);
        variables[L"NETHASH1649"] = CalculateNetPathEx(absoluteAppPath, 1649);
        variables[L"NETHASH1650"] = CalculateNetPathEx(absoluteAppPath, 1650);
        variables[L"NETHASH1651"] = CalculateNetPathEx(absoluteAppPath, 1651);
        variables[L"NETHASH1652"] = CalculateNetPathEx(absoluteAppPath, 1652);
        variables[L"NETHASH1653"] = CalculateNetPathEx(absoluteAppPath, 1653);
        variables[L"NETHASH1654"] = CalculateNetPathEx(absoluteAppPath, 1654);
        variables[L"NETHASH1655"] = CalculateNetPathEx(absoluteAppPath, 1655);
        variables[L"NETHASH1656"] = CalculateNetPathEx(absoluteAppPath, 1656);
        variables[L"NETHASH1657"] = CalculateNetPathEx(absoluteAppPath, 1657);
        variables[L"NETHASH1658"] = CalculateNetPathEx(absoluteAppPath, 1658);
        variables[L"NETHASH1659"] = CalculateNetPathEx(absoluteAppPath, 1659);
        variables[L"NETHASH1660"] = CalculateNetPathEx(absoluteAppPath, 1660);
        variables[L"NETHASH1661"] = CalculateNetPathEx(absoluteAppPath, 1661);
        variables[L"NETHASH1662"] = CalculateNetPathEx(absoluteAppPath, 1662);
        variables[L"NETHASH1663"] = CalculateNetPathEx(absoluteAppPath, 1663);
        variables[L"NETHASH1664"] = CalculateNetPathEx(absoluteAppPath, 1664);
        variables[L"NETHASH1665"] = CalculateNetPathEx(absoluteAppPath, 1665);
        variables[L"NETHASH1666"] = CalculateNetPathEx(absoluteAppPath, 1666);
        variables[L"NETHASH1667"] = CalculateNetPathEx(absoluteAppPath, 1667);
        variables[L"NETHASH1668"] = CalculateNetPathEx(absoluteAppPath, 1668);
        variables[L"NETHASH1669"] = CalculateNetPathEx(absoluteAppPath, 1669);
        variables[L"NETHASH1670"] = CalculateNetPathEx(absoluteAppPath, 1670);
        variables[L"NETHASH1671"] = CalculateNetPathEx(absoluteAppPath, 1671);
        variables[L"NETHASH1672"] = CalculateNetPathEx(absoluteAppPath, 1672);
        variables[L"NETHASH1673"] = CalculateNetPathEx(absoluteAppPath, 1673);
        variables[L"NETHASH1674"] = CalculateNetPathEx(absoluteAppPath, 1674);
        variables[L"NETHASH1675"] = CalculateNetPathEx(absoluteAppPath, 1675);
        variables[L"NETHASH1676"] = CalculateNetPathEx(absoluteAppPath, 1676);
        variables[L"NETHASH1677"] = CalculateNetPathEx(absoluteAppPath, 1677);
        variables[L"NETHASH1678"] = CalculateNetPathEx(absoluteAppPath, 1678);
        variables[L"NETHASH1679"] = CalculateNetPathEx(absoluteAppPath, 1679);
        variables[L"NETHASH1680"] = CalculateNetPathEx(absoluteAppPath, 1680);
        variables[L"NETHASH1681"] = CalculateNetPathEx(absoluteAppPath, 1681);
        variables[L"NETHASH1682"] = CalculateNetPathEx(absoluteAppPath, 1682);
        variables[L"NETHASH1683"] = CalculateNetPathEx(absoluteAppPath, 1683);
        variables[L"NETHASH1684"] = CalculateNetPathEx(absoluteAppPath, 1684);
        variables[L"NETHASH1685"] = CalculateNetPathEx(absoluteAppPath, 1685);
        variables[L"NETHASH1686"] = CalculateNetPathEx(absoluteAppPath, 1686);
        variables[L"NETHASH1687"] = CalculateNetPathEx(absoluteAppPath, 1687);
        variables[L"NETHASH1688"] = CalculateNetPathEx(absoluteAppPath, 1688);
        variables[L"NETHASH1689"] = CalculateNetPathEx(absoluteAppPath, 1689);
        variables[L"NETHASH1690"] = CalculateNetPathEx(absoluteAppPath, 1690);
        variables[L"NETHASH1691"] = CalculateNetPathEx(absoluteAppPath, 1691);
        variables[L"NETHASH1692"] = CalculateNetPathEx(absoluteAppPath, 1692);
        variables[L"NETHASH1693"] = CalculateNetPathEx(absoluteAppPath, 1693);
        variables[L"NETHASH1694"] = CalculateNetPathEx(absoluteAppPath, 1694);
        variables[L"NETHASH1695"] = CalculateNetPathEx(absoluteAppPath, 1695);
        variables[L"NETHASH1696"] = CalculateNetPathEx(absoluteAppPath, 1696);
        variables[L"NETHASH1697"] = CalculateNetPathEx(absoluteAppPath, 1697);
        variables[L"NETHASH1698"] = CalculateNetPathEx(absoluteAppPath, 1698);
        variables[L"NETHASH1699"] = CalculateNetPathEx(absoluteAppPath, 1699);
        variables[L"NETHASH1700"] = CalculateNetPathEx(absoluteAppPath, 1700);
        variables[L"NETHASH1701"] = CalculateNetPathEx(absoluteAppPath, 1701);
        variables[L"NETHASH1702"] = CalculateNetPathEx(absoluteAppPath, 1702);
        variables[L"NETHASH1703"] = CalculateNetPathEx(absoluteAppPath, 1703);
        variables[L"NETHASH1704"] = CalculateNetPathEx(absoluteAppPath, 1704);
        variables[L"NETHASH1705"] = CalculateNetPathEx(absoluteAppPath, 1705);
        variables[L"NETHASH1706"] = CalculateNetPathEx(absoluteAppPath, 1706);
        variables[L"NETHASH1707"] = CalculateNetPathEx(absoluteAppPath, 1707);
        variables[L"NETHASH1708"] = CalculateNetPathEx(absoluteAppPath, 1708);
        variables[L"NETHASH1709"] = CalculateNetPathEx(absoluteAppPath, 1709);
        variables[L"NETHASH1710"] = CalculateNetPathEx(absoluteAppPath, 1710);
        variables[L"NETHASH1711"] = CalculateNetPathEx(absoluteAppPath, 1711);
        variables[L"NETHASH1712"] = CalculateNetPathEx(absoluteAppPath, 1712);
        variables[L"NETHASH1713"] = CalculateNetPathEx(absoluteAppPath, 1713);
        variables[L"NETHASH1714"] = CalculateNetPathEx(absoluteAppPath, 1714);
        variables[L"NETHASH1715"] = CalculateNetPathEx(absoluteAppPath, 1715);
        variables[L"NETHASH1716"] = CalculateNetPathEx(absoluteAppPath, 1716);
        variables[L"NETHASH1717"] = CalculateNetPathEx(absoluteAppPath, 1717);
        variables[L"NETHASH1718"] = CalculateNetPathEx(absoluteAppPath, 1718);
        variables[L"NETHASH1719"] = CalculateNetPathEx(absoluteAppPath, 1719);
        variables[L"NETHASH1720"] = CalculateNetPathEx(absoluteAppPath, 1720);
        variables[L"NETHASH1721"] = CalculateNetPathEx(absoluteAppPath, 1721);
        variables[L"NETHASH1722"] = CalculateNetPathEx(absoluteAppPath, 1722);
        variables[L"NETHASH1723"] = CalculateNetPathEx(absoluteAppPath, 1723);
        variables[L"NETHASH1724"] = CalculateNetPathEx(absoluteAppPath, 1724);
        variables[L"NETHASH1725"] = CalculateNetPathEx(absoluteAppPath, 1725);
        variables[L"NETHASH1726"] = CalculateNetPathEx(absoluteAppPath, 1726);
        variables[L"NETHASH1727"] = CalculateNetPathEx(absoluteAppPath, 1727);
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

        // [新增] 获取文件版本和产品版本 (文件版本仅读取二进制 产品版本优先字符串)
        variables[L"EXEVER"] = L"";
        variables[L"APPVER"] = L"";
        DWORD verHandle = 0;
        DWORD verSize = GetFileVersionInfoSizeW(absoluteAppPath.c_str(), &verHandle);
        if (verSize > 0) {
            std::vector<BYTE> verData(verSize);
            if (GetFileVersionInfoW(absoluteAppPath.c_str(), verHandle, verSize, verData.data())) {

                // 1. 读取 VS_FIXEDFILEINFO 二进制版本号
                VS_FIXEDFILEINFO* verInfo = NULL;
                UINT size = 0;
                if (VerQueryValueW(verData.data(), L"\\", (LPVOID*)&verInfo, &size) && size >= sizeof(VS_FIXEDFILEINFO) && verInfo != NULL) {
                    // 文件版本 (EXEVER) 仅使用二进制版本
                    std::wstringstream fs;
                    fs << HIWORD(verInfo->dwFileVersionMS) << L"."
                       << LOWORD(verInfo->dwFileVersionMS) << L"."
                       << HIWORD(verInfo->dwFileVersionLS) << L"."
                       << LOWORD(verInfo->dwFileVersionLS);
                    variables[L"EXEVER"] = fs.str();

                    // 产品版本 (APPVER) 默认使用二进制版本作为回退
                    std::wstringstream ps;
                    ps << HIWORD(verInfo->dwProductVersionMS) << L"."
                       << LOWORD(verInfo->dwProductVersionMS) << L"."
                       << HIWORD(verInfo->dwProductVersionLS) << L"."
                       << LOWORD(verInfo->dwProductVersionLS);
                    variables[L"APPVER"] = ps.str();
                }

                // 2. 尝试从 StringFileInfo 获取产品版本的字符串版本 (覆盖二进制版本)
                struct LANGANDCODEPAGE {
                    WORD wLanguage;
                    WORD wCodePage;
                } *lpTranslate;
                UINT cbTranslate = 0;

                if (VerQueryValueW(verData.data(), L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate) && (cbTranslate >= sizeof(LANGANDCODEPAGE))) {
                    wchar_t subBlock[256];
                    wchar_t* lpBuffer = NULL;
                    UINT dwBytes = 0;

                    // 仅获取 ProductVersion (产品版本)
                    swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\ProductVersion", lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);
                    if (VerQueryValueW(verData.data(), subBlock, (LPVOID*)&lpBuffer, &dwBytes) && dwBytes > 0 && lpBuffer != NULL) {
                        std::wstring strVer = lpBuffer;
                        if (!strVer.empty()) {
                            variables[L"APPVER"] = strVer;
                        }
                    }
                }
            }
        }

        std::wstring workDirRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"General", L"workdir"), variables);
        std::wstring finalWorkDir = ResolveToAbsolutePath(workDirRaw, variables);
        if (finalWorkDir.empty() || !PathIsDirectoryW(finalWorkDir.c_str())) {
            finalWorkDir = appDir;
        }
        variables[L"WORKDIR"] = finalWorkDir;

        // [新增] 扫描并加载 loadfont 目录下的所有字体
        ProcessLoadFontConfig(iniContent, variables);

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
                            } else if constexpr (std::is_same_v<OpType, RegLinkOp>) {
                                op_data.backupCreated = true;
                                op_data.isCreated = true;
                            }
                        }, ssOp.data);
                        shutdownOpsForCrash.push_back(ssOp);
                    }
                }, op.data);
            }

            // <-- [新增] 为崩溃恢复场景定义受信任的PID（仅限启动器自身）
            std::set<DWORD> crashTrustedPids;
            crashTrustedPids.insert(launcherPid);

            // <-- [修改] 调用 PerformFullCleanup 时传递 crashTrustedPids
            PerformFullCleanup(afterOps, shutdownOpsForCrash, variables, crashTrustedPids, launcherPid, iniContent);

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

        // --- [新增] 提前解析并挂载注册表配置单元 (支持 [Before] 写入) ---
        std::wstring hookRegVal = GetValueFromIniContent(iniContent, L"Hook", L"hookreg");
        bool hasRegLink = HasRegLinkInBefore(iniContent);
        std::wstring regMountName;
        std::wstring hivePath;

        if (!hookRegVal.empty() || hasRegLink) {
            // 仅当设置了注册表挂钩重定向时才注入 YAP_HOOK_REG 变量
            if (!hookRegVal.empty()) {
                SetEnvironmentVariableW(L"YAP_HOOK_REG", hookRegVal.c_str());
            } else {
                SetEnvironmentVariableW(L"YAP_HOOK_REG", NULL);
            }

            std::wstring hookPathRaw = GetValueFromIniContent(iniContent, L"Hook", L"hookpath");
            std::wstring finalHookPath = ResolveToAbsolutePath(ExpandVariables(hookPathRaw, variables), variables);

            hivePath = variables[L"YAPROOT"] + L"\\YapHookReg.dat";
            if (!finalHookPath.empty()) {
                 hivePath = finalHookPath + L"\\YapHookReg.dat";
            }

            regMountName = GetHiveMountName(launcherBaseName);

            wchar_t parentDir[MAX_PATH];
            wcscpy_s(parentDir, MAX_PATH, hivePath.c_str());
            PathRemoveFileSpecW(parentDir);
            SHCreateDirectoryExW(NULL, parentDir, NULL);

            if (EnsureHiveFileExists(hivePath)) {
                HKEY hTest;
                if (RegOpenKeyExW(HKEY_USERS, regMountName.c_str(), 0, KEY_READ, &hTest) == ERROR_SUCCESS) {
                    RegCloseKey(hTest);
                } else {
                    RegLoadKeyW(HKEY_USERS, regMountName.c_str(), hivePath.c_str());

                    // 将已挂载的注册表配置单元设置为 Low Integrity（含继承标志）
                    {
                        PSECURITY_DESCRIPTOR pSD = nullptr;
                        // OICI 使完整性标签向下继承到子键和子值
                        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                                L"S:(ML;OICI;NW;;;LW)",
                                SDDL_REVISION_1,
                                &pSD,
                                nullptr))
                        {
                            PACL pSacl       = nullptr;
                            BOOL saclPresent = FALSE;
                            BOOL saclDefault = FALSE;
                            if (GetSecurityDescriptorSacl(pSD, &saclPresent, &pSacl, &saclDefault) && saclPresent)
                            {
                                std::wstring fullKeyPath = L"USERS\\" + regMountName;
                                SetNamedSecurityInfoW(
                                    const_cast<LPWSTR>(fullKeyPath.c_str()),
                                    SE_REGISTRY_KEY,
                                    LABEL_SECURITY_INFORMATION,
                                    nullptr, nullptr, nullptr,
                                    pSacl);
                            }
                            LocalFree(pSD);
                        }
                    }
                }
                SetEnvironmentVariableW(L"YAP_HOOK_REGPATH", regMountName.c_str());
            }
        } else {
            SetEnvironmentVariableW(L"YAP_HOOK_REG", NULL);
            SetEnvironmentVariableW(L"YAP_HOOK_REGPATH", NULL);
        }

        // <-- [新增] 为 [Before] 阶段的操作定义受信任的PID（仅限启动器自身）
        std::set<DWORD> beforeTrustedPids;
        beforeTrustedPids.insert(GetCurrentProcessId());

        for (auto& op : beforeOps) {
            std::visit([&](auto& arg) {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, ActionOpData>) {
                    // <-- [修改] 调用 ExecuteActionOperation 时传递 beforeTrustedPids
                    ExecuteActionOperation(arg, variables, beforeTrustedPids, launcherPid, iniContent);
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
		threadData.launcherPid = launcherPid;
        threadData.pipeName = sharedPipeName;
        threadData.regMountName = regMountName;
        threadData.hivePath = hivePath;

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

        UnloadTemporaryFonts();
        CloseHandle(hMutex);
        CoUninitialize();

    } else {
        // --- [修改] 第二个实例的处理逻辑 ---
        CloseHandle(hMutex);

        if (GetValueFromIniContent(iniContent, L"General", L"multiple") == L"1") {

            // 1. 解析所有 Hook 配置
            std::wstring hookFileVal = GetValueFromIniContent(iniContent, L"Hook", L"hookfile");
            if (hookFileVal.empty()) hookFileVal = L"0"; // 确保不为空

            std::wstring netBlockVal = GetValueFromIniContent(iniContent, L"Hook", L"hooknet");
            if (netBlockVal.empty()) netBlockVal = L"0"; // 确保不为空

            std::wstring hookPathRaw = GetValueFromIniContent(iniContent, L"Hook", L"hookpath");
            std::wstring finalHookPath = ResolveToAbsolutePath(ExpandVariables(hookPathRaw, variables), variables);

            std::wstring hookCopySizeVal = GetValueFromIniContent(iniContent, L"Hook", L"hookcopysize");
            std::wstring hookVolumeIdVal = GetValueFromIniContent(iniContent, L"Hook", L"hookvolumeid");
            std::wstring hookCdVal = GetValueFromIniContent(iniContent, L"Hook", L"hookcd");
            std::wstring hookLocaleVal = GetValueFromIniContent(iniContent, L"Hook", L"hooklocale");
            std::wstring hookFontVal = GetValueFromIniContent(iniContent, L"Hook", L"hookfont");
            std::wstring hookTimeVal = GetValueFromIniContent(iniContent, L"Hook", L"hooktime");
            std::wstring hookChildVal = GetValueFromIniContent(iniContent, L"Hook", L"hookchild");
            std::wstring hookRegVal = GetValueFromIniContent(iniContent, L"Hook", L"hookreg");

            if (hookChildVal.empty()) hookChildVal = L"1";

            // [新增] 多实例环境同步：解析 [Before] 区域的变量
            std::wstring childHookNamesVar;
            bool hasThirdPartyDlls = false;
            std::wstring extraDllsVar; // [新增] 用于存储拼接后的 DLL 路径
            {
                std::wstringstream stream(iniContent);
                std::wstring line;
                std::wstring currentSection;
                const std::wstring delimiter = L" :: ";

                while (std::getline(stream, line)) {
                    line = trim(line);
                    if (line.empty() || line[0] == L';' || line[0] == L'#') continue;
                    if (line[0] == L'[' && line.back() == L']') {
                        currentSection = line;
                        continue;
                    }

                    size_t delimiterPos = line.find(L'=');
                    if (delimiterPos == std::wstring::npos) continue;
                    std::wstring key = trim(line.substr(0, delimiterPos));
                    std::wstring val = trim(line.substr(delimiterPos + 1));

                    // A. 处理 [Hook] 区域特定逻辑
                    if (_wcsicmp(currentSection.c_str(), L"[Hook]") == 0) {
                        if (_wcsicmp(key.c_str(), L"Injector") == 0) {
                            hasThirdPartyDlls = true;
                            // [新增] 解析并收集路径
                            std::wstring expanded = ResolveToAbsolutePath(ExpandVariables(val, variables), variables);
                            if (!expanded.empty()) {
                                if (!extraDllsVar.empty()) extraDllsVar += L"|";
                                extraDllsVar += expanded;
                            }
                        }
                        else if (_wcsicmp(key.c_str(), L"hookchildname") == 0) childHookNamesVar += val + L";";
                    }

                    // B. 处理 [Before] 区域的环境变量同步
                    else if (_wcsicmp(currentSection.c_str(), L"[Before]") == 0) {
                        if (_wcsicmp(key.c_str(), L"uservar") == 0) {
                            auto parts = split_string(val, delimiter);
                            if (parts.size() == 2) {
                                variables[parts[0]] = ExpandVariables(parts[1], variables);
                            }
                        }
                        else if (_wcsicmp(key.c_str(), L"envvar") == 0) {
                            auto parts = split_string(val, delimiter);
                            if (parts.size() >= 2) {
                                EnvVarOp evOp;
                                evOp.name = parts[0];
                                evOp.value = parts[1];

                                // [核心修改] 强制设为 Process 类型
                                evOp.type = EnvVarType::Process;

                                // 立即应用到当前启动器进程环境 以便子进程继承
                                ActionHelpers::HandleEnvVar(evOp, variables, iniContent);
                            }
                        }
                    }
                }
            }

            // 2. [关键修复] 为后续实例设置完整环境变量 确保子进程继承
            SetEnvironmentVariableW(L"YAP_LAUNCHER_DIR", g_LauncherDir.c_str());
            SetEnvironmentVariableW(L"YAP_IPC_PIPE", sharedPipeName.c_str());
            SetEnvironmentVariableW(L"YAP_HOOK_FILE", hookFileVal.c_str());
            SetEnvironmentVariableW(L"YAP_HOOK_NET", netBlockVal.c_str());
            SetEnvironmentVariableW(L"YAP_HOOK_CHILD", hookChildVal.c_str());
            SetEnvironmentVariableW(L"YAP_HOOK_PATH", finalHookPath.empty() ? NULL : finalHookPath.c_str());

            if (!hookVolumeIdVal.empty()) SetEnvironmentVariableW(L"YAP_HOOK_VOLUME_ID", hookVolumeIdVal.c_str());

            // [新增] 设置第三方 DLL 环境变量
            if (!extraDllsVar.empty()) {
                SetEnvironmentVariableW(L"YAP_EXTRA_DLL", extraDllsVar.c_str());
            } else {
                SetEnvironmentVariableW(L"YAP_EXTRA_DLL", NULL);
            }

            // 条件设置：hookchildname
            if (!childHookNamesVar.empty()) {
                SetEnvironmentVariableW(L"YAP_HOOK_CHILD_NAME", childHookNamesVar.c_str());
            } else {
                SetEnvironmentVariableW(L"YAP_HOOK_CHILD_NAME", NULL);
            }

            // 条件设置：hookcopysize (必须 hookfile > 0 且配置不为空)
            if (_wtoi(hookFileVal.c_str()) > 0 && !hookCopySizeVal.empty()) {
                SetEnvironmentVariableW(L"YAP_HOOK_COPY_SIZE", hookCopySizeVal.c_str());
            } else {
                SetEnvironmentVariableW(L"YAP_HOOK_COPY_SIZE", NULL);
            }

            // 条件设置：hooklocale
            if (!hookLocaleVal.empty()) {
                SetEnvironmentVariableW(L"YAP_HOOK_LOCALE", hookLocaleVal.c_str());
            } else {
                SetEnvironmentVariableW(L"YAP_HOOK_LOCALE", NULL);
            }

            // 条件设置：hooktime
            if (!hookTimeVal.empty()) {
                SetEnvironmentVariableW(L"YAP_HOOK_TIME", hookTimeVal.c_str());
            } else {
                SetEnvironmentVariableW(L"YAP_HOOK_TIME", NULL);
            }

            // --- [新增] 条件设置：hookreg ---
            if (!hookRegVal.empty()) {
                SetEnvironmentVariableW(L"YAP_HOOK_REG", hookRegVal.c_str());
                // 为多实例计算并设置挂载路径环境变量
                std::wstring regMountName = GetHiveMountName(launcherBaseName);
                SetEnvironmentVariableW(L"YAP_HOOK_REGPATH", regMountName.c_str());
            } else {
                SetEnvironmentVariableW(L"YAP_HOOK_REG", NULL);
                SetEnvironmentVariableW(L"YAP_HOOK_REGPATH", NULL);
            }

            // 处理字体路径 (必须像第一实例那样解析成绝对路径)
            if (!hookFontVal.empty()) {
                std::wstring resolvedFontPath = ResolveToAbsolutePath(ExpandVariables(hookFontVal, variables), variables);
                if (PathFileExistsW(resolvedFontPath.c_str())) {
                    SetEnvironmentVariableW(L"YAP_HOOK_FONT", resolvedFontPath.c_str());
                } else {
                    SetEnvironmentVariableW(L"YAP_HOOK_FONT", hookFontVal.c_str());
                }
            }

            // 处理光驱伪装路径
            if (!hookCdVal.empty()) {
                std::wstring finalCdPath = ResolveToAbsolutePath(ExpandVariables(hookCdVal, variables), variables);
                SetEnvironmentVariableW(L"YAP_HOOK_CD", finalCdPath.c_str());
            }

            // 3. 判断是否需要 Hook 流程
            bool needHook = (_wtoi(hookFileVal.c_str()) > 0 || _wtoi(netBlockVal.c_str()) > 0 ||
                             !hookVolumeIdVal.empty() || !hookCdVal.empty() ||
                             !hookLocaleVal.empty() || !hookFontVal.empty() ||
                             !hookTimeVal.empty() || !hookRegVal.empty() || hasThirdPartyDlls);

            if (!needHook) {
                LaunchApplication(iniContent, variables);
            }
            else {
                // --- 需要 Hook：通过 IPC 请求第一个实例进行注入 ---

                // 1. 准备启动参数
                std::wstring absoluteAppPath = ResolveToAbsolutePath(appPathRaw, variables);
                std::wstring commandLine = ExpandVariables(GetValueFromIniContent(iniContent, L"General", L"commandline"), variables);
                std::wstring workDirRaw = ExpandVariables(GetValueFromIniContent(iniContent, L"General", L"workdir"), variables);
                std::wstring finalWorkDir = ResolveToAbsolutePath(workDirRaw, variables);

                if (finalWorkDir.empty()) {
                    wchar_t appDir[MAX_PATH];
                    wcscpy_s(appDir, absoluteAppPath.c_str());
                    PathRemoveFileSpecW(appDir);
                    finalWorkDir = appDir;
                }

                std::wstring fullCommandLine = L"\"" + absoluteAppPath + L"\" " + commandLine;
                wchar_t commandLineBuffer[4096];
                wcscpy_s(commandLineBuffer, fullCommandLine.c_str());

                STARTUPINFOW si = { sizeof(si) };
                PROCESS_INFORMATION pi = { 0 };

                // 3. 挂起启动
                if (CreateProcessW(NULL, commandLineBuffer, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, finalWorkDir.c_str(), &si, &pi)) {

                    // 4. 连接到第一个实例的 IPC 管道
                    bool injected = false;

                    // 等待管道可用 (最多等待 1 秒)
                    if (WaitNamedPipeW(sharedPipeName.c_str(), 1000)) {
                        IpcMessage msg;
                        msg.targetPid = pi.dwProcessId;
                        IpcResponse resp;
                        DWORD bytesRead;

                        // 发送注入请求
                        if (CallNamedPipeW(sharedPipeName.c_str(), &msg, sizeof(msg), &resp, sizeof(resp), &bytesRead, 5000)) {
                            if (resp.success) injected = true;
                        }
                    }

                    // 5. 恢复进程
                    ResumeThread(pi.hThread);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }
            }
        }
    }
}