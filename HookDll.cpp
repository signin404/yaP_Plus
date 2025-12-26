#include <windows.h>
#include <winternl.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include <algorithm>
#include <stdio.h>
#include "MinHook.h"
#include "IpcCommon.h"
#include <map>
#include <mutex>
#include <shared_mutex>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shlwapi.lib")

// -----------------------------------------------------------
// 1. 常量和宏补全
// -----------------------------------------------------------
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#endif

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE 0x00000001
#endif

#ifndef FileBasicInformation
#define FileBasicInformation ((FILE_INFORMATION_CLASS)4)
#endif

#ifndef FileRenameInformation
#define FileRenameInformation ((FILE_INFORMATION_CLASS)10)
#endif

#ifndef FileDispositionInformationEx
#define FileDispositionInformationEx ((FILE_INFORMATION_CLASS)64)
#endif

#ifndef FileStandardInformation
#define FileStandardInformation ((FILE_INFORMATION_CLASS)5)
#endif

#ifndef STATUS_DIRECTORY_NOT_EMPTY
#define STATUS_DIRECTORY_NOT_EMPTY ((NTSTATUS)0xC0000101L)
#endif

#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BBL)
#endif

#define SL_RESTART_SCAN 0x00000001
#define SL_RETURN_SINGLE_ENTRY 0x00000002
#define SL_INDEX_SPECIFIED 0x00000004

#ifndef SL_RESTART_SCAN
#define SL_RESTART_SCAN 0x00000001
#endif

#ifndef SL_RETURN_SINGLE_ENTRY
#define SL_RETURN_SINGLE_ENTRY 0x00000002
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

// 1. 补充 NTSTATUS 状态码
#ifndef STATUS_NO_MORE_FILES
#define STATUS_NO_MORE_FILES ((NTSTATUS)0x80000006L)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

// 2. 补充 FILE_INFORMATION_CLASS 枚举值
// winternl.h 通常只定义了部分值 这里使用宏强制补充
#ifndef FileDirectoryInformation
#define FileDirectoryInformation ((FILE_INFORMATION_CLASS)1)
#endif

#ifndef FileFullDirectoryInformation
#define FileFullDirectoryInformation ((FILE_INFORMATION_CLASS)2)
#endif

#ifndef FileBothDirectoryInformation
#define FileBothDirectoryInformation ((FILE_INFORMATION_CLASS)3)
#endif

#ifndef FileIdBothDirectoryInformation
#define FileIdBothDirectoryInformation ((FILE_INFORMATION_CLASS)37)
#endif

// 3. 补充 IsTombstone 辅助函数 (必须在 BuildMergedDirectoryList 之前定义)
// 辅助：判断是否为墓碑文件 (隐藏 + 系统)
bool IsTombstone(DWORD attrs) {
    return (attrs != INVALID_FILE_ATTRIBUTES) &&
           (attrs & FILE_ATTRIBUTE_HIDDEN) &&
           (attrs & FILE_ATTRIBUTE_SYSTEM);
}

// -----------------------------------------------------------
// 2. 补全缺失的 NT 结构体与枚举
// -----------------------------------------------------------

#ifndef FileEndOfFileInformation
#define FileEndOfFileInformation ((FILE_INFORMATION_CLASS)20)
#endif

typedef struct _FILE_END_OF_FILE_INFORMATION {
    LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION;

#ifndef FileRenameInformationEx
#define FileRenameInformationEx ((FILE_INFORMATION_CLASS)65)
#endif

// 定义 Ex 结构体 (标志位)
typedef struct _FILE_DISPOSITION_INFORMATION_EX {
    ULONG Flags;
} FILE_DISPOSITION_INFORMATION_EX, *PFILE_DISPOSITION_INFORMATION_EX;

// 标志位定义
#define FILE_DISPOSITION_DELETE 0x00000001
#define FILE_DISPOSITION_POSIX_SEMANTICS 0x00000002
#define FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK 0x00000004
#define FILE_DISPOSITION_ON_CLOSE 0x00000008
#define FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE 0x00000010

#ifndef ObjectNameInformation
#define ObjectNameInformation ((OBJECT_INFORMATION_CLASS)1)
#endif

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

#ifndef FileDispositionInformation
#define FileDispositionInformation ((FILE_INFORMATION_CLASS)13)
#endif

typedef struct _FILE_DISPOSITION_INFORMATION {
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

typedef struct _FILE_INTERNAL_INFORMATION {
    LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION, *PFILE_INTERNAL_INFORMATION;

typedef struct _FILE_EA_INFORMATION {
    ULONG EaSize;
} FILE_EA_INFORMATION, *PFILE_EA_INFORMATION;

typedef struct _FILE_ACCESS_INFORMATION {
    ACCESS_MASK AccessFlags;
} FILE_ACCESS_INFORMATION, *PFILE_ACCESS_INFORMATION;

typedef struct _FILE_POSITION_INFORMATION {
    LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;

typedef struct _FILE_MODE_INFORMATION {
    ULONG Mode;
} FILE_MODE_INFORMATION, *PFILE_MODE_INFORMATION;

typedef struct _FILE_ALIGNMENT_INFORMATION {
    ULONG AlignmentRequirement;
} FILE_ALIGNMENT_INFORMATION, *PFILE_ALIGNMENT_INFORMATION;

typedef struct _FILE_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

#ifndef _FILE_BASIC_INFORMATION_DEFINED
typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;
#define _FILE_BASIC_INFORMATION_DEFINED
#endif

#ifndef _FILE_STANDARD_INFORMATION_DEFINED
typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;
#define _FILE_STANDARD_INFORMATION_DEFINED
#endif

typedef struct _FILE_NETWORK_OPEN_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef struct _FILE_ALL_INFORMATION {
    FILE_BASIC_INFORMATION BasicInformation;
    FILE_STANDARD_INFORMATION StandardInformation;
    FILE_INTERNAL_INFORMATION InternalInformation;
    FILE_EA_INFORMATION EaInformation;
    FILE_ACCESS_INFORMATION AccessInformation;
    FILE_POSITION_INFORMATION PositionInformation;
    FILE_MODE_INFORMATION ModeInformation;
    FILE_ALIGNMENT_INFORMATION AlignmentInformation;
    FILE_NAME_INFORMATION NameInformation;
} FILE_ALL_INFORMATION, *PFILE_ALL_INFORMATION;

typedef struct _FILE_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    WCHAR FileName[1];
} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

// FILE_DIRECTORY_INFORMATION 结构体
typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

// FILE_ID_BOTH_DIR_INFORMATION 结构体
typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;

// 添加缺失的状态码
#ifndef STATUS_INVALID_INFO_CLASS
#define STATUS_INVALID_INFO_CLASS ((NTSTATUS)0xC0000003L)
#endif

// [新增] 补充缺失的目录信息结构体
typedef struct _FILE_NAMES_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;

typedef struct _FILE_ID_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;

// [新增] 补充枚举值
#ifndef FileNamesInformation
#define FileNamesInformation ((FILE_INFORMATION_CLASS)12)
#endif

#ifndef FileIdFullDirectoryInformation
#define FileIdFullDirectoryInformation ((FILE_INFORMATION_CLASS)38)
#endif

// -----------------------------------------------------------
// 3. 函数指针定义
// -----------------------------------------------------------

typedef NTSTATUS(NTAPI* P_NtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* P_NtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS(NTAPI* P_NtQueryAttributesFile)(POBJECT_ATTRIBUTES, PFILE_BASIC_INFORMATION);
typedef NTSTATUS(NTAPI* P_NtQueryFullAttributesFile)(POBJECT_ATTRIBUTES, PFILE_NETWORK_OPEN_INFORMATION);
typedef NTSTATUS(NTAPI* P_NtSetInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS(NTAPI* P_NtQueryDirectoryFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);
typedef NTSTATUS(NTAPI* P_NtQueryInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS(NTAPI* P_NtQueryDirectoryFileEx)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, ULONG, PUNICODE_STRING);
typedef NTSTATUS(NTAPI* P_NtQueryObject)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* P_NtDeleteFile)(POBJECT_ATTRIBUTES);
P_NtDeleteFile fpNtDeleteFile = NULL;

// CreateProcess 系列
typedef BOOL(WINAPI* P_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* P_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* P_CreateProcessAsUserW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* P_CreateProcessAsUserA)(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* P_CreateProcessWithTokenW)(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* P_CreateProcessWithLogonW)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef DWORD(WINAPI* P_GetFinalPathNameByHandleW)(HANDLE, LPWSTR, DWORD, DWORD);

// --- 全局变量 ---
wchar_t g_SandboxRoot[MAX_PATH] = { 0 };
wchar_t g_IpcPipeName[MAX_PATH] = { 0 };
wchar_t g_LauncherDir[MAX_PATH] = { 0 };

// --- 新增全局变量 ---
int g_HookMode = 2; // 默认模式 2 (全盘重定向)
std::wstring g_SystemDriveNt; // 例如 \??\C:
std::wstring g_WinDirNt;      // 例如 \??\C:\Windows

// 缓存的 NT 路径
std::wstring g_LauncherDirNt;
std::wstring g_UserProfileNt;
std::wstring g_UserProfileNtShort;
std::wstring g_UsersDirNt;      // [新增] Users 根目录 (长路径)
std::wstring g_UsersDirNtShort; // [新增] Users 根目录 (短路径)
std::wstring g_ProgramDataNt;
std::wstring g_ProgramDataNtShort;
std::wstring g_PublicNt;

// 定义目录项结构 用于缓存
struct CachedDirEntry {
    std::wstring FileName;
    std::wstring ShortName;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;   // FileSize
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
};

// 目录上下文 用于维护每个句柄的状态
struct DirContext {
    std::vector<CachedDirEntry> Entries;
    size_t CurrentIndex = 0;
    bool IsInitialized = false;
    std::wstring SearchPattern; // [新增] 保存当前的搜索模式
};

// 全局映射表：Handle -> Context
std::map<HANDLE, DirContext*> g_DirContextMap;
std::shared_mutex g_DirContextMutex; // 读写锁

// 原始 NtClose 指针 (需要 Hook 它来清理内存)
typedef NTSTATUS(NTAPI* P_NtClose)(HANDLE);
P_NtClose fpNtClose = NULL;

// --- 设备路径映射缓存 ---
std::vector<std::pair<std::wstring, std::wstring>> g_DeviceMap;

void RefreshDeviceMap() {
    g_DeviceMap.clear();
    wchar_t drives[512];
    if (GetLogicalDriveStringsW(512, drives)) {
        wchar_t* drive = drives;
        while (*drive) {
            // drive 是 "C:\" 我们需要 "C:"
            std::wstring driveStr = drive;
            if (!driveStr.empty() && driveStr.back() == L'\\') driveStr.pop_back();

            wchar_t devicePath[MAX_PATH];
            // QueryDosDeviceW("C:", ...) -> "\Device\HarddiskVolume1"
            if (QueryDosDeviceW(driveStr.c_str(), devicePath, MAX_PATH)) {
                g_DeviceMap.push_back({ std::wstring(devicePath), driveStr });
            }
            drive += wcslen(drive) + 1;
        }
    }
}

// 将 \Device\HarddiskVolumeX\Path 转换为 \??\C:\Path
std::wstring DevicePathToNtPath(const std::wstring& devicePath) {
    // 注意：不再这里调用 RefreshDeviceMap() 依赖 InitHookThread 初始化
    // 如果 g_DeviceMap 为空 说明初始化未完成或失败 直接返回原路径
    if (g_DeviceMap.empty()) return devicePath;

    for (const auto& pair : g_DeviceMap) {
        const std::wstring& devPrefix = pair.first;
        const std::wstring& driveLetter = pair.second;

        if (devicePath.find(devPrefix) == 0) {
            if (devicePath.length() == devPrefix.length() || devicePath[devPrefix.length()] == L'\\') {
                std::wstring suffix = devicePath.substr(devPrefix.length());
                return L"\\??\\" + driveLetter + suffix;
            }
        }
    }
    return devicePath;
}

thread_local bool g_IsInHook = false;

// 原始函数指针
P_NtCreateFile fpNtCreateFile = NULL;
P_NtOpenFile fpNtOpenFile = NULL;
P_NtQueryAttributesFile fpNtQueryAttributesFile = NULL;
P_NtQueryFullAttributesFile fpNtQueryFullAttributesFile = NULL;
P_NtSetInformationFile fpNtSetInformationFile = NULL;
P_NtQueryDirectoryFile fpNtQueryDirectoryFile = NULL;
P_NtQueryDirectoryFileEx fpNtQueryDirectoryFileEx = NULL;
P_NtQueryInformationFile fpNtQueryInformationFile = NULL;
P_NtQueryObject fpNtQueryObject = NULL;

P_CreateProcessW fpCreateProcessW = NULL;
P_CreateProcessA fpCreateProcessA = NULL;
P_CreateProcessAsUserW fpCreateProcessAsUserW = NULL;
P_CreateProcessAsUserA fpCreateProcessAsUserA = NULL;
P_CreateProcessWithTokenW fpCreateProcessWithTokenW = NULL;
P_CreateProcessWithLogonW fpCreateProcessWithLogonW = NULL;
P_GetFinalPathNameByHandleW fpGetFinalPathNameByHandleW = NULL;

// --- 调试日志 ---
void DebugLog(const wchar_t* format, ...) {
    DWORD lastErr = GetLastError();
    wchar_t buffer[2048];
    va_list args;
    va_start(args, format);
    _vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, format, args);
    va_end(args);

    OutputDebugStringW(buffer);
    SetLastError(lastErr);
}

// --- 辅助工具 ---

bool IsPipeOrDevice(LPCWSTR path) {
    if (!path) return false;
    if (wcsstr(path, L"NamedPipe")) return true;
    if (wcsstr(path, L"Pipe\\")) return true;
    if (wcsstr(path, L"PIPE\\")) return true;
    if (wcsstr(path, L"pipe\\")) return true;
    if (wcsstr(path, L"ConDrv")) return true;
    if (wcsstr(path, L"CONIN$")) return true;
    if (wcsstr(path, L"CONOUT$")) return true;
    return false;
}

void RecursiveCreateDirectory(wchar_t* path) {
    if (!path || !*path) return;
    DWORD attr = GetFileAttributesW(path);
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) return;
    wchar_t* p = wcsrchr(path, L'\\');
    if (!p) p = wcsrchr(path, L'/');
    if (p) {
        wchar_t saved = *p;
        *p = L'\0';
        RecursiveCreateDirectory(path);
        *p = saved;
    }
    CreateDirectoryW(path, NULL);
}

void EnsureDirectoryExistsNT(LPCWSTR ntPath) {
    if (wcsncmp(ntPath, L"\\??\\", 4) == 0) {
        LPCWSTR dosPath = ntPath + 4;
        wchar_t path[MAX_PATH];
        wcscpy_s(path, MAX_PATH, dosPath);
        PathRemoveFileSpecW(path);
        RecursiveCreateDirectory(path);
    }
}

std::wstring NtPathToDosPath(const std::wstring& ntPath) {
    if (ntPath.rfind(L"\\??\\", 0) == 0) {
        return ntPath.substr(4);
    }
    // [新增] 处理 \Device\HarddiskVolumeX 格式遗漏的情况
    // 如果无法转换为 DOS 路径 返回空字符串 避免 FindFirstFile 访问错误的路径
    if (ntPath.find(L"\\Device\\") == 0) {
        return L"";
    }
    return ntPath;
}

std::wstring ResolvePathFromAttr(POBJECT_ATTRIBUTES attr) {
    std::wstring fullPath;

    if (attr->RootDirectory) {
        ULONG len = 0;
        fpNtQueryObject(attr->RootDirectory, ObjectNameInformation, NULL, 0, &len);
        if (len > 0) {
            std::vector<BYTE> buffer(len);
            if (NT_SUCCESS(fpNtQueryObject(attr->RootDirectory, ObjectNameInformation, buffer.data(), len, &len))) {
                POBJECT_NAME_INFORMATION nameInfo = (POBJECT_NAME_INFORMATION)buffer.data();
                if (nameInfo->Name.Buffer) {
                    fullPath.assign(nameInfo->Name.Buffer, nameInfo->Name.Length / sizeof(WCHAR));
                }
            }
        }
        if (!fullPath.empty() && fullPath.back() != L'\\') {
            fullPath += L'\\';
        }
    }

    if (attr->ObjectName && attr->ObjectName->Buffer) {
        fullPath.append(attr->ObjectName->Buffer, attr->ObjectName->Length / sizeof(WCHAR));
    }

    return fullPath;
}

// [新增] 不区分大小写的字符串包含检查
bool ContainsCaseInsensitive(const std::wstring& str, const std::wstring& sub) {
    auto it = std::search(
        str.begin(), str.end(),
        sub.begin(), sub.end(),
        [](wchar_t ch1, wchar_t ch2) {
            return towlower(ch1) == towlower(ch2);
        }
    );
    return (it != str.end());
}

// [修改] 检查路径是否匹配前缀 并进行映射
bool CheckAndMap(const std::wstring& fullPath, const std::wstring& prefix, const std::wstring& replacement, std::wstring& outTarget) {
    if (prefix.empty()) return false;
    size_t pLen = prefix.length();

    // 检查前缀匹配 (不区分大小写)
    if (fullPath.length() >= pLen && _wcsnicmp(fullPath.c_str(), prefix.c_str(), pLen) == 0) {
        // 确保匹配的是完整目录名 (例如匹配 C:\User 而不是 C:\UsersOld)
        // 或者是完全相等
        if (fullPath.length() == pLen || fullPath[pLen] == L'\\') {
            outTarget += replacement;

            // 提取相对路径
            std::wstring rel = fullPath.substr(pLen);

            // 拼接逻辑优化：避免双斜杠
            if (!rel.empty()) {
                // 如果 outTarget 结尾有 \ 且 rel 开头有 \ 去掉一个
                if (!outTarget.empty() && outTarget.back() == L'\\' && rel[0] == L'\\') {
                    rel.erase(0, 1);
                }
                // 如果 outTarget 结尾没有 \ 且 rel 开头没有 \ 补一个 (除非 replacement 为空且 rel 为空)
                else if (!outTarget.empty() && outTarget.back() != L'\\' && rel[0] != L'\\') {
                    outTarget += L"\\";
                }
            }

            outTarget += rel;
            return true;
        }
    }
    return false;
}

// [新增] 检查路径是否在白名单内 (仅用于 hookfile=3)
bool IsPathAllowed(const std::wstring& ntPath) {
    // 1. 允许访问启动器目录
    if (!g_LauncherDirNt.empty() && ContainsCaseInsensitive(ntPath, g_LauncherDirNt)) return true;

    // 2. 允许访问 Windows 目录
    if (!g_WinDirNt.empty() && ContainsCaseInsensitive(ntPath, g_WinDirNt)) return true;

    // 3. 特殊处理：允许访问系统盘根目录 (为了能找到 Windows)
    // 但不允许访问根目录下的其他文件 这将在目录列举时过滤
    if (!g_SystemDriveNt.empty()) {
        // 精确匹配 \??\C: 或 \??\C: (注意：移除末尾的反斜杠以免造成续行注释错误)
        if (_wcsnicmp(ntPath.c_str(), g_SystemDriveNt.c_str(), g_SystemDriveNt.length()) == 0) {
            // 如果长度相等 或者是根目录反斜杠
            if (ntPath.length() == g_SystemDriveNt.length()) return true;
            if (ntPath.length() == g_SystemDriveNt.length() + 1 && ntPath.back() == L'\\') return true;
        }
    }

    // 4. 允许访问管道和设备 (防止程序崩溃)
    if (IsPipeOrDevice(ntPath.c_str())) return true;

    return false;
}

// [修改] 检查路径是否需要重定向
bool ShouldRedirect(const std::wstring& fullNtPath, std::wstring& targetPath) {
    if (g_SandboxRoot[0] == L'\0') return false;
    if (IsPipeOrDevice(fullNtPath.c_str())) return false;
    if (fullNtPath.rfind(L"\\??\\", 0) != 0) return false;
    if (ContainsCaseInsensitive(fullNtPath, g_SandboxRoot)) return false;

    // [新增] 模式 1 判断：仅重定向系统分区和启动器目录
    if (g_HookMode == 1) {
        bool isSystem = (!g_SystemDriveNt.empty() && _wcsnicmp(fullNtPath.c_str(), g_SystemDriveNt.c_str(), g_SystemDriveNt.length()) == 0);
        bool isLauncher = (!g_LauncherDirNt.empty() && ContainsCaseInsensitive(fullNtPath, g_LauncherDirNt));

        // 如果既不是系统盘 也不是启动器目录 不重定向 (直接访问真实路径)
        if (!isSystem && !isLauncher) {
            return false;
        }
    }

    // [新增] 模式 3 判断：虽然限制访问 但只要允许访问的路径 都进行重定向
    // 所以模式 3 的重定向逻辑与模式 2 相同 区别在于 Detour_NtCreateFile 里的拦截

    targetPath = L"\\??\\";
    targetPath += g_SandboxRoot;
    if (targetPath.back() == L'\\') targetPath.pop_back();

    // --- 1. 检查是否在启动器目录内 ---
    if (CheckAndMap(fullNtPath, g_LauncherDirNt, L"", targetPath)) return true;

    // --- 2. 检查当前用户目录 (user\current) ---
    if (CheckAndMap(fullNtPath, g_UserProfileNt, L"\\Users\\Current", targetPath) ||
        CheckAndMap(fullNtPath, g_UserProfileNtShort, L"\\Users\\Current", targetPath)) {
        return true;
    }

    // --- 3. 检查所有用户目录/ProgramData (user\all) ---
    if (CheckAndMap(fullNtPath, g_ProgramDataNt, L"\\Users\\All", targetPath) ||
        CheckAndMap(fullNtPath, g_ProgramDataNtShort, L"\\Users\\All", targetPath)) {
        return true;
    }

    // --- 4. 检查公用目录 (user\public) ---
    if (CheckAndMap(fullNtPath, g_PublicNt, L"\\Users\\Public", targetPath)) {
        return true;
    }

    // --- [新增] 5. 检查 Users 根目录 ---
    // 必须放在 user\current 和 user\public 之后
    // 映射: C:\Users -> \Users (即 Data\Users)
    // 映射: C:\Users\Other -> \Users\Other (即 Data\Users\Other)
    if (CheckAndMap(fullNtPath, g_UsersDirNt, L"\\Users", targetPath) ||
        CheckAndMap(fullNtPath, g_UsersDirNtShort, L"\\Users", targetPath)) {
        return true;
    }

    // --- 5. 默认绝对路径映射 ---
    std::wstring relPath = fullNtPath.substr(4);
    std::replace(relPath.begin(), relPath.end(), L'/', L'\\');
    size_t colonPos = relPath.find(L':');
    if (colonPos != std::wstring::npos) {
        relPath.erase(colonPos, 1);
    }
    targetPath += L"\\";
    targetPath += relPath;
    return true;
}

void PerformCopyOnWrite(const std::wstring& sourceNtPath, const std::wstring& targetNtPath) {
    std::wstring sourceDos = NtPathToDosPath(sourceNtPath);
    std::wstring targetDos = NtPathToDosPath(targetNtPath);

    DWORD srcAttrs = GetFileAttributesW(sourceDos.c_str());
    if (srcAttrs == INVALID_FILE_ATTRIBUTES) return;

    // 如果目标已存在 不需要复制
    if (GetFileAttributesW(targetDos.c_str()) != INVALID_FILE_ATTRIBUTES) return;

    // 1. 确保父目录存在
    wchar_t dirBuf[MAX_PATH];
    wcscpy_s(dirBuf, targetDos.c_str());
    PathRemoveFileSpecW(dirBuf);
    RecursiveCreateDirectory(dirBuf);

    // 2. 根据类型处理
    if (srcAttrs & FILE_ATTRIBUTE_DIRECTORY) {
        // 如果是目录 直接在沙盒创建空目录即可
        // 不需要复制内容 因为后续访问内容时会通过 BuildMergedDirectoryList 合并显示
        CreateDirectoryW(targetDos.c_str(), NULL);
    } else {
        // 如果是文件 执行复制
        DebugLog(L"Migrating: %s -> %s", sourceDos.c_str(), targetDos.c_str());
        CopyFileW(sourceDos.c_str(), targetDos.c_str(), TRUE);
    }
}

void ProcessQueryData(PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    // 占位符
}

struct RecursionGuard {
    RecursionGuard() { g_IsInHook = true; }
    ~RecursionGuard() { g_IsInHook = false; }
};

// --- NTDLL Hooks ---

// 辅助：将 WIN32_FIND_DATAW 转换为内部缓存格式
CachedDirEntry ConvertFindData(const WIN32_FIND_DATAW& fd) {
    CachedDirEntry entry;
    entry.FileName = fd.cFileName;
    entry.ShortName = fd.cAlternateFileName;
    entry.FileAttributes = fd.dwFileAttributes;

    entry.CreationTime.LowPart = fd.ftCreationTime.dwLowDateTime;
    entry.CreationTime.HighPart = fd.ftCreationTime.dwHighDateTime;

    entry.LastAccessTime.LowPart = fd.ftLastAccessTime.dwLowDateTime;
    entry.LastAccessTime.HighPart = fd.ftLastAccessTime.dwHighDateTime;

    entry.LastWriteTime.LowPart = fd.ftLastWriteTime.dwLowDateTime;
    entry.LastWriteTime.HighPart = fd.ftLastWriteTime.dwHighDateTime;

    entry.ChangeTime = entry.LastWriteTime; // Win32 没有 ChangeTime 暂用 WriteTime

    entry.EndOfFile.LowPart = fd.nFileSizeLow;
    entry.EndOfFile.HighPart = fd.nFileSizeHigh;

    entry.AllocationSize = entry.EndOfFile; // 简化处理
    return entry;
}

// [修复] 辅助：判断是否为驱动器根目录 (如 C: 或 C:\)
bool IsDriveRoot(const std::wstring& path) {
    if (path.empty()) return false;
    // 匹配 C:
    if (path.length() == 2 && path[1] == L':') return true;
    // 匹配 C:\ (注意：不匹配 C:\Windows)
    if (path.length() == 3 && path[1] == L':' && path[2] == L'\\') return true;
    return false;
}

// 核心：构建合并后的文件列表
void BuildMergedDirectoryList(const std::wstring& realPath, const std::wstring& sandboxPath, const std::wstring& pattern, std::vector<CachedDirEntry>& outList) {
    std::map<std::wstring, CachedDirEntry> mergedMap;

    // 1. 扫描真实目录
    if (!realPath.empty()) {
        std::wstring searchPath = realPath;
        if (searchPath.back() != L'\\') searchPath += L"\\";
        searchPath += pattern;

        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                std::wstring key = fd.cFileName;
                std::transform(key.begin(), key.end(), key.begin(), towlower);
                mergedMap[key] = ConvertFindData(fd);
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    // 2. 扫描沙盒目录
    if (!sandboxPath.empty()) {
        std::wstring searchPath = sandboxPath;
        if (searchPath.back() != L'\\') searchPath += L"\\";
        searchPath += pattern;

        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

                std::wstring key = fd.cFileName;
                std::transform(key.begin(), key.end(), key.begin(), towlower);

                if (IsTombstone(fd.dwFileAttributes)) {
                    mergedMap.erase(key);
                } else {
                    mergedMap[key] = ConvertFindData(fd);
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    // 3. [关键修复] 仅在非根目录时添加 . 和 ..
    // 驱动器根目录 (C:\) 不应该包含这些条目 否则会导致 Explorer 路径解析错误
    if (!IsDriveRoot(realPath)) {
        CachedDirEntry dotEntry = {};
        dotEntry.FileName = L".";
        dotEntry.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        outList.push_back(dotEntry);

        CachedDirEntry dotDotEntry = {};
        dotDotEntry.FileName = L"..";
        dotDotEntry.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        outList.push_back(dotDotEntry);
    }

    // 4. 转为 Vector
    for (const auto& pair : mergedMap) {
        outList.push_back(pair.second);
    }
}

// 辅助：检查 NT 路径对应的文件是否存在
bool NtPathExists(const std::wstring& ntPath) {
    std::wstring dosPath = NtPathToDosPath(ntPath);
    DWORD attrs = GetFileAttributesW(dosPath.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES;
}

NTSTATUS NTAPI Detour_NtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
) {
    if (g_IsInHook) return fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
    RecursionGuard guard;

    std::wstring fullNtPath = ResolvePathFromAttr(ObjectAttributes);

    // [新增] 模式 3：白名单拦截
    if (g_HookMode == 3) {
        // 如果路径不在白名单内 直接返回“文件未找到”
        // 注意：需要先处理 \Device\ 路径转换 确保判断准确
        std::wstring checkPath = fullNtPath;
        if (checkPath.find(L"\\Device\\") == 0) {
            checkPath = DevicePathToNtPath(checkPath);
        }

        if (!IsPathAllowed(checkPath)) {
            // 对程序隐藏：返回对象未找到
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }
    std::wstring targetNtPath;

    // 检查是否匹配重定向规则
    if (ShouldRedirect(fullNtPath, targetNtPath)) {

        bool isDirectory = (CreateOptions & FILE_DIRECTORY_FILE) != 0;

        // [修复 1] 完善写入判断逻辑
        // 只要是创建、覆盖、甚至 OpenIf (如果不存在则创建) 都视为写入意图
        bool isWrite = (DesiredAccess & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA));

        if (CreateDisposition == FILE_CREATE ||
            CreateDisposition == FILE_SUPERSEDE ||
            CreateDisposition == FILE_OVERWRITE ||
            CreateDisposition == FILE_OVERWRITE_IF ||
            CreateDisposition == FILE_OPEN_IF) {
            isWrite = true;
        }

        // 检查文件存在性
        bool sandboxExists = NtPathExists(targetNtPath);
        bool realExists = NtPathExists(fullNtPath);

        bool shouldRedirect = false;

        // **修复关键点2: 目录的读取操作不重定向**
        if (isDirectory && !isWrite) {
            // 对于目录的读取操作(列举文件),始终打开真实目录
            // 目录合并逻辑在 NtQueryDirectoryFile 中处理
            shouldRedirect = false;
            if (sandboxExists) {
                std::wstring sandboxDosPath = NtPathToDosPath(targetNtPath);
                DWORD attrs = GetFileAttributesW(sandboxDosPath.c_str());
                if (IsTombstone(attrs)) {
                    return STATUS_OBJECT_NAME_NOT_FOUND;
                }
            }
            if (!realExists && sandboxExists) {
                shouldRedirect = true;
            } else {
                // 打开真实目录(目录合并在查询时处理)
                return fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
            }
        } else if (isWrite) {
            // --- 写入操作逻辑 (包括目录创建) ---
            if (sandboxExists) {
                shouldRedirect = true;
            } else if (realExists) {
                PerformCopyOnWrite(fullNtPath, targetNtPath);
                shouldRedirect = true;
            } else {
                shouldRedirect = true; // 新建文件/目录 -> 强制重定向到沙盒
            }
        } else {
            // --- 文件的读取操作逻辑 ---
            if (sandboxExists) {
                // 检查是否为墓碑文件 (隐藏+系统)
                std::wstring sandboxDosPath = NtPathToDosPath(targetNtPath);
                DWORD attrs = GetFileAttributesW(sandboxDosPath.c_str());
                if (IsTombstone(attrs)) {
                    return STATUS_OBJECT_NAME_NOT_FOUND;
                }
                shouldRedirect = true;
            } else if (realExists) {
                // 穿透读取：直接读取原文件 不重定向
                shouldRedirect = false;
                return fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
            } else {
                // 都不存在 重定向到沙盒以报错
                shouldRedirect = true;
            }
        }

        if (shouldRedirect) {
            UNICODE_STRING uStr;
            RtlInitUnicodeString(&uStr, targetNtPath.c_str());

            PUNICODE_STRING oldName = ObjectAttributes->ObjectName;
            HANDLE oldRoot = ObjectAttributes->RootDirectory;

            ObjectAttributes->ObjectName = &uStr;
            ObjectAttributes->RootDirectory = NULL;

            // 确保目标目录存在
            if (isWrite || CreateDisposition == FILE_CREATE || CreateDisposition == FILE_OPEN_IF || CreateDisposition == FILE_OVERWRITE_IF || CreateDisposition == FILE_SUPERSEDE) {
                EnsureDirectoryExistsNT(targetNtPath.c_str());
            }

            NTSTATUS status = fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

            ObjectAttributes->ObjectName = oldName;
            ObjectAttributes->RootDirectory = oldRoot;

            return status;
        }
    }

    return fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS NTAPI Detour_NtOpenFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
) {
    // 如果你的实现是直接转发给 Detour_NtCreateFile 则不需要在这里添加
    // 因为 Detour_NtCreateFile 已经有了拦截逻辑
    // return Detour_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, NULL, 0, ShareAccess, FILE_OPEN, OpenOptions, NULL, 0);

    // --- 如果你的实现是调用原始 fpNtOpenFile 请使用以下代码 ---
    if (g_IsInHook) return fpNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
    RecursionGuard guard;

    // [新增] 模式 3：白名单拦截
    if (g_HookMode == 3) {
        std::wstring fullNtPath = ResolvePathFromAttr(ObjectAttributes);

        // 确保转换为 NT 路径以便 IsPathAllowed 识别
        if (fullNtPath.find(L"\\Device\\") == 0) {
            fullNtPath = DevicePathToNtPath(fullNtPath);
        }

        if (!IsPathAllowed(fullNtPath)) {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }
    return Detour_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, NULL, 0, ShareAccess, FILE_OPEN, OpenOptions, NULL, 0);
}

// 辅助：获取文件句柄对应的路径
std::wstring GetPathFromHandle(HANDLE hFile) {
    ULONG len = 0;
    fpNtQueryObject(hFile, ObjectNameInformation, NULL, 0, &len);
    if (len == 0) return L"";

    std::vector<BYTE> buffer(len);
    if (!NT_SUCCESS(fpNtQueryObject(hFile, ObjectNameInformation, buffer.data(), len, &len))) return L"";

    POBJECT_NAME_INFORMATION nameInfo = (POBJECT_NAME_INFORMATION)buffer.data();
    if (!nameInfo->Name.Buffer) return L"";

    return std::wstring(nameInfo->Name.Buffer, nameInfo->Name.Length / sizeof(WCHAR));
}

// [新增] 创建一个空的占位文件
void CreateDummyFile(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), 0, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
}

// [修改] Detour_NtDeleteFile
NTSTATUS NTAPI Detour_NtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes) {
    if (g_IsInHook) return fpNtDeleteFile(ObjectAttributes);
    RecursionGuard guard;

    std::wstring fullNtPath = ResolvePathFromAttr(ObjectAttributes);

    // [关键] 强制转换为 NT 路径
    if (fullNtPath.find(L"\\Device\\") == 0) {
        fullNtPath = DevicePathToNtPath(fullNtPath);
    }

    std::wstring targetNtPath;

    if (ShouldRedirect(fullNtPath, targetNtPath)) {
        std::wstring targetDosPath = NtPathToDosPath(targetNtPath);
        std::wstring fullDosPath = NtPathToDosPath(fullNtPath);

        DWORD sandboxAttrs = GetFileAttributesW(targetDosPath.c_str());
        bool sandboxExists = (sandboxAttrs != INVALID_FILE_ATTRIBUTES);

        DWORD realAttrs = GetFileAttributesW(fullDosPath.c_str());
        bool realExists = (realAttrs != INVALID_FILE_ATTRIBUTES);

        // --- 情况 1: 沙盒中存在文件 ---
        if (sandboxExists) {
            UNICODE_STRING uStr;
            RtlInitUnicodeString(&uStr, targetNtPath.c_str());
            PUNICODE_STRING oldName = ObjectAttributes->ObjectName;
            HANDLE oldRoot = ObjectAttributes->RootDirectory;
            ObjectAttributes->ObjectName = &uStr;
            ObjectAttributes->RootDirectory = NULL;
            NTSTATUS status = fpNtDeleteFile(ObjectAttributes);
            ObjectAttributes->ObjectName = oldName;
            ObjectAttributes->RootDirectory = oldRoot;
            return status;
        }
        // --- 情况 2: 仅真实路径有文件 (伪删除) ---
        else if (realExists) {
            // 1. 确保父目录存在
            std::wstring parentDir = targetDosPath;
            size_t lastSlash = parentDir.find_last_of(L'\\');
            if (lastSlash != std::wstring::npos) {
                parentDir = parentDir.substr(0, lastSlash);
                std::vector<wchar_t> buf(parentDir.begin(), parentDir.end());
                buf.push_back(0);
                RecursiveCreateDirectory(buf.data());
            }

            // 2. 创建墓碑
            HANDLE hFile = CreateFileW(targetDosPath.c_str(),
                                       GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                       FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);

            if (hFile != INVALID_HANDLE_VALUE) {
                CloseHandle(hFile);
                return STATUS_SUCCESS;
            } else {
                // 创建失败 返回错误 禁止回退
                return STATUS_ACCESS_DENIED;
            }
        }
        // --- 情况 3: 都不存在 ---
        else {
            // 重定向到沙盒以触发“文件未找到”错误
            UNICODE_STRING uStr;
            RtlInitUnicodeString(&uStr, targetNtPath.c_str());
            PUNICODE_STRING oldName = ObjectAttributes->ObjectName;
            HANDLE oldRoot = ObjectAttributes->RootDirectory;
            ObjectAttributes->ObjectName = &uStr;
            ObjectAttributes->RootDirectory = NULL;
            NTSTATUS status = fpNtDeleteFile(ObjectAttributes);
            ObjectAttributes->ObjectName = oldName;
            ObjectAttributes->RootDirectory = oldRoot;
            return status;
        }
    }

    return fpNtDeleteFile(ObjectAttributes);
}

// [新增] 辅助：将文件转换为墓碑 (截断 + 隐藏 + 系统)
NTSTATUS ConvertToTombstone(const std::wstring& filePath) {
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    // 1. 尝试打开文件以修改属性和内容
    // 必须使用宽松的共享模式 因为应用程序此时正持有该文件的句柄
    hFile = CreateFileW(filePath.c_str(),
        GENERIC_WRITE | FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        DebugLog(L"Tombstone Failed: Open Error %d for %s", GetLastError(), filePath.c_str());
        return STATUS_ACCESS_DENIED;
    }

    NTSTATUS status = STATUS_SUCCESS;

    // 2. 截断为 0 字节
    FILE_END_OF_FILE_INFORMATION eofInfo;
    eofInfo.EndOfFile.QuadPart = 0;
    status = fpNtSetInformationFile(hFile, &iosb, &eofInfo, sizeof(eofInfo), FileEndOfFileInformation);

    if (!NT_SUCCESS(status)) {
        DebugLog(L"Tombstone Failed: Truncate Error 0x%X", status);
        CloseHandle(hFile);
        return status;
    }

    // 3. 设置属性为 Hidden + System
    FILE_BASIC_INFORMATION basicInfo = { 0 };
    // 为了安全 先查询现有时间 避免时间戳被清零
    status = fpNtQueryInformationFile(hFile, &iosb, &basicInfo, sizeof(basicInfo), FileBasicInformation);
    if (NT_SUCCESS(status)) {
        basicInfo.FileAttributes = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
        status = fpNtSetInformationFile(hFile, &iosb, &basicInfo, sizeof(basicInfo), FileBasicInformation);
    }

    if (!NT_SUCCESS(status)) {
        DebugLog(L"Tombstone Failed: SetAttr Error 0x%X", status);
    } else {
        DebugLog(L"Tombstone Created: %s", filePath.c_str());
    }

    CloseHandle(hFile);
    return status;
}

NTSTATUS NTAPI Detour_NtSetInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
) {
    if (g_IsInHook) return fpNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    RecursionGuard guard;

    // 1. 检查是否为删除操作
    bool isDelete = false;
    if (FileInformationClass == FileDispositionInformation) {
        isDelete = ((PFILE_DISPOSITION_INFORMATION)FileInformation)->DeleteFile;
    }
    else if (FileInformationClass == FileDispositionInformationEx) {
        isDelete = (((PFILE_DISPOSITION_INFORMATION_EX)FileInformation)->Flags & FILE_DISPOSITION_DELETE) != 0;
    }

    // 如果不是删除操作 或者请求取消删除 (Delete=FALSE) 直接放行
    if (!isDelete) {
        return fpNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    }

    // 2. 获取路径
    std::wstring rawPath = GetPathFromHandle(FileHandle);
    if (rawPath.empty()) {
        return fpNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    }

    // 3. 路径标准化
    std::wstring ntPath = DevicePathToNtPath(rawPath);
    std::wstring targetPath;

    // 4. 检查是否需要重定向
    if (!ShouldRedirect(ntPath, targetPath)) {
        return fpNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    }

    // 5. 判断目标位置
    // 构造沙盒根目录的 NT 路径前缀
    std::wstring sandboxRootNt = L"\\??\\";
    sandboxRootNt += g_SandboxRoot;

    // 检查句柄是否已经指向沙盒内的文件
    bool isHandleInSandbox = ContainsCaseInsensitive(ntPath, sandboxRootNt);

    std::wstring targetDosPath = NtPathToDosPath(targetPath); // 这是理论上的沙盒路径

    // --- 分支 A: 句柄指向沙盒内的文件 (CoW 副本) ---
    if (isHandleInSandbox) {
        // [关键修复] 绝对不能调用原始的 Delete 否则副本会被物理删除
        // 我们需要将这个副本“原地”转化为墓碑

        std::wstring sandboxDosPath = NtPathToDosPath(ntPath);

        NTSTATUS status = ConvertToTombstone(sandboxDosPath);

        if (NT_SUCCESS(status)) {
            // 欺骗 App：删除成功
            IoStatusBlock->Status = STATUS_SUCCESS;
            IoStatusBlock->Information = 0;
            return STATUS_SUCCESS;
        } else {
            // 如果转化失败（例如文件被独占锁定） 我们只能返回错误
            // 依然不能调用原始删除
            IoStatusBlock->Status = status;
            return status;
        }
    }

    // --- 分支 B: 句柄指向真实文件 (尚未 CoW) ---
    // 这种情况通常发生在你没有 DELETE 权限打开文件 却尝试用 SetInfo 删除
    // 或者 NtCreateFile Hook 漏掉了某些情况
    else {
        std::wstring realDosPath = NtPathToDosPath(ntPath);
        DWORD realAttrs = GetFileAttributesW(realDosPath.c_str());

        if (realAttrs != INVALID_FILE_ATTRIBUTES) {
            // 1. 确保沙盒父目录存在
            std::wstring parentDir = targetDosPath;
            size_t lastSlash = parentDir.find_last_of(L'\\');
            if (lastSlash != std::wstring::npos) {
                parentDir = parentDir.substr(0, lastSlash);
                std::vector<wchar_t> buf(parentDir.begin(), parentDir.end());
                buf.push_back(0);
                RecursiveCreateDirectory(buf.data());
            }

            // 2. 创建新的墓碑文件
            HANDLE hTombstone = CreateFileW(
                targetDosPath.c_str(),
                GENERIC_WRITE,
                0,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
                NULL
            );

            if (hTombstone != INVALID_HANDLE_VALUE) {
                CloseHandle(hTombstone);
                DebugLog(L"Fake Delete Created Tombstone: %s", targetDosPath.c_str());
                IoStatusBlock->Status = STATUS_SUCCESS;
                IoStatusBlock->Information = 0;
                return STATUS_SUCCESS;
            } else {
                DebugLog(L"Fake Delete Failed to Create Tombstone: %s", targetDosPath.c_str());
                IoStatusBlock->Status = STATUS_ACCESS_DENIED;
                return STATUS_ACCESS_DENIED;
            }
        }
    }

    // 如果逻辑走到这里 说明既不在沙盒 真实路径也没文件 或者其他异常
    // 调用原始函数让系统处理（通常返回文件未找到）
    return fpNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

NTSTATUS NTAPI Detour_NtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation) {
    if (g_IsInHook) return fpNtQueryAttributesFile(ObjectAttributes, FileInformation);
    RecursionGuard guard;

    std::wstring fullNtPath = ResolvePathFromAttr(ObjectAttributes);

    // [新增] 模式 3：白名单拦截
    if (g_HookMode == 3) {
        std::wstring checkPath = fullNtPath;
        // 确保转换为 NT 路径
        if (checkPath.find(L"\\Device\\") == 0) {
            checkPath = DevicePathToNtPath(checkPath);
        }

        if (!IsPathAllowed(checkPath)) {
            // 欺骗程序：文件不存在
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }

    std::wstring targetNtPath;
    if (ShouldRedirect(fullNtPath, targetNtPath)) {
        UNICODE_STRING uStr;
        RtlInitUnicodeString(&uStr, targetNtPath.c_str());
        PUNICODE_STRING oldName = ObjectAttributes->ObjectName;
        HANDLE oldRoot = ObjectAttributes->RootDirectory;
        ObjectAttributes->ObjectName = &uStr;
        ObjectAttributes->RootDirectory = NULL;
        NTSTATUS status = fpNtQueryAttributesFile(ObjectAttributes, FileInformation);
        ObjectAttributes->ObjectName = oldName;
        ObjectAttributes->RootDirectory = oldRoot;
        if (status == STATUS_SUCCESS) return status;
    }
    return fpNtQueryAttributesFile(ObjectAttributes, FileInformation);
}

NTSTATUS NTAPI Detour_NtQueryFullAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_NETWORK_OPEN_INFORMATION FileInformation) {
    if (g_IsInHook) return fpNtQueryFullAttributesFile(ObjectAttributes, FileInformation);
    RecursionGuard guard;

    std::wstring fullNtPath = ResolvePathFromAttr(ObjectAttributes);

    // [新增] 模式 3：白名单拦截
    if (g_HookMode == 3) {
        std::wstring checkPath = fullNtPath;
        // 确保转换为 NT 路径
        if (checkPath.find(L"\\Device\\") == 0) {
            checkPath = DevicePathToNtPath(checkPath);
        }

        if (!IsPathAllowed(checkPath)) {
            // 欺骗程序：文件不存在
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }

    std::wstring targetNtPath;
    if (ShouldRedirect(fullNtPath, targetNtPath)) {
        UNICODE_STRING uStr;
        RtlInitUnicodeString(&uStr, targetNtPath.c_str());
        PUNICODE_STRING oldName = ObjectAttributes->ObjectName;
        HANDLE oldRoot = ObjectAttributes->RootDirectory;
        ObjectAttributes->ObjectName = &uStr;
        ObjectAttributes->RootDirectory = NULL;
        NTSTATUS status = fpNtQueryFullAttributesFile(ObjectAttributes, FileInformation);
        ObjectAttributes->ObjectName = oldName;
        ObjectAttributes->RootDirectory = oldRoot;
        if (status == STATUS_SUCCESS) return status;
    }
    return fpNtQueryFullAttributesFile(ObjectAttributes, FileInformation);
}

// [新增] 智能获取真实路径和沙盒路径
bool GetRealAndSandboxPaths(HANDLE hFile, std::wstring& outRealDos, std::wstring& outSandboxDos) {
    // 1. 获取原始设备路径 (例如 \Device\HarddiskVolume2\Portable\Data\C)
    std::wstring rawPath = GetPathFromHandle(hFile);
    if (rawPath.empty()) return false;

    // 2. [关键修复] 转换为 NT DOS 路径 (例如 \??\D:\Portable\Data\C)
    std::wstring handleNtPath = DevicePathToNtPath(rawPath);

    // 构造沙盒的 NT 路径前缀用于比较
    std::wstring sandboxRootNt = L"\\??\\";
    sandboxRootNt += g_SandboxRoot;
    // 移除末尾斜杠以防万一 确保匹配准确
    if (sandboxRootNt.back() == L'\\') sandboxRootNt.pop_back();

    // 3. 检查句柄是否已经指向沙盒 (反向解析)
    // 使用不区分大小写的比较更安全 或者确保路径都已规范化
    if (handleNtPath.size() >= sandboxRootNt.size() &&
        _wcsnicmp(handleNtPath.c_str(), sandboxRootNt.c_str(), sandboxRootNt.size()) == 0) {

        // 句柄在沙盒内 例如: \??\D:\Portable\Data\C
        size_t rootLen = sandboxRootNt.length();

        // 提取相对部分: \C
        std::wstring relPath = handleNtPath.substr(rootLen);

        std::wstring realNtPath;

        // 简单启发式反向映射 (针对 \C\ 这种驱动器结构)
        if (relPath.length() >= 3 && relPath[0] == L'\\' && relPath[2] == L'\\') {
            // \C\Windows -> \??\C:\Windows
            wchar_t driveLetter = relPath[1];
            realNtPath = L"\\??\\";
            realNtPath += driveLetter;
            realNtPath += L":";
            realNtPath += relPath.substr(2);
        }
        // 针对根目录 \C
        else if (relPath.length() == 2 && relPath[0] == L'\\') {
             wchar_t driveLetter = relPath[1];
             realNtPath = L"\\??\\";
             realNtPath += driveLetter;
             realNtPath += L":";
             // 注意：这里不需要补斜杠 NtPathToDosPath 会处理为 C:
             // BuildMergedDirectoryList 拼接 pattern 时会补斜杠变成 C:\*
        }
        else {
            // 对于 Users 等特殊目录 如果需要支持反向合并 需要在这里添加逻辑
            // 比如检测 \Users 映射回 C:\Users
            // 目前暂不支持 返回 false
            return false;
        }

        outSandboxDos = NtPathToDosPath(handleNtPath);
        outRealDos = NtPathToDosPath(realNtPath);
        return true;
    }

    // 4. 句柄指向真实路径 (正向解析)
    else {
        std::wstring targetNtPath;
        // ShouldRedirect 内部已经处理了 \??\ 前缀检查 现在传入转换后的路径就能正常工作了
        if (ShouldRedirect(handleNtPath, targetNtPath)) {
            outRealDos = NtPathToDosPath(handleNtPath);
            outSandboxDos = NtPathToDosPath(targetNtPath);
            return true;
        }
    }

    return false;
}

// [新增] 生成简单的 FileId (基于文件名哈希)
LARGE_INTEGER GenerateFileId(const std::wstring& name) {
    LARGE_INTEGER id;
    std::hash<std::wstring> hasher;
    // 简单的哈希 确保非零
    size_t h = hasher(name);
    id.QuadPart = (LONGLONG)(h == 0 ? 1 : h);
    return id;
}

// [新增] 内部公共查询逻辑
NTSTATUS HandleDirectoryQuery(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
) {
    std::wstring rawPath = GetPathFromHandle(FileHandle);
    if (rawPath.empty()) return STATUS_INVALID_HANDLE;

    std::wstring ntDirPath = DevicePathToNtPath(rawPath);
    std::wstring targetPath;

    if (!ShouldRedirect(ntDirPath, targetPath)) {
        return STATUS_NOT_SUPPORTED;
    }

    std::vector<CachedDirEntry> localEntries;
    bool needsBuild = false;
    DirContext* ctx = nullptr;
    std::wstring currentPattern = L"*"; // 默认匹配所有

    // 获取请求的 Pattern (如果有)
    if (FileName && FileName->Length > 0) {
        currentPattern.assign(FileName->Buffer, FileName->Length / sizeof(wchar_t));
    }

    // --- 阶段 1: 检查是否需要构建 ---
    {
        std::shared_lock<std::shared_mutex> lock(g_DirContextMutex);

        // 逻辑变更：只要 Context 存在且已初始化 就不需要重新构建 (除非 RestartScan)
        // 我们总是构建完整的列表 (*) 所以不需要根据 FileName 重新构建

        if (RestartScan) {
            needsBuild = true;
        } else {
            auto it = g_DirContextMap.find(FileHandle);
            if (it == g_DirContextMap.end()) {
                needsBuild = true;
            } else {
                ctx = it->second;
                if (!ctx->IsInitialized) needsBuild = true;
            }
        }
    }

    // --- 阶段 2: 执行 I/O (无锁) ---
    if (needsBuild) {
        std::wstring realDosPath = NtPathToDosPath(ntDirPath);
        std::wstring sandboxDosPath = NtPathToDosPath(targetPath);

        // [关键修复] 总是构建完整列表 "*" 忽略当前的 FileName
        // 这样缓存中就包含了所有文件 后续过滤由输出阶段处理
        BuildMergedDirectoryList(realDosPath, sandboxDosPath, L"*", localEntries);
    }

    // --- 阶段 3: 更新上下文 ---
    {
        std::unique_lock<std::shared_mutex> lock(g_DirContextMutex);

        if (RestartScan) {
            auto it = g_DirContextMap.find(FileHandle);
            if (it != g_DirContextMap.end()) {
                delete it->second;
                g_DirContextMap.erase(it);
            }
            ctx = nullptr;
        }

        auto it = g_DirContextMap.find(FileHandle);
        if (it == g_DirContextMap.end()) {
            ctx = new DirContext();
            g_DirContextMap[FileHandle] = ctx;
        } else {
            ctx = it->second;
        }

        if (needsBuild) {
            ctx->Entries = std::move(localEntries);
            ctx->CurrentIndex = 0;
            ctx->IsInitialized = true;
        }

        // [关键修复] 更新搜索模式
        // 如果是 RestartScan 或者 第一次调用 (FileName != NULL) 更新 Pattern
        // 如果 FileName == NULL 保持之前的 Pattern (继续之前的搜索)
        if (RestartScan || (FileName && FileName->Length > 0)) {
            ctx->SearchPattern = currentPattern;
        }
        // 兜底：如果 Pattern 为空 设为 *
        if (ctx->SearchPattern.empty()) {
            ctx->SearchPattern = L"*";
        }
    }

    // --- 阶段 4: 填充缓冲区 ---
    std::shared_lock<std::shared_mutex> readLock(g_DirContextMutex);

    if (!ctx || !ctx->IsInitialized) {
        IoStatusBlock->Status = STATUS_UNSUCCESSFUL;
        return STATUS_UNSUCCESSFUL;
    }

    ULONG bytesWritten = 0;
    char* buffer = (char*)FileInformation;
    ULONG offset = 0;
    void* prevEntryPtr = nullptr;

    // 遍历列表
    while (ctx->CurrentIndex < ctx->Entries.size()) {
        const CachedDirEntry& entry = ctx->Entries[ctx->CurrentIndex];

        // [关键修复] 过滤逻辑：使用 PathMatchSpecW 进行通配符匹配
        // 如果不匹配 跳过此条目 继续下一个
        if (!PathMatchSpecW(entry.FileName.c_str(), ctx->SearchPattern.c_str())) {
            ctx->CurrentIndex++;
            continue;
        }

        // [新增] 模式 3：目录列举过滤
        if (g_HookMode == 3) {
            // 构造该条目的完整 NT 路径
            // ntDirPath 是当前列举的目录 (例如 \??\C:)
            std::wstring fullEntryPath = ntDirPath;
            if (fullEntryPath.back() != L'\\') fullEntryPath += L"\\";
            fullEntryPath += entry.FileName;

            // 检查该子项是否允许被看到
            // 逻辑：
            // 1. 如果它是白名单目录的前缀 (例如 C:\ -> C:\Windows) 允许
            // 2. 如果它在白名单目录内部 (例如 C:\Windows -> C:\Windows\System32) 允许

            bool isVisible = false;

            // 检查是否是允许路径本身或其子路径
            if (IsPathAllowed(fullEntryPath)) {
                isVisible = true;
            }
            // 特殊检查：如果当前条目是白名单路径的父级路径的一部分
            // 例如：白名单是 C:\Windows 当前列举 C:\ 条目是 Windows -> 可见
            // 当前列举 C:\ 条目是 Program Files -> 不可见
            else {
                // 检查 g_WinDirNt 是否以 fullEntryPath 开头
                if (!g_WinDirNt.empty() && ContainsCaseInsensitive(g_WinDirNt, fullEntryPath)) isVisible = true;
                if (!g_LauncherDirNt.empty() && ContainsCaseInsensitive(g_LauncherDirNt, fullEntryPath)) isVisible = true;
            }

            // 总是显示 . 和 ..
            if (entry.FileName == L"." || entry.FileName == L"..") isVisible = true;

            if (!isVisible) {
                ctx->CurrentIndex++;
                continue; // 跳过此条目 相当于隐藏
            }
        }

        ULONG fileNameBytes = (ULONG)(entry.FileName.length() * sizeof(wchar_t));
        ULONG entrySize = 0;

        // 计算大小
        switch (FileInformationClass) {
            case FileDirectoryInformation: entrySize = FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName) + fileNameBytes; break;
            case FileFullDirectoryInformation: entrySize = FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName) + fileNameBytes; break;
            case FileBothDirectoryInformation: entrySize = FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + fileNameBytes; break;
            case FileIdBothDirectoryInformation: entrySize = FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName) + fileNameBytes; break;
            case FileNamesInformation: entrySize = FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName) + fileNameBytes; break;
            case FileIdFullDirectoryInformation: entrySize = FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName) + fileNameBytes; break;
            default:
                IoStatusBlock->Status = STATUS_INVALID_INFO_CLASS;
                IoStatusBlock->Information = 0;
                return STATUS_INVALID_INFO_CLASS;
        }

        entrySize = (entrySize + 7) & ~7; // 8字节对齐

        if (offset + entrySize > Length) {
            if (prevEntryPtr) {
                *(ULONG*)prevEntryPtr = 0;
                IoStatusBlock->Status = STATUS_SUCCESS;
                IoStatusBlock->Information = bytesWritten;
                return STATUS_SUCCESS;
            } else {
                IoStatusBlock->Status = STATUS_BUFFER_OVERFLOW;
                IoStatusBlock->Information = 0;
                return STATUS_BUFFER_OVERFLOW;
            }
        }

        void* entryPtr = buffer + offset;
        memset(entryPtr, 0, entrySize);
        LARGE_INTEGER fileId = GenerateFileId(entry.FileName);

        // 填充数据
        switch (FileInformationClass) {
            case FileDirectoryInformation: {
                FILE_DIRECTORY_INFORMATION* info = (FILE_DIRECTORY_INFORMATION*)entryPtr;
                info->NextEntryOffset = entrySize;
                info->FileAttributes = entry.FileAttributes;
                info->CreationTime = entry.CreationTime;
                info->LastAccessTime = entry.LastAccessTime;
                info->LastWriteTime = entry.LastWriteTime;
                info->ChangeTime = entry.ChangeTime;
                info->EndOfFile = entry.EndOfFile;
                info->AllocationSize = entry.AllocationSize;
                info->FileNameLength = fileNameBytes;
                memcpy(info->FileName, entry.FileName.c_str(), fileNameBytes);
                break;
            }
            case FileFullDirectoryInformation: {
                FILE_FULL_DIR_INFORMATION* info = (FILE_FULL_DIR_INFORMATION*)entryPtr;
                info->NextEntryOffset = entrySize;
                info->FileAttributes = entry.FileAttributes;
                info->CreationTime = entry.CreationTime;
                info->LastAccessTime = entry.LastAccessTime;
                info->LastWriteTime = entry.LastWriteTime;
                info->ChangeTime = entry.ChangeTime;
                info->EndOfFile = entry.EndOfFile;
                info->AllocationSize = entry.AllocationSize;
                info->FileNameLength = fileNameBytes;
                info->EaSize = 0;
                memcpy(info->FileName, entry.FileName.c_str(), fileNameBytes);
                break;
            }
            case FileBothDirectoryInformation: {
                FILE_BOTH_DIR_INFORMATION* info = (FILE_BOTH_DIR_INFORMATION*)entryPtr;
                info->NextEntryOffset = entrySize;
                info->FileAttributes = entry.FileAttributes;
                info->CreationTime = entry.CreationTime;
                info->LastAccessTime = entry.LastAccessTime;
                info->LastWriteTime = entry.LastWriteTime;
                info->ChangeTime = entry.ChangeTime;
                info->EndOfFile = entry.EndOfFile;
                info->AllocationSize = entry.AllocationSize;
                info->FileNameLength = fileNameBytes;
                info->EaSize = 0;
                size_t shortLen = min(entry.ShortName.length(), 12);
                info->ShortNameLength = (CCHAR)(shortLen * sizeof(wchar_t));
                if (shortLen > 0) memcpy(info->ShortName, entry.ShortName.c_str(), shortLen * sizeof(wchar_t));
                memcpy(info->FileName, entry.FileName.c_str(), fileNameBytes);
                break;
            }
            case FileIdBothDirectoryInformation: {
                FILE_ID_BOTH_DIR_INFORMATION* info = (FILE_ID_BOTH_DIR_INFORMATION*)entryPtr;
                info->NextEntryOffset = entrySize;
                info->FileAttributes = entry.FileAttributes;
                info->CreationTime = entry.CreationTime;
                info->LastAccessTime = entry.LastAccessTime;
                info->LastWriteTime = entry.LastWriteTime;
                info->ChangeTime = entry.ChangeTime;
                info->EndOfFile = entry.EndOfFile;
                info->AllocationSize = entry.AllocationSize;
                info->FileNameLength = fileNameBytes;
                info->EaSize = 0;
                size_t shortLen = min(entry.ShortName.length(), 12);
                info->ShortNameLength = (CCHAR)(shortLen * sizeof(wchar_t));
                if (shortLen > 0) memcpy(info->ShortName, entry.ShortName.c_str(), shortLen * sizeof(wchar_t));
                info->FileId = fileId;
                memcpy(info->FileName, entry.FileName.c_str(), fileNameBytes);
                break;
            }
            case FileNamesInformation: {
                FILE_NAMES_INFORMATION* info = (FILE_NAMES_INFORMATION*)entryPtr;
                info->NextEntryOffset = entrySize;
                info->FileIndex = 0;
                info->FileNameLength = fileNameBytes;
                memcpy(info->FileName, entry.FileName.c_str(), fileNameBytes);
                break;
            }
            case FileIdFullDirectoryInformation: {
                FILE_ID_FULL_DIR_INFORMATION* info = (FILE_ID_FULL_DIR_INFORMATION*)entryPtr;
                info->NextEntryOffset = entrySize;
                info->FileAttributes = entry.FileAttributes;
                info->CreationTime = entry.CreationTime;
                info->LastAccessTime = entry.LastAccessTime;
                info->LastWriteTime = entry.LastWriteTime;
                info->ChangeTime = entry.ChangeTime;
                info->EndOfFile = entry.EndOfFile;
                info->AllocationSize = entry.AllocationSize;
                info->FileNameLength = fileNameBytes;
                info->EaSize = 0;
                info->FileId = fileId;
                memcpy(info->FileName, entry.FileName.c_str(), fileNameBytes);
                break;
            }
        }

        ctx->CurrentIndex++;
        bytesWritten += entrySize;
        offset += entrySize;
        prevEntryPtr = entryPtr;

        if (ReturnSingleEntry) {
            *(ULONG*)entryPtr = 0;
            break;
        }
    }

    if (prevEntryPtr) {
        *(ULONG*)prevEntryPtr = 0;
    }

    // 如果没有写入任何字节 说明没有更多文件了 (或者过滤后没有匹配项)
    if (bytesWritten == 0) {
        IoStatusBlock->Status = STATUS_NO_MORE_FILES;
        IoStatusBlock->Information = 0;
        return STATUS_NO_MORE_FILES;
    }

    IoStatusBlock->Status = STATUS_SUCCESS;
    IoStatusBlock->Information = bytesWritten;
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI Detour_NtQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
) {
    if (g_IsInHook) return fpNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
    RecursionGuard guard;

    // 调用公共处理逻辑
    NTSTATUS status = HandleDirectoryQuery(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);

    // 如果不需要重定向 (STATUS_NOT_SUPPORTED) 或句柄无效 调用原始函数
    if (status == STATUS_NOT_SUPPORTED || status == STATUS_INVALID_HANDLE) {
        return fpNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
    }

    // 模拟异步完成信号 (如果提供了 Event)
    if (NT_SUCCESS(status) && Event && Event != INVALID_HANDLE_VALUE) {
        SetEvent(Event);
    }

    // 注意：这里忽略了 ApcRoutine 因为手动模拟 APC 比较复杂且通常不需要
    return status;
}

NTSTATUS NTAPI Detour_NtQueryDirectoryFileEx(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName
) {
    if (g_IsInHook) return fpNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
    RecursionGuard guard;

    // 解析 Ex 标志位
    BOOLEAN restartScan = (QueryFlags & SL_RESTART_SCAN) != 0;
    BOOLEAN returnSingle = (QueryFlags & SL_RETURN_SINGLE_ENTRY) != 0;

    // 调用公共处理逻辑
    NTSTATUS status = HandleDirectoryQuery(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass, returnSingle, FileName, restartScan);

    if (status == STATUS_NOT_SUPPORTED || status == STATUS_INVALID_HANDLE) {
        return fpNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
    }

    if (NT_SUCCESS(status) && Event && Event != INVALID_HANDLE_VALUE) {
        SetEvent(Event);
    }

    return status;
}

NTSTATUS NTAPI Detour_NtQueryInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
    ULONG Length, FILE_INFORMATION_CLASS FileInformationClass
) {
    if (g_IsInHook) return fpNtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    RecursionGuard guard;
    return fpNtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

NTSTATUS NTAPI Detour_NtClose(HANDLE Handle) {
    // 清理 Context
    {
        std::unique_lock<std::shared_mutex> lock(g_DirContextMutex);
        auto it = g_DirContextMap.find(Handle);
        if (it != g_DirContextMap.end()) {
            delete it->second;
            g_DirContextMap.erase(it);
        }
    }

    // 调用原始 NtClose
    return fpNtClose(Handle);
}

// --- 路径处理辅助函数 ---

// 辅助：将 ANSI 转换为 Wide
std::wstring AnsiToWide(LPCSTR text) {
    if (!text) return L"";
    int size = MultiByteToWideChar(CP_ACP, 0, text, -1, NULL, 0);
    std::wstring res(size - 1, 0);
    MultiByteToWideChar(CP_ACP, 0, text, -1, &res[0], size);
    return res;
}

// 辅助：将 Wide 转换为 ANSI
std::string WideToAnsi(LPCWSTR text) {
    if (!text) return "";
    int size = WideCharToMultiByte(CP_ACP, 0, text, -1, NULL, 0, NULL, NULL);
    std::string res(size - 1, 0);
    WideCharToMultiByte(CP_ACP, 0, text, -1, &res[0], size, NULL, NULL);
    return res;
}

// 辅助：尝试重定向 DOS 路径 (输入 C:\... 输出 Z:\Portable\Data\C\...)
// 如果不需要重定向或重定向后文件/目录不存在 返回空字符串
std::wstring TryRedirectDosPath(LPCWSTR dosPath, bool isDirectory) {
    if (!dosPath || !*dosPath) return L"";

    wchar_t fullPath[MAX_PATH];
    if (GetFullPathNameW(dosPath, MAX_PATH, fullPath, NULL) == 0) return L"";

    std::wstring ntPath = L"\\??\\" + std::wstring(fullPath);
    std::wstring targetNtPath;

    if (ShouldRedirect(ntPath, targetNtPath)) {
        std::wstring targetDosPath = NtPathToDosPath(targetNtPath);
        DWORD attrs = GetFileAttributesW(targetDosPath.c_str());

        // 检查是否存在
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            // 如果我们需要的是目录 确保它是目录；如果是文件 确保它不是目录
            if (isDirectory) {
                if (attrs & FILE_ATTRIBUTE_DIRECTORY) return targetDosPath;
            } else {
                // 这里的逻辑稍微放宽 只要存在即可 因为有时候文件属性可能有误
                return targetDosPath;
            }
        }
    }
    return L"";
}

// 辅助：从命令行提取 EXE 路径
std::wstring GetTargetExePath(LPCWSTR lpApp, LPWSTR lpCmd) {
    if (lpApp && *lpApp) return lpApp;
    if (!lpCmd || !*lpCmd) return L"";

    std::wstring cmd = lpCmd;
    std::wstring exePath;
    if (cmd.front() == L'"') {
        size_t end = cmd.find(L'"', 1);
        if (end != std::wstring::npos) exePath = cmd.substr(1, end - 1);
    } else {
        size_t end = cmd.find(L' ');
        if (end != std::wstring::npos) exePath = cmd.substr(0, end);
        else exePath = cmd;
    }
    return exePath;
}

// --- IPC & Process Hooks ---

bool RequestInjectionFromLauncher(DWORD targetPid) {
    DWORD lastErr = GetLastError();
    wchar_t pipeName[MAX_PATH];
    if (g_IpcPipeName[0] != L'\0') {
        wcscpy_s(pipeName, MAX_PATH, g_IpcPipeName);
    } else {
        if (GetEnvironmentVariableW(L"YAP_IPC_PIPE", pipeName, MAX_PATH) == 0) {
            SetLastError(lastErr);
            return false;
        }
    }
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 5; i++) {
        hPipe = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) break;
        if (GetLastError() == ERROR_PIPE_BUSY) WaitNamedPipeW(pipeName, 500);
        Sleep(100);
    }
    if (hPipe == INVALID_HANDLE_VALUE) {
        SetLastError(lastErr);
        return false;
    }
    IpcMessage msg;
    msg.targetPid = targetPid;
    wcscpy_s(msg.workDir, L"");
    DWORD bytesWritten;
    WriteFile(hPipe, &msg, sizeof(msg), &bytesWritten, NULL);
    IpcResponse resp;
    DWORD bytesRead;
    bool result = false;
    if (ReadFile(hPipe, &resp, sizeof(resp), &bytesRead, NULL)) {
        result = resp.success;
        if(result) DebugLog(L"IPC Success: Injected PID %d", targetPid);
    }
    CloseHandle(hPipe);
    SetLastError(lastErr);
    return result;
}

// --- CreateProcess Hooks ---

// 统一的处理逻辑模板
template<typename Func, typename CharType>
BOOL CreateProcessInternal(
    Func originalFunc,
    const CharType* lpApplicationName,
    CharType* lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    const CharType* lpCurrentDirectory,
    LPVOID lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    bool isAnsi
) {
    // 1. 处理 ApplicationName (EXE 路径)
    std::wstring exePathW;
    if (isAnsi) exePathW = AnsiToWide((LPCSTR)lpApplicationName);
    else exePathW = (LPCWSTR)lpApplicationName ? (LPCWSTR)lpApplicationName : L"";

    std::wstring cmdLineW;
    if (isAnsi) cmdLineW = AnsiToWide((LPCSTR)lpCommandLine);
    else cmdLineW = (LPWSTR)lpCommandLine ? (LPWSTR)lpCommandLine : L"";

    std::wstring targetExe = GetTargetExePath(exePathW.c_str(), (LPWSTR)cmdLineW.c_str());
    std::wstring redirectedExe = TryRedirectDosPath(targetExe.c_str(), false);

    // 2. 处理 CurrentDirectory (工作目录)
    std::wstring curDirW;
    if (isAnsi) curDirW = AnsiToWide((LPCSTR)lpCurrentDirectory);
    else curDirW = (LPCWSTR)lpCurrentDirectory ? (LPCWSTR)lpCurrentDirectory : L"";

    std::wstring redirectedDir = TryRedirectDosPath(curDirW.c_str(), true);

    // 3. 准备新的参数
    const void* finalAppName = lpApplicationName;
    const void* finalCurDir = lpCurrentDirectory;

    std::string ansiExe, ansiDir; // 保持生命周期

    if (!redirectedExe.empty()) {
        DebugLog(L"CreateProcess Redirect EXE: %s -> %s", targetExe.c_str(), redirectedExe.c_str());
        if (isAnsi) {
            ansiExe = WideToAnsi(redirectedExe.c_str());
            finalAppName = ansiExe.c_str();
        } else {
            finalAppName = redirectedExe.c_str();
        }
    }

    if (!redirectedDir.empty()) {
        DebugLog(L"CreateProcess Redirect DIR: %s -> %s", curDirW.c_str(), redirectedDir.c_str());
        if (isAnsi) {
            ansiDir = WideToAnsi(redirectedDir.c_str());
            finalCurDir = ansiDir.c_str();
        } else {
            finalCurDir = redirectedDir.c_str();
        }
    }

    // 4. 调用原始函数
    PROCESS_INFORMATION localPI = { 0 };
    LPPROCESS_INFORMATION pPI = lpProcessInformation ? lpProcessInformation : &localPI;
    BOOL callerWantedSuspended = (dwCreationFlags & CREATE_SUSPENDED);
    DWORD newCreationFlags = dwCreationFlags | CREATE_SUSPENDED;

    BOOL result;
    if (isAnsi) {
        result = ((P_CreateProcessA)originalFunc)((LPCSTR)finalAppName, (LPSTR)lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, newCreationFlags, lpEnvironment, (LPCSTR)finalCurDir, (LPSTARTUPINFOA)lpStartupInfo, pPI);
    } else {
        result = ((P_CreateProcessW)originalFunc)((LPCWSTR)finalAppName, (LPWSTR)lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, newCreationFlags, lpEnvironment, (LPCWSTR)finalCurDir, (LPSTARTUPINFOW)lpStartupInfo, pPI);
    }

    // 5. 注入与恢复
    if (result) {
        RequestInjectionFromLauncher(pPI->dwProcessId);
        if (!callerWantedSuspended) ResumeThread(pPI->hThread);
        if (!lpProcessInformation) { CloseHandle(localPI.hProcess); CloseHandle(localPI.hThread); }
    }

    return result;
}

// --- 具体钩子实现 ---

BOOL WINAPI Detour_CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    if (g_IsInHook) return fpCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    RecursionGuard guard;
    DWORD lastErr = GetLastError();
    BOOL res = CreateProcessInternal(fpCreateProcessW, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, false);
    SetLastError(lastErr);
    return res;
}

BOOL WINAPI Detour_CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    if (g_IsInHook) return fpCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    RecursionGuard guard;
    DWORD lastErr = GetLastError();
    BOOL res = CreateProcessInternal(fpCreateProcessA, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, true);
    SetLastError(lastErr);
    return res;
}

BOOL WINAPI Detour_CreateProcessAsUserW(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    if (g_IsInHook) return fpCreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    RecursionGuard guard;
    // AsUser 系列稍微特殊 需要单独处理或适配 Internal 这里为了简洁直接展开逻辑 或者使用 lambda 封装
    // 为了代码复用 我们可以稍微修改 Internal 让它接受 Token 但这里直接复制逻辑可能更清晰

    // 简化的逻辑复用：
    std::wstring exePathW = (LPCWSTR)lpApplicationName ? (LPCWSTR)lpApplicationName : L"";
    std::wstring cmdLineW = (LPWSTR)lpCommandLine ? (LPWSTR)lpCommandLine : L"";
    std::wstring targetExe = GetTargetExePath(exePathW.c_str(), (LPWSTR)cmdLineW.c_str());
    std::wstring redirectedExe = TryRedirectDosPath(targetExe.c_str(), false);

    std::wstring curDirW = (LPCWSTR)lpCurrentDirectory ? (LPCWSTR)lpCurrentDirectory : L"";
    std::wstring redirectedDir = TryRedirectDosPath(curDirW.c_str(), true);

    LPCWSTR finalAppName = redirectedExe.empty() ? lpApplicationName : redirectedExe.c_str();
    LPCWSTR finalCurDir = redirectedDir.empty() ? lpCurrentDirectory : redirectedDir.c_str();

    if(!redirectedExe.empty()) DebugLog(L"AsUser Redirect EXE: %s", redirectedExe.c_str());
    if(!redirectedDir.empty()) DebugLog(L"AsUser Redirect DIR: %s", redirectedDir.c_str());

    PROCESS_INFORMATION localPI = { 0 };
    LPPROCESS_INFORMATION pPI = lpProcessInformation ? lpProcessInformation : &localPI;
    BOOL callerWantedSuspended = (dwCreationFlags & CREATE_SUSPENDED);
    DWORD newCreationFlags = dwCreationFlags | CREATE_SUSPENDED;

    BOOL result = fpCreateProcessAsUserW(hToken, finalAppName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, newCreationFlags, lpEnvironment, finalCurDir, lpStartupInfo, pPI);

    if (result) {
        RequestInjectionFromLauncher(pPI->dwProcessId);
        if (!callerWantedSuspended) ResumeThread(pPI->hThread);
        if (!lpProcessInformation) { CloseHandle(localPI.hProcess); CloseHandle(localPI.hThread); }
    }
    return result;
}

BOOL WINAPI Detour_CreateProcessAsUserA(HANDLE hToken, LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    if (g_IsInHook) return fpCreateProcessAsUserA(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    RecursionGuard guard;

    std::wstring exePathW = AnsiToWide(lpApplicationName);
    std::wstring cmdLineW = AnsiToWide(lpCommandLine);
    std::wstring targetExe = GetTargetExePath(exePathW.c_str(), (LPWSTR)cmdLineW.c_str());
    std::wstring redirectedExe = TryRedirectDosPath(targetExe.c_str(), false);

    std::wstring curDirW = AnsiToWide(lpCurrentDirectory);
    std::wstring redirectedDir = TryRedirectDosPath(curDirW.c_str(), true);

    std::string ansiExe, ansiDir;
    LPCSTR finalAppName = lpApplicationName;
    LPCSTR finalCurDir = lpCurrentDirectory;

    if (!redirectedExe.empty()) {
        ansiExe = WideToAnsi(redirectedExe.c_str());
        finalAppName = ansiExe.c_str();
    }
    if (!redirectedDir.empty()) {
        ansiDir = WideToAnsi(redirectedDir.c_str());
        finalCurDir = ansiDir.c_str();
    }

    PROCESS_INFORMATION localPI = { 0 };
    LPPROCESS_INFORMATION pPI = lpProcessInformation ? lpProcessInformation : &localPI;
    BOOL callerWantedSuspended = (dwCreationFlags & CREATE_SUSPENDED);
    DWORD newCreationFlags = dwCreationFlags | CREATE_SUSPENDED;

    BOOL result = fpCreateProcessAsUserA(hToken, finalAppName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, newCreationFlags, lpEnvironment, finalCurDir, lpStartupInfo, pPI);

    if (result) {
        RequestInjectionFromLauncher(pPI->dwProcessId);
        if (!callerWantedSuspended) ResumeThread(pPI->hThread);
        if (!lpProcessInformation) { CloseHandle(localPI.hProcess); CloseHandle(localPI.hThread); }
    }
    return result;
}

BOOL WINAPI Detour_CreateProcessWithTokenW(HANDLE hToken, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    if (g_IsInHook) return fpCreateProcessWithTokenW(hToken, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    RecursionGuard guard;

    std::wstring exePathW = (LPCWSTR)lpApplicationName ? (LPCWSTR)lpApplicationName : L"";
    std::wstring cmdLineW = (LPWSTR)lpCommandLine ? (LPWSTR)lpCommandLine : L"";
    std::wstring targetExe = GetTargetExePath(exePathW.c_str(), (LPWSTR)cmdLineW.c_str());
    std::wstring redirectedExe = TryRedirectDosPath(targetExe.c_str(), false);

    std::wstring curDirW = (LPCWSTR)lpCurrentDirectory ? (LPCWSTR)lpCurrentDirectory : L"";
    std::wstring redirectedDir = TryRedirectDosPath(curDirW.c_str(), true);

    LPCWSTR finalAppName = redirectedExe.empty() ? lpApplicationName : redirectedExe.c_str();
    LPCWSTR finalCurDir = redirectedDir.empty() ? lpCurrentDirectory : redirectedDir.c_str();

    PROCESS_INFORMATION localPI = { 0 };
    LPPROCESS_INFORMATION pPI = lpProcessInformation ? lpProcessInformation : &localPI;
    BOOL callerWantedSuspended = (dwCreationFlags & CREATE_SUSPENDED);
    DWORD newCreationFlags = dwCreationFlags | CREATE_SUSPENDED;

    BOOL result = fpCreateProcessWithTokenW(hToken, dwLogonFlags, finalAppName, lpCommandLine, newCreationFlags, lpEnvironment, finalCurDir, lpStartupInfo, pPI);

    if (result) {
        RequestInjectionFromLauncher(pPI->dwProcessId);
        if (!callerWantedSuspended) ResumeThread(pPI->hThread);
        if (!lpProcessInformation) { CloseHandle(localPI.hProcess); CloseHandle(localPI.hThread); }
    }
    return result;
}

BOOL WINAPI Detour_CreateProcessWithLogonW(LPCWSTR lpUsername, LPCWSTR lpDomain, LPCWSTR lpPassword, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    if (g_IsInHook) return fpCreateProcessWithLogonW(lpUsername, lpDomain, lpPassword, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    RecursionGuard guard;

    std::wstring exePathW = (LPCWSTR)lpApplicationName ? (LPCWSTR)lpApplicationName : L"";
    std::wstring cmdLineW = (LPWSTR)lpCommandLine ? (LPWSTR)lpCommandLine : L"";
    std::wstring targetExe = GetTargetExePath(exePathW.c_str(), (LPWSTR)cmdLineW.c_str());
    std::wstring redirectedExe = TryRedirectDosPath(targetExe.c_str(), false);

    std::wstring curDirW = (LPCWSTR)lpCurrentDirectory ? (LPCWSTR)lpCurrentDirectory : L"";
    std::wstring redirectedDir = TryRedirectDosPath(curDirW.c_str(), true);

    LPCWSTR finalAppName = redirectedExe.empty() ? lpApplicationName : redirectedExe.c_str();
    LPCWSTR finalCurDir = redirectedDir.empty() ? lpCurrentDirectory : redirectedDir.c_str();

    PROCESS_INFORMATION localPI = { 0 };
    LPPROCESS_INFORMATION pPI = lpProcessInformation ? lpProcessInformation : &localPI;
    BOOL callerWantedSuspended = (dwCreationFlags & CREATE_SUSPENDED);
    DWORD newCreationFlags = dwCreationFlags | CREATE_SUSPENDED;

    BOOL result = fpCreateProcessWithLogonW(lpUsername, lpDomain, lpPassword, dwLogonFlags, finalAppName, lpCommandLine, newCreationFlags, lpEnvironment, finalCurDir, lpStartupInfo, pPI);

    if (result) {
        RequestInjectionFromLauncher(pPI->dwProcessId);
        if (!callerWantedSuspended) ResumeThread(pPI->hThread);
        if (!lpProcessInformation) { CloseHandle(localPI.hProcess); CloseHandle(localPI.hThread); }
    }
    return result;
}

DWORD WINAPI Detour_GetFinalPathNameByHandleW(HANDLE hFile, LPWSTR lpszFilePath, DWORD cchFilePath, DWORD dwFlags) {
    if (g_IsInHook) return fpGetFinalPathNameByHandleW(hFile, lpszFilePath, cchFilePath, dwFlags);
    RecursionGuard guard;
    DWORD lastErr = GetLastError();
    DWORD result = fpGetFinalPathNameByHandleW(hFile, lpszFilePath, cchFilePath, dwFlags);
    if (result > 0 && result < cchFilePath) {
        if (wcsstr(lpszFilePath, g_SandboxRoot)) {
            // 暂时不处理反向映射
        }
    }
    SetLastError(lastErr);
    return result;
}

// --- 初始化 ---

// 辅助函数：获取 NT 格式的短路径
std::wstring GetNtShortPath(const wchar_t* longPath) {
    if (!longPath || !*longPath) return L"";

    // 获取短路径 (8.3 格式)
    DWORD len = GetShortPathNameW(longPath, NULL, 0);
    if (len == 0) return L"";

    std::vector<wchar_t> buffer(len);
    GetShortPathNameW(longPath, buffer.data(), len);

    std::wstring shortPath = buffer.data();
    if (shortPath.empty()) return L"";

    // 转换为 NT 路径
    return L"\\??\\" + shortPath;
}

DWORD WINAPI InitHookThread(LPVOID) {
    // [新增] 初始化设备路径映射
    RefreshDeviceMap();

    wchar_t buffer[MAX_PATH] = { 0 };
    std::wstring mapName = GetConfigMapName(GetCurrentProcessId());
    HANDLE hMap = OpenFileMappingW(FILE_MAP_READ, FALSE, mapName.c_str());
    if (hMap) {
        void* pBuf = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, sizeof(HookConfig));
        if (pBuf) {
            HookConfig* config = (HookConfig*)pBuf;
            wcscpy_s(g_SandboxRoot, MAX_PATH, config->hookPath);
            wcscpy_s(g_IpcPipeName, MAX_PATH, config->pipeName);
            wcscpy_s(g_LauncherDir, MAX_PATH, config->launcherDir);
            UnmapViewOfFile(pBuf);
        }
        CloseHandle(hMap);
    }
    wchar_t envBuf[64];
    if (GetEnvironmentVariableW(L"YAP_HOOK_MODE", envBuf, 64) > 0) {
        g_HookMode = _wtoi(envBuf);
    }
    // 容错：默认为 2
    if (g_HookMode < 1 || g_HookMode > 3) g_HookMode = 2;
    if (g_SandboxRoot[0] == L'\0') {
        if (GetEnvironmentVariableW(L"YAP_HOOK_PATH", buffer, MAX_PATH) > 0) wcscpy_s(g_SandboxRoot, MAX_PATH, buffer);
    }
    if (g_IpcPipeName[0] == L'\0') {
        if (GetEnvironmentVariableW(L"YAP_IPC_PIPE", buffer, MAX_PATH) > 0) wcscpy_s(g_IpcPipeName, MAX_PATH, buffer);
    }
    if (g_SandboxRoot[0] == L'\0') {
        DebugLog(L"Init Failed: YAP_HOOK_PATH not found");
        return 0;
    }

    // [新增] 初始化系统目录变量
    wchar_t sysBuf[MAX_PATH];
    if (GetEnvironmentVariableW(L"SystemDrive", sysBuf, MAX_PATH)) {
        g_SystemDriveNt = L"\\??\\";
        g_SystemDriveNt += sysBuf; // \??\C:
    }
    if (GetEnvironmentVariableW(L"SystemRoot", sysBuf, MAX_PATH)) {
        g_WinDirNt = L"\\??\\";
        g_WinDirNt += sysBuf; // \??\C:\Windows
    }

    // [新增] 初始化特殊目录的 NT 路径
    if (g_LauncherDir[0] != L'\0') {
        g_LauncherDirNt = L"\\??\\";
        g_LauncherDirNt += g_LauncherDir;
    }

    if (GetEnvironmentVariableW(L"USERPROFILE", buffer, MAX_PATH)) {
        g_UserProfileNt = L"\\??\\";
        g_UserProfileNt += buffer;
        g_UserProfileNtShort = GetNtShortPath(buffer);

        // [新增] 计算 Users 根目录 (例如 C:\Users)
        // 逻辑：取 UserProfile 的父目录
        std::wstring temp = g_UserProfileNt;
        if (!temp.empty() && temp.back() == L'\\') temp.pop_back(); // 去除末尾斜杠

        size_t lastSlash = temp.find_last_of(L'\\');
        if (lastSlash != std::wstring::npos) {
            // 简单的防错：确保不是驱动器根目录 (例如 \??\C:)
            // \??\C: 长度为 6 我们要求路径长度大于此才截取
            if (lastSlash > 6) {
                g_UsersDirNt = temp.substr(0, lastSlash);
            }
        }

        // [新增] 计算 Users 根目录的短路径
        if (!g_UserProfileNtShort.empty()) {
            std::wstring tempShort = g_UserProfileNtShort;
            if (!tempShort.empty() && tempShort.back() == L'\\') tempShort.pop_back();
            size_t lastSlashShort = tempShort.find_last_of(L'\\');
            if (lastSlashShort != std::wstring::npos) {
                if (lastSlashShort > 6) {
                    g_UsersDirNtShort = tempShort.substr(0, lastSlashShort);
                }
            }
        }
    }

    if (GetEnvironmentVariableW(L"ALLUSERSPROFILE", buffer, MAX_PATH)) {
        g_ProgramDataNt = L"\\??\\";
        g_ProgramDataNt += buffer;
        // [新增] 获取短路径版本
        g_ProgramDataNtShort = GetNtShortPath(buffer);
    }

    if (GetEnvironmentVariableW(L"PUBLIC", buffer, MAX_PATH)) {
        g_PublicNt = L"\\??\\";
        g_PublicNt += buffer;
    }

    DebugLog(L"Hook Initialized (NT Mode). Root: %s", g_SandboxRoot);

    if (MH_Initialize() != MH_OK) return 0;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        MH_CreateHook(GetProcAddress(hNtdll, "NtCreateFile"), &Detour_NtCreateFile, reinterpret_cast<LPVOID*>(&fpNtCreateFile));
        MH_CreateHook(GetProcAddress(hNtdll, "NtOpenFile"), &Detour_NtOpenFile, reinterpret_cast<LPVOID*>(&fpNtOpenFile));
        MH_CreateHook(GetProcAddress(hNtdll, "NtQueryAttributesFile"), &Detour_NtQueryAttributesFile, reinterpret_cast<LPVOID*>(&fpNtQueryAttributesFile));
        MH_CreateHook(GetProcAddress(hNtdll, "NtQueryFullAttributesFile"), &Detour_NtQueryFullAttributesFile, reinterpret_cast<LPVOID*>(&fpNtQueryFullAttributesFile));
        MH_CreateHook(GetProcAddress(hNtdll, "NtQueryInformationFile"), &Detour_NtQueryInformationFile, reinterpret_cast<LPVOID*>(&fpNtQueryInformationFile));
        MH_CreateHook(GetProcAddress(hNtdll, "NtQueryDirectoryFile"), &Detour_NtQueryDirectoryFile, reinterpret_cast<LPVOID*>(&fpNtQueryDirectoryFile));

        MH_CreateHook(GetProcAddress(hNtdll, "NtSetInformationFile"), &Detour_NtSetInformationFile, reinterpret_cast<LPVOID*>(&fpNtSetInformationFile));
        MH_CreateHook(GetProcAddress(hNtdll, "NtDeleteFile"), &Detour_NtDeleteFile, reinterpret_cast<LPVOID*>(&fpNtDeleteFile));
        MH_CreateHook(GetProcAddress(hNtdll, "NtClose"), &Detour_NtClose, reinterpret_cast<LPVOID*>(&fpNtClose));

        fpNtQueryObject = (P_NtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");

        void* pNtQueryDirectoryFileEx = (void*)GetProcAddress(hNtdll, "NtQueryDirectoryFileEx");
        if (pNtQueryDirectoryFileEx) {
            MH_CreateHook(pNtQueryDirectoryFileEx, &Detour_NtQueryDirectoryFileEx, reinterpret_cast<LPVOID*>(&fpNtQueryDirectoryFileEx));
        }
    }

    MH_CreateHook(&CreateProcessW, &Detour_CreateProcessW, reinterpret_cast<LPVOID*>(&fpCreateProcessW));
    MH_CreateHook(&CreateProcessA, &Detour_CreateProcessA, reinterpret_cast<LPVOID*>(&fpCreateProcessA));

    HMODULE hAdvapi32 = LoadLibraryW(L"advapi32.dll");
    if (hAdvapi32) {
        void* pCreateProcessAsUserW = (void*)GetProcAddress(hAdvapi32, "CreateProcessAsUserW");
        if (pCreateProcessAsUserW) MH_CreateHook(pCreateProcessAsUserW, &Detour_CreateProcessAsUserW, reinterpret_cast<LPVOID*>(&fpCreateProcessAsUserW));
        void* pCreateProcessAsUserA = (void*)GetProcAddress(hAdvapi32, "CreateProcessAsUserA");
        if (pCreateProcessAsUserA) MH_CreateHook(pCreateProcessAsUserA, &Detour_CreateProcessAsUserA, reinterpret_cast<LPVOID*>(&fpCreateProcessAsUserA));
        void* pCreateProcessWithTokenW = (void*)GetProcAddress(hAdvapi32, "CreateProcessWithTokenW");
        if (pCreateProcessWithTokenW) MH_CreateHook(pCreateProcessWithTokenW, &Detour_CreateProcessWithTokenW, reinterpret_cast<LPVOID*>(&fpCreateProcessWithTokenW));
        void* pCreateProcessWithLogonW = (void*)GetProcAddress(hAdvapi32, "CreateProcessWithLogonW");
        if (pCreateProcessWithLogonW) MH_CreateHook(pCreateProcessWithLogonW, &Detour_CreateProcessWithLogonW, reinterpret_cast<LPVOID*>(&fpCreateProcessWithLogonW));
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32) {
        void* pGetFinalPathNameByHandleW = (void*)GetProcAddress(hKernel32, "GetFinalPathNameByHandleW");
        if (pGetFinalPathNameByHandleW) {
             MH_CreateHook(pGetFinalPathNameByHandleW, &Detour_GetFinalPathNameByHandleW, reinterpret_cast<LPVOID*>(&fpGetFinalPathNameByHandleW));
        }
    }

    MH_EnableHook(MH_ALL_HOOKS);

    std::wstring eventName = GetReadyEventName(GetCurrentProcessId());
    HANDLE hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, eventName.c_str());
    if (hEvent) {
        SetEvent(hEvent);
        CloseHandle(hEvent);
    }

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        CreateThread(NULL, 0, InitHookThread, NULL, 0, NULL);
    } else if (dwReason == DLL_PROCESS_DETACH) {
        MH_Uninitialize();
    }
    return TRUE;
}