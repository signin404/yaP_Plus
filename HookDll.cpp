#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <icmpapi.h>
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
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "winhttp.lib")

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

#ifndef STATUS_INVALID_DEVICE_REQUEST
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xC0000010L)
#endif

#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BBL)
#endif

#ifndef FileNameInformation
#define FileNameInformation ((FILE_INFORMATION_CLASS)9)
#endif

#ifndef FileAllInformation
#define FileAllInformation ((FILE_INFORMATION_CLASS)18)
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

#ifndef FileLinkInformation
#define FileLinkInformation ((FILE_INFORMATION_CLASS)11)
#endif

typedef struct _FILE_LINK_INFORMATION {
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_LINK_INFORMATION, *PFILE_LINK_INFORMATION;

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

// --- 函数指针定义 ---
typedef int (WSAAPI* P_connect)(SOCKET s, const struct sockaddr* name, int namelen);
typedef int (WSAAPI* P_WSAConnect)(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);

// ICMP (Ping)
typedef DWORD (WINAPI* P_IcmpSendEcho)(HANDLE, IPAddr, LPVOID, WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
typedef DWORD (WINAPI* P_IcmpSendEcho2)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, IPAddr, LPVOID, WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
typedef DWORD (WINAPI* P_Icmp6SendEcho2)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PSOCKADDR_IN6, PSOCKADDR_IN6, LPVOID, WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
typedef DWORD (WINAPI* P_IcmpSendEcho2Ex)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, IPAddr, IPAddr, LPVOID, WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);

// DNS & UDP
typedef int (WSAAPI* P_GetAddrInfoW)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
typedef int (WSAAPI* P_sendto)(SOCKET, const char*, int, int, const struct sockaddr*, int);

// UDP 高级函数
typedef int (WSAAPI* P_WSASendTo)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

// WinINet (IE内核/旧版应用常用)
typedef HINTERNET (WINAPI* P_InternetConnectW)(HINTERNET, LPCWSTR, INTERNET_PORT, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET (WINAPI* P_InternetConnectA)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET (WINAPI* P_InternetOpenUrlW)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET (WINAPI* P_InternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);

// WinHTTP (服务/更新程序常用)
typedef HINTERNET (WINAPI* P_WinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);

// 旧版 DNS
typedef struct hostent* (WSAAPI* P_gethostbyname)(const char*);

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
int g_HookMode = 1; // [新增] 默认模式 1
std::wstring g_SystemDriveNt; // [新增] 系统盘符 NT 路径 (如 \??\C:)
std::wstring g_SystemDriveLetter; // [新增] 系统盘符 DOS 路径 (如 C:)
std::wstring g_LauncherDriveNt; // 启动器所在盘符 NT 路径 (如 \??\Z:)
std::vector<std::wstring> g_SystemWhitelist; // 系统盘白名单
bool g_BlockNetwork = false; // 网络拦截开关
bool g_HookChild = true; // [新增] 子进程挂钩开关 默认开启
std::wstring g_CurrentProcessPathNt; // [新增] 当前进程 NT 路径 用于自身镜像保护

P_connect fpConnect = NULL;
P_WSAConnect fpWSAConnect = NULL;
P_IcmpSendEcho fpIcmpSendEcho = NULL;
P_IcmpSendEcho2 fpIcmpSendEcho2 = NULL;
P_Icmp6SendEcho2 fpIcmp6SendEcho2 = NULL;
P_IcmpSendEcho2Ex fpIcmpSendEcho2Ex = NULL;
P_GetAddrInfoW fpGetAddrInfoW = NULL;
P_sendto fpSendTo = NULL;
P_WSASendTo fpWSASendTo = NULL;
P_InternetConnectW fpInternetConnectW = NULL;
P_WinHttpConnect fpWinHttpConnect = NULL;
P_InternetConnectA fpInternetConnectA = NULL;
P_InternetOpenUrlW fpInternetOpenUrlW = NULL;
P_InternetOpenUrlA fpInternetOpenUrlA = NULL;
P_gethostbyname fpGethostbyname = NULL;

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

// [新增] 进程类型枚举
enum ProcessType {
    ProcType_Generic = 0,
    ProcType_Msi_Installer,
    ProcType_Office_Outlook,
    ProcType_Mozilla_Firefox,
    ProcType_Explorer,
    // [新增]
    ProcType_TiWorker,          // TiWorker.exe (Windows Modules Installer Worker)
    ProcType_WMP,               // wmplayer.exe
    ProcType_SvcHost,           // svchost.exe (用于 Windows Update 等)
    ProcType_DllHost            // dllhost.exe (用于 WebCache)
};

// [新增] 当前进程类型
ProcessType g_CurrentProcessType = ProcType_Generic;

// [新增] 初始化进程类型 (在 InitHookThread 中调用)
void InitProcessType() {
    if (g_CurrentProcessPathNt.empty()) return;

    // 获取文件名部分
    size_t lastSlash = g_CurrentProcessPathNt.find_last_of(L'\\');
    std::wstring exeName = (lastSlash != std::wstring::npos) ?
                           g_CurrentProcessPathNt.substr(lastSlash + 1) : g_CurrentProcessPathNt;

    std::transform(exeName.begin(), exeName.end(), exeName.begin(), towlower);

    if (exeName == L"msiexec.exe") {
        g_CurrentProcessType = ProcType_Msi_Installer;
        DebugLog(L"Compat: Detected MSI Installer");
    }
    else if (exeName == L"outlook.exe") {
        g_CurrentProcessType = ProcType_Office_Outlook;
        DebugLog(L"Compat: Detected Outlook");
    }
    else if (exeName == L"firefox.exe") {
        g_CurrentProcessType = ProcType_Mozilla_Firefox;
        DebugLog(L"Compat: Detected Firefox");
    }
    else if (exeName == L"explorer.exe") {
        g_CurrentProcessType = ProcType_Explorer;
        DebugLog(L"Compat: Detected Explorer");
    }
    else if (exeName == L"tiworker.exe") {
        g_CurrentProcessType = ProcType_TiWorker;
        DebugLog(L"Compat: Detected TiWorker");
    }
    else if (exeName == L"wmplayer.exe") {
        g_CurrentProcessType = ProcType_WMP;
        DebugLog(L"Compat: Detected Windows Media Player");
    }
    else if (exeName == L"svchost.exe") {
        g_CurrentProcessType = ProcType_SvcHost;
        DebugLog(L"Compat: Detected SvcHost");
    }
    else if (exeName == L"dllhost.exe") {
        g_CurrentProcessType = ProcType_DllHost;
        DebugLog(L"Compat: Detected DllHost");
    }
}

// 初始化系统盘白名单 (在 InitHookThread 中调用)
void InitSystemWhitelist() {
    if (g_SystemDriveNt.empty()) return;

    // 基础目录 (目录及其子目录可见)
    const wchar_t* dirs[] = {
        L"$RECYCLE.BIN",
        L"Documents and Settings",
        L"Program Files",
        L"Program Files (x86)",
        L"ProgramData",
        L"Recovery",
        L"System Volume Information",
        L"Users",
        L"Windows"
    };

    // 根目录特定文件 (仅文件可见)
    const wchar_t* files[] = {
        L"diskpt0.sys",
        L"DumpStack.log.tmp",
        L"pagefile.sys",
        L"swapfile.sys"
    };

    for (const auto& dir : dirs) {
        std::wstring path = g_SystemDriveNt + L"\\" + dir;
        g_SystemWhitelist.push_back(path);
    }

    for (const auto& file : files) {
        std::wstring path = g_SystemDriveNt + L"\\" + file;
        g_SystemWhitelist.push_back(path);
    }
}

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

// 缓存的 NT 路径
std::wstring g_LauncherDirNt;
std::wstring g_UserProfileNt;
std::wstring g_UserProfileNtShort;
std::wstring g_UsersDirNt;      // [新增] Users 根目录 (长路径)
std::wstring g_UsersDirNtShort; // [新增] Users 根目录 (短路径)
std::wstring g_ProgramDataNt;
std::wstring g_ProgramDataNtShort;
std::wstring g_PublicNt;

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

// --- 辅助工具 ---

// 辅助：将 ANSI 转换为 Wide
std::wstring AnsiToWide(LPCSTR text) {
    if (!text) return L"";
    int size = MultiByteToWideChar(CP_ACP, 0, text, -1, NULL, 0);
    if (size <= 0) return L"";
    std::wstring res(size - 1, 0);
    MultiByteToWideChar(CP_ACP, 0, text, -1, &res[0], size);
    return res;
}

// 辅助：将 Wide 转换为 ANSI
std::string WideToAnsi(LPCWSTR text) {
    if (!text) return "";
    int size = WideCharToMultiByte(CP_ACP, 0, text, -1, NULL, 0, NULL, NULL);
    if (size <= 0) return "";
    std::string res(size - 1, 0);
    WideCharToMultiByte(CP_ACP, 0, text, -1, &res[0], size, NULL, NULL);
    return res;
}

// [新增] 移除 NTFS 交换数据流 (ADS) 后缀
// 逻辑参考 file.c: File_MatchPath2
std::wstring StripAds(const std::wstring& path) {
    size_t lastBackslash = path.rfind(L'\\');
    if (lastBackslash != std::wstring::npos) {
        size_t colonPos = path.find(L':', lastBackslash + 1);
        if (colonPos != std::wstring::npos) {
            return path.substr(0, colonPos);
        }
    }
    return path;
}

// 辅助：判断是否为特殊设备、管道、网络驱动等 不应被重定向
bool IsPipeOrDevice(LPCWSTR path) {
    if (!path) return false;

    // [新增] 自身镜像保护 (防止重定向自身 EXE)
    if (!g_CurrentProcessPathNt.empty()) {
        if (_wcsicmp(path, g_CurrentProcessPathNt.c_str()) == 0) return true;
    }

    // [新增] 虚拟别名 SysNative (32位程序访问64位系统目录)
    if (wcsstr(path, L"SysNative")) return true;

    // --- 1. IPC (进程间通信) ---
    if (wcsstr(path, L"NamedPipe")) return true;
    if (wcsstr(path, L"Pipe\\")) return true;
    if (wcsstr(path, L"PIPE\\")) return true;
    if (wcsstr(path, L"pipe\\")) return true;
    if (wcsstr(path, L"Mailslot")) return true;
    if (wcsstr(path, L"RPC Control")) return true;
    // [新增] Outlook 特殊 IPC
    if (wcsstr(path, L"OICE_")) return true;

    // --- 2. 控制台/终端 ---
    if (wcsstr(path, L"ConDrv")) return true;
    if (wcsstr(path, L"CONIN$")) return true;
    if (wcsstr(path, L"CONOUT$")) return true;
    if (wcsstr(path, L"\\??\\CON")) return true;

    // --- 3. 关键系统驱动 ---
    if (wcsstr(path, L"Afd")) return true;
    if (wcsstr(path, L"AFD")) return true;
    if (wcsstr(path, L"KsecDD")) return true;
    if (wcsstr(path, L"MountPointManager")) return true;
    if (wcsstr(path, L"Nsi")) return true;
    if (wcsstr(path, L"NSI")) return true;

    // [新增] 补充 file.c.txt 中遗漏的系统目录
    if (wcsstr(path, L"catroot2")) return true;
    if (wcsstr(path, L"drivers\\etc")) return true;

    // --- 4. 网络与共享 (Network & Redirectors) ---
    if (wcsstr(path, L"Dfs")) return true;
    if (wcsstr(path, L"\\UNC\\")) return true;
    if (wcsstr(path, L"\\Mup\\")) return true;
    // [新增] 关键重定向器
    if (wcsstr(path, L"LanmanRedirector")) return true; // SMB
    if (wcsstr(path, L"hgfs")) return true;             // VMware Shared Folders
    // [新增] 网络重定向器前缀格式 (如 \Device\Mup\;LanmanRedirector)
    if (wcsstr(path, L";LanmanRedirector")) return true;

    // --- 5. 硬件与磁盘 (Hardware & Raw Disk) ---
    if (wcsstr(path, L"Volume{")) return true;
    if (wcsstr(path, L"CdRom")) return true;
    if (wcsstr(path, L"Harddisk")) return true;
    // [新增] 物理驱动器
    if (wcsstr(path, L"PhysicalDrive")) return true;

    // PnP 设备标识
    if (wcsstr(path, L"hid#")) return true;
    if (wcsstr(path, L"HID#")) return true;
    if (wcsstr(path, L"usb#")) return true;
    if (wcsstr(path, L"USB#")) return true;
    if (wcsstr(path, L"pci#")) return true;
    if (wcsstr(path, L"PCI#")) return true;
    if (wcsstr(path, L"acpi#")) return true;
    if (wcsstr(path, L"scsi#")) return true;
    if (wcsstr(path, L"storage#")) return true;
    if (wcsstr(path, L"display#")) return true;
    if (wcsstr(path, L"monitor#")) return true;
    if (wcsstr(path, L"hdaudio#")) return true;
    if (wcsstr(path, L"root#")) return true;

    // --- 6. [新增] 必须直通的系统特殊目录 (源自 File_GetName_SkipWow64Link) ---
    if (wcsstr(path, L"spool")) return true;        // 打印机
    if (wcsstr(path, L"driverstore")) return true;  // 驱动存储
    if (wcsstr(path, L"catroot")) return true;      // 签名目录
    if (wcsstr(path, L"logfiles")) return true;     // 系统日志

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

// [新增] 路径规范化：解析短文件名、符号链接、Junction
// 必须放在 NtPathToDosPath 之后，Detour_NtCreateFile 之前
std::wstring NormalizeNtPath(const std::wstring& ntPath) {
    if (ntPath.empty()) return ntPath;

    // 1. 转换为 DOS 路径以便使用 Win32 API
    std::wstring dosPath = NtPathToDosPath(ntPath);
    if (dosPath.empty()) return ntPath; // 无法转换，保持原样

    // 2. 尝试打开文件获取最终路径 (解析 Symlink/Junction/短文件名)
    // FILE_FLAG_BACKUP_SEMANTICS 用于打开目录
    HANDLE hFile = CreateFileW(dosPath.c_str(),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        wchar_t finalPath[MAX_PATH];
        // VOLUME_NAME_DOS 返回 \\?\C:\Path 格式
        DWORD len = GetFinalPathNameByHandleW(hFile, finalPath, MAX_PATH, VOLUME_NAME_DOS);
        CloseHandle(hFile);

        if (len > 0 && len < MAX_PATH) {
            std::wstring res = finalPath;
            // 将 \\?\ 转换为 NT 格式 \??\ (注意注释末尾不要加反斜杠)
            if (res.rfind(L"\\\\?\\", 0) == 0) {
                return L"\\??\\" + res.substr(4);
            }
            return res;
        }
    }
    else {
        // 3. 文件不存在 (可能是创建新文件)，尝试展开短文件名
        // GetLongPathNameW 即使文件不存在，只要路径组件存在也能工作
        wchar_t longPath[MAX_PATH];
        if (GetLongPathNameW(dosPath.c_str(), longPath, MAX_PATH) > 0) {
            return L"\\??\\" + std::wstring(longPath);
        }
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

// [新增] 核心可见性判断函数 (Mode 3 专用)
bool IsPathVisible(const std::wstring& fullNtPath) {
    // 1. 沙盒内的路径始终可见
    std::wstring sandboxPrefix = L"\\??\\" + std::wstring(g_SandboxRoot);
    if (ContainsCaseInsensitive(fullNtPath, sandboxPrefix)) return true;

    // 2. 检查是否为系统盘
    if (!g_SystemDriveNt.empty() && fullNtPath.find(g_SystemDriveNt) == 0) {
        // 根目录可见 (\??\C: 或 \??\C:\)
        if (fullNtPath.length() == g_SystemDriveNt.length() ||
           (fullNtPath.length() == g_SystemDriveNt.length() + 1 && fullNtPath.back() == L'\\')) {
            return true;
        }

        // 检查白名单
        for (const auto& whitePath : g_SystemWhitelist) {
            // 检查是否是白名单路径本身或其子路径
            if (fullNtPath.size() >= whitePath.size()) {
                if (_wcsnicmp(fullNtPath.c_str(), whitePath.c_str(), whitePath.size()) == 0) {
                    // 确保匹配完整路径段
                    if (fullNtPath.size() == whitePath.size() || fullNtPath[whitePath.size()] == L'\\') {
                        return true;
                    }
                }
            }
        }
        return false; // 系统盘其他路径隐藏
    }

    // 3. 检查是否为启动器所在盘
    if (!g_LauncherDriveNt.empty() && fullNtPath.find(g_LauncherDriveNt) == 0) {
        // 根目录可见
        if (fullNtPath.length() == g_LauncherDriveNt.length() ||
           (fullNtPath.length() == g_LauncherDriveNt.length() + 1 && fullNtPath.back() == L'\\')) {
            return true;
        }

        // 逻辑：启动器目录及其子目录可见 + 到根目录的路径可见
        // 情况 A: 访问的是启动器目录或其子目录
        if (fullNtPath.size() >= g_LauncherDirNt.size()) {
            if (_wcsnicmp(fullNtPath.c_str(), g_LauncherDirNt.c_str(), g_LauncherDirNt.size()) == 0) {
                if (fullNtPath.size() == g_LauncherDirNt.size() || fullNtPath[g_LauncherDirNt.size()] == L'\\') {
                    return true;
                }
            }
        }

        // 情况 B: 访问的是启动器目录的父级路径
        if (g_LauncherDirNt.size() > fullNtPath.size()) {
            if (_wcsnicmp(g_LauncherDirNt.c_str(), fullNtPath.c_str(), fullNtPath.size()) == 0) {
                if (g_LauncherDirNt[fullNtPath.size()] == L'\\') {
                    return true;
                }
            }
        }

        return false; // 启动器盘其他路径隐藏
    }

    // 4. 其他分区 -> 隐藏
    return false;
}

// [修改] 检查路径是否需要重定向
bool ShouldRedirect(const std::wstring& fullNtPath, std::wstring& targetPath) {
    if (g_SandboxRoot[0] == L'\0') return false;
    if (g_HookMode == 0) return false;

    // [新增] ADS 处理：使用剥离流名称后的路径进行判断
    std::wstring pathToCheck = StripAds(fullNtPath);

    if (IsPipeOrDevice(pathToCheck.c_str())) return false;

    // [新增] 过滤 Shell Namespace GUID (例如 ::{20D04FE0...})
    if (wcsstr(pathToCheck.c_str(), L"::{") != NULL) return false;

    if (fullNtPath.rfind(L"\\??\\", 0) != 0) return false;

    if (ContainsCaseInsensitive(fullNtPath, g_SandboxRoot)) return false;

    targetPath = L"\\??\\";
    targetPath += g_SandboxRoot;
    if (targetPath.back() == L'\\') targetPath.pop_back();

    // -------------------------------------------------------
    // 1. 特殊目录映射 (优先级最高 适用于所有模式)
    // -------------------------------------------------------

    // [启动器目录] -> 映射为沙盒根目录 (相对路径)
    // 例如: Z:\Portable\App\Config.ini -> Sandbox\Config.ini
    if (!g_LauncherDirNt.empty()) {
        if (CheckAndMap(fullNtPath, g_LauncherDirNt, L"", targetPath)) return true;
    }

    // [当前用户目录] -> Users\Current
    // 例如: C:\Users\Admin\AppData -> Sandbox\Users\Current\AppData
    if (CheckAndMap(fullNtPath, g_UserProfileNt, L"\\Users\\Current", targetPath) ||
        CheckAndMap(fullNtPath, g_UserProfileNtShort, L"\\Users\\Current", targetPath)) {
        return true;
    }

    // [所有用户目录/ProgramData] -> Users\All
    // 例如: C:\ProgramData -> Sandbox\Users\All
    if (CheckAndMap(fullNtPath, g_ProgramDataNt, L"\\Users\\All", targetPath) ||
        CheckAndMap(fullNtPath, g_ProgramDataNtShort, L"\\Users\\All", targetPath)) {
        return true;
    }

    // [公用目录] -> Users\Public
    if (CheckAndMap(fullNtPath, g_PublicNt, L"\\Users\\Public", targetPath)) {
        return true;
    }

    // [Users 根目录] -> Users
    // 例如: C:\Users -> Sandbox\Users
    if (CheckAndMap(fullNtPath, g_UsersDirNt, L"\\Users", targetPath) ||
        CheckAndMap(fullNtPath, g_UsersDirNtShort, L"\\Users", targetPath)) {
        return true;
    }

    // -------------------------------------------------------
    // 2. 通用路径映射 (根据模式决定策略)
    // -------------------------------------------------------

    // --- Mode 3: 激进隔离策略 ---
    if (g_HookMode == 3) {

        std::wstring relPath = fullNtPath.substr(4);
        std::replace(relPath.begin(), relPath.end(), L'/', L'\\');

        // 处理驱动器号冒号 (C: -> C)
        size_t colonPos = relPath.find(L':');
        if (colonPos != std::wstring::npos) {
            relPath.erase(colonPos, 1);
        }

        targetPath += L"\\";
        targetPath += relPath;
        return true;
    }

    // --- Mode 1: 系统盘过滤 ---
    if (g_HookMode == 1) {
        // 检查是否以系统盘符开头 (例如 \??\C:)
        if (!g_SystemDriveNt.empty()) {
            if (fullNtPath.size() < g_SystemDriveNt.size() ||
                _wcsnicmp(fullNtPath.c_str(), g_SystemDriveNt.c_str(), g_SystemDriveNt.size()) != 0) {
                // 不是系统盘 -> 不重定向 (直接读写原路径)
                return false;
            }
        }
    }

    // --- Mode 2 & Mode 1(系统盘部分): 默认绝对路径映射 ---
    // 映射为 Sandbox\DriveLetter\Path
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
        CreateDirectoryW(targetDos.c_str(), NULL);
    } else {
        // [新增] Windows Media Player 补丁
        // file.c: Dll_ImageType == DLL_IMAGE_WINDOWS_MEDIA_PLAYER
        // 不复制 .wmdb 文件的内容，因为它们太大且会被重建
        if (g_CurrentProcessType == ProcType_WMP) {
            if (sourceDos.length() > 5 &&
                _wcsicmp(sourceDos.c_str() + sourceDos.length() - 5, L".wmdb") == 0) {

                // 仅创建空文件，不复制内容
                HANDLE hFile = CreateFileW(targetDos.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, srcAttrs, NULL);
                if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

                DebugLog(L"Compat: WMP - Skipped content copy for %s", sourceDos.c_str());
                return;
            }
        }

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

    // 1. 扫描真实目录 (保持不变)
    if (!realPath.empty()) {
        std::wstring realNtPath = L"\\??\\" + realPath;
        if (g_HookMode != 3 || IsPathVisible(realNtPath)) {

            std::wstring searchPath = realPath;
            if (searchPath.back() != L'\\') searchPath += L"\\";
            searchPath += pattern;

            WIN32_FIND_DATAW fd;

            // --- 智能 WOW64 重定向控制 ---
            PVOID oldRedirectionValue = NULL;
            BOOL isWow64 = FALSE;
            bool needDisable = false;

            IsWow64Process(GetCurrentProcess(), &isWow64);

            if (isWow64) {
                if (StrStrIW(realPath.c_str(), L"System32") != NULL) {
                    if (!g_SystemDriveLetter.empty() &&
                        _wcsnicmp(realPath.c_str(), g_SystemDriveLetter.c_str(), g_SystemDriveLetter.length()) == 0) {
                        needDisable = true;
                    }
                }
            }

            if (needDisable) {
                Wow64DisableWow64FsRedirection(&oldRedirectionValue);
            }

            HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);

            if (needDisable) {
                Wow64RevertWow64FsRedirection(oldRedirectionValue);
            }

            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

                    if (g_HookMode == 3) {
                        std::wstring childNtPath = realNtPath;
                        if (childNtPath.back() != L'\\') childNtPath += L"\\";
                        childNtPath += fd.cFileName;

                        if (!IsPathVisible(childNtPath)) {
                            continue;
                        }
                    }

                    std::wstring key = fd.cFileName;
                    std::transform(key.begin(), key.end(), key.begin(), towlower);
                    mergedMap[key] = ConvertFindData(fd);
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
        }
    }

    // 2. 扫描沙盒目录 (标准路径)
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
                mergedMap[key] = ConvertFindData(fd); // 直接覆盖
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    // [新增] 3. 扫描沙盒内的 Sysnative 目录 (解决 WOW64 下 drivers 等目录的分离问题)
    BOOL isWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &isWow64);

    // 仅当是 32 位进程，且沙盒路径中包含 System32 时才触发
    if (isWow64 && !sandboxPath.empty()) {
        // 查找 System32 (不区分大小写)
        const wchar_t* pSys32 = StrStrIW(sandboxPath.c_str(), L"\\System32");
        if (pSys32) {
            // 构造 Sysnative 路径
            // 例如: ...\Sandbox\C\Windows\System32\drivers -> ...\Sandbox\C\Windows\Sysnative\drivers
            std::wstring sysnativePath = sandboxPath;
            size_t pos = pSys32 - sandboxPath.c_str();

            // 替换 System32 为 Sysnative
            sysnativePath.replace(pos + 1, 8, L"Sysnative");

            // 检查该目录是否存在
            DWORD attrs = GetFileAttributesW(sysnativePath.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {

                std::wstring searchPath = sysnativePath;
                if (searchPath.back() != L'\\') searchPath += L"\\";
                searchPath += pattern;

                WIN32_FIND_DATAW fd;
                HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                        std::wstring key = fd.cFileName;
                        std::transform(key.begin(), key.end(), key.begin(), towlower);

                        // [策略] 如果 Sysnative 里有文件，也合并进来
                        // 通常 Sysnative 里的文件优先级更高（代表真实的64位文件）
                        mergedMap[key] = ConvertFindData(fd);
                    } while (FindNextFileW(hFind, &fd));
                    FindClose(hFind);
                }
            }
        }
    }

    // 4. 添加 . 和 ..
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

    // 5. 转为 Vector
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
    // 递归守卫：防止 Hook 内部调用 API 导致死循环
    if (g_IsInHook) return fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
    RecursionGuard guard;

    // 1. 路径解析与规范化
    std::wstring rawNtPath = ResolvePathFromAttr(ObjectAttributes);
    std::wstring fullNtPath = NormalizeNtPath(rawNtPath); // 解析短文件名、符号链接

    // [兼容性补丁 - 预处理]
    // [MSI Installer] 移除 ACCESS_SYSTEM_SECURITY
    // MSI 访问 .msi 文件时常请求此权限导致失败
    if (g_CurrentProcessType == ProcType_Msi_Installer) {
        if (DesiredAccess & ACCESS_SYSTEM_SECURITY) {
            if (fullNtPath.length() > 4 &&
                _wcsicmp(fullNtPath.c_str() + fullNtPath.length() - 4, L".msi") == 0) {
                DesiredAccess &= ~ACCESS_SYSTEM_SECURITY;
                DebugLog(L"Compat: MSI - Stripped ACCESS_SYSTEM_SECURITY for %s", fullNtPath.c_str());
            }
        }
    }

    // [TiWorker] 移除 ACCESS_SYSTEM_SECURITY
    // Windows 更新进程通常没有权限获取 SACL
    if (g_CurrentProcessType == ProcType_TiWorker) {
        if (DesiredAccess & ACCESS_SYSTEM_SECURITY) {
            DesiredAccess &= ~ACCESS_SYSTEM_SECURITY;
            DebugLog(L"Compat: TiWorker - Stripped ACCESS_SYSTEM_SECURITY");
        }
    }

    // [Firefox] 移除插件 EXE 的 GENERIC_WRITE
    // Firefox 106+ 尝试写权限打开插件 EXE
    if (g_CurrentProcessType == ProcType_Mozilla_Firefox) {
        if (DesiredAccess & GENERIC_WRITE) {
            if (fullNtPath.length() > 4 &&
                _wcsicmp(fullNtPath.c_str() + fullNtPath.length() - 4, L".exe") == 0) {
                DesiredAccess &= ~GENERIC_WRITE;
                DebugLog(L"Compat: Firefox - Stripped GENERIC_WRITE for %s", fullNtPath.c_str());
            }
        }
    }

    // [Explorer] 移除只读文件的写属性请求
    // 资源管理器右键属性时常请求写权限
    if (g_CurrentProcessType == ProcType_Explorer && CreateDisposition == FILE_OPEN) {
        if ((DesiredAccess & FILE_WRITE_ATTRIBUTES) && !(DesiredAccess & (FILE_WRITE_DATA | DELETE))) {
             DesiredAccess &= ~FILE_WRITE_ATTRIBUTES;
        }
    }

    // [Outlook] OICE_ 临时文件安全描述符处理
    // 清除 SecurityDescriptor 以避免权限问题
    if (g_CurrentProcessType == ProcType_Office_Outlook) {
        if (fullNtPath.find(L"\\OICE_") != std::wstring::npos) {
            if (ObjectAttributes && ObjectAttributes->SecurityDescriptor) {
                ObjectAttributes->SecurityDescriptor = NULL;
                DebugLog(L"Compat: Outlook - Cleared SecurityDescriptor for OICE_ file");
            }
        }
    }

    // [System Services] 强制迁移只读数据库
    // 针对被系统锁定的数据库 (catdb, DataStore.edb, WebCache)，强制请求写权限以触发 CoW
    if (g_CurrentProcessType == ProcType_SvcHost || g_CurrentProcessType == ProcType_DllHost) {
        bool isLockedDb = false;
        if (ContainsCaseInsensitive(fullNtPath, L"catdb")) isLockedDb = true;
        if (ContainsCaseInsensitive(fullNtPath, L"DataStore.edb")) isLockedDb = true;
        if (ContainsCaseInsensitive(fullNtPath, L"WebCache")) isLockedDb = true;

        if (isLockedDb) {
            if (!(DesiredAccess & (GENERIC_WRITE | FILE_WRITE_DATA))) {
                DesiredAccess |= FILE_GENERIC_WRITE;
                DebugLog(L"Compat: SystemDB - Forced Write Access to trigger migration for %s", fullNtPath.c_str());
            }
        }
    }

    // [重定向逻辑]
    std::wstring targetNtPath;

    if (ShouldRedirect(fullNtPath, targetNtPath)) {
        bool isDirectory = (CreateOptions & FILE_DIRECTORY_FILE) != 0;
        // 判断是否为写入操作 (包括显式写权限和创建/覆盖操作)
        bool isWrite = (DesiredAccess & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA));
        if (CreateDisposition == FILE_CREATE || CreateDisposition == FILE_SUPERSEDE || CreateDisposition == FILE_OVERWRITE || CreateDisposition == FILE_OVERWRITE_IF || CreateDisposition == FILE_OPEN_IF) {
            isWrite = true;
        }

        bool sandboxExists = NtPathExists(targetNtPath);
        bool realExists = NtPathExists(fullNtPath);

        // [Mode 3] 可见性检查：如果真实文件存在但被策略隐藏，视为不存在
        if (g_HookMode == 3 && realExists) {
            if (!IsPathVisible(fullNtPath)) {
                realExists = false;
            }
        }

        bool shouldRedirect = false;

        // 逻辑分支：
        if (isDirectory && !isWrite) {
            // 只读目录访问
            shouldRedirect = false;
            if (!realExists && sandboxExists) {
                shouldRedirect = true; // 真实不存在，沙盒存在 -> 进沙盒
            } else if (realExists) {
                // 真实存在 -> 访问真实目录 (内容合并由 NtQueryDirectoryFile 处理)
                // 除非沙盒里有，真实里没有，否则优先访问真实以获得更好的性能和兼容性
                // 但如果沙盒里也有，且我们想优先看沙盒属性？通常目录属性不重要，内容才重要。
                // 这里保持原逻辑：优先真实。
                shouldRedirect = false;
            } else {
                shouldRedirect = true; // 都不存在 -> 进沙盒报错
            }
        } else if (isWrite) {
            // 写入操作
            if (sandboxExists) {
                shouldRedirect = true; // 沙盒已有 -> 直接写沙盒
            } else if (realExists) {
                // 真实有，沙盒没有 -> 写时复制 (CoW)
                PerformCopyOnWrite(fullNtPath, targetNtPath);
                shouldRedirect = true;
            } else {
                shouldRedirect = true; // 都不存在 -> 在沙盒创建
            }
        } else {
            // 只读文件访问
            if (sandboxExists) {
                shouldRedirect = true; // 沙盒有 -> 读沙盒 (可能是修改过的副本)
            } else if (realExists) {
                shouldRedirect = false; // 沙盒没有 -> 读真实
            } else {
                shouldRedirect = true; // 都不存在 -> 进沙盒报错
            }
        }

        // 执行重定向
        if (shouldRedirect) {
            UNICODE_STRING uStr;
            RtlInitUnicodeString(&uStr, targetNtPath.c_str());
            PUNICODE_STRING oldName = ObjectAttributes->ObjectName;
            HANDLE oldRoot = ObjectAttributes->RootDirectory;

            // 替换路径
            ObjectAttributes->ObjectName = &uStr;
            ObjectAttributes->RootDirectory = NULL; // 必须清空 RootDirectory，因为我们提供了完整路径

            // 如果是写入或创建，确保沙盒内父目录存在
            if (isWrite || CreateDisposition == FILE_CREATE || CreateDisposition == FILE_OPEN_IF || CreateDisposition == FILE_OVERWRITE_IF || CreateDisposition == FILE_SUPERSEDE) {
                EnsureDirectoryExistsNT(targetNtPath.c_str());
            }

            NTSTATUS status = fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

            // 恢复原始参数
            ObjectAttributes->ObjectName = oldName;
            ObjectAttributes->RootDirectory = oldRoot;

            return status;
        }
    }

    // 不重定向，直接调用原始函数
    NTSTATUS status = fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

    // [兼容性补丁 - 重试逻辑]
    // [通用补丁] 自动降级权限重试
    // 很多程序请求 FILE_WRITE_ATTRIBUTES 但实际上并不需要它来读取文件
    if (status == STATUS_ACCESS_DENIED && (DesiredAccess & FILE_WRITE_ATTRIBUTES)) {
        if (CreateDisposition == FILE_OPEN || CreateDisposition == FILE_OPEN_IF) {
            ACCESS_MASK downgradedAccess = DesiredAccess & ~FILE_WRITE_ATTRIBUTES;
            if (downgradedAccess != 0) {
                status = fpNtCreateFile(FileHandle, downgradedAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
                if (NT_SUCCESS(status)) {
                    DebugLog(L"Compat: Auto-downgraded access (removed FILE_WRITE_ATTRIBUTES) for %s", fullNtPath.c_str());
                }
            }
        }
    }

    return status;
}

NTSTATUS NTAPI Detour_NtOpenFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
) {
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

    std::wstring rawNtPath = ResolvePathFromAttr(ObjectAttributes);

    if (rawNtPath.find(L"\\Device\\") == 0) {
        rawNtPath = DevicePathToNtPath(rawNtPath);
    }

    // [修改] 增加路径规范化，确保删除操作也能正确识别短文件名和链接
    std::wstring fullNtPath = NormalizeNtPath(rawNtPath);

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
            // 直接重定向到沙盒路径 调用原始 NtDeleteFile 进行物理删除
            // NtDeleteFile 默认不经过回收站 直接删除
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
        // --- 情况 2: 仅真实路径有文件 ---
        else if (realExists) {
            // [修改] 不再创建墓碑 直接返回成功
            // 欺骗应用程序文件已删除 但实际上什么都没做
            return STATUS_SUCCESS;
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

    // [新增] 拦截硬链接创建 (FileLinkInformation)
    // Sandboxie 逻辑：不支持在沙盒内创建指向外部的硬链接，也不支持沙盒内硬链接
    // 返回 STATUS_INVALID_DEVICE_REQUEST 会迫使大多数程序（如 cmd, msi）回退到 CopyFile
    if (FileInformationClass == FileLinkInformation) {
        // 可选：检查是否真的涉及沙盒路径，为了简化和安全，全局拦截或仅拦截涉及重定向的句柄
        // 这里采用安全策略：如果句柄指向的文件在重定向范围内，则拦截
        std::wstring rawPath = GetPathFromHandle(FileHandle);
        if (!rawPath.empty()) {
            std::wstring ntPath = DevicePathToNtPath(rawPath);
            std::wstring targetPath;
            if (ShouldRedirect(ntPath, targetPath)) {
                DebugLog(L"Blocked HardLink creation for: %s", ntPath.c_str());
                return STATUS_INVALID_DEVICE_REQUEST;
            }
        }
    }

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
    std::wstring sandboxRootNt = L"\\??\\";
    sandboxRootNt += g_SandboxRoot;

    // 检查句柄是否已经指向沙盒内的文件
    bool isHandleInSandbox = ContainsCaseInsensitive(ntPath, sandboxRootNt);

    // --- 分支 A: 句柄指向沙盒内的文件 ---
    if (isHandleInSandbox) {
        // [修改] 之前是转换为墓碑 现在直接调用原始函数进行物理删除
        // 因为句柄已经指向沙盒文件 直接放行即可
        return fpNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    }

    // --- 分支 B: 句柄指向真实文件 (尚未 CoW) ---
    else {
        std::wstring realDosPath = NtPathToDosPath(ntPath);
        DWORD realAttrs = GetFileAttributesW(realDosPath.c_str());

        if (realAttrs != INVALID_FILE_ATTRIBUTES) {
            // [修改] 真实文件存在 但我们不想删除它 也不想创建墓碑
            // 直接伪造成功
            IoStatusBlock->Status = STATUS_SUCCESS;
            IoStatusBlock->Information = 0;
            return STATUS_SUCCESS;
        }
    }

    // 异常情况 交给系统处理
    return fpNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

NTSTATUS NTAPI Detour_NtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation) {
    if (g_IsInHook) return fpNtQueryAttributesFile(ObjectAttributes, FileInformation);
    RecursionGuard guard;

    std::wstring rawNtPath = ResolvePathFromAttr(ObjectAttributes);
    std::wstring fullNtPath = NormalizeNtPath(rawNtPath);

    // [新增] Explorer Autorun.inf 优化
    // file.c: File_NtQueryFullAttributesFileImpl 中的优化
    if (g_CurrentProcessType == ProcType_Explorer) {
        if (fullNtPath.length() >= 12 &&
            _wcsicmp(fullNtPath.c_str() + fullNtPath.length() - 12, L"\\autorun.inf") == 0) {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }

    std::wstring targetNtPath;

    if (ShouldRedirect(fullNtPath, targetNtPath)) {
        // 1. 优先检查沙盒
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

        // 2. [新增] 如果沙盒没有 检查真实路径是否被隐藏
        if (g_HookMode == 3) {
            if (!IsPathVisible(fullNtPath)) {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
        }
    }
    return fpNtQueryAttributesFile(ObjectAttributes, FileInformation);
}

NTSTATUS NTAPI Detour_NtQueryFullAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_NETWORK_OPEN_INFORMATION FileInformation) {
    if (g_IsInHook) return fpNtQueryFullAttributesFile(ObjectAttributes, FileInformation);
    RecursionGuard guard;

    std::wstring rawNtPath = ResolvePathFromAttr(ObjectAttributes);
    std::wstring fullNtPath = NormalizeNtPath(rawNtPath);
    std::wstring targetNtPath;

    // [兼容性补丁 - 预处理]
    // [Explorer] Autorun.inf 优化
    // 防止资源管理器扫描所有驱动器导致卡顿
    if (g_CurrentProcessType == ProcType_Explorer) {
        if (fullNtPath.length() >= 12 &&
            _wcsicmp(fullNtPath.c_str() + fullNtPath.length() - 12, L"\\autorun.inf") == 0) {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }


    // [重定向逻辑]
    if (ShouldRedirect(fullNtPath, targetNtPath)) {
        UNICODE_STRING uStr;
        RtlInitUnicodeString(&uStr, targetNtPath.c_str());
        PUNICODE_STRING oldName = ObjectAttributes->ObjectName;
        HANDLE oldRoot = ObjectAttributes->RootDirectory;
        ObjectAttributes->ObjectName = &uStr;
        ObjectAttributes->RootDirectory = NULL;

        // 1. 优先查询沙盒
        NTSTATUS status = fpNtQueryFullAttributesFile(ObjectAttributes, FileInformation);

        ObjectAttributes->ObjectName = oldName;
        ObjectAttributes->RootDirectory = oldRoot;

        if (status == STATUS_SUCCESS) return status;

        // 2. [Mode 3] 隐藏检查
        // 如果沙盒里没有，且模式为 3，检查真实文件是否应该被隐藏
        if (g_HookMode == 3) {
            if (!IsPathVisible(fullNtPath)) {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
        }
    }

    // 查询真实文件
    NTSTATUS status = fpNtQueryFullAttributesFile(ObjectAttributes, FileInformation);

    // [兼容性补丁 - 后处理]
    // [MSI Installer] Config.Msi 补丁
    // MSI 必须能访问 Config.Msi，如果失败则尝试创建
    if (status == STATUS_OBJECT_NAME_NOT_FOUND && g_CurrentProcessType == ProcType_Msi_Installer) {
        if (fullNtPath.length() >= 11 &&
            _wcsicmp(fullNtPath.c_str() + fullNtPath.length() - 11, L"\\Config.Msi") == 0) {

            std::wstring dosPath = NtPathToDosPath(fullNtPath);
            if (!dosPath.empty()) {
                // 尝试创建目录 (CreateDirectory 会自动处理重定向逻辑，如果在 Hook 范围内)
                if (CreateDirectoryW(dosPath.c_str(), NULL)) {
                    DebugLog(L"Compat: MSI - Created missing Config.Msi at %s", dosPath.c_str());
                    // 重试查询
                    status = fpNtQueryFullAttributesFile(ObjectAttributes, FileInformation);
                }
            }
        }
    }

    return status;
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

    NTSTATUS status = fpNtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);

    // 拦截 FileNameInformation (用于 GetFinalPathNameByHandle 等 API)
    if (NT_SUCCESS(status) && FileInformationClass == FileNameInformation) {

        PFILE_NAME_INFORMATION nameInfo = (PFILE_NAME_INFORMATION)FileInformation;

        if (nameInfo->FileNameLength > 0) {
            // 构造要移除的子串: \Sandbox\C
            // 这需要根据你的 g_SandboxRoot 动态计算
            // 这是一个优化点，如果你的沙盒结构固定，可以直接硬编码逻辑
        }
    }

    // 另外：FileAllInformation 也包含 NameInformation，也需要处理
    if (NT_SUCCESS(status) && FileInformationClass == FileAllInformation) {
        // PFILE_ALL_INFORMATION allInfo = (PFILE_ALL_INFORMATION)FileInformation;
        // 处理 allInfo->NameInformation ...
    }

    return status;
}

NTSTATUS NTAPI Detour_NtQueryObject(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
) {
    // 1. 调用原始函数
    NTSTATUS status = fpNtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

    // 2. 仅处理成功且查询类型为 ObjectNameInformation 的情况
    if (NT_SUCCESS(status) && ObjectInformationClass == ObjectNameInformation && ObjectInformation) {

        POBJECT_NAME_INFORMATION nameInfo = (POBJECT_NAME_INFORMATION)ObjectInformation;

        // 确保缓冲区有效且有内容
        if (nameInfo->Name.Buffer && nameInfo->Name.Length > 0) {

            // 构造沙盒 NT 前缀: \??\Z:\Sandbox
            // 注意：建议将此字符串缓存为全局变量，避免每次调用都构造 std::wstring
            static std::wstring sandboxPrefix = L"\\??\\" + std::wstring(g_SandboxRoot);
            size_t prefixLenBytes = sandboxPrefix.length() * sizeof(wchar_t);

            // 检查是否以沙盒路径开头
            if (nameInfo->Name.Length > prefixLenBytes) {
                if (_wcsnicmp(nameInfo->Name.Buffer, sandboxPrefix.c_str(), sandboxPrefix.length()) == 0) {

                    // 检查分隔符 (确保不是部分匹配，如 \SandboxOld)
                    if (nameInfo->Name.Buffer[sandboxPrefix.length()] == L'\\') {

                        // 原始: \??\Z:\Sandbox \ C \ Windows...
                        // 目标: \??\C:\Windows...

                        // 指向: C\Windows...
                        wchar_t* pRel = nameInfo->Name.Buffer + sandboxPrefix.length() + 1;

                        // 计算剩余长度
                        size_t relLenBytes = nameInfo->Name.Length - (prefixLenBytes + sizeof(wchar_t));

                        // 简单的启发式还原: 检查是否是驱动器结构 (C\...)
                        if (relLenBytes >= 2 * sizeof(wchar_t) && pRel[1] == L'\\') {
                             // 构造 \??\C:\Windows...

                             // 1. 搬运盘符 'C' 到 Buffer[4] (紧跟在 \??\ 后)
                             nameInfo->Name.Buffer[4] = pRel[0];

                             // 2. 补冒号 ':' 到 Buffer[5]
                             nameInfo->Name.Buffer[5] = L':';

                             // 3. 搬运剩余路径 (\Windows...) 到 Buffer[6]
                             // 源: pRel + 1 (即 \Windows...)
                             // 长度: relLenBytes - 1个字符(盘符)
                             size_t moveLenBytes = relLenBytes - sizeof(wchar_t);

                             memmove(&nameInfo->Name.Buffer[6], &pRel[1], moveLenBytes);

                             // 4. 更新长度: \??\ (4) + C: (2) + \Windows...
                             nameInfo->Name.Length = (USHORT)( (6 * sizeof(wchar_t)) + moveLenBytes );

                             // 5. 截断字符串 (安全起见)
                             if (nameInfo->Name.MaximumLength >= nameInfo->Name.Length + sizeof(wchar_t)) {
                                 nameInfo->Name.Buffer[nameInfo->Name.Length / sizeof(wchar_t)] = L'\0';
                             }
                        }
                        // 如果不是驱动器结构 (例如 Users\...)，可能需要更复杂的逻辑
                        // 但对于大多数基于驱动器的沙盒，上述逻辑已足够覆盖 99% 的情况
                    }
                }
            }
        }
    }

    return status;
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

// --- Winsock Hooks ---

// 辅助：判断是否为内网/私有 IP 地址
bool IsIntranetIp32(ULONG ipNetworkOrder) {
    // 将网络字节序转换为主机字节序以便比较
    ULONG ip = ntohl(ipNetworkOrder);

    // 1. Loopback: 127.0.0.0/8
    if ((ip & 0xFF000000) == 0x7F000000) return true;
    // 2. Private: 10.0.0.0/8
    if ((ip & 0xFF000000) == 0x0A000000) return true;
    // 3. Private: 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    if ((ip & 0xFFF00000) == 0xAC100000) return true;
    // 4. Private: 192.168.0.0/16
    if ((ip & 0xFFFF0000) == 0xC0A80000) return true;
    // 5. Link-Local: 169.254.0.0/16
    if ((ip & 0xFFFF0000) == 0xA9FE0000) return true;
    // 6. Multicast: 224.0.0.0/4 (组播 常用于局域网发现)
    if ((ip & 0xF0000000) == 0xE0000000) return true;
    // 7. Broadcast: 255.255.255.255
    if (ip == 0xFFFFFFFF) return true;

    return false;
}

bool IsIntranetAddress(const struct sockaddr* name) {
    if (!name) return false;

    if (name->sa_family == AF_INET) {
        const struct sockaddr_in* sin = (const struct sockaddr_in*)name;
        return IsIntranetIp32(sin->sin_addr.s_addr);
    }
    else if (name->sa_family == AF_INET6) {
        const struct sockaddr_in6* sin6 = (const struct sockaddr_in6*)name;

        // Loopback ::1
        if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr)) return true;
        // Link-Local fe80::/10
        if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) return true;
        // Unique Local fc00::/7 (IPv6 私有地址)
        const UCHAR* b = sin6->sin6_addr.u.Byte;
        if ((b[0] & 0xFE) == 0xFC) return true;
        // Multicast ff00::/8
        if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr)) return true;

        return false;
    }
    // 对于非 IP 协议（如蓝牙 AF_BTH） 默认放行 或者根据需求拦截
    return true;
}

// 辅助：判断字符串是否为有效的 IP 地址 (IPv4 或 IPv6)
bool IsIpAddressString(PCWSTR str) {
    if (!str) return false;

    SOCKADDR_STORAGE sa;
    int len = sizeof(sa);

    // 尝试解析为 IPv4
    if (WSAStringToAddressW((LPWSTR)str, AF_INET, NULL, (LPSOCKADDR)&sa, &len) == 0) return true;

    // 尝试解析为 IPv6
    len = sizeof(sa);
    if (WSAStringToAddressW((LPWSTR)str, AF_INET6, NULL, (LPSOCKADDR)&sa, &len) == 0) return true;

    return false;
}

// 辅助：解析域名并判断是否解析为内网 IP
bool IsIntranetHost(LPCWSTR pNodeName) {
    if (!pNodeName || !*pNodeName) return false;

    // 1. 如果直接是 IP 字符串 判断 IP
    if (IsIpAddressString(pNodeName)) {
        // 转换字符串为 IP 结构比较麻烦 这里偷懒：
        // 让它走下面的 GetAddrInfoW 流程 反正效果一样
    }

    // 2. 检查 localhost
    if (_wcsicmp(pNodeName, L"localhost") == 0) return true;

    // 3. 解析域名 (使用原始函数 fpGetAddrInfoW 避免死循环)
    ADDRINFOW hints = { 0 };
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    PADDRINFOW pResult = NULL;

    if (fpGetAddrInfoW && fpGetAddrInfoW(pNodeName, NULL, &hints, &pResult) == 0) {
        bool isIntranet = false;
        PADDRINFOW ptr = pResult;
        while (ptr != NULL) {
            if (IsIntranetAddress(ptr->ai_addr)) {
                isIntranet = true;
                break;
            }
            ptr = ptr->ai_next;
        }
        FreeAddrInfoW(pResult);
        return isIntranet;
    }

    // 如果解析失败 为了安全起见 默认视为外网并拦截
    return false;
}

// 辅助：从 URL 中提取主机名
std::wstring GetHostFromUrl(LPCWSTR url) {
    if (!url) return L"";

    // 使用 InternetCrackUrl 解析
    URL_COMPONENTSW urlComp = { 0 };
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwHostNameLength = 1; // 设置非0值以指示我们需要获取 HostName

    // 预分配缓冲区
    wchar_t hostName[2048] = { 0 };
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = 2048;

    if (InternetCrackUrlW(url, 0, 0, &urlComp)) {
        return std::wstring(hostName);
    }
    return L"";
}

int WSAAPI Detour_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    // 放行内网 IP
    if (IsIntranetAddress(name)) {
        return fpConnect(s, name, namelen);
    }
    // 拦截公网 IP
    WSASetLastError(WSAEACCES);
    return SOCKET_ERROR;
}

int WSAAPI Detour_WSAConnect(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) {
    if (IsIntranetAddress(name)) {
        return fpWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    }
    WSASetLastError(WSAEACCES);
    return SOCKET_ERROR;
}

// --- UDP Hook (拦截 sendto) ---
int WSAAPI Detour_sendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen) {
    if (IsIntranetAddress(to)) {
        return fpSendTo(s, buf, len, flags, to, tolen);
    }
    WSASetLastError(WSAEACCES);
    return SOCKET_ERROR;
}

// --- UDP 高级拦截 ---
int WSAAPI Detour_WSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr* lpTo, int iTolen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (g_BlockNetwork) {
        // 如果指定了目标地址 必须检查
        if (lpTo) {
            if (IsIntranetAddress(lpTo)) {
                return fpWSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
            }
            WSASetLastError(WSAEACCES);
            return SOCKET_ERROR;
        }
        // 如果 lpTo 为空（已连接的 UDP 套接字） 通常在 connect 时已检查过 放行
    }
    return fpWSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
}

// --- WinINet 拦截 ---
HINTERNET WINAPI Detour_InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) {
    if (g_BlockNetwork) {
        if (!IsIntranetHost(lpszServerName)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return NULL;
        }
    }
    return fpInternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

// --- WinINet ANSI 拦截 ---
HINTERNET WINAPI Detour_InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) {
    if (g_BlockNetwork) {
        // 转换为 Wide 字符串进行检查
        std::wstring serverNameW = AnsiToWide(lpszServerName);
        if (!IsIntranetHost(serverNameW.c_str())) {
            SetLastError(ERROR_ACCESS_DENIED);
            return NULL;
        }
    }
    return fpInternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

// --- InternetOpenUrl (Unicode) 拦截 ---
HINTERNET WINAPI Detour_InternetOpenUrlW(HINTERNET hInternet, LPCWSTR lpszUrl, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext) {
    if (g_BlockNetwork) {
        std::wstring host = GetHostFromUrl(lpszUrl);
        // 如果解析不出主机名 或者主机名不是内网 则拦截
        if (host.empty() || !IsIntranetHost(host.c_str())) {
            SetLastError(ERROR_ACCESS_DENIED);
            return NULL;
        }
    }
    return fpInternetOpenUrlW(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
}

// --- InternetOpenUrl (ANSI) 拦截 ---
HINTERNET WINAPI Detour_InternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext) {
    if (g_BlockNetwork) {
        std::wstring urlW = AnsiToWide(lpszUrl);
        std::wstring host = GetHostFromUrl(urlW.c_str());
        if (host.empty() || !IsIntranetHost(host.c_str())) {
            SetLastError(ERROR_ACCESS_DENIED);
            return NULL;
        }
    }
    return fpInternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
}

// --- 旧版 DNS (gethostbyname) 拦截 ---
struct hostent* WSAAPI Detour_gethostbyname(const char* name) {
    if (g_BlockNetwork) {
        std::wstring nameW = AnsiToWide(name);
        // 允许 localhost
        if (_wcsicmp(nameW.c_str(), L"localhost") == 0) {
            return fpGethostbyname(name);
        }

        // 这里的逻辑比较特殊：gethostbyname 返回的是 IP 列表
        // 我们无法预知它解析出的是内网还是外网 IP
        // 策略：
        // 1. 如果输入的是纯 IP 字符串 放行（让 connect 去拦截）
        // 2. 如果是域名 直接拦截因为内网域名解析通常走 DNS 而 gethostbyname 是非常老的 API
        //    现代内网环境（mDNS/LLMNR）它支持不好 且容易泄露隐私
        //    如果确实需要支持内网旧版域名解析 可以放行 依靠 connect 拦截 IP
        //    但为了安全 这里默认拦截非 IP 字符串

        if (IsIpAddressString(nameW.c_str())) {
             return fpGethostbyname(name);
        }

        WSASetLastError(WSAHOST_NOT_FOUND);
        return NULL;
    }
    return fpGethostbyname(name);
}

// --- WinHTTP 拦截 ---
HINTERNET WINAPI Detour_WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved) {
    if (g_BlockNetwork) {
        if (!IsIntranetHost(pswzServerName)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return NULL;
        }
    }
    return fpWinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
}

// --- ICMP Hooks (拦截 Ping) ---
DWORD WINAPI Detour_IcmpSendEcho(HANDLE IcmpHandle, IPAddr DestinationAddress, LPVOID RequestData, WORD RequestSize, PIP_OPTION_INFORMATION RequestOptions, LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout) {
    // DestinationAddress 是 ULONG (IPv4)
    if (IsIntranetIp32(DestinationAddress)) {
        return fpIcmpSendEcho(IcmpHandle, DestinationAddress, RequestData, RequestSize, RequestOptions, ReplyBuffer, ReplySize, Timeout);
    }
    SetLastError(ERROR_ACCESS_DENIED);
    return 0;
}

DWORD WINAPI Detour_IcmpSendEcho2(HANDLE IcmpHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, IPAddr DestinationAddress, LPVOID RequestData, WORD RequestSize, PIP_OPTION_INFORMATION RequestOptions, LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout) {
    if (IsIntranetIp32(DestinationAddress)) {
        return fpIcmpSendEcho2(IcmpHandle, Event, ApcRoutine, ApcContext, DestinationAddress, RequestData, RequestSize, RequestOptions, ReplyBuffer, ReplySize, Timeout);
    }
    SetLastError(ERROR_ACCESS_DENIED);
    return 0;
}

// 新增：拦截 IcmpSendEcho2Ex (Windows 8+ ping.exe 使用此函数)
DWORD WINAPI Detour_IcmpSendEcho2Ex(HANDLE IcmpHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, IPAddr SourceAddress, IPAddr DestinationAddress, LPVOID RequestData, WORD RequestSize, PIP_OPTION_INFORMATION RequestOptions, LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout) {
    // 检查目标地址 (DestinationAddress)
    if (IsIntranetIp32(DestinationAddress)) {
        return fpIcmpSendEcho2Ex(IcmpHandle, Event, ApcRoutine, ApcContext, SourceAddress, DestinationAddress, RequestData, RequestSize, RequestOptions, ReplyBuffer, ReplySize, Timeout);
    }
    SetLastError(ERROR_ACCESS_DENIED);
    return 0;
}

// IPv6 Ping
DWORD WINAPI Detour_Icmp6SendEcho2(HANDLE IcmpHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PSOCKADDR_IN6 SourceAddress, PSOCKADDR_IN6 DestinationAddress, LPVOID RequestData, WORD RequestSize, PIP_OPTION_INFORMATION RequestOptions, LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout) {
    // 构造 sockaddr 结构以复用 IsIntranetAddress
    if (IsIntranetAddress((struct sockaddr*)DestinationAddress)) {
        return fpIcmp6SendEcho2(IcmpHandle, Event, ApcRoutine, ApcContext, SourceAddress, DestinationAddress, RequestData, RequestSize, RequestOptions, ReplyBuffer, ReplySize, Timeout);
    }
    SetLastError(ERROR_ACCESS_DENIED);
    return 0;
}

// --- DNS Hook (拦截域名解析) ---
int WSAAPI Detour_GetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName, const ADDRINFOW* pHints, PADDRINFOW* ppResult) {
    // 始终放行 DNS 解析 以便支持内网主机名解析
    // 真正的拦截由 connect/sendto/IcmpSendEcho 负责（它们会检查解析出来的 IP）
    return fpGetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
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
    // 1. 刷新设备映射
    RefreshDeviceMap();

    wchar_t buffer[MAX_PATH] = { 0 };

    // 2. 读取内存映射配置
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

    // 3. 读取 Hook 模式 (文件重定向)
    if (GetEnvironmentVariableW(L"YAP_HOOK_FILE", buffer, MAX_PATH) > 0) {
        g_HookMode = _wtoi(buffer);
        // 注意：这里允许 g_HookMode 为 0
    }

    // [新增] 读取子进程挂钩配置
    wchar_t childBuffer[64];
    if (GetEnvironmentVariableW(L"YAP_HOOK_CHILD", childBuffer, 64) > 0) {
        int val = _wtoi(childBuffer);
        // hookchild=2 表示不挂钩子进程
        if (val == 2) {
            g_HookChild = false;
        }
    }

    // [新增] 读取网络拦截开关
    wchar_t netBuffer[64];
    if (GetEnvironmentVariableW(L"YAP_HOOK_NET", netBuffer, 64) > 0) {
        g_BlockNetwork = (_wtoi(netBuffer) == 1);
    }

    // 4. [新增] 获取系统盘符并初始化白名单
    if (GetSystemDirectoryW(buffer, MAX_PATH) > 0) {
        buffer[2] = L'\0'; // 截断为 "C:"
        g_SystemDriveLetter = buffer;
        g_SystemDriveNt = L"\\??\\";
        g_SystemDriveNt += buffer;
        InitSystemWhitelist();
    }

    // [新增] 获取当前进程路径用于自身保护
    if (GetModuleFileNameW(NULL, buffer, MAX_PATH) > 0) {
        std::wstring dosPath = buffer;
        g_CurrentProcessPathNt = L"\\??\\" + dosPath;

        // [新增] 识别进程类型
        InitProcessType();
    }

    // 5. 环境变量回退 (如果内存映射没读到)
    if (g_SandboxRoot[0] == L'\0') {
        if (GetEnvironmentVariableW(L"YAP_HOOK_PATH", buffer, MAX_PATH) > 0) wcscpy_s(g_SandboxRoot, MAX_PATH, buffer);
    }
    if (g_IpcPipeName[0] == L'\0') {
        if (GetEnvironmentVariableW(L"YAP_IPC_PIPE", buffer, MAX_PATH) > 0) wcscpy_s(g_IpcPipeName, MAX_PATH, buffer);
    }

    // 检查根目录是否获取成功
    if (g_SandboxRoot[0] == L'\0') {
        DebugLog(L"Init Failed: YAP_HOOK_PATH not found");
        return 0;
    }

    // 6. 初始化特殊目录 NT 路径
    if (g_LauncherDir[0] != L'\0') {
        g_LauncherDirNt = L"\\??\\";
        g_LauncherDirNt += g_LauncherDir;

        // [新增] 计算启动器盘符 (例如 \??\Z:)
        if (g_LauncherDirNt.length() >= 6) {
            g_LauncherDriveNt = g_LauncherDirNt.substr(0, 6);
        }
    }

    // 初始化 UserProfile 等路径
    if (GetEnvironmentVariableW(L"USERPROFILE", buffer, MAX_PATH)) {
        g_UserProfileNt = L"\\??\\";
        g_UserProfileNt += buffer;
        g_UserProfileNtShort = GetNtShortPath(buffer);

        std::wstring temp = g_UserProfileNt;
        if (!temp.empty() && temp.back() == L'\\') temp.pop_back();
        size_t lastSlash = temp.find_last_of(L'\\');
        if (lastSlash != std::wstring::npos && lastSlash > 6) {
            g_UsersDirNt = temp.substr(0, lastSlash);
        }

        if (!g_UserProfileNtShort.empty()) {
            std::wstring tempShort = g_UserProfileNtShort;
            if (!tempShort.empty() && tempShort.back() == L'\\') tempShort.pop_back();
            size_t lastSlashShort = tempShort.find_last_of(L'\\');
            if (lastSlashShort != std::wstring::npos && lastSlashShort > 6) {
                g_UsersDirNtShort = tempShort.substr(0, lastSlashShort);
            }
        }
    }

    if (GetEnvironmentVariableW(L"ALLUSERSPROFILE", buffer, MAX_PATH)) {
        g_ProgramDataNt = L"\\??\\";
        g_ProgramDataNt += buffer;
        g_ProgramDataNtShort = GetNtShortPath(buffer);
    }

    if (GetEnvironmentVariableW(L"PUBLIC", buffer, MAX_PATH)) {
        g_PublicNt = L"\\??\\";
        g_PublicNt += buffer;
    }

    DebugLog(L"Hook Initialized. Mode: %d, Root: %s", g_HookMode, g_SandboxRoot);

    // 7. 初始化 MinHook
    if (MH_Initialize() != MH_OK) return 0;

    // =======================================================
    // 分组挂钩逻辑
    // =======================================================

    // --- 组 A: 文件系统 Hook (仅当 hookfile > 0 时挂钩) ---
    if (g_HookMode > 0) {
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
            MH_CreateHook(GetProcAddress(hNtdll, "NtQueryObject"), &Detour_NtQueryObject, reinterpret_cast<LPVOID*>(&fpNtQueryObject));

            fpNtQueryObject = (P_NtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");

            void* pNtQueryDirectoryFileEx = (void*)GetProcAddress(hNtdll, "NtQueryDirectoryFileEx");
            if (pNtQueryDirectoryFileEx) {
                MH_CreateHook(pNtQueryDirectoryFileEx, &Detour_NtQueryDirectoryFileEx, reinterpret_cast<LPVOID*>(&fpNtQueryDirectoryFileEx));
            }
        }

        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (hKernel32) {
            void* pGetFinalPathNameByHandleW = (void*)GetProcAddress(hKernel32, "GetFinalPathNameByHandleW");
            if (pGetFinalPathNameByHandleW) {
                MH_CreateHook(pGetFinalPathNameByHandleW, &Detour_GetFinalPathNameByHandleW, reinterpret_cast<LPVOID*>(&fpGetFinalPathNameByHandleW));
            }
        }
    }

    // --- 组 B: 进程创建 Hook (只要启用了任意功能 就需要挂钩以实现子进程注入) ---
    if (g_HookChild && (g_HookMode > 0 || g_BlockNetwork)) {
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
    }

    // --- 组 C: 网络 Hook (仅当 hooknet=1 时挂钩) ---
    if (g_BlockNetwork) {
        // 1. Winsock Hooks (TCP/UDP/DNS)
        HMODULE hWinsock = LoadLibraryW(L"ws2_32.dll");
        if (hWinsock) {
            void* pConnect = (void*)GetProcAddress(hWinsock, "connect");
            void* pWSAConnect = (void*)GetProcAddress(hWinsock, "WSAConnect");
            void* pGetAddrInfoW = (void*)GetProcAddress(hWinsock, "GetAddrInfoW");
            void* pSendTo = (void*)GetProcAddress(hWinsock, "sendto");
            void* pWSASendTo = (void*)GetProcAddress(hWinsock, "WSASendTo");
            void* pGethostbyname = (void*)GetProcAddress(hWinsock, "gethostbyname");

            if (pGethostbyname) MH_CreateHook(pGethostbyname, &Detour_gethostbyname, reinterpret_cast<LPVOID*>(&fpGethostbyname));
            if (pWSASendTo) MH_CreateHook(pWSASendTo, &Detour_WSASendTo, reinterpret_cast<LPVOID*>(&fpWSASendTo));
            if (pConnect) MH_CreateHook(pConnect, &Detour_connect, reinterpret_cast<LPVOID*>(&fpConnect));
            if (pWSAConnect) MH_CreateHook(pWSAConnect, &Detour_WSAConnect, reinterpret_cast<LPVOID*>(&fpWSAConnect));
            if (pGetAddrInfoW) MH_CreateHook(pGetAddrInfoW, &Detour_GetAddrInfoW, reinterpret_cast<LPVOID*>(&fpGetAddrInfoW));
            if (pSendTo) MH_CreateHook(pSendTo, &Detour_sendto, reinterpret_cast<LPVOID*>(&fpSendTo));
        }

        // 2. IP Helper Hooks (ICMP/Ping)
        HMODULE hIphlpapi = LoadLibraryW(L"iphlpapi.dll");
        if (hIphlpapi) {
            void* pIcmpSendEcho = (void*)GetProcAddress(hIphlpapi, "IcmpSendEcho");
            void* pIcmpSendEcho2 = (void*)GetProcAddress(hIphlpapi, "IcmpSendEcho2");
            // [新增] 获取 IcmpSendEcho2Ex 地址
            void* pIcmpSendEcho2Ex = (void*)GetProcAddress(hIphlpapi, "IcmpSendEcho2Ex");
            void* pIcmp6SendEcho2 = (void*)GetProcAddress(hIphlpapi, "Icmp6SendEcho2");

            if (pIcmpSendEcho) MH_CreateHook(pIcmpSendEcho, &Detour_IcmpSendEcho, reinterpret_cast<LPVOID*>(&fpIcmpSendEcho));
            if (pIcmpSendEcho2) MH_CreateHook(pIcmpSendEcho2, &Detour_IcmpSendEcho2, reinterpret_cast<LPVOID*>(&fpIcmpSendEcho2));
            // [新增] 创建 Hook
            if (pIcmpSendEcho2Ex) MH_CreateHook(pIcmpSendEcho2Ex, &Detour_IcmpSendEcho2Ex, reinterpret_cast<LPVOID*>(&fpIcmpSendEcho2Ex));
            if (pIcmp6SendEcho2) MH_CreateHook(pIcmp6SendEcho2, &Detour_Icmp6SendEcho2, reinterpret_cast<LPVOID*>(&fpIcmp6SendEcho2));
        }
        // 3. [新增] WinINet Hooks
        HMODULE hWinInet = LoadLibraryW(L"wininet.dll");
        if (hWinInet) {
            // 原有 Unicode Connect
            void* pInternetConnectW = (void*)GetProcAddress(hWinInet, "InternetConnectW");
            if (pInternetConnectW) MH_CreateHook(pInternetConnectW, &Detour_InternetConnectW, reinterpret_cast<LPVOID*>(&fpInternetConnectW));

            // [新增] ANSI Connect
            void* pInternetConnectA = (void*)GetProcAddress(hWinInet, "InternetConnectA");
            if (pInternetConnectA) MH_CreateHook(pInternetConnectA, &Detour_InternetConnectA, reinterpret_cast<LPVOID*>(&fpInternetConnectA));

            // [新增] InternetOpenUrl W & A
            void* pInternetOpenUrlW = (void*)GetProcAddress(hWinInet, "InternetOpenUrlW");
            if (pInternetOpenUrlW) MH_CreateHook(pInternetOpenUrlW, &Detour_InternetOpenUrlW, reinterpret_cast<LPVOID*>(&fpInternetOpenUrlW));

            void* pInternetOpenUrlA = (void*)GetProcAddress(hWinInet, "InternetOpenUrlA");
            if (pInternetOpenUrlA) MH_CreateHook(pInternetOpenUrlA, &Detour_InternetOpenUrlA, reinterpret_cast<LPVOID*>(&fpInternetOpenUrlA));
        }

        // 4. [新增] WinHTTP Hooks
        HMODULE hWinHttp = LoadLibraryW(L"winhttp.dll");
        if (hWinHttp) {
            void* pWinHttpConnect = (void*)GetProcAddress(hWinHttp, "WinHttpConnect");
            if (pWinHttpConnect) MH_CreateHook(pWinHttpConnect, &Detour_WinHttpConnect, reinterpret_cast<LPVOID*>(&fpWinHttpConnect));
        }
    }

    // 9. 启用所有已创建的 Hook
    // MinHook 只会启用之前调用过 MH_CreateHook 的函数 未创建的会被忽略
    MH_EnableHook(MH_ALL_HOOKS);

    // 10. 通知启动器就绪
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