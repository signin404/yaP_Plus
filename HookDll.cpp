#include <windows.h>
#include <winternl.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include <algorithm>
#include <stdio.h>
#include "MinHook.h"
#include "IpcCommon.h"

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

#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE 0x00000001
#endif

// -----------------------------------------------------------
// 2. 补全缺失的 NT 结构体与枚举
// -----------------------------------------------------------

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

// [修改] 检查路径是否需要重定向
bool ShouldRedirect(const std::wstring& fullNtPath, std::wstring& targetPath) {
    if (g_SandboxRoot[0] == L'\0') return false;
    if (IsPipeOrDevice(fullNtPath.c_str())) return false;

    if (fullNtPath.rfind(L"\\??\\", 0) != 0) return false;

    if (ContainsCaseInsensitive(fullNtPath, g_SandboxRoot)) return false;

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

    if (GetFileAttributesW(sourceDos.c_str()) == INVALID_FILE_ATTRIBUTES) return;
    if (GetFileAttributesW(targetDos.c_str()) != INVALID_FILE_ATTRIBUTES) return;

    wchar_t dirBuf[MAX_PATH];
    wcscpy_s(dirBuf, targetDos.c_str());
    PathRemoveFileSpecW(dirBuf);
    RecursiveCreateDirectory(dirBuf);

    DebugLog(L"Migrating: %s -> %s", sourceDos.c_str(), targetDos.c_str());
    CopyFileW(sourceDos.c_str(), targetDos.c_str(), TRUE);
}

void ProcessQueryData(PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    // 占位符
}

struct RecursionGuard {
    RecursionGuard() { g_IsInHook = true; }
    ~RecursionGuard() { g_IsInHook = false; }
};

// --- NTDLL Hooks ---

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
    std::wstring targetNtPath;

    if (ShouldRedirect(fullNtPath, targetNtPath)) {

        bool isWrite = (DesiredAccess & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA));

        if (isWrite) {
            if (CreateDisposition == FILE_OPEN || CreateDisposition == FILE_OPEN_IF || CreateDisposition == FILE_OVERWRITE || CreateDisposition == FILE_OVERWRITE_IF) {
                PerformCopyOnWrite(fullNtPath, targetNtPath);
            }
        }

        UNICODE_STRING uStr;
        RtlInitUnicodeString(&uStr, targetNtPath.c_str());

        PUNICODE_STRING oldName = ObjectAttributes->ObjectName;
        HANDLE oldRoot = ObjectAttributes->RootDirectory;

        ObjectAttributes->ObjectName = &uStr;
        ObjectAttributes->RootDirectory = NULL;

        if (CreateDisposition == FILE_CREATE || CreateDisposition == FILE_OPEN_IF || CreateDisposition == FILE_OVERWRITE_IF || CreateDisposition == FILE_SUPERSEDE) {
            EnsureDirectoryExistsNT(targetNtPath.c_str());
        }

        NTSTATUS status = fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

        ObjectAttributes->ObjectName = oldName;
        ObjectAttributes->RootDirectory = oldRoot;

        if (status == STATUS_SUCCESS) {
            return status;
        }

        if (!isWrite && (CreateDisposition == FILE_OPEN || CreateDisposition == FILE_OPEN_IF)) {
             // Fallthrough to original call
        } else {
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

NTSTATUS NTAPI Detour_NtSetInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
) {
    if (g_IsInHook) return fpNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    RecursionGuard guard;

    // 检查是否为破坏性操作
    bool isDestructive = (FileInformationClass == FileDispositionInformation ||
                          FileInformationClass == FileBasicInformation ||
                          FileInformationClass == FileRenameInformation);

    if (!isDestructive) {
        return fpNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    }

    // 获取当前句柄指向的路径
    std::wstring currentPath = GetPathFromHandle(FileHandle);
    if (currentPath.empty()) {
        return fpNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    }

    // 如果已经是沙盒路径，直接放行 (让系统去修改沙盒里的文件)
    if (ContainsCaseInsensitive(currentPath, g_SandboxRoot)) {
        // TODO: 这里未来可以优化“虚拟删除”逻辑 (即删除沙盒文件后创建墓碑文件)
        // 目前先允许直接删除沙盒内的副本
        return fpNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    }

    // --- 关键逻辑：句柄指向真实文件 ---

    // 检查该路径是否属于应该被重定向的范围
    std::wstring targetNtPath;
    if (!ShouldRedirect(currentPath, targetNtPath)) {
        // 如果不在重定向规则内（例如 D:\ 盘文件且没配置重定向），则允许修改真实文件
        return fpNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    }

    // 既然应该重定向，但句柄却是真实的，说明 NtCreateFile 没拦截住（或者是只读打开后又想修改）
    // 我们必须在这里进行“亡羊补牢”：将操作应用到沙盒，保护真实文件。

    DebugLog(L"Intercepted Destructive Op on Real File: %s", currentPath.c_str());

    // 1. 确保沙盒中有副本 (Copy-on-Write)
    PerformCopyOnWrite(currentPath, targetNtPath);

    // 2. 将 NT 路径转换为 DOS 路径以便使用 Win32 API 操作沙盒文件
    std::wstring targetDosPath = NtPathToDosPath(targetNtPath);

    // 3. 根据操作类型，在沙盒文件上执行操作
    if (FileInformationClass == FileDispositionInformation) {
        FILE_DISPOSITION_INFORMATION* info = (FILE_DISPOSITION_INFORMATION*)FileInformation;
        if (info->DeleteFile) {
            DebugLog(L"Redirect Delete: %s", targetDosPath.c_str());
            // 在沙盒中创建“墓碑”文件或直接删除沙盒副本
            // 简单起见，我们先删除沙盒副本，并创建一个特殊的 0 字节文件作为删除标记
            // (更完善的实现需要配合 NtQueryDirectoryFile 过滤该标记)

            // 这里我们模拟成功，但不删除真实文件
            // 如果沙盒里有副本，删掉副本
            DeleteFileW(targetDosPath.c_str());

            // 创建一个墓碑文件 (可选，防止再次读取)
            // HANDLE hMarker = CreateFileW(targetDosPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            // if (hMarker != INVALID_HANDLE_VALUE) CloseHandle(hMarker);
        }
    }
    else if (FileInformationClass == FileBasicInformation) {
        FILE_BASIC_INFORMATION* info = (FILE_BASIC_INFORMATION*)FileInformation;
        DebugLog(L"Redirect Attributes: %s", targetDosPath.c_str());

        // 使用 Win32 API 修改沙盒文件的属性
        // 注意：时间戳为 0 或 -1 表示不修改
        HANDLE hSandbox = CreateFileW(targetDosPath.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hSandbox != INVALID_HANDLE_VALUE) {
            // 我们需要调用原始 NT 函数来设置沙盒文件的属性，因为 Win32 SetFileTime/Attr 不够灵活
            IO_STATUS_BLOCK ioBlock;
            fpNtSetInformationFile(hSandbox, &ioBlock, FileInformation, Length, FileInformationClass);
            CloseHandle(hSandbox);
        }
    }
    else if (FileInformationClass == FileRenameInformation) {
        // 重命名稍微复杂，因为涉及新路径
        // 简单处理：如果是重命名，我们通常不支持跨卷重命名到沙盒外
        // 这里暂时返回成功欺骗程序，或者尝试在沙盒内重命名
        DebugLog(L"Redirect Rename: Blocked for safety");
    }

    // 4. 无论如何，返回成功 (STATUS_SUCCESS)，欺骗应用程序它已经修改了文件
    // 绝对不要调用原始函数去操作真实句柄！
    IoStatusBlock->Status = STATUS_SUCCESS;
    IoStatusBlock->Information = 0;
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI Detour_NtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation) {
    if (g_IsInHook) return fpNtQueryAttributesFile(ObjectAttributes, FileInformation);
    RecursionGuard guard;
    std::wstring fullNtPath = ResolvePathFromAttr(ObjectAttributes);
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

NTSTATUS NTAPI Detour_NtQueryDirectoryFile(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName, BOOLEAN RestartScan
) {
    if (g_IsInHook) return fpNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
    RecursionGuard guard;
    NTSTATUS status = fpNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
    if (status == STATUS_SUCCESS && IoStatusBlock->Information > 0) {
        ProcessQueryData(FileInformation, Length, FileInformationClass);
    }
    return status;
}

NTSTATUS NTAPI Detour_NtQueryDirectoryFileEx(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName
) {
    if (g_IsInHook) return fpNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
    RecursionGuard guard;
    NTSTATUS status = fpNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
    if (status == STATUS_SUCCESS && IoStatusBlock->Information > 0) {
        ProcessQueryData(FileInformation, Length, FileInformationClass);
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
            // \??\C: 长度为 6，我们要求路径长度大于此才截取
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