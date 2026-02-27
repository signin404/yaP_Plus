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
#include <mswsock.h>
#include <shellapi.h>
#include <numeric>
#include <set>
#include <sddl.h>
#include <aclapi.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma pack(push, 1)
#pragma pack(pop)

// 导出函数转发
#pragma comment(linker, "/export:GetFileVersionInfoA=C:\\Windows\\System32\\version.GetFileVersionInfoA")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=C:\\Windows\\System32\\version.GetFileVersionInfoByHandle")
#pragma comment(linker, "/export:GetFileVersionInfoExA=C:\\Windows\\System32\\version.GetFileVersionInfoExA")
#pragma comment(linker, "/export:GetFileVersionInfoExW=C:\\Windows\\System32\\version.GetFileVersionInfoExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeW")
#pragma comment(linker, "/export:GetFileVersionInfoW=C:\\Windows\\System32\\version.GetFileVersionInfoW")
#pragma comment(linker, "/export:VerFindFileA=C:\\Windows\\System32\\version.VerFindFileA")
#pragma comment(linker, "/export:VerFindFileW=C:\\Windows\\System32\\version.VerFindFileW")
#pragma comment(linker, "/export:VerInstallFileA=C:\\Windows\\System32\\version.VerInstallFileA")
#pragma comment(linker, "/export:VerInstallFileW=C:\\Windows\\System32\\version.VerInstallFileW")
#pragma comment(linker, "/export:VerLanguageNameA=C:\\Windows\\System32\\version.VerLanguageNameA")
#pragma comment(linker, "/export:VerLanguageNameW=C:\\Windows\\System32\\version.VerLanguageNameW")
#pragma comment(linker, "/export:VerQueryValueA=C:\\Windows\\System32\\version.VerQueryValueA")
#pragma comment(linker, "/export:VerQueryValueW=C:\\Windows\\System32\\version.VerQueryValueW")

// -----------------------------------------------------------
// 1. 常量和宏补全
// -----------------------------------------------------------

// [新增] 辅助宏：计算对齐
#define ALIGN_UP(x, align) (((x) + ((align) - 1)) & ~((align) - 1))

// [新增] 用于惰性 CoW 的值墓碑标记 (Sandboxie 风格)
#define YAPBOX_VALUE_TOMBSTONE_TYPE 0x79617062 // 'yapb'

// --- Sandboxie 魔数时间戳定义 ---
#define DELETE_MARK_LOW   0xDEAD44A0
#define DELETE_MARK_HIGH  0x01B01234

#ifndef _KEY_WRITE_TIME_INFORMATION_DEFINED
#define _KEY_WRITE_TIME_INFORMATION_DEFINED
#endif

// 标志位定义
#define FILE_DISPOSITION_DELETE 0x00000001
#define FILE_DISPOSITION_POSIX_SEMANTICS 0x00000002
#define FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK 0x00000004
#define FILE_DISPOSITION_ON_CLOSE 0x00000008
#define FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE 0x00000010

// 辅助宏：判断是否为 ATOM (类名可能是字符串也可能是整数 ID)
#define IS_ATOM(x) (((ULONG_PTR)(x) & 0xFFFF0000) == 0)

// 字节序转换
#define SWAPWORD(x) MAKEWORD(HIBYTE(x), LOBYTE(x))
#define SWAPLONG(x) MAKELONG(SWAPWORD(HIWORD(x)), SWAPWORD(LOWORD(x)))

// [新增] 判断是否包含注册表写入/修改权限
#ifndef IS_REG_WRITE_ACCESS
#define IS_REG_WRITE_ACCESS(access) (((access) & (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | DELETE | WRITE_DAC | WRITE_OWNER | MAXIMUM_ALLOWED | GENERIC_WRITE | GENERIC_ALL)) != 0)
#endif

// [新增] 补充注册表创建状态宏
#ifndef REG_CREATED_NEW_KEY
#define REG_CREATED_NEW_KEY (0x00000001L)
#endif

#ifndef _KEY_INFORMATION_CLASS_DEFINED
#define _KEY_INFORMATION_CLASS_DEFINED
#endif

#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

#ifndef _KEY_VALUE_INFORMATION_CLASS_DEFINED
#define _KEY_VALUE_INFORMATION_CLASS_DEFINED
#endif

// --- 注册表重定向相关常量与指针 ---
#ifndef REG_PROCESS_APPKEY
#define REG_PROCESS_APPKEY 0x00000001
#endif

#ifndef KEY_WOW64_32KEY
#define KEY_WOW64_32KEY 0x0200
#endif
#ifndef KEY_WOW64_64KEY
#define KEY_WOW64_64KEY 0x0100
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#endif

#ifndef STATUS_OBJECT_PATH_NOT_FOUND
#define STATUS_OBJECT_PATH_NOT_FOUND ((NTSTATUS)0xC000003AL)
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

#ifndef FileInternalInformation
#define FileInternalInformation ((FILE_INFORMATION_CLASS)6)
#endif

#ifndef FSCTL_GET_REPARSE_POINT
#define FSCTL_GET_REPARSE_POINT 0x000900A8
#endif

#ifndef IO_REPARSE_TAG_MOUNT_POINT
#define IO_REPARSE_TAG_MOUNT_POINT 0xA0000003
#endif

#ifndef IO_REPARSE_TAG_SYMLINK
#define IO_REPARSE_TAG_SYMLINK 0xA000000C
#endif

#ifndef FileNamesInformation
#define FileNamesInformation ((FILE_INFORMATION_CLASS)12)
#endif

#ifndef FileIdFullDirectoryInformation
#define FileIdFullDirectoryInformation ((FILE_INFORMATION_CLASS)38)
#endif

#ifndef STATUS_INVALID_INFO_CLASS
#define STATUS_INVALID_INFO_CLASS ((NTSTATUS)0xC0000003L)
#endif

#ifndef FileDispositionInformation
#define FileDispositionInformation ((FILE_INFORMATION_CLASS)13)
#endif

#ifndef ObjectNameInformation
#define ObjectNameInformation ((OBJECT_INFORMATION_CLASS)1)
#endif

#ifndef FileRenameInformationEx
#define FileRenameInformationEx ((FILE_INFORMATION_CLASS)65)
#endif

#ifndef FileEndOfFileInformation
#define FileEndOfFileInformation ((FILE_INFORMATION_CLASS)20)
#endif

#ifndef FileLinkInformation
#define FileLinkInformation ((FILE_INFORMATION_CLASS)11)
#endif

#ifndef FILE_DEVICE_CD_ROM
#define FILE_DEVICE_CD_ROM 0x00000002
#endif

#ifndef FILE_READ_ONLY_DEVICE
#define FILE_READ_ONLY_DEVICE 0x00000002
#endif

#ifndef FILE_REMOVABLE_MEDIA
#define FILE_REMOVABLE_MEDIA 0x00000001
#endif

#ifndef _FILE_BASIC_INFORMATION_DEFINED
#define _FILE_BASIC_INFORMATION_DEFINED
#endif

#ifndef _FILE_STANDARD_INFORMATION_DEFINED
#define _FILE_STANDARD_INFORMATION_DEFINED
#endif

// -----------------------------------------------------------
// 2. 补全缺失的 NT 结构体与枚举
// -----------------------------------------------------------

// --- [新增] 事务注册表相关函数指针 ---
typedef NTSTATUS (NTAPI *P_NtCreateKeyTransacted)(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class,
    ULONG CreateOptions,
    HANDLE TransactionHandle,
    PULONG Disposition
);

typedef NTSTATUS (NTAPI *P_NtOpenKeyTransacted)(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE TransactionHandle
);

typedef NTSTATUS (NTAPI *P_NtQueryMultipleValueKey)(
    HANDLE KeyHandle,
    PKEY_VALUE_ENTRY ValueEntries,
    ULONG EntryCount,
    PVOID ValueBuffer,
    PULONG BufferLength,
    PULONG RequiredBufferLength
);

typedef NTSTATUS (NTAPI *P_NtNotifyChangeKey)(
    HANDLE KeyHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG CompletionFilter,
    BOOLEAN WatchTree,
    PVOID Buffer,
    ULONG BufferSize,
    BOOLEAN Asynchronous
);

typedef NTSTATUS (NTAPI *P_NtNotifyChangeMultipleKeys)(
    HANDLE MasterKeyHandle,
    ULONG Count,
    POBJECT_ATTRIBUTES SlaveObjects,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG CompletionFilter,
    BOOLEAN WatchTree,
    PVOID Buffer,
    ULONG BufferSize,
    BOOLEAN Asynchronous
);

typedef struct _KEY_WRITE_TIME_INFORMATION {
    LARGE_INTEGER LastWriteTime;
} KEY_WRITE_TIME_INFORMATION, *PKEY_WRITE_TIME_INFORMATION;

// 1. 基础信息 (包含名称)
typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

// 2. 节点信息 (包含名称和类名)
typedef struct _KEY_NODE_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_NODE_INFORMATION, *PKEY_NODE_INFORMATION;

// 3. 完整信息 (包含类名和统计信息 不含键名)
typedef struct _KEY_FULL_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG SubKeys;
    ULONG MaxNameLen;
    ULONG MaxClassLen;
    ULONG Values;
    ULONG MaxValueNameLen;
    ULONG MaxValueDataLen;
    WCHAR Class[1];
} KEY_FULL_INFORMATION, *PKEY_FULL_INFORMATION;

// 4. 名称信息
typedef struct _KEY_NAME_INFORMATION {
    ULONG NameLength;
    WCHAR Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

// 注册表信息类枚举
typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation = 0,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation,
    KeyCachedInformation,
    KeyFlagsInformation,
    KeyVirtualizationInformation,
    KeyHandleTagsInformation,
    KeyTrustInformation,
    KeyLayerInformation,
    MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef struct _YAP_SYSTEM_TIMEOFDAY_INFORMATION {
    LARGE_INTEGER BootTime;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeZoneBias;
    ULONG TimeZoneId;
    ULONG Reserved;
    ULONGLONG BootTimeBias;
    ULONGLONG SleepTimeBias;
} YAP_SYSTEM_TIMEOFDAY_INFORMATION, *PYAP_SYSTEM_TIMEOFDAY_INFORMATION;

// [新增] 设备信息结构体 (用于伪装光驱)
typedef struct _FILE_FS_DEVICE_INFORMATION {
    ULONG DeviceType;
    ULONG Characteristics;
} FILE_FS_DEVICE_INFORMATION, *PFILE_FS_DEVICE_INFORMATION;

// [新增] 属性信息结构体 (用于伪装 CDFS)
typedef struct _FILE_FS_ATTRIBUTE_INFORMATION {
    ULONG FileSystemAttributes;
    LONG  MaximumComponentNameLength;
    ULONG FileSystemNameLength;
    WCHAR FileSystemName[1];
} FILE_FS_ATTRIBUTE_INFORMATION, *PFILE_FS_ATTRIBUTE_INFORMATION;

// 注册表 TZI 二进制结构定义
typedef struct _REG_TZI_FORMAT {
    LONG Bias;
    LONG StandardBias;
    LONG DaylightBias;
    SYSTEMTIME StandardDate;
    SYSTEMTIME DaylightDate;
} REG_TZI_FORMAT;

typedef struct _TIME_FIELDS {
    SHORT Year;
    SHORT Month;
    SHORT Day;
    SHORT Hour;
    SHORT Minute;
    SHORT Second;
    SHORT Milliseconds;
    SHORT Weekday;
} TIME_FIELDS, *PTIME_FIELDS;

typedef struct _RTL_TIME_ZONE_INFORMATION {
    LONG Bias;
    WCHAR StandardName[32];
    TIME_FIELDS StandardStart;
    LONG StandardBias;
    WCHAR DaylightName[32];
    TIME_FIELDS DaylightStart;
    LONG DaylightBias;
} RTL_TIME_ZONE_INFORMATION, *PRTL_TIME_ZONE_INFORMATION;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation = 0,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataOffset;
    ULONG DataLength;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

typedef struct _KEY_VALUE_BASIC_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 {
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION_ALIGN64, *PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64;

// [新增] 文件系统信息类枚举
typedef enum _FSINFOCLASS {
    FileFsVolumeInformation = 1,
    FileFsLabelInformation,      // 2
    FileFsSizeInformation,       // 3
    FileFsDeviceInformation,     // 4
    FileFsAttributeInformation,  // 5
    FileFsControlInformation,    // 6
    FileFsFullSizeInformation,   // 7
    FileFsObjectIdInformation,   // 8
    FileFsDriverPathInformation, // 9
    FileFsVolumeFlagsInformation,// 10
    FileFsSectorSizeInformation, // 11
    FileFsDataCopyInformation,   // 12
    FileFsMetadataSizeInformation, // 13
    FileFsFullSizeInformationEx, // 14
    FileFsMaximumInformation
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

// [新增] 卷信息结构体
typedef struct _FILE_FS_VOLUME_INFORMATION {
    LARGE_INTEGER VolumeCreationTime;
    ULONG         VolumeSerialNumber;
    ULONG         VolumeLabelLength;
    BOOLEAN       SupportsObjects;
    WCHAR         VolumeLabel[1];
} FILE_FS_VOLUME_INFORMATION, *PFILE_FS_VOLUME_INFORMATION;

typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG Flags;
            WCHAR PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR  DataBuffer[1];
        } GenericReparseBuffer;
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;

typedef struct _FILE_RENAME_INFORMATION {
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;

typedef struct _FILE_LINK_INFORMATION {
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_LINK_INFORMATION, *PFILE_LINK_INFORMATION;

typedef struct _FILE_END_OF_FILE_INFORMATION {
    LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION;

// 定义 Ex 结构体 (标志位)
typedef struct _FILE_DISPOSITION_INFORMATION_EX {
    ULONG Flags;
} FILE_DISPOSITION_INFORMATION_EX, *PFILE_DISPOSITION_INFORMATION_EX;

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

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

typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

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

// -----------------------------------------------------------
// 3. 函数指针定义
// -----------------------------------------------------------

// [新增] CreateProcessInternalW 的函数原型定义
typedef BOOL (WINAPI *P_CreateProcessInternalW)(
    HANDLE hToken,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    PHANDLE hNewToken
);

typedef NTSTATUS (NTAPI *P_NtQueryKey)(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *P_NtSetInformationKey)(HANDLE, KEY_SET_INFORMATION_CLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* P_NtCreateKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
typedef NTSTATUS(NTAPI* P_NtOpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* P_NtOpenKeyEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS(NTAPI* P_NtDeleteKey)(HANDLE);
typedef NTSTATUS(NTAPI* P_NtEnumerateKey)(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* P_NtEnumerateValueKey)(HANDLE, ULONG, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* P_NtSetValueKey)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* P_NtQueryValueKey)(HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *P_NtDeleteValueKey)(HANDLE KeyHandle, PUNICODE_STRING ValueName);
typedef NTSTATUS (NTAPI *P_NtRenameKey)(HANDLE KeyHandle, PUNICODE_STRING NewName);
typedef NTSTATUS(NTAPI* P_RtlFormatCurrentUserKeyPath)(PUNICODE_STRING);

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
typedef NTSTATUS(NTAPI* P_NtCreateNamedPipeFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* P_NtQueryVolumeInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FS_INFORMATION_CLASS);
typedef NTSTATUS(NTAPI* P_NtResumeProcess)(HANDLE ProcessHandle);
typedef NTSTATUS(NTAPI* P_NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef int (WSAAPI* P_connect)(SOCKET s, const struct sockaddr* name, int namelen);
typedef int (WSAAPI* P_WSAConnect)(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);
typedef BOOL (PASCAL *LPFN_CONNECTEX)(SOCKET, const struct sockaddr*, int, PVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef int (WSAAPI* P_WSAIoctl)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef BOOL (WSAAPI* P_WSAConnectByNameW)(SOCKET, LPWSTR, LPWSTR, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR, LPDWORD, const struct timeval*, LPWSAOVERLAPPED);
typedef BOOL (WSAAPI* P_WSAConnectByList)(SOCKET, PSOCKET_ADDRESS_LIST, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR, const struct timeval*, LPWSAOVERLAPPED);
// ConnectEx 的 GUID
const GUID g_GuidConnectEx = WSAID_CONNECTEX;

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

// [新增] ShellExecuteExW 函数指针
typedef BOOL(WINAPI* P_ShellExecuteExW)(SHELLEXECUTEINFOW*);

// CreateProcess 系列
typedef BOOL(WINAPI* P_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* P_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* P_CreateProcessAsUserW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* P_CreateProcessAsUserA)(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* P_CreateProcessWithTokenW)(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* P_CreateProcessWithLogonW)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef DWORD(WINAPI* P_GetFinalPathNameByHandleW)(HANDLE, LPWSTR, DWORD, DWORD);

// GDI 函数指针
typedef HFONT(WINAPI* P_CreateFontIndirectW)(const LOGFONTW*);
typedef HFONT(WINAPI* P_CreateFontIndirectExW)(const ENUMLOGFONTEXDVW*);

// [新增] GetStockObject 函数指针
typedef HGDIOBJ(WINAPI* P_GetStockObject)(int);

// GDI+ 函数指针与类型
typedef int GpStatus;
typedef void GpFontCollection;
typedef void GpFontFamily;
typedef GpStatus(WINAPI* P_GdipCreateFontFamilyFromName)(const WCHAR*, GpFontCollection*, GpFontFamily**);

// --- [新增] NLS 函数指针 ---
typedef UINT(WINAPI* P_GetACP)(void);
typedef UINT(WINAPI* P_GetOEMCP)(void);
typedef LCID(WINAPI* P_GetUserDefaultLCID)(void);
typedef LCID(WINAPI* P_GetSystemDefaultLCID)(void);
typedef LCID(WINAPI* P_GetThreadLocale)(void);
typedef LANGID(WINAPI* P_GetUserDefaultLangID)(void);
typedef LANGID(WINAPI* P_GetSystemDefaultLangID)(void);
typedef int(WINAPI* P_GetLocaleInfoW)(LCID, LCTYPE, LPWSTR, int);

// [新增] 字符串转换函数指针
typedef int(WINAPI* P_MultiByteToWideChar)(UINT, DWORD, LPCCH, int, LPWSTR, int);
typedef int(WINAPI* P_WideCharToMultiByte)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);

// --- [新增] UI语言函数指针 ---
typedef LANGID(WINAPI* P_GetUserDefaultUILanguage)(void);
typedef LANGID(WINAPI* P_GetSystemDefaultUILanguage)(void);

// --- [新增] 字体枚举函数指针 ---
typedef int (WINAPI* P_EnumFontFamiliesExW)(HDC, LPLOGFONTW, FONTENUMPROCW, LPARAM, DWORD);
typedef int (WINAPI* P_EnumFontFamiliesW)(HDC, LPCWSTR, FONTENUMPROCW, LPARAM);
typedef int (WINAPI* P_EnumFontsW)(HDC, LPCWSTR, FONTENUMPROCW, LPARAM);

// --- [新增] Ntdll 字符串函数指针 ---
typedef NTSTATUS(NTAPI* P_RtlMultiByteToUnicodeN)(PWCH, ULONG, PULONG, PCSTR, ULONG);
typedef NTSTATUS(NTAPI* P_RtlUnicodeToMultiByteN)(PCHAR, ULONG, PULONG, PCWSTR, ULONG);

// --- [新增] ANSI 字体函数指针 ---
typedef HFONT(WINAPI* P_CreateFontIndirectA)(const LOGFONTA*);
typedef HFONT(WINAPI* P_CreateFontA)(int, int, int, int, int, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPCSTR);

// --- [新增] ANSI 注册表函数指针 ---
typedef LSTATUS(WINAPI* P_RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS(WINAPI* P_RegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LSTATUS(WINAPI* P_RegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS(WINAPI* P_RegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LSTATUS(WINAPI* P_RegDeleteKeyA)(HKEY, LPCSTR);
typedef LSTATUS(WINAPI* P_RegDeleteValueA)(HKEY, LPCSTR);
typedef LSTATUS(WINAPI* P_RegEnumKeyExA)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
typedef LSTATUS(WINAPI* P_RegEnumValueA)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);

// --- [新增] User32 窗口函数指针 ---
typedef HWND(WINAPI* P_CreateWindowExA)(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);
typedef int(WINAPI* P_GetWindowTextA)(HWND, LPSTR, int);
typedef LRESULT(WINAPI* P_DefWindowProcA)(HWND, UINT, WPARAM, LPARAM);

// --- [新增] 消息与进程退出函数指针 ---
typedef LRESULT(WINAPI* P_SendMessageA)(HWND, UINT, WPARAM, LPARAM);
typedef VOID(WINAPI* P_ExitProcess)(UINT);
typedef NTSTATUS(NTAPI* P_NtTerminateProcess)(HANDLE, NTSTATUS);

// --- [新增] ANSI 字体枚举指针 ---
typedef int (WINAPI* P_EnumFontFamiliesExA)(HDC, LPLOGFONTA, FONTENUMPROCA, LPARAM, DWORD);
typedef int (WINAPI* P_EnumFontFamiliesA)(HDC, LPCSTR, FONTENUMPROCA, LPARAM);

// --- [新增] 窗口过程与底层退出函数指针 ---
typedef VOID(NTAPI* P_RtlExitUserProcess)(NTSTATUS);
typedef VOID(WINAPI* P_PostQuitMessage)(int);

// --- [新增] 时区伪造相关 ---
typedef DWORD(WINAPI* P_GetTimeZoneInformation)(LPTIME_ZONE_INFORMATION);
typedef DWORD(WINAPI* P_GetDynamicTimeZoneInformation)(PDYNAMIC_TIME_ZONE_INFORMATION);

// GetDriveTypeW 函数指针
typedef UINT(WINAPI* P_GetDriveTypeW)(LPCWSTR);

// [新增] 驱动器枚举函数指针
typedef DWORD(WINAPI* P_GetLogicalDrives)(void);
typedef DWORD(WINAPI* P_GetLogicalDriveStringsW)(DWORD, LPWSTR);

// --- [新增] 资源加载函数指针 ---
typedef NTSTATUS(NTAPI* P_LdrResSearchResource)(PVOID, PULONG_PTR, ULONG, ULONG, PVOID*, PULONG, PVOID, PVOID);

// --- [新增] NLS 代码页信息函数指针 ---
typedef BOOL(WINAPI* P_GetCPInfo)(UINT, LPCPINFO);
typedef BOOL(WINAPI* P_GetCPInfoExW)(UINT, DWORD, LPCPINFOEXW);
typedef BOOL(WINAPI* P_IsValidCodePage)(UINT);

// --- [新增] 时间伪造函数指针 ---
typedef VOID(WINAPI* P_GetSystemTime)(LPSYSTEMTIME);
typedef VOID(WINAPI* P_GetLocalTime)(LPSYSTEMTIME);
typedef VOID(WINAPI* P_GetSystemTimeAsFileTime)(LPFILETIME);
typedef VOID(WINAPI* P_GetSystemTimePreciseAsFileTime)(LPFILETIME);

// --- [新增] NtQuerySystemTime 及 KernelBase 函数指针 ---
typedef NTSTATUS(NTAPI* P_NtQuerySystemTime)(PLARGE_INTEGER);

// --- WinExec 函数指针 ---
typedef UINT(WINAPI* P_WinExec)(LPCSTR, UINT);

// 原始 NtClose 指针 (需要 Hook 它来清理内存)
typedef NTSTATUS(NTAPI* P_NtClose)(HANDLE);

// 命令行处理工具集
namespace CmdUtils {

    bool IsWhitespace(wchar_t ch) {
        return wcschr(L" \t\n\r", ch) != nullptr;
    }

    // 移除字符串末尾的空白
    void TrimTrailingWhitespace(std::wstring& text) {
        while (!text.empty() && IsWhitespace(text.back())) {
            text.pop_back();
        }
    }

    // 查找独立的开关（确保不是另一个单词的子串）
    // [修改] 使用 const std::wstring& 代替 std::wstring_view
    size_t FindStandaloneSwitch(
        const std::wstring& command_line,
        const std::wstring& flag) {
        auto pos = command_line.find(flag);
        while (pos != std::wstring::npos) {
            const bool at_start = pos == 0 || IsWhitespace(command_line[pos - 1]);
            const auto after = pos + flag.size();
            const bool at_end =
                after >= command_line.size() || IsWhitespace(command_line[after]);
            if (at_start && at_end) {
                return pos;
            }
            pos = command_line.find(flag, pos + flag.size());
        }
        return std::wstring::npos;
    }

    // 处理 --single-argument 这种特殊情况
    // 返回值: {前半部分(可解析), 后半部分(保留原样)}
    std::pair<std::wstring, std::wstring> SplitSingleArgumentSwitch(
        const std::wstring& command_line) {
        // [修改] 移除 constexpr string_view
        const std::wstring kSingleArgument = L"--single-argument";
        const auto single_argument_pos =
            FindStandaloneSwitch(command_line, kSingleArgument);

        if (single_argument_pos == std::wstring::npos) {
            return { command_line, L"" };
        }

        std::wstring prefix = command_line.substr(0, single_argument_pos);
        std::wstring suffix = command_line.substr(single_argument_pos);
        TrimTrailingWhitespace(prefix);

        return { std::move(prefix), std::move(suffix) };
    }

    // 使用系统 API 解析命令行参数
    std::vector<std::wstring> ParseCommandLineArgs(const std::wstring& command_line) {
        std::vector<std::wstring> args;
        if (command_line.empty()) return args;

        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(command_line.c_str(), &argc);
        if (!argv) return args;

        for (int i = 0; i < argc; ++i) {
            args.emplace_back(argv[i]);
        }
        LocalFree(argv);
        return args;
    }

    // 辅助：给参数加引号（如果包含空格）
    std::wstring QuoteArg(const std::wstring& arg) {
        if (arg.empty()) return L"\"\"";
        if (arg.find_first_of(L" \t\"") == std::wstring::npos) return arg;

        std::wstring quoted;
        quoted.push_back(L'"');
        for (auto it = arg.begin(); it != arg.end(); ++it) {
            if (*it == L'"') {
                int backslash_count = 0;
                auto back_it = it;
                while (back_it != arg.begin() && *(--back_it) == L'\\') {
                    backslash_count++;
                }
                quoted.append(backslash_count, L'\\');
                quoted.append(L"\\\"");
            }
            else {
                quoted.push_back(*it);
            }
        }
        if (quoted.back() == L'\\') {
            int backslash_count = 0;
            auto back_it = quoted.end();
            while (back_it != quoted.begin() && *(--back_it) == L'\\') {
                backslash_count++;
            }
            quoted.append(backslash_count, L'\\');
        }
        quoted.push_back(L'"');
        return quoted;
    }

    // 核心逻辑：合并参数并处理 Feature Flags
    std::wstring ProcessAndReassemble(
        const std::wstring& raw_cmd_line,
        const std::vector<std::wstring>& extra_args
    ) {
        // [修改] 移除结构化绑定 auto [a, b] = ...
        std::pair<std::wstring, std::wstring> split_res = SplitSingleArgumentSwitch(raw_cmd_line);
        std::wstring main_cmd = split_res.first;
        std::wstring suffix = split_res.second;

        auto args = ParseCommandLineArgs(main_cmd);

        if (!args.empty()) {
            args.insert(args.begin() + 1, extra_args.begin(), extra_args.end());
        } else {
            args = extra_args;
        }

        std::vector<std::wstring> final_args;
        final_args.reserve(args.size());

        std::wstring combined_disable_features;
        std::wstring combined_enable_features;

        const std::wstring disable_prefix = L"--disable-features=";
        const std::wstring enable_prefix = L"--enable-features=";

        for (const auto& arg : args) {
            if (arg.rfind(disable_prefix, 0) == 0) {
                if (!combined_disable_features.empty()) combined_disable_features.append(L",");
                combined_disable_features.append(arg.substr(disable_prefix.length()));
            }
            else if (arg.rfind(enable_prefix, 0) == 0) {
                if (!combined_enable_features.empty()) combined_enable_features.append(L",");
                combined_enable_features.append(arg.substr(enable_prefix.length()));
            }
            else {
                final_args.push_back(arg);
            }
        }

        if (!combined_disable_features.empty()) {
            final_args.push_back(disable_prefix + combined_disable_features);
        }

        if (!combined_enable_features.empty()) {
            final_args.push_back(enable_prefix + combined_enable_features);
        }

        std::wstring result;
        for (size_t i = 0; i < final_args.size(); ++i) {
            result.append(QuoteArg(final_args[i]));
            if (i < final_args.size() - 1) {
                result.push_back(L' ');
            }
        }

        if (!suffix.empty()) {
            if (!result.empty()) result.push_back(L' ');
            result.append(suffix);
        }

        return result;
    }
}

// --- 注册表枚举合并缓存 ---
struct CachedRegKey {
    std::wstring Name;
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    std::wstring Class;
};

struct CachedRegValue {
    std::wstring Name;
    ULONG TitleIndex;
    ULONG Type;
    std::vector<BYTE> Data;
};

struct RegContext {
    std::wstring FullPath;
    HANDLE hRealKey = NULL; // [新增] 缓存对应的真实键句柄
    HANDLE hMonitorKey = NULL; // [新增] 用于 NtNotifyChangeKey 的沙盒监视句柄
    std::vector<CachedRegKey> SubKeys;
    std::vector<CachedRegValue> Values;
    bool KeysInitialized = false;
    bool ValuesInitialized = false;
};

// --- 全局变量 ---
wchar_t g_SandboxRoot[MAX_PATH] = { 0 };
wchar_t g_IpcPipeName[MAX_PATH] = { 0 };
wchar_t g_LauncherDir[MAX_PATH] = { 0 };
int g_HookMode = 1; // [新增] 默认模式 1
std::vector<std::wstring> g_ChildHookWhitelist;
long long g_HookCopySizeLimit = -1; // [新增] CoW 文件大小限制 (-1 表示不限制)
std::wstring g_SystemDriveNt; // [新增] 系统盘符 NT 路径 (如 \??\C:)
std::wstring g_SystemDriveLetter; // [新增] 系统盘符 DOS 路径 (如 C:)
std::wstring g_LauncherDriveNt; // 启动器所在盘符 NT 路径 (如 \??\Z:)
std::vector<std::wstring> g_SystemWhitelist; // 系统盘白名单
int g_BlockNetwork = 0; // 0=Off, 1=Block Public, 2=Block All DNS
bool g_HookChild = true; // [新增] 子进程挂钩开关 默认开启
std::wstring g_CurrentProcessPathNt; // [新增] 当前进程 NT 路径 用于自身镜像保护
std::wstring g_SandboxDevicePath;   // 沙盒的完整设备路径 (如 \Device\HarddiskVolume2\Sandbox)
std::wstring g_SandboxRelativePath; // 沙盒的相对路径 (如 \Sandbox)
std::wstring g_PipePrefix; // 例如: "YapBox_00000001_"
DWORD g_FakeVolumeSerial = 0;
bool g_HookVolumeId = false;
std::wstring g_OverrideFontName; // 存储 hookfont 指定的字体名称
HFONT g_hNewGSOFont = NULL;      // [新增] 用于替换 GetStockObject 的字体句柄
std::vector<std::wstring> g_ExtraDlls; // [新增] 第三方 DLL 列表
std::wstring g_CurrentProcessNameLower; // 缓存当前进程名

bool g_HookReg = false;
HKEY g_hAppHive = NULL; // 私有配置单元 (AppKey) 的句柄
std::wstring g_CurrentUserSidPath; // 例如: \REGISTRY\USER\S-1-5-21-xxxxx
std::wstring g_RegMountPathNt; // [新增] 注册表挂载点 NT 路径 (例如 \REGISTRY\USER\YapBoxReg_xxx)
std::map<HANDLE, RegContext*> g_RegContextMap;
std::shared_mutex g_RegContextMutex;

// 缓存的 NT 路径
std::wstring g_LauncherDirNt;
std::wstring g_UserProfileNt;
std::wstring g_UserProfileNtShort;
std::wstring g_UsersDirNt;      // [新增] Users 根目录 (长路径)
std::wstring g_UsersDirNtShort; // [新增] Users 根目录 (短路径)
std::wstring g_ProgramDataNt;
std::wstring g_ProgramDataNtShort;
std::wstring g_PublicNt;

// --- 光驱伪装相关全局变量 ---
std::wstring g_HookCdPath;      // 真实路径 (DOS): Z:\Other\ISO
std::wstring g_HookCdNtPath;    // 真实路径 (NT): \??\Z:\Other\ISO
std::wstring g_HookCdDevicePath; // [新增] 真实路径 (Device): \Device\HarddiskVolume1\Other\ISO
wchar_t g_VirtualCdDrive = 0;   // 虚拟盘符: 'M'
std::wstring g_VirtualCdNtPrefix; // 虚拟盘符前缀: \??\M:

// --- [新增] 区域伪造全局变量 ---
UINT g_FakeACP = 0;
LCID g_FakeLCID = 0;
BYTE g_FakeCharSet = 0; // [新增] 字体字符集 (例如 128 = Shift-JIS)
std::wstring g_FakeACPStr;   // 存储 "932"
std::wstring g_FakeOEMCPStr; // 存储 "932"
LANGID g_FakeLangID = 0;     // 存储 0x0411

// 全局伪造的时区信息
DYNAMIC_TIME_ZONE_INFORMATION g_FakeDTZI = { 0 };
bool g_EnableTimeZoneHook = false;

// 全局时间偏移量 (100ns 单位)
long long g_TimeOffset = 0;
bool g_EnableTimeHook = false;

// [新增] 防止时间函数递归调用的标志
thread_local bool g_InTimeHook = false;
thread_local bool g_IsInHook = false;

// 辅助类：自动设置和清除标志
struct TimeRecursionGuard {
    TimeRecursionGuard() { g_InTimeHook = true; }
    ~TimeRecursionGuard() { g_InTimeHook = false; }
};

//[修改] 直接定义并自动初始化全局架构标志
inline bool InitIsWin64() {
#ifdef _WIN64
    return true; // 64位编译环境下 系统必然是64位
#else
    BOOL isWow64 = FALSE;
    // 32位编译环境下 如果当前是Wow64进程 说明系统是64位
    if (IsWow64Process(GetCurrentProcess(), &isWow64)) {
        return isWow64 != FALSE;
    }
    return false;
#endif
}

inline bool InitIsWow64Process() {
#ifdef _WIN64
    return false; // 64位进程本身不是Wow64进程
#else
    BOOL isWow64 = FALSE;
    if (IsWow64Process(GetCurrentProcess(), &isWow64)) {
        return isWow64 != FALSE;
    }
    return false;
#endif
}

bool g_IsWin64 = InitIsWin64();
bool g_IsWow64Process = InitIsWow64Process();

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
LPFN_CONNECTEX fpConnectEx_Real = NULL; // 保存系统真实的 ConnectEx
P_WSAIoctl fpWSAIoctl = NULL;           // 保存系统真实的 WSAIoctl
P_NtCreateKey fpNtCreateKey = NULL;
P_NtOpenKey fpNtOpenKey = NULL;
P_NtOpenKeyEx fpNtOpenKeyEx = NULL;
P_NtDeleteKey fpNtDeleteKey = NULL;
P_NtEnumerateKey fpNtEnumerateKey = NULL;
P_NtEnumerateValueKey fpNtEnumerateValueKey = NULL;
P_RtlFormatCurrentUserKeyPath fpRtlFormatCurrentUserKeyPath = NULL;
P_NtSetValueKey fpNtSetValueKey = NULL;
P_NtQueryValueKey fpNtQueryValueKey = NULL;
P_NtDeleteValueKey fpNtDeleteValueKey = NULL;
P_NtRenameKey fpNtRenameKey = NULL;
P_NtDeleteFile fpNtDeleteFile = NULL;
P_NtCreateNamedPipeFile fpNtCreateNamedPipeFile = NULL;
P_NtQueryVolumeInformationFile fpNtQueryVolumeInformationFile = NULL;
P_NtResumeProcess fpNtResumeProcess = NULL;
P_NtQuerySystemInformation fpNtQuerySystemInformation = NULL;
P_WSAConnectByNameW fpWSAConnectByNameW = NULL;
P_WSAConnectByList fpWSAConnectByList = NULL;
P_ShellExecuteExW fpShellExecuteExW = NULL;
P_CreateFontIndirectW fpCreateFontIndirectW = NULL;
P_CreateFontIndirectExW fpCreateFontIndirectExW = NULL;
P_GetStockObject fpGetStockObject = NULL;
P_GdipCreateFontFamilyFromName fpGdipCreateFontFamilyFromName = NULL;
P_GetACP fpGetACP = NULL;
P_GetOEMCP fpGetOEMCP = NULL;
P_GetUserDefaultLCID fpGetUserDefaultLCID = NULL;
P_GetSystemDefaultLCID fpGetSystemDefaultLCID = NULL;
P_GetThreadLocale fpGetThreadLocale = NULL;
P_GetUserDefaultLangID fpGetUserDefaultLangID = NULL;
P_GetSystemDefaultLangID fpGetSystemDefaultLangID = NULL;
P_GetLocaleInfoW fpGetLocaleInfoW = NULL;
P_MultiByteToWideChar fpMultiByteToWideChar = NULL;
P_WideCharToMultiByte fpWideCharToMultiByte = NULL;
P_GetUserDefaultUILanguage fpGetUserDefaultUILanguage = NULL;
P_GetSystemDefaultUILanguage fpGetSystemDefaultUILanguage = NULL;
P_EnumFontFamiliesExW fpEnumFontFamiliesExW = NULL;
P_EnumFontFamiliesW fpEnumFontFamiliesW = NULL;
P_EnumFontsW fpEnumFontsW = NULL;
P_RtlMultiByteToUnicodeN fpRtlMultiByteToUnicodeN = NULL;
P_RtlUnicodeToMultiByteN fpRtlUnicodeToMultiByteN = NULL;
P_CreateFontIndirectA fpCreateFontIndirectA = NULL;
P_CreateFontA fpCreateFontA = NULL;
P_RegOpenKeyExA fpRegOpenKeyExA = NULL;
P_RegCreateKeyExA fpRegCreateKeyExA = NULL;
P_RegQueryValueExA fpRegQueryValueExA = NULL;
P_RegSetValueExA fpRegSetValueExA = NULL;
P_RegDeleteKeyA fpRegDeleteKeyA = NULL;
P_RegDeleteValueA fpRegDeleteValueA = NULL;
P_RegEnumKeyExA fpRegEnumKeyExA = NULL;
P_RegEnumValueA fpRegEnumValueA = NULL;
P_CreateWindowExA fpCreateWindowExA = NULL;
P_GetWindowTextA fpGetWindowTextA = NULL;
P_DefWindowProcA fpDefWindowProcA = NULL;
P_SendMessageA fpSendMessageA = NULL;
P_ExitProcess fpExitProcess = NULL;
P_NtTerminateProcess fpNtTerminateProcess = NULL;
P_EnumFontFamiliesExA fpEnumFontFamiliesExA = NULL;
P_EnumFontFamiliesA fpEnumFontFamiliesA = NULL;
P_RtlExitUserProcess fpRtlExitUserProcess = NULL;
P_PostQuitMessage fpPostQuitMessage = NULL;
P_GetTimeZoneInformation fpGetTimeZoneInformation = NULL;
P_GetDynamicTimeZoneInformation fpGetDynamicTimeZoneInformation = NULL;
P_GetDriveTypeW fpGetDriveTypeW = NULL;
P_GetLogicalDrives fpGetLogicalDrives = NULL;
P_GetLogicalDriveStringsW fpGetLogicalDriveStringsW = NULL;
P_LdrResSearchResource fpLdrResSearchResource = NULL;
P_GetCPInfo fpGetCPInfo = NULL;
P_GetCPInfoExW fpGetCPInfoExW = NULL;
P_IsValidCodePage fpIsValidCodePage = NULL;
P_GetSystemTime fpGetSystemTime = NULL;
P_GetLocalTime fpGetLocalTime = NULL;
P_GetSystemTimeAsFileTime fpGetSystemTimeAsFileTime = NULL;
P_GetSystemTimePreciseAsFileTime fpGetSystemTimePreciseAsFileTime = NULL;
P_NtQuerySystemTime fpNtQuerySystemTime = NULL;
P_WinExec fpWinExec = NULL;
P_NtClose fpNtClose = NULL;
P_NtQueryKey fpNtQueryKey = NULL;
P_NtSetInformationKey fpNtSetInformationKey = NULL;
P_NtQueryMultipleValueKey fpNtQueryMultipleValueKey = NULL;
P_NtNotifyChangeKey fpNtNotifyChangeKey = NULL;
P_NtNotifyChangeMultipleKeys fpNtNotifyChangeMultipleKeys = NULL;
P_NtCreateKeyTransacted fpNtCreateKeyTransacted = NULL;
P_NtOpenKeyTransacted fpNtOpenKeyTransacted = NULL;
P_CreateProcessInternalW fpCreateProcessInternalW = nullptr;

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

// KernelBase 专用指针 (避免与 Kernel32 指针冲突)
P_GetSystemTime fpGetSystemTime_KB = NULL;
P_GetLocalTime fpGetLocalTime_KB = NULL;
P_GetSystemTimeAsFileTime fpGetSystemTimeAsFileTime_KB = NULL;
P_GetSystemTimePreciseAsFileTime fpGetSystemTimePreciseAsFileTime_KB = NULL;

extern P_NtEnumerateKey fpNtEnumerateKey;
extern P_NtEnumerateValueKey fpNtEnumerateValueKey;
extern P_NtQuerySystemInformation fpNtQuerySystemInformation;

// 函数前向声明 (Forward Declarations)
bool ShouldRedirect(const std::wstring& fullNtPath, std::wstring& targetPath);
void RecursiveCreatePathWithSync(const std::wstring& sandboxDosPath);

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

// [新增] 初始化子进程白名单 (在 InitHookThread 中调用)
void InitChildHookWhitelist() {
    wchar_t buffer[4096];
    if (GetEnvironmentVariableW(L"YAP_HOOK_CHILD_NAME", buffer, 4096) > 0) {
        wchar_t* next_token = NULL;
        wchar_t* token = wcstok_s(buffer, L";", &next_token);
        while (token) {
            g_ChildHookWhitelist.push_back(token);
            token = wcstok_s(NULL, L";", &next_token);
        }
    }
}

// [新增] 检查是否应该挂钩该子进程
bool ShouldHookChildProcess(const std::wstring& exePath) {
    // 1. 如果总开关关闭 直接返回 false
    if (!g_HookChild) return false;

    // 2. 如果白名单为空 默认挂钩所有子进程
    if (g_ChildHookWhitelist.empty()) return true;

    // 3. 获取文件名 (例如 C:\Path\To\1.exe -> 1.exe)
    const wchar_t* fileName = PathFindFileNameW(exePath.c_str());
    if (!fileName || *fileName == L'\0') return false; // 无法获取文件名 保守起见不挂钩

    // 4. 检查文件名是否在白名单中 (不区分大小写)
    for (const auto& allowedName : g_ChildHookWhitelist) {
        if (_wcsicmp(fileName, allowedName.c_str()) == 0) {
            return true;
        }
    }

    // 5. 有白名单但未匹配 不挂钩
    return false;
}

// [新增] 进程类型枚举
enum ProcessType {
    ProcType_Generic = 0,
    ProcType_Msi_Installer,
    ProcType_Office_Outlook,
    ProcType_Mozilla_Firefox,
    ProcType_Explorer,
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
    LARGE_INTEGER FileId;      // [新增] 真实文件 ID
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

// --- [修改] 字体文件解析与加载工具 (支持 TTF/OTF/TTC) ---

// TTC 文件头
struct TTC_HEADER {
    char   szTag[4]; // 'ttcf'
    USHORT uMajorVersion;
    USHORT uMinorVersion;
    ULONG  uNumFonts;
    // 后面紧跟 uNumFonts 个 ULONG 偏移量
};

// TTF/OTF 表头
struct TT_OFFSET_TABLE {
    USHORT uMajorVersion;
    USHORT uMinorVersion;
    USHORT uNumOfTables;
    USHORT uSearchRange;
    USHORT uEntrySelector;
    USHORT uRangeShift;
};

struct TT_TABLE_DIRECTORY {
    char   szTag[4];
    ULONG  uCheckSum;
    ULONG  uOffset;
    ULONG  uLength;
};

struct TT_NAME_TABLE_HEADER {
    USHORT uFSelector;
    USHORT uNRCount;
    USHORT uStorageOffset;
};

struct TT_NAME_RECORD {
    USHORT uPlatformID;
    USHORT uEncodingID;
    USHORT uLanguageID;
    USHORT uNameID;
    USHORT uStringLength;
    USHORT uStringOffset;
};

// 内部辅助：解析单个 TTF/OTF 数据块的名称
std::wstring ParseSingleFontName(const BYTE* pBase, const BYTE* pFontStart, size_t totalSize) {
    // 边界检查
    if (pFontStart < pBase || (size_t)(pFontStart - pBase) + sizeof(TT_OFFSET_TABLE) > totalSize) return L"";

    const TT_OFFSET_TABLE* pOffsetTable = (const TT_OFFSET_TABLE*)pFontStart;
    USHORT numTables = SWAPWORD(pOffsetTable->uNumOfTables);
    ULONG nameTableOffset = 0;

    // 1. 查找 'name' 表
    const TT_TABLE_DIRECTORY* pTableDir = (const TT_TABLE_DIRECTORY*)(pFontStart + sizeof(TT_OFFSET_TABLE));
    for (int i = 0; i < numTables; ++i) {
        // 边界检查
        if ((const BYTE*)&pTableDir[i + 1] > pBase + totalSize) return L"";

        if (memcmp(pTableDir[i].szTag, "name", 4) == 0) {
            nameTableOffset = SWAPLONG(pTableDir[i].uOffset);
            break;
        }
    }

    if (nameTableOffset == 0 || nameTableOffset + sizeof(TT_NAME_TABLE_HEADER) > totalSize) return L"";

    // 2. 解析 'name' 表头
    const BYTE* pNameTable = pBase + nameTableOffset;
    const TT_NAME_TABLE_HEADER* pNameHeader = (const TT_NAME_TABLE_HEADER*)pNameTable;
    USHORT count = SWAPWORD(pNameHeader->uNRCount);
    USHORT stringOffset = SWAPWORD(pNameHeader->uStorageOffset);

    const TT_NAME_RECORD* pRecord = (const TT_NAME_RECORD*)(pNameTable + sizeof(TT_NAME_TABLE_HEADER));

    // 3. 遍历名称记录 (优先找 Windows Platform, Font Family)
    for (int i = 0; i < count; ++i) {
        // 边界检查
        if ((const BYTE*)&pRecord[i + 1] > pBase + totalSize) break;

        USHORT platformID = SWAPWORD(pRecord[i].uPlatformID);
        USHORT nameID = SWAPWORD(pRecord[i].uNameID);
        // USHORT languageID = SWAPWORD(pRecord[i].uLanguageID);

        // Platform ID: 3 (Windows)
        // Name ID: 1 (Font Family Name)
        if (platformID == 3 && nameID == 1) {
            USHORT length = SWAPWORD(pRecord[i].uStringLength);
            USHORT offset = SWAPWORD(pRecord[i].uStringOffset);

            // 字符串在 name 表内的绝对偏移
            const BYTE* pStrStart = pNameTable + stringOffset + offset;

            if (pStrStart + length <= pBase + totalSize) {
                std::wstring name;
                // 转换 Big-Endian Unicode (UTF-16BE)
                for (int j = 0; j < length; j += 2) {
                    wchar_t wc = (pStrStart[j] << 8) | pStrStart[j + 1];
                    if (wc == 0) break;
                    name += wc;
                }
                return name;
            }
        }
    }
    return L"";
}

// 主函数：从内存数据中解析字体名称 (支持 TTC/TTF/OTF)
std::wstring GetFontNameFromMemory(const std::vector<BYTE>& fontData) {
    if (fontData.size() < sizeof(TTC_HEADER)) return L"";

    const BYTE* pData = fontData.data();
    size_t dataSize = fontData.size();

    // 检查是否为 TTC 集合 ('ttcf')
    if (memcmp(pData, "ttcf", 4) == 0) {
        const TTC_HEADER* pTtcHeader = (const TTC_HEADER*)pData;
        ULONG numFonts = SWAPLONG(pTtcHeader->uNumFonts);

        // TTC 头部后面紧跟偏移量数组
        const ULONG* pOffsets = (const ULONG*)(pData + sizeof(TTC_HEADER)); // 简化处理 忽略版本差异带来的细微结构变化

        // 遍历 TTC 中的字体 返回第一个成功解析的名称
        for (ULONG i = 0; i < numFonts; ++i) {
            if ((const BYTE*)&pOffsets[i + 1] > pData + dataSize) break;

            ULONG offset = SWAPLONG(pOffsets[i]);
            if (offset >= dataSize) continue;

            std::wstring name = ParseSingleFontName(pData, pData + offset, dataSize);
            if (!name.empty()) {
                // DebugLog(L"FontHook: Found TTC font name: %s", name.c_str());
                return name; // 返回第一个找到的字体名
            }
        }
        return L"";
    }
    else {
        // 普通 TTF/OTF
        return ParseSingleFontName(pData, pData, dataSize);
    }
}

// 加载字体文件并返回名称 (保持不变 只需确保它调用了新的 GetFontNameFromMemory)
std::wstring LoadCustomFontFile(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return L"";

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0) { CloseHandle(hFile); return L""; }

    std::vector<BYTE> buffer(fileSize);
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL)) {
        CloseHandle(hFile);
        return L"";
    }
    CloseHandle(hFile);

    // 解析名称 (现在支持 TTC)
    std::wstring fontName = GetFontNameFromMemory(buffer);
    if (fontName.empty()) {
        DebugLog(L"FontHook: Failed to parse font name from %s", filePath.c_str());
        return L"";
    }

    // 加载资源 (AddFontMemResourceEx 支持 TTC 会加载集合中所有字体)
    DWORD numFonts = 0;
    HANDLE hFontRes = AddFontMemResourceEx(buffer.data(), fileSize, NULL, &numFonts);

    if (hFontRes) {
        DebugLog(L"FontHook: Loaded file '%s' as '%s'", filePath.c_str(), fontName.c_str());
        return fontName;
    } else {
        DebugLog(L"FontHook: AddFontMemResourceEx failed for %s", filePath.c_str());
        return L"";
    }
}

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

// [新增] 初始化路径欺骗缓存 (在 InitHookThread 中调用)
void InitSpoofing() {
    if (g_SandboxRoot[0] == L'\0') return;

    // 1. 计算相对路径 (\Sandbox)
    // g_SandboxRoot 格式如 Z:\Sandbox
    const wchar_t* pColon = wcschr(g_SandboxRoot, L':');
    if (pColon && pColon[1] == L'\\') {
        g_SandboxRelativePath = pColon + 1; // \Sandbox
        // 移除末尾斜杠
        if (g_SandboxRelativePath.length() > 1 && g_SandboxRelativePath.back() == L'\\') {
            g_SandboxRelativePath.pop_back();
        }
    }

    // 2. 计算设备路径 (\Device\HarddiskVolumeX\Sandbox)
    std::wstring driveStr(g_SandboxRoot, 2); // Z:
    wchar_t deviceBuf[MAX_PATH];
    if (QueryDosDeviceW(driveStr.c_str(), deviceBuf, MAX_PATH)) {
        g_SandboxDevicePath = deviceBuf;
        g_SandboxDevicePath += g_SandboxRelativePath;
    }

    DebugLog(L"Spoof Init: Device='%s', Rel='%s'", g_SandboxDevicePath.c_str(), g_SandboxRelativePath.c_str());
}

// [新增] 辅助：根据盘符获取设备路径 (C: -> \Device\HarddiskVolume1)
std::wstring GetDevicePathByDrive(wchar_t driveLetter) {
    // 遍历 g_DeviceMap (格式: \Device\HarddiskVolume1 -> C:)
    // 注意：g_DeviceMap 在 InitHookThread 中已初始化
    std::wstring driveStr;
    driveStr += driveLetter;
    driveStr += L":";

    for (const auto& pair : g_DeviceMap) {
        if (_wcsicmp(pair.second.c_str(), driveStr.c_str()) == 0) {
            return pair.first;
        }
    }
    return L"";
}

// 辅助：获取文件句柄对应的路径
std::wstring GetPathFromHandle(HANDLE hFile) {
    if (!fpNtQueryObject) return L""; // 防止空指针
    ULONG len = 0;
    fpNtQueryObject(hFile, ObjectNameInformation, NULL, 0, &len);
    if (len == 0) return L"";

    std::vector<BYTE> buffer(len + 2); // 多分配一点防止溢出
    if (!NT_SUCCESS(fpNtQueryObject(hFile, ObjectNameInformation, buffer.data(), len, &len))) return L"";

    POBJECT_NAME_INFORMATION nameInfo = (POBJECT_NAME_INFORMATION)buffer.data();
    if (!nameInfo->Name.Buffer || nameInfo->Name.Length == 0) return L"";

    return std::wstring(nameInfo->Name.Buffer, nameInfo->Name.Length / sizeof(WCHAR));
}

// [新增] 判断句柄是否指向沙盒内对象
// 依赖 g_SandboxDevicePath (由 InitSpoofing 初始化)
bool IsHandleInSandbox(HANDLE hFile) {
    if (!hFile || hFile == INVALID_HANDLE_VALUE) return false;
    if (g_SandboxDevicePath.empty()) return false;

    std::wstring path = GetPathFromHandle(hFile);
    if (path.empty()) return false;

    // 检查路径前缀是否匹配沙盒设备路径
    // 例如: \Device\HarddiskVolume2\Sandbox
    if (path.size() >= g_SandboxDevicePath.size() &&
        _wcsnicmp(path.c_str(), g_SandboxDevicePath.c_str(), g_SandboxDevicePath.size()) == 0) {
        return true;
    }
    return false;
}

// [新增] File ID 混淆/还原算法 (XOR 翻转)
// 移植自 file.c: IS_DELETE_MARK 附近的逻辑
void ToggleFileIdScramble(PLARGE_INTEGER pId) {
    if (pId) {
        pId->LowPart ^= 0xFFFFFFFF;
        pId->HighPart ^= 0xFFFFFFFF;
    }
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

// [新增] 获取重解析点目标 (Junction/Symlink)
std::wstring GetReparseTarget(const std::wstring& path) {
    // 打开重解析点本身
    // [修改] 增加 FILE_READ_ATTRIBUTES 权限 这是读取 Reparse Tag 的标准要求
    HANDLE hFile = CreateFileW(path.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) return L"";

    // 16KB 缓冲区
    std::vector<BYTE> buffer(16 * 1024);
    DWORD bytesReturned = 0;
    std::wstring target = L"";

    if (DeviceIoControl(hFile, FSCTL_GET_REPARSE_POINT, NULL, 0, buffer.data(), (DWORD)buffer.size(), &bytesReturned, NULL)) {
        PREPARSE_DATA_BUFFER pData = (PREPARSE_DATA_BUFFER)buffer.data();

        WCHAR* pPathBuffer = NULL;
        USHORT offset = 0;
        USHORT length = 0;

        if (pData->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
            pPathBuffer = pData->MountPointReparseBuffer.PathBuffer;
            offset = pData->MountPointReparseBuffer.SubstituteNameOffset;
            length = pData->MountPointReparseBuffer.SubstituteNameLength;
        }
        else if (pData->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
            pPathBuffer = pData->SymbolicLinkReparseBuffer.PathBuffer;
            offset = pData->SymbolicLinkReparseBuffer.SubstituteNameOffset;
            length = pData->SymbolicLinkReparseBuffer.SubstituteNameLength;
        }

        if (pPathBuffer) {
            target.assign(pPathBuffer + offset / sizeof(WCHAR), length / sizeof(WCHAR));

            // 处理 NT 前缀 \??\ (例如 \??\C:\Windows -> C:\Windows)
            if (target.rfind(L"\\??\\", 0) == 0) {
                target = target.substr(4);
            }
        }
    }

    CloseHandle(hFile);
    return target;
}

// [新增] 路径规范化：解析短文件名、符号链接、Junction
// 必须放在 NtPathToDosPath 之后 Detour_NtCreateFile 之前
std::wstring NormalizeNtPath(const std::wstring& ntPath) {
    if (ntPath.empty()) return ntPath;

    // 1. 转换为 DOS 路径
    std::wstring currentPath = NtPathToDosPath(ntPath);
    if (currentPath.empty()) return ntPath;

    std::wstring pathToCheck = currentPath;
    std::wstring suffix = L"";

    // 防止无限循环
    int maxDepth = 32;

    // 2. 逐层向上检查是否存在重解析点
    while (maxDepth-- > 0) {
        // 尝试获取当前路径组件的重解析目标
        // 如果是普通文件/目录或不存在 返回空字符串
        // 如果是 Junction/Symlink 返回目标路径 (例如 Z:\aaa)
        std::wstring target = GetReparseTarget(pathToCheck.c_str());

        if (!target.empty()) {
            // 发现重解析点
            // 拼接后缀 (例如 Z:\aaa + \ + 1.txt)
            if (!suffix.empty()) {
                if (target.back() != L'\\') target += L"\\";
                target += suffix;
            }

            // 更新当前路径 并重置循环以检查新路径中是否还包含 Junction
            currentPath = target;
            pathToCheck = currentPath;
            suffix = L"";
            continue;
        }

        // 当前层级不是重解析点
        // 剥离最后一层 继续向上查找父目录
        size_t lastSlash = pathToCheck.find_last_of(L'\\');
        if (lastSlash == std::wstring::npos) break; // 已到达根目录

        std::wstring component = pathToCheck.substr(lastSlash + 1);
        pathToCheck = pathToCheck.substr(0, lastSlash);

        if (suffix.empty()) suffix = component;
        else suffix = component + L"\\" + suffix;
    }

    // 3. 转回 NT 路径
    // 如果解析出了 Z:\aaa\1.txt 这里返回 \??\Z:\aaa\1.txt
    return L"\\??\\" + currentPath;
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

// [新增] 复制文件时间戳 (Creation, Access, Write)
bool CopyFileTimestamps(LPCWSTR srcPath, LPCWSTR destPath) {
    HANDLE hSrc = CreateFileW(srcPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hSrc == INVALID_HANDLE_VALUE) return false;

    FILETIME ftCreate, ftAccess, ftWrite;
    bool result = false;
    if (GetFileTime(hSrc, &ftCreate, &ftAccess, &ftWrite)) {
        HANDLE hDest = CreateFileW(destPath, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (hDest != INVALID_HANDLE_VALUE) {
            if (SetFileTime(hDest, &ftCreate, &ftAccess, &ftWrite)) {
                result = true;
            }
            CloseHandle(hDest);
        }
    }
    CloseHandle(hSrc);
    return result;
}

// [新增] 复制文件属性 (Hidden, System 等) 并剥离 ReadOnly
bool CopyFileAttributesAndStripReadOnly(LPCWSTR srcPath, LPCWSTR destPath) {
    DWORD srcAttrs = GetFileAttributesW(srcPath);
    if (srcAttrs == INVALID_FILE_ATTRIBUTES) return false;

    // 核心逻辑：剥离只读属性
    // 如果源文件是只读的 复制到沙盒后必须变为可写 否则 CoW 失去意义
    DWORD destAttrs = srcAttrs & ~FILE_ATTRIBUTE_READONLY;

    // 确保至少有一个属性 (防止为 0)
    if (destAttrs == 0) destAttrs = FILE_ATTRIBUTE_NORMAL;

    return SetFileAttributesW(destPath, destAttrs) != FALSE;
}

// [新增] 启用 SE_RESTORE_NAME 特权 (用于设置短文件名)
void EnableRestorePrivilege() {
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        LookupPrivilegeValueW(NULL, SE_RESTORE_NAME, &tp.Privileges[0].Luid);
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, 0);
        CloseHandle(hToken);
    }
}

// [新增] 复制短文件名 (8.3 Filename)
// 移植自 file.c: File_CopyShortName
void CopyShortName(LPCWSTR realPath, LPCWSTR sandboxPath) {
    // 1. 获取真实文件的短文件名
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(realPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;
    FindClose(hFind);

    // 如果没有短文件名 或短文件名与长文件名相同 则无需设置
    if (fd.cAlternateFileName[0] == L'\0' || wcscmp(fd.cFileName, fd.cAlternateFileName) == 0) {
        return;
    }

    // 2. 打开沙盒文件以设置短文件名
    // 注意：设置 ShortName 需要 DELETE 权限 (Windows 内部机制要求) 和 SE_RESTORE_NAME 特权
    HANDLE hFile = CreateFileW(sandboxPath,
        GENERIC_WRITE | DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, // 支持目录
        NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        // 构造 FILE_NAME_INFORMATION 结构
        size_t len = wcslen(fd.cAlternateFileName);
        size_t bufSize = sizeof(FILE_NAME_INFORMATION) + len * sizeof(WCHAR);
        std::vector<BYTE> buffer(bufSize);

        PFILE_NAME_INFORMATION info = (PFILE_NAME_INFORMATION)buffer.data();
        info->FileNameLength = (ULONG)(len * sizeof(WCHAR));
        memcpy(info->FileName, fd.cAlternateFileName, info->FileNameLength);

        IO_STATUS_BLOCK iosb;
        // FileShortNameInformation = 40
        fpNtSetInformationFile(hFile, &iosb, info, (ULONG)bufSize, (FILE_INFORMATION_CLASS)40);

        CloseHandle(hFile);
    }
}

// [重写] 执行写时复制 (Migration)
// 返回值: 0=Success, 1=Failed, 2=AccessDenied(SizeLimit)
int PerformCopyOnWrite(const std::wstring& sourceNtPath, const std::wstring& targetNtPath, bool copyContents = true) {
    std::wstring sourceDos = NtPathToDosPath(sourceNtPath);
    std::wstring targetDos = NtPathToDosPath(targetNtPath);

    if (sourceDos.empty() || targetDos.empty()) return 1;

    DWORD srcAttrs = GetFileAttributesW(sourceDos.c_str());
    if (srcAttrs == INVALID_FILE_ATTRIBUTES) return 1;

    // 1. 检查目标是否已存在 (避免重复迁移)
    if (GetFileAttributesW(targetDos.c_str()) != INVALID_FILE_ATTRIBUTES) return 0;

    // [新增] 检查文件大小限制 (仅针对文件且需要复制内容时)
    if (copyContents && g_HookCopySizeLimit > 0 && !(srcAttrs & FILE_ATTRIBUTE_DIRECTORY)) {
        WIN32_FILE_ATTRIBUTE_DATA attrs;
        if (GetFileAttributesExW(sourceDos.c_str(), GetFileExInfoStandard, &attrs)) {
            long long fileSize = ((long long)attrs.nFileSizeHigh << 32) | attrs.nFileSizeLow;
            if (fileSize > g_HookCopySizeLimit) {
                DebugLog(L"CoW: Blocked large file %s (%lld bytes)", sourceDos.c_str(), fileSize);
                return 2; // 返回特定错误码：大小超限
            }
        }
    }

    // 2. 确保父目录存在
    wchar_t dirBuf[MAX_PATH];
    wcscpy_s(dirBuf, MAX_PATH, targetDos.c_str());
    PathRemoveFileSpecW(dirBuf);
    RecursiveCreatePathWithSync(dirBuf);

    bool success = false;

    // 3. 分类处理
    if (srcAttrs & FILE_ATTRIBUTE_DIRECTORY) {
        // --- 目录迁移 ---
        if (CreateDirectoryW(targetDos.c_str(), NULL)) {
            CopyFileAttributesAndStripReadOnly(sourceDos.c_str(), targetDos.c_str());
            CopyFileTimestamps(sourceDos.c_str(), targetDos.c_str());
            // [新增] 复制短文件名
            CopyShortName(sourceDos.c_str(), targetDos.c_str());

            success = true;
            DebugLog(L"CoW: Migrated Directory %s", targetDos.c_str());
        }
    }
    else {
        // --- 文件迁移 ---
        if (copyContents) {
            // A. 尝试复制文件内容
            if (CopyFileW(sourceDos.c_str(), targetDos.c_str(), TRUE)) {
                CopyFileAttributesAndStripReadOnly(sourceDos.c_str(), targetDos.c_str());
                CopyFileTimestamps(sourceDos.c_str(), targetDos.c_str());
                // [新增] 复制短文件名
                CopyShortName(sourceDos.c_str(), targetDos.c_str());

                success = true;
                DebugLog(L"CoW: Migrated File %s", targetDos.c_str());
            }
            else {
                DWORD err = GetLastError();
                DebugLog(L"CoW: Failed to copy %s (Error: %d)", sourceDos.c_str(), err);
            }
        }
        else {
            // B. 仅创建占位文件 (针对 FILE_DELETE_ON_CLOSE 优化)
            HANDLE hFile = CreateFileW(targetDos.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                CloseHandle(hFile);
                CopyFileAttributesAndStripReadOnly(sourceDos.c_str(), targetDos.c_str());
                CopyFileTimestamps(sourceDos.c_str(), targetDos.c_str());
                // [新增] 复制短文件名
                CopyShortName(sourceDos.c_str(), targetDos.c_str());

                success = true;
                DebugLog(L"CoW: Migrated File Stub %s", targetDos.c_str());
            }
        }
    }

    return success ? 0 : 1;
}

// [新增] 智能递归创建目录 (同步属性和短文件名)
void RecursiveCreatePathWithSync(const std::wstring& sandboxDosPath) {
    if (sandboxDosPath.empty()) return;

    // 如果目录已存在 直接返回
    DWORD attrs = GetFileAttributesW(sandboxDosPath.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) return;

    // 递归处理父目录
    size_t lastSlash = sandboxDosPath.find_last_of(L'\\');
    if (lastSlash != std::wstring::npos) {
        RecursiveCreatePathWithSync(sandboxDosPath.substr(0, lastSlash));
    }

    // 创建当前目录
    if (CreateDirectoryW(sandboxDosPath.c_str(), NULL)) {

        std::wstring sandboxRoot = NtPathToDosPath(L"\\??\\" + std::wstring(g_SandboxRoot));

        if (sandboxDosPath.size() > sandboxRoot.size() &&
            _wcsnicmp(sandboxDosPath.c_str(), sandboxRoot.c_str(), sandboxRoot.size()) == 0) {

            std::wstring relPath = sandboxDosPath.substr(sandboxRoot.size());
            // relPath 如 "\C\Windows"

            if (relPath.length() >= 3 && relPath[0] == L'\\' && relPath[2] == L'\\') {
                wchar_t drive = relPath[1];
                std::wstring realPath = std::wstring(1, drive) + L":" + relPath.substr(2);

                // 同步属性、时间戳和短文件名
                if (GetFileAttributesW(realPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                    CopyFileAttributesAndStripReadOnly(realPath.c_str(), sandboxDosPath.c_str());
                    CopyFileTimestamps(realPath.c_str(), sandboxDosPath.c_str());
                    CopyShortName(realPath.c_str(), sandboxDosPath.c_str());
                }
            }
        }
    }
}

void EnsureDirectoryExistsNT(LPCWSTR ntPath) {
    if (wcsncmp(ntPath, L"\\??\\", 4) == 0) {
        LPCWSTR dosPath = ntPath + 4;
        wchar_t path[MAX_PATH];
        wcscpy_s(path, MAX_PATH, dosPath);
        PathRemoveFileSpecW(path);
        RecursiveCreatePathWithSync(path);
    }
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

// [新增] 递归合并目录树 (将真实目录内容合并到沙盒目录)
// 用于在重命名目录前 确保沙盒目录包含真实目录的所有内容
void CopyDirectoryTree(const std::wstring& srcDir, const std::wstring& destDir) {
    std::wstring searchPath = srcDir + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);

    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

        std::wstring srcPath = srcDir + L"\\" + fd.cFileName;
        std::wstring destPath = destDir + L"\\" + fd.cFileName;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // 如果是目录
            // 1. 确保目标目录存在
            if (GetFileAttributesW(destPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                CreateDirectoryW(destPath.c_str(), NULL);
                // 同步目录属性
                CopyFileAttributesAndStripReadOnly(srcPath.c_str(), destPath.c_str());
            }
            // 2. 递归处理
            CopyDirectoryTree(srcPath, destPath);
        }
        else {
            // 如果是文件 且目标不存在 则复制
            if (GetFileAttributesW(destPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                if (CopyFileW(srcPath.c_str(), destPath.c_str(), TRUE)) {
                    CopyFileAttributesAndStripReadOnly(srcPath.c_str(), destPath.c_str());
                    CopyFileTimestamps(srcPath.c_str(), destPath.c_str());
                    DebugLog(L"Merge: Copied %s to %s", srcPath.c_str(), destPath.c_str());
                }
            }
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
}

struct RecursionGuard {
    RecursionGuard() { g_IsInHook = true; }
    ~RecursionGuard() { g_IsInHook = false; }
};

// --- 注册表重定向辅助函数 ---
// 获取当前进程名 (小写 懒加载)
const std::wstring& GetCurrentProcessNameLower() {
    if (g_CurrentProcessNameLower.empty()) {
        wchar_t path[MAX_PATH];
        if (GetModuleFileNameW(NULL, path, MAX_PATH)) {
            wchar_t* name = wcsrchr(path, L'\\');
            g_CurrentProcessNameLower = name ? name + 1 : path;
            std::transform(g_CurrentProcessNameLower.begin(), g_CurrentProcessNameLower.end(), g_CurrentProcessNameLower.begin(), towlower);
        }
    }
    return g_CurrentProcessNameLower;
}

// 检查是否需要伪造特定的注册表值
// 返回 true 表示需要伪造 outData 和 outType 将被填充
bool TryGetAppCompatValue(const std::wstring& valueName, DWORD& outData, ULONG& outType) {
    const std::wstring& proc = GetCurrentProcessNameLower();

    // 1. Internet Explorer / WebBrowser Control 兼容性
    // 禁用保护模式 (Protected Mode) 防止 IE 尝试启动 Broker 进程
    if (proc == L"iexplore.exe" || proc == L"microsoftedgecp.exe" || true) { // "true" 表示对所有进程生效 防止内嵌 WebBrowser 控件崩溃
        // Zone 设定: 2500 = Protected Mode. 3 = OFF, 0 = ON.
        if (valueName == L"2500") {
            outType = REG_DWORD; outData = 3; return true;
        }
        // 显式关闭保护模式
        if (_wcsicmp(valueName.c_str(), L"ProtectedModeOffForAllZones") == 0) {
            outType = REG_DWORD; outData = 1; return true;
        }
        // 隐藏“保护模式已关闭”的警告条
        if (_wcsicmp(valueName.c_str(), L"NoProtectedModeBanner") == 0) {
            outType = REG_DWORD; outData = 1; return true;
        }
        // 禁用 IE9+ 的 USER32 Detours (Sandboxie 特有 防止冲突)
        if (_wcsicmp(valueName.c_str(), L"DetourDialogs") == 0) {
            outType = REG_DWORD; outData = 0; return true;
        }
    }

    // 2. Adobe Acrobat / Reader 兼容性
    // 禁用 Adobe 自带的沙盒 (Protected Mode) 和更新检查
    if (proc == L"acrord32.exe" || proc == L"acrobat.exe" || proc == L"acrodist.exe") {
        if (_wcsicmp(valueName.c_str(), L"bProtectedMode") == 0) {
            outType = REG_DWORD; outData = 0; return true; // 关沙盒
        }
        if (_wcsicmp(valueName.c_str(), L"iCheckReader") == 0) {
            outType = REG_DWORD; outData = 0; return true; // 关更新
        }
    }

    // 3. 通用兼容性 (SRP / CreateProcess)
    // 禁用 Authenticode 检查 防止递归调用 SandboxieCrypto 导致死锁
    if (_wcsicmp(valueName.c_str(), L"AuthenticodeEnabled") == 0) {
        outType = REG_DWORD; outData = 0; return true;
    }

    return false;
}

// 解析注册表对象属性为完整 NT 路径
std::wstring ResolveRegPathFromAttr(POBJECT_ATTRIBUTES attr) {
    std::wstring fullPath;

    // 1. 解析 RootDirectory
    if (attr->RootDirectory) {
        // 检查预定义句柄 (强制转换为 ULONG_PTR 比较)
        ULONG_PTR rootHandle = (ULONG_PTR)attr->RootDirectory;

        if (rootHandle == (ULONG_PTR)HKEY_CURRENT_USER) {
             fullPath = g_CurrentUserSidPath;
        }
        else if (rootHandle == (ULONG_PTR)HKEY_LOCAL_MACHINE) {
             fullPath = L"\\REGISTRY\\MACHINE";
        }
        else if (rootHandle == (ULONG_PTR)HKEY_CLASSES_ROOT) {
             // HKCR 是合并视图 但在 NT 路径中通常映射到 Machine Classes
             // 或者让系统去处理 但这里我们需要一个基准路径
             fullPath = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes";
        }
        else if (rootHandle == (ULONG_PTR)HKEY_USERS) {
             fullPath = L"\\REGISTRY\\USER";
        }
        else if (rootHandle == (ULONG_PTR)HKEY_CURRENT_CONFIG) {
             fullPath = L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current";
        }
        else {
            // 普通句柄 查询对象名称
            if (fpNtQueryObject) {
                ULONG len = 0;
                fpNtQueryObject(attr->RootDirectory, ObjectNameInformation, NULL, 0, &len);
                if (len > 0) {
                    std::vector<BYTE> buffer(len + 2); // +2 防止溢出
                    if (NT_SUCCESS(fpNtQueryObject(attr->RootDirectory, ObjectNameInformation, buffer.data(), len, &len))) {
                        POBJECT_NAME_INFORMATION nameInfo = (POBJECT_NAME_INFORMATION)buffer.data();
                        if (nameInfo->Name.Buffer) {
                            fullPath.assign(nameInfo->Name.Buffer, nameInfo->Name.Length / sizeof(WCHAR));
                        }
                    }
                }
            }
        }

        if (!fullPath.empty() && fullPath.back() != L'\\') {
            fullPath += L'\\';
        }
    }

    // 2. 拼接 ObjectName
    if (attr->ObjectName && attr->ObjectName->Buffer) {
        fullPath.append(attr->ObjectName->Buffer, attr->ObjectName->Length / sizeof(WCHAR));
    }

    // ========== [新增] 路径规范化 (移植自 Sandboxie) ==========
    if (!fullPath.empty()) {
        std::wstring lowerPath = fullPath;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), towlower);

        // 1. 统一 ControlSetXXX 为 CurrentControlSet
        // 匹配 \registry\machine\system\controlset001 等 (前缀长度 35)
        if (lowerPath.compare(0, 35, L"\\registry\\machine\\system\\controlset") == 0 && lowerPath.length() >= 38) {
            // 确保后面 3 个字符是数字 (例如 001, 002)
            if (iswdigit(fullPath[35]) && iswdigit(fullPath[36]) && iswdigit(fullPath[37])) {
                fullPath = L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet" + fullPath.substr(38);
                // 更新 lowerPath 以供后续匹配
                lowerPath = fullPath;
                std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), towlower);
            }
        }

        // 2. 统一 \REGISTRY\USER\CURRENT 为 当前用户 SID
        // 匹配 \registry\user\current (前缀长度 23)
        if (lowerPath.compare(0, 23, L"\\registry\\user\\current") == 0) {
            // 确保是完整路径节点 (末尾 或者以 \ 继续)
            if (lowerPath.length() == 23 || lowerPath[23] == L'\\') {
                fullPath = g_CurrentUserSidPath + fullPath.substr(23);
                lowerPath = fullPath;
                std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), towlower);
            }
        }

        // 3. WinSxS (SideBySide) 重定向 (Vista+)
        // 匹配 \registry\machine\software\microsoft\windows\currentversion\sidebyside (前缀长度 70)
        if (lowerPath.compare(0, 70, L"\\registry\\machine\\software\\microsoft\\windows\\currentversion\\sidebyside") == 0) {
            if (lowerPath.length() == 70 || lowerPath[70] == L'\\') {
                fullPath = L"\\REGISTRY\\MACHINE\\COMPONENTS" + fullPath.substr(70);
            }
        }
    }

    return fullPath;
}

// [新增] 辅助函数：通过句柄获取内核解析后的真实 NT 路径
std::wstring GetNameFromHandle(HANDLE hKey) {
    if (!hKey || !fpNtQueryKey) return L"";
    ULONG len = 0;
    NTSTATUS st = fpNtQueryKey(hKey, KeyNameInformation, NULL, 0, &len);
    if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL || len > 0) {
        std::vector<BYTE> buf(len + 2);
        if (NT_SUCCESS(fpNtQueryKey(hKey, KeyNameInformation, buf.data(), len, &len))) {
            PKEY_NAME_INFORMATION info = (PKEY_NAME_INFORMATION)buf.data();
            return std::wstring(info->Name, info->NameLength / sizeof(WCHAR));
        }
    }
    return L"";
}

// [替换] 完善的 WOW64 路径修正 (移植自 Sandboxie Key_FixNameWow64)
std::wstring FixRegPathWow64(const std::wstring& path, ACCESS_MASK DesiredAccess) {
    // 如果不是 64 位系统 不需要重定向
    if (!g_IsWin64) return path;

    // 排除 Office ClickToRun 等特殊路径 (Sandboxie 兼容性逻辑)
    if (_wcsnicmp(path.c_str(), L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Office", 43) == 0) {
        return path;
    }

    bool wants32 = false;
    if (DesiredAccess & KEY_WOW64_32KEY) {
        wants32 = true;
    } else if (DesiredAccess & KEY_WOW64_64KEY) {
        wants32 = false;
    } else {
        wants32 = g_IsWow64Process;
    }

    std::wstring lowerPath = path;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), towlower);

    // 如果明确需要 64 位视图 或者路径中已经包含 wow6432node 则不处理
    if (!wants32 || lowerPath.find(L"wow6432node") != std::wstring::npos) {
        return path;
    }

    // 核心逻辑：利用 Windows 内核的重定向机制
    std::wstring currentPath = path;
    std::wstring choppedPath = L"";
    HANDLE hTemp = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;

    // [修正] 显式指定 WOW64 标志 确保内核使用正确的视图进行路径解析
    ACCESS_MASK openAccess = KEY_QUERY_VALUE;
    if (wants32) {
        openAccess |= KEY_WOW64_32KEY;
    } else {
        openAccess |= KEY_WOW64_64KEY;
    }

    while (!currentPath.empty()) {
        RtlInitUnicodeString(&us, currentPath.c_str());
        InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS st = fpNtOpenKey(&hTemp, openAccess, &oa);
        if (NT_SUCCESS(st)) {
            break; // 成功打开
        }

        // 如果找不到 砍掉最后一级目录继续往上找 (应对新建键的情况)
        size_t pos = currentPath.rfind(L'\\');
        if (pos == std::wstring::npos || pos == 0) {
            break;
        }

        std::wstring chopped = currentPath.substr(pos);
        choppedPath = chopped + choppedPath;
        currentPath = currentPath.substr(0, pos);
    }

    if (hTemp) {
        std::wstring realResolvedPath = GetNameFromHandle(hTemp);
        fpNtClose(hTemp);

        if (!realResolvedPath.empty()) {
            std::wstring finalPath = realResolvedPath + choppedPath;

            // 清理可能出现的双重 Wow6432Node
            std::wstring lowerFinal = finalPath;
            std::transform(lowerFinal.begin(), lowerFinal.end(), lowerFinal.begin(), towlower);
            size_t doubleWow = lowerFinal.find(L"\\wow6432node\\wow6432node");

            if (doubleWow != std::wstring::npos) {
                finalPath.erase(doubleWow, 12); // 删掉一个 \Wow6432Node
            }
            return finalPath;
        }
    }

    return path; // 回退到原路径
}

// ========== [新增] 权限与降权 (Low Integrity) 支持 ==========
// 检查当前进程是否是受限令牌 (Low Integrity / AppContainer)
bool IsRestrictedToken() {
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD isRestricted = 0;
        DWORD len = 0;
        if (GetTokenInformation(hToken, TokenIsRestricted, &isRestricted, sizeof(isRestricted), &len) && isRestricted) {
            CloseHandle(hToken);
            return true;
        }

        PTOKEN_MANDATORY_LABEL pTIL = NULL;
        GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &len);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, len);
            if (pTIL && GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, len, &len)) {
                DWORD dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
                    (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid)-1));
                LocalFree(pTIL);
                CloseHandle(hToken);
                return dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_RID;
            }
            if (pTIL) LocalFree(pTIL);
        }
        CloseHandle(hToken);
    }
    return false;
}

// 降低指定注册表键的完整性级别 (Mandatory Integrity Control) 为 Low
bool SetLowLabelKeyByName(const std::wstring& ntPath) {
    HANDLE hKey = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, ntPath.c_str());
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // 尝试以 WRITE_OWNER | WRITE_DAC 权限打开
    if (NT_SUCCESS(fpNtOpenKey(&hKey, WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY, &oa)) ||
        NT_SUCCESS(fpNtOpenKey(&hKey, WRITE_DAC, &oa))) {

        PSECURITY_DESCRIPTOR pSD = NULL;
        // S:(ML;;NW;;;LW) 表示 Low Mandatory Level
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;;NW;;;LW)", SDDL_REVISION_1, &pSD, NULL)) {
            PACL pSacl = NULL;
            BOOL saclPresent = FALSE, saclDefaulted = FALSE;
            GetSecurityDescriptorSacl(pSD, &saclPresent, &pSacl, &saclDefaulted);

            DWORD res = SetSecurityInfo(hKey, SE_REGISTRY_KEY, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, pSacl);
            LocalFree(pSD);
            fpNtClose(hKey);
            return res == ERROR_SUCCESS;
        }
        fpNtClose(hKey);
    }
    return false;
}

// --- [新增] 清除键的所有值 (用于复活墓碑键时) ---
void ClearSandboxKeyValues(HANDLE hKey) {
    if (!fpNtEnumerateValueKey || !fpNtDeleteValueKey) return;

    // 使用固定缓冲区避免频繁 vector 分配 4KB 通常足够存储 KeyValueBasicInformation
    BYTE staticBuf[4096];
    ULONG len = 0;

    while (true) {
        // 始终枚举索引 0
        NTSTATUS st = fpNtEnumerateValueKey(hKey, 0, KeyValueBasicInformation, staticBuf, sizeof(staticBuf), &len);

        if (st == STATUS_NO_MORE_ENTRIES) break;

        PKEY_VALUE_BASIC_INFORMATION info = (PKEY_VALUE_BASIC_INFORMATION)staticBuf;
        std::vector<BYTE> dynamicBuf;

        // 如果缓冲区不够 分配堆内存
        if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL) {
            try {
                dynamicBuf.resize(len);
            } catch (...) { break; } // 内存分配失败保护

            st = fpNtEnumerateValueKey(hKey, 0, KeyValueBasicInformation, dynamicBuf.data(), len, &len);
            if (!NT_SUCCESS(st)) break;
            info = (PKEY_VALUE_BASIC_INFORMATION)dynamicBuf.data();
        } else if (!NT_SUCCESS(st)) {
            break; // 其他错误 (如权限不足)
        }

        UNICODE_STRING uName;
        uName.Buffer = info->Name;
        uName.Length = (USHORT)info->NameLength;
        uName.MaximumLength = (USHORT)info->NameLength;

        // 删除值
        st = fpNtDeleteValueKey(hKey, &uName);
        if (!NT_SUCCESS(st)) break; // 防止死循环
    }
}

// 递归物理删除沙盒键（含所有子键）
void DeleteSandboxKeyRecursive(const std::wstring& fullPath) {
    HANDLE hKey = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uStr;
    RtlInitUnicodeString(&uStr, fullPath.c_str());
    InitializeObjectAttributes(&oa, &uStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    if (NT_SUCCESS(fpNtOpenKey(&hKey, KEY_ENUMERATE_SUB_KEYS | DELETE, &oa))) {
        while (true) {
            ULONG len = 0;
            // [修复] 使用 vector 保证内存对齐 并支持动态扩容
            std::vector<BYTE> buf(1024);

            // 始终枚举 index=0 因为每次删除后列表会缩短
            NTSTATUS st = fpNtEnumerateKey(hKey, 0, KeyBasicInformation, buf.data(), (ULONG)buf.size(), &len);

            // [修复] 处理缓冲区不足的情况 防止死循环或漏删
            if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL) {
                buf.resize(len);
                st = fpNtEnumerateKey(hKey, 0, KeyBasicInformation, buf.data(), (ULONG)buf.size(), &len);
            }

            if (!NT_SUCCESS(st)) break;

            PKEY_BASIC_INFORMATION info = (PKEY_BASIC_INFORMATION)buf.data();
            std::wstring childName(info->Name, info->NameLength / sizeof(WCHAR));
            std::wstring childPath = fullPath + L"\\" + childName;
            DeleteSandboxKeyRecursive(childPath);
        }
        fpNtDeleteKey(hKey);
        fpNtClose(hKey);
    }
}

// [辅助函数] 从沙盒绝对路径反推真实绝对路径
// 输入: \REGISTRY\USER\YapBoxReg_...\Machine\Software\Classes
// 输出: \REGISTRY\MACHINE\SOFTWARE\Classes
bool GetRealFromSandboxPath(const std::wstring& sandboxPath, std::wstring& outReal) {
    if (g_RegMountPathNt.empty()) return false;

    // 检查前缀是否匹配沙盒挂载点 [修复] 使用 _wcsnicmp
    if (_wcsnicmp(sandboxPath.c_str(), g_RegMountPathNt.c_str(), g_RegMountPathNt.length()) != 0) return false;

    // 提取相对路径 (例如 \User\Software\Classes)
    std::wstring relPath = sandboxPath.substr(g_RegMountPathNt.length());
    if (relPath.empty() || relPath[0] != L'\\') return false;

    std::wstring sub = relPath.substr(1); // 去掉开头的 \

    // 根据子根进行反向映射 [修复] 使用不区分大小写的比较
    if (_wcsicmp(sub.c_str(), L"Machine") == 0 || _wcsnicmp(sub.c_str(), L"Machine\\", 8) == 0) {
        outReal = L"\\REGISTRY\\MACHINE" + sub.substr(7);
    }
    else if (_wcsicmp(sub.c_str(), L"Users") == 0 || _wcsnicmp(sub.c_str(), L"Users\\", 6) == 0) {
        outReal = L"\\REGISTRY\\USER" + sub.substr(5);
    }
    else if (_wcsicmp(sub.c_str(), L"User") == 0 || _wcsnicmp(sub.c_str(), L"User\\", 5) == 0) {
        outReal = g_CurrentUserSidPath + sub.substr(4);
    }
    else if (_wcsicmp(sub.c_str(), L"Classes") == 0 || _wcsnicmp(sub.c_str(), L"Classes\\", 8) == 0) {
        outReal = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes" + sub.substr(7);
    }
    else if (_wcsicmp(sub.c_str(), L"Config") == 0 || _wcsnicmp(sub.c_str(), L"Config\\", 7) == 0) {
        outReal = L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current" + sub.substr(6);
    }
    else {
        return false;
    }
    return true;
}

// 使指定沙盒路径的父键枚举缓存失效
void InvalidateParentRegContext(const std::wstring& sandboxKeyPath) {
    size_t pos = sandboxKeyPath.rfind(L'\\');
    if (pos == std::wstring::npos) return;
    std::wstring parentPath = sandboxKeyPath.substr(0, pos);

    // [修复] 计算对应的真实路径 确保缓存了真实路径的上下文也被失效
    std::wstring realParentPath;
    GetRealFromSandboxPath(parentPath, realParentPath);

    std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
    for (auto& pair : g_RegContextMap) {
        if (_wcsicmp(pair.second->FullPath.c_str(), parentPath.c_str()) == 0 ||
            (!realParentPath.empty() && _wcsicmp(pair.second->FullPath.c_str(), realParentPath.c_str()) == 0)) {
            pair.second->KeysInitialized = false;
            pair.second->SubKeys.clear();
        }
    }
}

// [新增] 检查注册表路径是否在白名单中 (需要直通真实注册表)
bool IsSystemCriticalRegPath(const std::wstring& path) {
    std::wstring lowerPath = path;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), towlower);

    // 辅助 lambda：检查是否包含关键词
    auto contains = [&](const wchar_t* sub) {
        return lowerPath.find(sub) != std::wstring::npos;
    };

    // 1. Classes (COM 组件) - 核心修复
    // 匹配 \Software\Classes 和 \Software\Wow6432Node\Classes
    // if (contains(L"\\software\\classes") || contains(L"\\software\\wow6432node\\classes")) return true;

    // [新增] 每用户 COM 类配置单元 \REGISTRY\USER\SID_Classes (Vista+ HKCR 合并视图)
    // 路径形如 \REGISTRY\USER\S-1-5-21-xxx_Classes\CLSID\...
    // if (contains(L"_classes\\") ||
		// (lowerPath.length() >= 8 && lowerPath.compare(lowerPath.length() - 8, 8, L"_classes") == 0)) return true;

    // 2. 音频与多媒体
    if (contains(L"mmdevices")) return true;
    if (contains(L"audiocore")) return true;
    if (contains(L"drivers32")) return true;
    if (contains(L"drivers.desc")) return true;

    // 3. DirectX
    if (contains(L"microsoft\\directx")) return true;
    if (contains(L"direct3d")) return true;
    if (contains(L"directdraw")) return true;
    if (contains(L"directsound")) return true;  // ← 修复 DirectSound Error
    if (contains(L"directinput")) return true;  // ← 预防
    if (contains(L"directplay")) return true;   // ← 预防

    // 4. 硬件设备类
    if (contains(L"control\\class")) return true;
    if (contains(L"control\\deviceclasses")) return true;

    // 5. 密码学与证书
    if (contains(L"cryptography")) return true;
    if (contains(L"systemcertificates")) return true;

    // 6. 基础服务
    if (contains(L"services\\bfe")) return true; // 防火墙
    if (contains(L"currentversion\\sidebyside")) return true; // WinSxS
    if (contains(L"\\registry\\machine\\components")) return true; // WinSxS

    // 7. Office ClickToRun (Sandboxie 源码中提到的)
    if (contains(L"clicktorun")) return true;

    // 8. IE Zones
    if (contains(L"internet settings\\zones")) return true;

    // ==========[新增] AppHive 直通 (移植自 Sandboxie) ==========
    // 9. AppHive (UWP/Centennial 私有配置单元)
    // 路径形如 \REGISTRY\A\... 必须直通 否则现代应用无法运行
    if (lowerPath.compare(0, 13, L"\\registry\\a\\") == 0) return true;

    return false;
}

// 判断注册表路径是否需要重定向 并输出相对于 AppHive 的相对路径
bool ShouldRedirectReg(const std::wstring& fullNtPath, std::wstring& relPathOut) {
    if (!g_HookReg || !g_hAppHive || g_CurrentUserSidPath.empty()) return false;

    // [修复] 使用不区分大小写的 _wcsnicmp 替换 find
    if (!g_RegMountPathNt.empty() && _wcsnicmp(fullNtPath.c_str(), g_RegMountPathNt.c_str(), g_RegMountPathNt.length()) == 0) return false;

    // [新增] === 关键修复：白名单检查 ===
    // 如果是 COM、音频、驱动相关路径 强制直通真实注册表
    if (IsSystemCriticalRegPath(fullNtPath)) {
        return false;
    }

    // 定义各根键的 NT 路径前缀
    std::wstring prefixMachine = L"\\REGISTRY\\MACHINE";
    std::wstring prefixUser = g_CurrentUserSidPath;
    // std::wstring prefixClasses = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes";
    std::wstring prefixUsersRoot = L"\\REGISTRY\\USER";
    std::wstring prefixConfig = L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current";

    /*
    // 1. 匹配 HKCR (优先级高于 HKLM)
    if (_wcsnicmp(fullNtPath.c_str(), prefixClasses.c_str(), prefixClasses.length()) == 0) {
        std::wstring sub = fullNtPath.substr(prefixClasses.length());
        if (!sub.empty() && sub[0] == L'\\') sub = sub.substr(1);
        relPathOut = L"Classes";
        if (!sub.empty()) relPathOut += L"\\" + sub;
        return true;
    }
    */

    // 2. 匹配 HKCC
    if (_wcsnicmp(fullNtPath.c_str(), prefixConfig.c_str(), prefixConfig.length()) == 0) {
        std::wstring sub = fullNtPath.substr(prefixConfig.length());
        if (!sub.empty() && sub[0] == L'\\') sub = sub.substr(1);
        relPathOut = L"Config";
        if (!sub.empty()) relPathOut += L"\\" + sub;
        return true;
    }

    // 3. 匹配 HKCU
    if (_wcsnicmp(fullNtPath.c_str(), prefixUser.c_str(), prefixUser.length()) == 0) {
        std::wstring sub = fullNtPath.substr(prefixUser.length());

        // [关键修复] sub 必须为空(精确匹配)或以 \ 开头(子键)
        // 若以 _ 开头说明是同级配置单元(如 SID_Classes), 不是 HKCU 子键, 不应重定向
        if (!sub.empty() && sub[0] != L'\\') return false;

        if (!sub.empty() && sub[0] == L'\\') sub = sub.substr(1);

        if (IsSystemCriticalRegPath(fullNtPath)) return false;

        relPathOut = L"User";
        if (!sub.empty()) relPathOut += L"\\" + sub;
        return true;
    }

    // 4. 匹配 HKLM
    if (_wcsnicmp(fullNtPath.c_str(), prefixMachine.c_str(), prefixMachine.length()) == 0) {
        // [新增] 排除 SOFTWARE\Classes (虽然上面 IsSystemCriticalRegPath 已经处理了 双重保险)
        // if (ContainsCaseInsensitive(fullNtPath, L"\\SOFTWARE\\Classes")) return false;

        std::wstring sub = fullNtPath.substr(prefixMachine.length());
        if (!sub.empty() && sub[0] == L'\\') sub = sub.substr(1);
        relPathOut = L"Machine";
        if (!sub.empty()) relPathOut += L"\\" + sub;
        return true;
    }

    // 5. 匹配 HKU (排除掉已经处理的 HKCU 和沙盒挂载点)
    if (_wcsnicmp(fullNtPath.c_str(), prefixUsersRoot.c_str(), prefixUsersRoot.length()) == 0) {
        std::wstring sub = fullNtPath.substr(prefixUsersRoot.length());
        if (!sub.empty() && sub[0] == L'\\') sub = sub.substr(1);

        // 如果 sub 为空 说明访问的是 \REGISTRY\USER 根
        // 如果不为空 且不是当前用户 SID 则映射到 Users
        relPathOut = L"Users";
        if (!sub.empty()) relPathOut += L"\\" + sub;
        return true;
    }

    return false;
}

// 递归创建注册表键 (相对于 AppHive)
void EnsureRegPathExistsRelative(const std::wstring& relPath) {
    if (relPath.empty() || !g_hAppHive) return;

    size_t currentPos = 0;
    while (true) {
        size_t nextSlash = relPath.find(L'\\', currentPos);
        if (nextSlash == std::wstring::npos) break; // 只创建父级 最后一级由 NtCreateKey 创建

        std::wstring subPath = relPath.substr(0, nextSlash);

        HANDLE hKey = NULL;
        UNICODE_STRING uStr;
        OBJECT_ATTRIBUTES oa;
        RtlInitUnicodeString(&uStr, subPath.c_str());

        // 关键：RootDirectory 指向我们的私有 Hive
        InitializeObjectAttributes(&oa, &uStr, OBJ_CASE_INSENSITIVE, (HANDLE)g_hAppHive, NULL);

        ULONG disposition;
        NTSTATUS status = fpNtCreateKey(&hKey, KEY_READ | KEY_WRITE, &oa, 0, NULL, 0, &disposition);

        // ========== [新增] 降权处理 (移植自 Sandboxie Key_CreatePath) ==========
        if (status == STATUS_ACCESS_DENIED && IsRestrictedToken()) {
            // 如果创建失败 说明父键权限过高 降低父键的完整性级别
            std::wstring parentNtPath = g_RegMountPathNt;
            if (currentPos > 0) {
                parentNtPath += L"\\" + relPath.substr(0, currentPos - 1);
            }
            SetLowLabelKeyByName(parentNtPath);

            // 重试创建
            status = fpNtCreateKey(&hKey, KEY_READ | KEY_WRITE, &oa, 0, NULL, 0, &disposition);
        }

        if (NT_SUCCESS(status)) {
            fpNtClose(hKey);
        }

        currentPos = nextSlash + 1;
    }
}

// [新增] 检查真实键是否存在 如果存在则在沙盒中创建结构 (影子键)
bool EnsureShadowKeyExists(HANDLE SandboxParent, PUNICODE_STRING ObjectName, HANDLE RealParent, ACCESS_MASK DesiredAccess = KEY_WRITE) {
    HANDLE hRealChild = NULL;
    OBJECT_ATTRIBUTES oaReal;
    InitializeObjectAttributes(&oaReal, ObjectName, OBJ_CASE_INSENSITIVE, RealParent, NULL);

    // 1. 探测真实键是否存在
    NTSTATUS status = fpNtOpenKey(&hRealChild, KEY_QUERY_VALUE, &oaReal);
    if (!NT_SUCCESS(status)) {
        return false;
    }

    // 2. 真实存在 在沙盒中创建影子结构
    HANDLE hNewKey = NULL;
    OBJECT_ATTRIBUTES oaNew;
    InitializeObjectAttributes(&oaNew, ObjectName, OBJ_CASE_INSENSITIVE, SandboxParent, NULL);

    ULONG disposition;
    status = fpNtCreateKey(&hNewKey, KEY_READ | KEY_WRITE, &oaNew, 0, NULL, 0, &disposition);

    if (NT_SUCCESS(status)) {
        fpNtClose(hNewKey);
        fpNtClose(hRealChild);
        return true;
    }
    fpNtClose(hRealChild);
    return false;
}

// [新增] 获取句柄对应的真实路径和沙盒路径
bool GetRegPaths(HANDLE hKey, std::wstring& outReal, std::wstring& outSandbox) {
    std::wstring keyPath = GetPathFromHandle(hKey);
    if (keyPath.empty()) return false;

    // 检查是否在沙盒内 [修复] 使用 _wcsnicmp
    if (g_HookReg && !g_RegMountPathNt.empty() && _wcsnicmp(keyPath.c_str(), g_RegMountPathNt.c_str(), g_RegMountPathNt.length()) == 0) {
        outSandbox = keyPath;
        std::wstring relPath = keyPath.substr(g_RegMountPathNt.length());
        if (relPath.empty() || relPath[0] != L'\\') return false;
        std::wstring sub = relPath.substr(1);

        // [修复] 使用不区分大小写的比较
        if (_wcsicmp(sub.c_str(), L"Machine") == 0 || _wcsnicmp(sub.c_str(), L"Machine\\", 8) == 0) {
            outReal = L"\\REGISTRY\\MACHINE" + sub.substr(7);
        }
        else if (_wcsicmp(sub.c_str(), L"Users") == 0 || _wcsnicmp(sub.c_str(), L"Users\\", 6) == 0) {
            outReal = L"\\REGISTRY\\USER" + sub.substr(5);
        }
        else if (_wcsicmp(sub.c_str(), L"User") == 0 || _wcsnicmp(sub.c_str(), L"User\\", 5) == 0) {
            outReal = g_CurrentUserSidPath + sub.substr(4);
        }
        else if (_wcsicmp(sub.c_str(), L"Classes") == 0 || _wcsnicmp(sub.c_str(), L"Classes\\", 8) == 0) {
            outReal = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes" + sub.substr(7);
        }
        else if (_wcsicmp(sub.c_str(), L"Config") == 0 || _wcsnicmp(sub.c_str(), L"Config\\", 7) == 0) {
            outReal = L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current" + sub.substr(6);
        }
        else {
            return false;
        }
        return true;
    }
    else {
        // 句柄指向真实路径
        outReal = keyPath;
        std::wstring relPath;

        if (ShouldRedirectReg(outReal, relPath)) {
            outSandbox = g_RegMountPathNt + L"\\" + relPath;
            return true;
        }
    }
    return false;
}

// [新增] 枚举指定路径的子键到 Map (用于去重)
void EnumerateKeysToMap(const std::wstring& path, std::map<std::wstring, CachedRegKey>& map) {
    HANDLE hKey;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uStr;
    RtlInitUnicodeString(&uStr, path.c_str());
    InitializeObjectAttributes(&oa, &uStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // 尝试打开键
    if (NT_SUCCESS(fpNtOpenKey(&hKey, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &oa))) {
        ULONG index = 0;
        ULONG len;
        std::vector<BYTE> buf(4096);

        while (true) {
            NTSTATUS status = fpNtEnumerateKey(hKey, index, KeyNodeInformation, buf.data(), (ULONG)buf.size(), &len);

            // 处理缓冲区不足的情况 (虽然预分配了4k 但仍可能不足)
            if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL) {
                if (len > buf.size()) buf.resize(len);
                continue; // 重试
            }

            if (status == STATUS_NO_MORE_ENTRIES) break;
            if (!NT_SUCCESS(status)) break;

            PKEY_NODE_INFORMATION info = (PKEY_NODE_INFORMATION)buf.data();
            std::wstring name(info->Name, info->NameLength / sizeof(WCHAR));

            CachedRegKey entry;
            entry.Name = name;
            entry.LastWriteTime = info->LastWriteTime;
            entry.TitleIndex = info->TitleIndex;
            if (info->ClassLength > 0 && info->ClassOffset > 0) {
                // 边界检查
                if (info->ClassOffset + info->ClassLength <= buf.size()) {
                    entry.Class.assign((WCHAR*)(buf.data() + info->ClassOffset), info->ClassLength / sizeof(WCHAR));
                }
            }

            std::wstring keyName = name;
            std::transform(keyName.begin(), keyName.end(), keyName.begin(), towlower);
            map[keyName] = entry;

            index++;
        }
        fpNtClose(hKey);
    }
}

// [新增] 枚举指定路径的值到 Map
void EnumerateValuesToMap(const std::wstring& path, std::map<std::wstring, CachedRegValue>& map) {
    HANDLE hKey;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uStr;
    RtlInitUnicodeString(&uStr, path.c_str());
    InitializeObjectAttributes(&oa, &uStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    if (NT_SUCCESS(fpNtOpenKey(&hKey, KEY_QUERY_VALUE, &oa))) {
        ULONG index = 0;
        ULONG len;
        std::vector<BYTE> buf(4096);

        while (true) {
            NTSTATUS status = fpNtEnumerateValueKey(hKey, index, KeyValueFullInformation, buf.data(), (ULONG)buf.size(), &len);
            if (status == STATUS_NO_MORE_ENTRIES) break;
            if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL) {
                buf.resize(len);
                continue;
            }
            if (!NT_SUCCESS(status)) break;

            PKEY_VALUE_FULL_INFORMATION info = (PKEY_VALUE_FULL_INFORMATION)buf.data();
            std::wstring name(info->Name, info->NameLength / sizeof(WCHAR));

            CachedRegValue entry;
            entry.Name = name;
            entry.TitleIndex = info->TitleIndex;
            entry.Type = info->Type;
            if (info->DataLength > 0) {
                BYTE* pData = (BYTE*)info + info->DataOffset;
                entry.Data.assign(pData, pData + info->DataLength);
            }

            std::wstring keyName = name;
            std::transform(keyName.begin(), keyName.end(), keyName.begin(), towlower);
            map[keyName] = entry;

            index++;
        }
        fpNtClose(hKey);
    }
}

// [新增] 尝试打开对应的真实键 (用于读取回退)
HANDLE OpenRealKeyForFallback(const std::wstring& realPath) {
    HANDLE hReal = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uStr;
    RtlInitUnicodeString(&uStr, realPath.c_str());
    InitializeObjectAttributes(&oa, &uStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // 只读打开
    if (NT_SUCCESS(fpNtOpenKey(&hReal, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &oa))) {
        return hReal;
    }
    return NULL;
}

// [新增] 确保绝对路径存在 (用于创建影子键)
// 输入: \REGISTRY\USER\YapBoxReg_...\User\Software\Rime\Weasel
void EnsureSandboxPathExists(const std::wstring& fullSandboxPath) {
    if (fullSandboxPath.empty()) return;

    // 我们需要逐级创建为了简单 我们利用 EnsureRegPathExistsRelative
    // 先转成相对路径 [修复] 使用 _wcsnicmp
    if (_wcsnicmp(fullSandboxPath.c_str(), g_RegMountPathNt.c_str(), g_RegMountPathNt.length()) == 0) {
        std::wstring relPath = fullSandboxPath.substr(g_RegMountPathNt.length());
        if (!relPath.empty() && relPath[0] == L'\\') relPath = relPath.substr(1);
        EnsureRegPathExistsRelative(relPath);
    }
}

// 检查时间戳是否为删除标记
bool IsDeleteMark(const LARGE_INTEGER& li) {
    return (li.LowPart == DELETE_MARK_LOW && li.HighPart == DELETE_MARK_HIGH);
}

// 检查键是否被标记为删除
bool IsKeyMarkedDeleted(HANDLE hKey) {
    KEY_BASIC_INFORMATION kbi;
    ULONG len;
    NTSTATUS status = fpNtQueryKey(hKey, KeyBasicInformation, &kbi, sizeof(kbi), &len);
    // [修复] STATUS_BUFFER_OVERFLOW 时固定字段 (LastWriteTime) 已被填充 必须一并检查
    if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) {
        return IsDeleteMark(kbi.LastWriteTime);
    }
    return false;
}

// --- [新增] 清除键中的所有非墓碑值 (保留 YAPBOX_VALUE_TOMBSTONE_TYPE 值墓碑) ---
void CleanNonTombstoneValues(HANDLE hKey) {
    if (!fpNtEnumerateValueKey || !fpNtDeleteValueKey) return;

    BYTE staticBuf[4096];
    ULONG len = 0;
    ULONG index = 0;

    while (true) {
        NTSTATUS st = fpNtEnumerateValueKey(hKey, index, KeyValueBasicInformation, staticBuf, sizeof(staticBuf), &len);
        if (st == STATUS_NO_MORE_ENTRIES) break;

        std::vector<BYTE> dynamicBuf;
        PKEY_VALUE_BASIC_INFORMATION info = (PKEY_VALUE_BASIC_INFORMATION)staticBuf;

        if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL) {
            try { dynamicBuf.resize(len); } catch (...) { break; }
            st = fpNtEnumerateValueKey(hKey, index, KeyValueBasicInformation, dynamicBuf.data(), len, &len);
            if (!NT_SUCCESS(st)) break;
            info = (PKEY_VALUE_BASIC_INFORMATION)dynamicBuf.data();
        } else if (!NT_SUCCESS(st)) {
            break;
        }

        // 保留值墓碑 只删除非墓碑值
        if (info->Type == YAPBOX_VALUE_TOMBSTONE_TYPE) {
            index++; // 跳过墓碑
            continue;
        }

        UNICODE_STRING vName;
        vName.Buffer = info->Name;
        vName.Length = (USHORT)info->NameLength;
        vName.MaximumLength = (USHORT)info->NameLength;

        if (NT_SUCCESS(fpNtDeleteValueKey(hKey, &vName))) {
            continue; // 删除成功 列表缩短 不递增 index
        }
        index++; // 删除失败（权限等） 跳过避免死循环
    }
}

// --- [新增] 递归清除沙盒键及其子键中的所有非墓碑值 ---
void CleanNonTombstoneValuesRecursive(const std::wstring& sandboxPath) {
    HANDLE hKey = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uStr;
    RtlInitUnicodeString(&uStr, sandboxPath.c_str());
    InitializeObjectAttributes(&oa, &uStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // 尝试以完全权限打开 失败则降级
    if (!NT_SUCCESS(fpNtOpenKey(&hKey, KEY_ALL_ACCESS, &oa))) {
        if (!NT_SUCCESS(fpNtOpenKey(&hKey, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_ENUMERATE_SUB_KEYS, &oa))) {
            return; // 无法打开 跳过
        }
    }

    // 清除本键的非墓碑值
    CleanNonTombstoneValues(hKey);

    // 枚举子键并递归
    ULONG index = 0, len = 0;
    std::vector<BYTE> buf(1024);

    while (true) {
        NTSTATUS st = fpNtEnumerateKey(hKey, index, KeyBasicInformation, buf.data(), (ULONG)buf.size(), &len);
        if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL) {
            buf.resize(len);
            continue;
        }
        if (!NT_SUCCESS(st)) break;

        PKEY_BASIC_INFORMATION info = (PKEY_BASIC_INFORMATION)buf.data();
        std::wstring childName(info->Name, info->NameLength / sizeof(WCHAR));
        std::wstring childPath = sandboxPath + L"\\" + childName;

        CleanNonTombstoneValuesRecursive(childPath);
        index++;
    }

    fpNtClose(hKey);
}

// 设置键的时间戳（用于标记删除或复活）
NTSTATUS SetKeyLastWriteTime(HANDLE hKey, bool isDelete) {
    KEY_WRITE_TIME_INFORMATION kwti;
    if (isDelete) {
        kwti.LastWriteTime.LowPart = DELETE_MARK_LOW;
        kwti.LastWriteTime.HighPart = DELETE_MARK_HIGH;
    } else {
        // 复活：设置为当前系统时间
        GetSystemTimeAsFileTime((LPFILETIME)&kwti.LastWriteTime);
    }

    // 需要 KEY_SET_VALUE 权限
    return fpNtSetInformationKey(hKey, KeyWriteTimeInformation, &kwti, sizeof(kwti));
}

// --- 注册表 NT API Hook 实现 ---
NTSTATUS NTAPI Detour_NtQueryValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
) {
    // 1. 尝试从当前句柄 (通常是沙盒句柄) 查询
    // 注意：这里不加 RecursionGuard 因为 fpNtQueryValueKey 是原始函数 不会递归
    NTSTATUS status = fpNtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

    // ========== [新增] 特定应用兼容性伪造 (移植自 Sandboxie) ==========
    // 无论原始调用是否成功 只要程序查询敏感值 我们都强制覆盖为“安全”的值
    // 仅处理最常用的 KeyValuePartialInformation (RegQueryValueEx 默认使用此类型)
    if (ValueName && ValueName->Buffer && KeyValueInformationClass == KeyValuePartialInformation) {
        std::wstring queryName(ValueName->Buffer, ValueName->Length / sizeof(WCHAR));
        DWORD fakeData = 0;
        ULONG fakeType = REG_DWORD;

        if (TryGetAppCompatValue(queryName, fakeData, fakeType)) {
            ULONG requiredSize = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + sizeof(DWORD);

            if (ResultLength) *ResultLength = requiredSize;

            if (Length >= requiredSize) {
                PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)KeyValueInformation;
                info->TitleIndex = 0;
                info->Type = fakeType;
                info->DataLength = sizeof(DWORD);
                memcpy(info->Data, &fakeData, sizeof(DWORD));
                return STATUS_SUCCESS; // 强制返回成功
            } else {
                return STATUS_BUFFER_OVERFLOW;
            }
        }
    }

    // [新增] 检查是否是值墓碑 (惰性 CoW 删除标记)
    if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) {
        ULONG type = 0;
        if (KeyValueInformationClass == KeyValueBasicInformation) type = ((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->Type;
        else if (KeyValueInformationClass == KeyValueFullInformation) type = ((PKEY_VALUE_FULL_INFORMATION)KeyValueInformation)->Type;
        else if (KeyValueInformationClass == KeyValuePartialInformation) type = ((PKEY_VALUE_PARTIAL_INFORMATION)KeyValueInformation)->Type;

        if (type == YAPBOX_VALUE_TOMBSTONE_TYPE) {
            status = STATUS_OBJECT_NAME_NOT_FOUND; // 伪装成不存在
        }
    }

    // 2. [回退逻辑] 如果沙盒中未找到该值 (STATUS_OBJECT_NAME_NOT_FOUND)
    // 且启用了注册表 Hook 尝试从缓存的真实句柄中读取
    if (status == STATUS_OBJECT_NAME_NOT_FOUND && g_HookReg && !g_IsInHook) {
        HANDLE hReal = NULL;

        // 从 Context 中查找缓存的真实句柄
        {
            std::shared_lock<std::shared_mutex> lock(g_RegContextMutex);
            auto it = g_RegContextMap.find(KeyHandle);
            if (it != g_RegContextMap.end()) {
                hReal = it->second->hRealKey;
            }
        }

        // 如果找到了真实句柄 尝试从中查询
        if (hReal) {
            // 使用 RecursionGuard 防止某些底层 Hook 再次触发
            RecursionGuard guard;
            status = fpNtQueryValueKey(hReal, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
        }
    }

    // 3. [区域伪造逻辑] 如果查询成功 (或缓冲区溢出 说明值存在) 且启用了区域伪造
    // 我们需要拦截 ACP/OEMCP 的查询结果
    if ((NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) && g_FakeACP != 0 && ValueName && ValueName->Buffer) {

        // 检查是否查询的是 ACP 或 OEMCP
        // 注册表路径通常是: HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage
        // ValueName 分别是 "ACP" 或 "OEMCP"

        bool isACP = (ValueName->Length >= 6 && _wcsnicmp(ValueName->Buffer, L"ACP", 3) == 0 && (ValueName->Length == 6 || ValueName->Buffer[3] == L'\0'));
        bool isOEMCP = (ValueName->Length >= 10 && _wcsnicmp(ValueName->Buffer, L"OEMCP", 5) == 0 && (ValueName->Length == 10 || ValueName->Buffer[5] == L'\0'));

        if (isACP || isOEMCP) {
            const std::wstring& fakeVal = isACP ? g_FakeACPStr : g_FakeOEMCPStr;
            ULONG fakeDataSize = (ULONG)((fakeVal.length() + 1) * sizeof(wchar_t)); // 包含 NULL 结尾

            // 根据查询的信息类进行处理
            if (KeyValueInformationClass == KeyValuePartialInformation) {
                // 结构: Header + Data
                ULONG requiredSize = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + fakeDataSize;

                if (Length >= requiredSize) {
                    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)KeyValueInformation;
                    info->Type = REG_SZ;
                    info->DataLength = fakeDataSize;
                    memcpy(info->Data, fakeVal.c_str(), fakeDataSize);
                    status = STATUS_SUCCESS;
                } else {
                    status = STATUS_BUFFER_OVERFLOW;
                }

                if (ResultLength) *ResultLength = requiredSize;
            }
            else if (KeyValueInformationClass == KeyValueFullInformation) {
                // 结构: Header + Name + Padding + Data
                // 注意：这里我们只修改 Data 部分 假设 Name 部分已经由 fpNtQueryValueKey 填充好了
                // 如果原始查询失败(回退逻辑也没找到) 这里进不来 所以 info 里的 Name 是有效的

                PKEY_VALUE_FULL_INFORMATION info = (PKEY_VALUE_FULL_INFORMATION)KeyValueInformation;

                // 如果原始状态是 SUCCESS 我们可以直接修改数据
                // 如果原始状态是 OVERFLOW 我们需要重新计算大小

                // 简单起见 如果原始调用成功读取了数据 我们检查是否有空间覆写
                if (status == STATUS_SUCCESS) {
                    if (info->DataLength >= fakeDataSize) {
                        // 原数据空间足够 直接覆盖
                        info->Type = REG_SZ;
                        info->DataLength = fakeDataSize;
                        // DataOffset 是相对于结构体起始的偏移
                        memcpy((BYTE*)info + info->DataOffset, fakeVal.c_str(), fakeDataSize);
                    } else {
                        // 原数据空间不足 (例如原值是 "1252" 长度 10 我们要写 "936" 长度 8 通常够用)
                        // 如果不够 返回 OVERFLOW
                        // 但通常代码页字符串长度都很短 这里做个防御性编程
                        // 如果空间不够 我们只能告诉调用者需要更多内存
                        // 重新计算所需大小
                        ULONG dataOffset = info->DataOffset;
                        ULONG requiredSize = dataOffset + fakeDataSize;

                        if (Length >= requiredSize) {
                             info->Type = REG_SZ;
                             info->DataLength = fakeDataSize;
                             memcpy((BYTE*)info + dataOffset, fakeVal.c_str(), fakeDataSize);
                        } else {
                             status = STATUS_BUFFER_OVERFLOW;
                             if (ResultLength) *ResultLength = requiredSize;
                        }
                    }
                }
                else if (status == STATUS_BUFFER_OVERFLOW) {
                    // 如果原始查询就溢出了 我们需要修正 ResultLength
                    // 原始 ResultLength 是基于真实值的 我们需要基于伪造值计算
                    // 这比较麻烦 因为我们不知道 Name 有多长
                    // 但通常程序会先查长度再分配内存
                    // 此时我们无法修改 ResultLength 准确值 因为不知道 NameLength
                    // 只能寄希望于程序分配足够大的缓冲区（通常 MAX_PATH）
                    // 或者 我们可以忽略这次修正 等程序分配了内存再次调用时 会进入上面的 STATUS_SUCCESS 分支
                }
            }
        }
    }

    return status;
}

NTSTATUS NTAPI Detour_NtRenameKey(HANDLE KeyHandle, PUNICODE_STRING NewName) {
    if (g_IsInHook || !g_HookReg || !g_hAppHive || !NewName || !NewName->Buffer)
        return fpNtRenameKey(KeyHandle, NewName);
    RecursionGuard guard;

    // 只处理沙盒内的句柄 [修复] 使用 _wcsnicmp
    std::wstring currentPath = GetPathFromHandle(KeyHandle);
    if (currentPath.empty() || _wcsnicmp(currentPath.c_str(), g_RegMountPathNt.c_str(), g_RegMountPathNt.length()) != 0)
        return fpNtRenameKey(KeyHandle, NewName);

    // 构造目标沙盒路径
    size_t pos = currentPath.rfind(L'\\');
    if (pos == std::wstring::npos) return fpNtRenameKey(KeyHandle, NewName);

    std::wstring parentSandboxPath = currentPath.substr(0, pos);
    std::wstring newName(NewName->Buffer, NewName->Length / sizeof(WCHAR));
    std::wstring targetSandboxPath = parentSandboxPath + L"\\" + newName;

    // 检查目标路径是否有墓碑键 有则物理删除以让路
    HANDLE hTarget = NULL;
    OBJECT_ATTRIBUTES oaTarget;
    UNICODE_STRING usTarget;
    RtlInitUnicodeString(&usTarget, targetSandboxPath.c_str());
    InitializeObjectAttributes(&oaTarget, &usTarget, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // [修复] 使用 MAXIMUM_ALLOWED 打开 确保拥有 Rename 所需的权限 并修复 Use-After-Close 漏洞
    if (NT_SUCCESS(fpNtOpenKey(&hTarget, MAXIMUM_ALLOWED, &oaTarget))) {
        bool hasTomb = IsKeyMarkedDeleted(hTarget);

        if (hasTomb) {
            wchar_t tempName[64];
            swprintf_s(tempName, L"__YBTmp%u_%u__", GetTickCount(), GetCurrentThreadId());
            UNICODE_STRING usTempName;
            RtlInitUnicodeString(&usTempName, tempName);

            // 把墓碑键 rename 到临时名（目标名现在空出来了）
            NTSTATUS mvSt = fpNtRenameKey(hTarget, &usTempName);
            fpNtClose(hTarget); // [修复] 必须在 Rename 之后 Close

            if (!NT_SUCCESS(mvSt)) {
                DeleteSandboxKeyRecursive(targetSandboxPath);
                return fpNtRenameKey(KeyHandle, NewName); // 回退
            }

            // 正式 rename 源键到目标名
            NTSTATUS status = fpNtRenameKey(KeyHandle, NewName);

            // 清理临时键（递归删除）
            std::wstring tempPath = parentSandboxPath + L"\\" + tempName;
            DeleteSandboxKeyRecursive(tempPath);

            if (NT_SUCCESS(status)) InvalidateParentRegContext(currentPath);
            return status;
        }
        fpNtClose(hTarget);
    } else if (NT_SUCCESS(fpNtOpenKey(&hTarget, KEY_QUERY_VALUE, &oaTarget))) {
        // 降级回退：如果无法以高权限打开 则尝试直接物理删除
        bool hasTomb = IsKeyMarkedDeleted(hTarget);
        fpNtClose(hTarget);
        if (hasTomb) {
            DeleteSandboxKeyRecursive(targetSandboxPath);
        }
    }

    NTSTATUS status = fpNtRenameKey(KeyHandle, NewName);

    if (NT_SUCCESS(status)) {
        // 使父键枚举缓存失效
        InvalidateParentRegContext(currentPath);
    }

    return status;
}

NTSTATUS NTAPI Detour_NtCreateKey(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class,
    ULONG CreateOptions,
    PULONG Disposition)
{
    if (g_IsInHook || !g_hAppHive || g_CurrentUserSidPath.empty()) {
        return fpNtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
    }
    RecursionGuard guard;

    std::wstring fullNtPath = ResolveRegPathFromAttr(ObjectAttributes);

    // --- 1. 白名单检查 (保持不变) ---
    std::wstring realPathCandidate;
    bool isSandboxPath = false;
    if (!g_RegMountPathNt.empty() && _wcsnicmp(fullNtPath.c_str(), g_RegMountPathNt.c_str(), g_RegMountPathNt.length()) == 0) {
        isSandboxPath = true;
        GetRealFromSandboxPath(fullNtPath, realPathCandidate);
    } else {
        realPathCandidate = fullNtPath;
    }

    // ========== [新增] WOW64 路径重定向修正 ==========
    std::wstring fixedRealPath = FixRegPathWow64(realPathCandidate, DesiredAccess);
    if (fixedRealPath != realPathCandidate) {
        realPathCandidate = fixedRealPath;
        if (!isSandboxPath) {
            fullNtPath = fixedRealPath;
        } else {
            // 如果是沙盒路径 且真实路径因为 WOW64 发生了改变 (例如插入了 Wow6432Node)
            // 需要重新计算沙盒路径 fullNtPath
            std::wstring relPath;
            if (ShouldRedirectReg(realPathCandidate, relPath)) {
                fullNtPath = g_RegMountPathNt + L"\\" + relPath;
            }
        }
    }

    if (!realPathCandidate.empty() && IsSystemCriticalRegPath(realPathCandidate)) {
        UNICODE_STRING usReal;
        RtlInitUnicodeString(&usReal, realPathCandidate.c_str());
        OBJECT_ATTRIBUTES oaReal = *ObjectAttributes;
        oaReal.ObjectName = &usReal;
        oaReal.RootDirectory = NULL;

        NTSTATUS status = fpNtCreateKey(KeyHandle, DesiredAccess, &oaReal, TitleIndex, Class, CreateOptions, Disposition);
        if (status == STATUS_ACCESS_DENIED) {
            ACCESS_MASK readOnlyAccess = DesiredAccess & (KEY_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | READ_CONTROL);
            if (readOnlyAccess == 0) readOnlyAccess = KEY_READ;
            status = fpNtOpenKey(KeyHandle, readOnlyAccess, &oaReal);
            if (NT_SUCCESS(status) && Disposition) *Disposition = REG_OPENED_EXISTING_KEY;
        }
        return status;
    }

    // --- 2. 重定向逻辑 ---
    std::wstring relPath;
    if (ShouldRedirectReg(fullNtPath, relPath)) {
        EnsureRegPathExistsRelative(relPath);
        std::wstring targetSandboxFull = g_RegMountPathNt + L"\\" + relPath;

        UNICODE_STRING uStr;
        RtlInitUnicodeString(&uStr, relPath.c_str());
        OBJECT_ATTRIBUTES oaModified = *ObjectAttributes;
        oaModified.ObjectName = &uStr;
        oaModified.RootDirectory = (HANDLE)g_hAppHive;

        // 直接尝试创建/打开沙盒键
        NTSTATUS status = fpNtCreateKey(KeyHandle, DesiredAccess, &oaModified, TitleIndex, Class, CreateOptions, Disposition);

        // ========== [新增] 降权处理 (移植自 Sandboxie Key_NtCreateKeyImpl) ==========
        if (status == STATUS_ACCESS_DENIED && IsRestrictedToken()) {
            // 降低目标键及其父键的完整性级别
            SetLowLabelKeyByName(targetSandboxFull);
            size_t pos = targetSandboxFull.rfind(L'\\');
            if (pos != std::wstring::npos) {
                SetLowLabelKeyByName(targetSandboxFull.substr(0, pos));
            }
            // 重试
            status = fpNtCreateKey(KeyHandle, DesiredAccess, &oaModified, TitleIndex, Class, CreateOptions, Disposition);
        }

        if (NT_SUCCESS(status)) {
			// [新增] 预防式降权：如果当前是沙盒路径 且是新创建的键
			// 无论当前进程是什么权限 都尝试将新键设为 Low IL
			// 这样后续的 Low IL 进程（如 Chrome内核）也能访问它
			if (isSandboxPath && (Disposition && *Disposition == REG_CREATED_NEW_KEY)) {
				// 只有当当前进程有权修改 DACL/SACL 时 (Medium/High) 才能成功
				// 如果当前已经是 Low 它创建出来的本来就是 Low 这里失败也没关系
				SetLowLabelKeyByName(targetSandboxFull); // 或者使用句柄版本 SetLowLabelKeyByHandle(*KeyHandle)
			}

            // [核心修复] 打开一个拥有完全权限的临时句柄 用于执行维护操作
            // 避免因用户申请的 DesiredAccess 权限不足 (如缺少 KEY_QUERY_VALUE) 导致复活/清理失败
            HANDLE hMaintenance = NULL;
            OBJECT_ATTRIBUTES oaMaint;
            UNICODE_STRING usMaint;
            RtlInitUnicodeString(&usMaint, targetSandboxFull.c_str());
            InitializeObjectAttributes(&oaMaint, &usMaint, OBJ_CASE_INSENSITIVE, NULL, NULL);

            // 使用 KEY_ALL_ACCESS 确保我们可以查询、枚举、写入时间戳
            NTSTATUS maintStatus = fpNtOpenKey(&hMaintenance, KEY_ALL_ACCESS, &oaMaint);

            // 如果 KEY_ALL_ACCESS 失败 (极少见) 尝试最小必要权限
            if (!NT_SUCCESS(maintStatus)) {
                maintStatus = fpNtOpenKey(&hMaintenance, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_ENUMERATE_SUB_KEYS, &oaMaint);
            }

            if (NT_SUCCESS(maintStatus)) {
                bool isNewKey = false;
                bool isResurrected = false;

                // 检查是否是“已删除”的键 (墓碑)
                if (IsKeyMarkedDeleted(hMaintenance)) {
                    // === 复活 (Resurrection) ===
                    // 1. 重置时间戳为当前时间
                    SetKeyLastWriteTime(hMaintenance, false);

                    // 2. 清空该键下的所有值
                    ClearSandboxKeyValues(hMaintenance);

                    // 3. 标记为“新建”
                    if (Disposition) *Disposition = REG_CREATED_NEW_KEY;

                    isResurrected = true;
                    isNewKey = true;
                }
                else {
                    // 常规新建检查
                    if (Disposition && *Disposition == REG_CREATED_NEW_KEY) {
                        isNewKey = true;
                    }
                }

                // [核心] 惰性 CoW 初始化：屏蔽真实值
                if (isNewKey) {
                    HANDLE hRealCheck = NULL;
                    OBJECT_ATTRIBUTES oaRealCheck;
                    UNICODE_STRING usRealCheck;
                    RtlInitUnicodeString(&usRealCheck, fullNtPath.c_str());
                    InitializeObjectAttributes(&oaRealCheck, &usRealCheck, OBJ_CASE_INSENSITIVE, NULL, NULL);

                    // 打开真实键
                    if (NT_SUCCESS(fpNtOpenKey(&hRealCheck, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &oaRealCheck))) {
                        ULONG idx = 0, vlen = 0;
                        BYTE staticValBuf[4096]; // 使用栈内存
                        BYTE dummyByte = 0;

                        while (true) {
                            NTSTATUS st = fpNtEnumerateValueKey(hRealCheck, idx, KeyValueBasicInformation, staticValBuf, sizeof(staticValBuf), &vlen);

                            // 处理大值
                            std::vector<BYTE> dynamicValBuf;
                            PKEY_VALUE_BASIC_INFORMATION vinfo = (PKEY_VALUE_BASIC_INFORMATION)staticValBuf;

                            if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL) {
                                try { dynamicValBuf.resize(vlen); } catch(...) { break; }
                                st = fpNtEnumerateValueKey(hRealCheck, idx, KeyValueBasicInformation, dynamicValBuf.data(), vlen, &vlen);
                                if (!NT_SUCCESS(st)) break;
                                vinfo = (PKEY_VALUE_BASIC_INFORMATION)dynamicValBuf.data();
                            } else if (!NT_SUCCESS(st)) {
                                break;
                            }

                            UNICODE_STRING vName;
                            vName.Buffer = vinfo->Name;
                            vName.Length = (USHORT)vinfo->NameLength;
                            vName.MaximumLength = (USHORT)vinfo->NameLength;

                            // 写入值墓碑 (使用 hMaintenance 句柄)
                            fpNtSetValueKey(hMaintenance, &vName, 0, YAPBOX_VALUE_TOMBSTONE_TYPE, &dummyByte, 0);

                            idx++;
                        }
                        fpNtClose(hRealCheck);
                    }
                }

                // 关闭临时维护句柄
                fpNtClose(hMaintenance);
            }

            // 刷新父级缓存
            InvalidateParentRegContext(targetSandboxFull);

            // 更新当前键的 Context
            HANDLE hReal = NULL;
            OBJECT_ATTRIBUTES oaReal;
            UNICODE_STRING usReal;
            RtlInitUnicodeString(&usReal, fullNtPath.c_str());
            InitializeObjectAttributes(&oaReal, &usReal, OBJ_CASE_INSENSITIVE, NULL, NULL);
            fpNtOpenKey(&hReal, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &oaReal);

            std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
            auto it = g_RegContextMap.find(*KeyHandle);
            if (it != g_RegContextMap.end()) {
                if (it->second->hRealKey) fpNtClose(it->second->hRealKey);
                it->second->hRealKey = hReal;
                it->second->FullPath = targetSandboxFull;
                it->second->KeysInitialized = false;
                it->second->ValuesInitialized = false;
                it->second->SubKeys.clear();
                it->second->Values.clear();
            } else {
                RegContext* ctx = new RegContext();
                ctx->FullPath = targetSandboxFull;
                ctx->hRealKey = hReal;
                g_RegContextMap[*KeyHandle] = ctx;
            }
        }
        return status;
    }

    // --- 3. 非重定向路径 (直接创建) ---
    NTSTATUS status = fpNtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);

    if (NT_SUCCESS(status)) {
        if (isSandboxPath) {
             // [修复] 使用临时句柄进行维护 并补全值墓碑初始化
             HANDLE hMaint = NULL;
             OBJECT_ATTRIBUTES oaM;
             UNICODE_STRING usM;
             RtlInitUnicodeString(&usM, fullNtPath.c_str());
             InitializeObjectAttributes(&oaM, &usM, OBJ_CASE_INSENSITIVE, NULL, NULL);

             if (NT_SUCCESS(fpNtOpenKey(&hMaint, KEY_ALL_ACCESS, &oaM))) {
                 bool needValueTombstones = false;
                 if (IsKeyMarkedDeleted(hMaint)) {
                    // === 复活 (Resurrection) ===
                    SetKeyLastWriteTime(hMaint, false);
                    ClearSandboxKeyValues(hMaint);
                    if (Disposition) *Disposition = REG_CREATED_NEW_KEY;
                    InvalidateParentRegContext(fullNtPath);
                    needValueTombstones = true;
                 }
                 else if (Disposition && *Disposition == REG_CREATED_NEW_KEY) {
                    // 首次在沙盒创建、但真实路径已有同名键
                    needValueTombstones = true;
                 }
                 // [核心修复] 惰性 CoW 值墓碑初始化：屏蔽真实路径的值
                 if (needValueTombstones) {
                    std::wstring realPathForTombstone;
                    if (GetRealFromSandboxPath(fullNtPath, realPathForTombstone)) {
                        HANDLE hRealCheck = NULL;
                        OBJECT_ATTRIBUTES oaRealCheck;
                        UNICODE_STRING usRealCheck;
                        RtlInitUnicodeString(&usRealCheck, realPathForTombstone.c_str());
                        InitializeObjectAttributes(&oaRealCheck, &usRealCheck, OBJ_CASE_INSENSITIVE, NULL, NULL);
                        if (NT_SUCCESS(fpNtOpenKey(&hRealCheck, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &oaRealCheck))) {
                            ULONG idx = 0, vlen = 0;
                            BYTE staticValBuf[4096];
                            BYTE dummyByte = 0;
                            while (true) {
                                NTSTATUS st = fpNtEnumerateValueKey(hRealCheck, idx, KeyValueBasicInformation, staticValBuf, sizeof(staticValBuf), &vlen);
                                std::vector<BYTE> dynamicValBuf;
                                PKEY_VALUE_BASIC_INFORMATION vinfo = (PKEY_VALUE_BASIC_INFORMATION)staticValBuf;
                                if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL) {
                                    try { dynamicValBuf.resize(vlen); } catch(...) { break; }
                                    st = fpNtEnumerateValueKey(hRealCheck, idx, KeyValueBasicInformation, dynamicValBuf.data(), vlen, &vlen);
                                    if (!NT_SUCCESS(st)) break;
                                    vinfo = (PKEY_VALUE_BASIC_INFORMATION)dynamicValBuf.data();
                                } else if (!NT_SUCCESS(st)) {
                                    break;
                                }
                                UNICODE_STRING vName;
                                vName.Buffer = vinfo->Name;
                                vName.Length = (USHORT)vinfo->NameLength;
                                vName.MaximumLength = (USHORT)vinfo->NameLength;
                                // 写入值墓碑
                                fpNtSetValueKey(hMaint, &vName, 0, YAPBOX_VALUE_TOMBSTONE_TYPE, &dummyByte, 0);
                                idx++;
                            }
                            fpNtClose(hRealCheck);
                        }
                    }
                 }
                 fpNtClose(hMaint);
             }
        }

        std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
        auto it = g_RegContextMap.find(*KeyHandle);
        if (it == g_RegContextMap.end()) {
            RegContext* ctx = new RegContext();
            ctx->FullPath = fullNtPath;
            ctx->hRealKey = NULL;
            g_RegContextMap[*KeyHandle] = ctx;
        }
    }

    return status;
}

NTSTATUS NTAPI Detour_NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    if (g_IsInHook || !g_hAppHive || g_CurrentUserSidPath.empty()) return fpNtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
    RecursionGuard guard;

    // 1. 解析完整路径
    std::wstring fullNtPath = ResolveRegPathFromAttr(ObjectAttributes);

    // 2. 检查是否为沙盒路径并获取真实路径候选
    bool isSandboxPath = false;
    std::wstring realPathCandidate;

    // [修复] 使用 _wcsnicmp
    if (!g_RegMountPathNt.empty() && _wcsnicmp(fullNtPath.c_str(), g_RegMountPathNt.c_str(), g_RegMountPathNt.length()) == 0) {
        isSandboxPath = true;
        GetRealFromSandboxPath(fullNtPath, realPathCandidate);
    } else {
        realPathCandidate = fullNtPath;
    }

    // ========== [新增] WOW64 路径重定向修正 ==========
    std::wstring fixedRealPath = FixRegPathWow64(realPathCandidate, DesiredAccess);
    if (fixedRealPath != realPathCandidate) {
        realPathCandidate = fixedRealPath;
        if (!isSandboxPath) {
            fullNtPath = fixedRealPath;
        } else {
            // 如果是沙盒路径 且真实路径因为 WOW64 发生了改变 (例如插入了 Wow6432Node)
            // 需要重新计算沙盒路径 fullNtPath
            std::wstring relPath;
            if (ShouldRedirectReg(realPathCandidate, relPath)) {
                fullNtPath = g_RegMountPathNt + L"\\" + relPath;
            }
        }
    }

    // 3. [核心修复] 白名单检查 (DirectSound/Drivers 等)
    // 如果是系统关键路径 强制使用绝对路径打开真实键 丢弃可能指向沙盒的 RootDirectory
    if (!realPathCandidate.empty() && IsSystemCriticalRegPath(realPathCandidate)) {
        UNICODE_STRING usReal;
        RtlInitUnicodeString(&usReal, realPathCandidate.c_str());

        OBJECT_ATTRIBUTES oaReal = *ObjectAttributes;
        oaReal.ObjectName = &usReal;
        oaReal.RootDirectory = NULL; // 丢弃父句柄

        return fpNtOpenKey(KeyHandle, DesiredAccess, &oaReal);
    }

    // 4. 常规重定向逻辑
    OBJECT_ATTRIBUTES oaModified = *ObjectAttributes;
    UNICODE_STRING usRedirected;
    std::wstring relPath;
    bool isRedirectedRoot = false;

    // 如果不是沙盒路径 且符合重定向规则 (例如 HKLM\Software\MyGame)
    if (!isSandboxPath && ShouldRedirectReg(fullNtPath, relPath)) {
        RtlInitUnicodeString(&usRedirected, relPath.c_str());
        oaModified.ObjectName = &usRedirected;
        oaModified.RootDirectory = (HANDLE)g_hAppHive;
        isRedirectedRoot = true;
    }

    // 调用原始函数
    NTSTATUS status = fpNtOpenKey(KeyHandle, DesiredAccess, &oaModified);

    if (NT_SUCCESS(status)) {
        // 检查是否被标记为删除
        if (IsKeyMarkedDeleted(*KeyHandle)) {
            fpNtClose(*KeyHandle);
            *KeyHandle = NULL;
            return STATUS_OBJECT_NAME_NOT_FOUND; // 告诉程序找不到
        }
    }

    // 如果沙盒中未找到 且不是因为墓碑导致的 尝试读取真实注册表 (Copy-on-Read / Fallback)
    if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
        std::wstring realPathForCheck;
        bool canCheckReal = false;

        if (isRedirectedRoot) {
            realPathForCheck = fullNtPath;
            canCheckReal = true;
        } else if (GetRealFromSandboxPath(fullNtPath, realPathForCheck)) {
            canCheckReal = true;
        }

        if (canCheckReal) {
            HANDLE hRealCheck = NULL;
            OBJECT_ATTRIBUTES oaReal;
            UNICODE_STRING usReal;
            RtlInitUnicodeString(&usReal, realPathForCheck.c_str());
            InitializeObjectAttributes(&oaReal, &usReal, OBJ_CASE_INSENSITIVE, NULL, NULL);

            // [修复] 动态计算回退权限：剔除写权限 保留请求的读/枚举权限
            ACCESS_MASK fallbackAccess = DesiredAccess & ~(KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | DELETE | WRITE_DAC | WRITE_OWNER);
            if (fallbackAccess == 0) fallbackAccess = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS;

            if (NT_SUCCESS(fpNtOpenKey(&hRealCheck, fallbackAccess, &oaReal))) {
                if (IS_REG_WRITE_ACCESS(DesiredAccess)) {
                    // 写权限请求：执行 Copy-on-Write
                    std::wstring relPathToCreate;
                    if (isRedirectedRoot) {
                        relPathToCreate = relPath;
                    } else {
                        relPathToCreate = fullNtPath.substr(g_RegMountPathNt.length());
                        if (!relPathToCreate.empty() && relPathToCreate[0] == L'\\') relPathToCreate = relPathToCreate.substr(1);
                    }

                    EnsureRegPathExistsRelative(relPathToCreate);

                    HANDLE hNewKey = NULL;
                    UNICODE_STRING usCreate;
                    OBJECT_ATTRIBUTES oaCreate;
                    RtlInitUnicodeString(&usCreate, relPathToCreate.c_str());
                    InitializeObjectAttributes(&oaCreate, &usCreate, OBJ_CASE_INSENSITIVE, (HANDLE)g_hAppHive, NULL);

                    ULONG disposition;
                    if (NT_SUCCESS(fpNtCreateKey(&hNewKey, KEY_READ | KEY_WRITE, &oaCreate, 0, NULL, 0, &disposition))) {
                        fpNtClose(hNewKey);
                        status = fpNtOpenKey(KeyHandle, DesiredAccess, &oaModified);
                    }
                } else {
                    // 只读请求：直接返回真实句柄
                    *KeyHandle = hRealCheck;
                    status = STATUS_SUCCESS;

                    // 更新上下文映射
                    std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
                    auto it = g_RegContextMap.find(*KeyHandle);
                    if (it != g_RegContextMap.end()) {
                        if (it->second->hRealKey) fpNtClose(it->second->hRealKey);
                        it->second->hRealKey = NULL;
                        it->second->FullPath = realPathForCheck;
                        it->second->KeysInitialized = false;
                        it->second->ValuesInitialized = false;
                        it->second->SubKeys.clear();
                        it->second->Values.clear();
                    } else {
                        RegContext* ctx = new RegContext();
                        ctx->hRealKey = NULL;
                        ctx->FullPath = realPathForCheck;
                        g_RegContextMap[*KeyHandle] = ctx;
                    }
                    return status;
                }
                fpNtClose(hRealCheck);
            }
        }
    }

    // 6. 更新上下文缓存
    if (NT_SUCCESS(status)) {
        std::wstring realPathForCheck;
        bool canCheckReal = false;

        if (isRedirectedRoot) {
            realPathForCheck = fullNtPath;
            canCheckReal = true;
        } else if (GetRealFromSandboxPath(fullNtPath, realPathForCheck)) {
            canCheckReal = true;
        }

        HANDLE hRealTarget = NULL;
        if (canCheckReal) {
            OBJECT_ATTRIBUTES oaReal;
            UNICODE_STRING usReal;
            RtlInitUnicodeString(&usReal, realPathForCheck.c_str());
            InitializeObjectAttributes(&oaReal, &usReal, OBJ_CASE_INSENSITIVE, NULL, NULL);
            fpNtOpenKey(&hRealTarget, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &oaReal);
        }

        std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
        auto it = g_RegContextMap.find(*KeyHandle);
        if (it != g_RegContextMap.end()) {
            if (it->second->hRealKey) fpNtClose(it->second->hRealKey);
            it->second->hRealKey = hRealTarget;
            it->second->FullPath = isRedirectedRoot ? (g_RegMountPathNt + L"\\" + relPath) : fullNtPath;
            it->second->KeysInitialized = false;
            it->second->ValuesInitialized = false;
            it->second->SubKeys.clear();
            it->second->Values.clear();
        } else {
            RegContext* ctx = new RegContext();
            ctx->hRealKey = hRealTarget;
            ctx->FullPath = isRedirectedRoot ? (g_RegMountPathNt + L"\\" + relPath) : fullNtPath;
            g_RegContextMap[*KeyHandle] = ctx;
        }
    }

    return status;
}

NTSTATUS NTAPI Detour_NtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions) {
    if (g_IsInHook || !g_hAppHive || g_CurrentUserSidPath.empty()) return fpNtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
    RecursionGuard guard;

    // 1. 解析路径与白名单检查
    std::wstring fullNtPath = ResolveRegPathFromAttr(ObjectAttributes);
    std::wstring realPathCandidate;
    bool isSandboxPath = false;

    if (!g_RegMountPathNt.empty() && _wcsnicmp(fullNtPath.c_str(), g_RegMountPathNt.c_str(), g_RegMountPathNt.length()) == 0) {
        isSandboxPath = true;
        GetRealFromSandboxPath(fullNtPath, realPathCandidate);
    } else {
        realPathCandidate = fullNtPath;
    }

    // ========== [新增] WOW64 路径重定向修正 ==========
    std::wstring fixedRealPath = FixRegPathWow64(realPathCandidate, DesiredAccess);
    if (fixedRealPath != realPathCandidate) {
        realPathCandidate = fixedRealPath;
        if (!isSandboxPath) {
            fullNtPath = fixedRealPath;
        } else {
            // 如果是沙盒路径 且真实路径因为 WOW64 发生了改变 (例如插入了 Wow6432Node)
            // 需要重新计算沙盒路径 fullNtPath
            std::wstring relPath;
            if (ShouldRedirectReg(realPathCandidate, relPath)) {
                fullNtPath = g_RegMountPathNt + L"\\" + relPath;
            }
        }
    }

    // 白名单直通
    if (!realPathCandidate.empty() && IsSystemCriticalRegPath(realPathCandidate)) {
        UNICODE_STRING usReal;
        RtlInitUnicodeString(&usReal, realPathCandidate.c_str());
        OBJECT_ATTRIBUTES oaReal = *ObjectAttributes;
        oaReal.ObjectName = &usReal;
        oaReal.RootDirectory = NULL;
        return fpNtOpenKeyEx(KeyHandle, DesiredAccess, &oaReal, OpenOptions);
    }

    // 2. 重定向逻辑
    OBJECT_ATTRIBUTES oaModified = *ObjectAttributes;
    UNICODE_STRING usRedirected;
    std::wstring relPath;
    bool isRedirectedRoot = false;

    if (!isSandboxPath && ShouldRedirectReg(fullNtPath, relPath)) {
        RtlInitUnicodeString(&usRedirected, relPath.c_str());
        oaModified.ObjectName = &usRedirected;
        oaModified.RootDirectory = (HANDLE)g_hAppHive;
        isRedirectedRoot = true;
    }

    // 3. 尝试打开
    NTSTATUS status = fpNtOpenKeyEx(KeyHandle, DesiredAccess, &oaModified, OpenOptions);

    // 4. [新增] 检查魔数时间戳 (逻辑删除检查)
    bool isMarkedDeleted = false;
    if (NT_SUCCESS(status)) {
        // 检查是否是沙盒内的键
        std::wstring openedPath = GetPathFromHandle(*KeyHandle);
        if (!openedPath.empty() && _wcsnicmp(openedPath.c_str(), g_RegMountPathNt.c_str(), g_RegMountPathNt.length()) == 0) {
            if (IsKeyMarkedDeleted(*KeyHandle)) {
                isMarkedDeleted = true;
                fpNtClose(*KeyHandle);
                *KeyHandle = NULL;
                status = STATUS_OBJECT_NAME_NOT_FOUND; // 伪装成找不到
            }
        }
    }

    // 5. 回退逻辑 (Fallback) - 仅当未找到且未被标记删除时
    if (status == STATUS_OBJECT_NAME_NOT_FOUND && !isMarkedDeleted) {
        std::wstring realPathForCheck;
        bool canCheckReal = false;

        if (isRedirectedRoot) {
            realPathForCheck = fullNtPath;
            canCheckReal = true;
        } else if (GetRealFromSandboxPath(fullNtPath, realPathForCheck)) {
            canCheckReal = true;
        }

        if (canCheckReal) {
            HANDLE hRealCheck = NULL;
            OBJECT_ATTRIBUTES oaReal;
            UNICODE_STRING usReal;
            RtlInitUnicodeString(&usReal, realPathForCheck.c_str());
            InitializeObjectAttributes(&oaReal, &usReal, OBJ_CASE_INSENSITIVE, NULL, NULL);

            // 动态计算回退权限
            ACCESS_MASK fallbackAccess = DesiredAccess & ~(KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | DELETE | WRITE_DAC | WRITE_OWNER);
            if (fallbackAccess == 0) fallbackAccess = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS;

            if (NT_SUCCESS(fpNtOpenKeyEx(&hRealCheck, fallbackAccess, &oaReal, OpenOptions))) {
                if (IS_REG_WRITE_ACCESS(DesiredAccess)) {
                    // 写权限请求：执行 Copy-on-Write (惰性模式：只创建空键)
                    std::wstring relPathToCreate;
                    if (isRedirectedRoot) {
                        relPathToCreate = relPath;
                    } else {
                        relPathToCreate = fullNtPath.substr(g_RegMountPathNt.length());
                        if (!relPathToCreate.empty() && relPathToCreate[0] == L'\\') relPathToCreate = relPathToCreate.substr(1);
                    }

                    EnsureRegPathExistsRelative(relPathToCreate);

                    HANDLE hNewKey = NULL;
                    UNICODE_STRING usCreate;
                    OBJECT_ATTRIBUTES oaCreate;
                    RtlInitUnicodeString(&usCreate, relPathToCreate.c_str());
                    InitializeObjectAttributes(&oaCreate, &usCreate, OBJ_CASE_INSENSITIVE, (HANDLE)g_hAppHive, NULL);

                    ULONG disposition;
                    if (NT_SUCCESS(fpNtCreateKey(&hNewKey, KEY_READ | KEY_WRITE, &oaCreate, 0, NULL, 0, &disposition))) {
                        // 惰性 CoW: 这里不需要 CopyRegistryValues
                        fpNtClose(hNewKey);
                        status = fpNtOpenKeyEx(KeyHandle, DesiredAccess, &oaModified, OpenOptions);
                    }
                } else {
                    // 只读请求：返回真实句柄
                    *KeyHandle = hRealCheck;
                    status = STATUS_SUCCESS;

                    std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
                    auto it = g_RegContextMap.find(*KeyHandle);
                    if (it != g_RegContextMap.end()) {
                        if (it->second->hRealKey) fpNtClose(it->second->hRealKey);
                        it->second->hRealKey = NULL;
                        it->second->FullPath = realPathForCheck;
                        it->second->KeysInitialized = false;
                        it->second->ValuesInitialized = false;
                        it->second->SubKeys.clear();
                        it->second->Values.clear();
                    } else {
                        RegContext* ctx = new RegContext();
                        ctx->hRealKey = NULL;
                        ctx->FullPath = realPathForCheck;
                        g_RegContextMap[*KeyHandle] = ctx;
                    }
                    return status;
                }
                fpNtClose(hRealCheck);
            }
        }
    }

    if (NT_SUCCESS(status)) {
        std::wstring realPathForCheck;
        bool canCheckReal = false;

        if (isRedirectedRoot) {
            realPathForCheck = fullNtPath;
            canCheckReal = true;
        } else if (GetRealFromSandboxPath(fullNtPath, realPathForCheck)) {
            canCheckReal = true;
        }

        HANDLE hRealTarget = NULL;
        if (canCheckReal) {
            OBJECT_ATTRIBUTES oaReal;
            UNICODE_STRING usReal;
            RtlInitUnicodeString(&usReal, realPathForCheck.c_str());
            InitializeObjectAttributes(&oaReal, &usReal, OBJ_CASE_INSENSITIVE, NULL, NULL);
            fpNtOpenKeyEx(&hRealTarget, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &oaReal, OpenOptions);
        }

        std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
        auto it = g_RegContextMap.find(*KeyHandle);
        if (it != g_RegContextMap.end()) {
            if (it->second->hRealKey) fpNtClose(it->second->hRealKey);
            it->second->hRealKey = hRealTarget;
            it->second->FullPath = isRedirectedRoot ? (g_RegMountPathNt + L"\\" + relPath) : fullNtPath;
            it->second->KeysInitialized = false;
            it->second->ValuesInitialized = false;
            it->second->SubKeys.clear();
            it->second->Values.clear();
        } else {
            RegContext* ctx = new RegContext();
            ctx->hRealKey = hRealTarget;
            ctx->FullPath = isRedirectedRoot ? (g_RegMountPathNt + L"\\" + relPath) : fullNtPath;
            g_RegContextMap[*KeyHandle] = ctx;
        }
    }

    return status;
}

NTSTATUS NTAPI Detour_NtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
    if (g_IsInHook || !g_HookReg) return fpNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
    RecursionGuard guard;

    // 1. 获取当前句柄的真实 NT 路径 (这是唯一真理)
    std::wstring currentNtPath = GetPathFromHandle(KeyHandle);
    if (currentNtPath.empty()) {
        return fpNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
    }

    // 2. 解析出用于合并的 Real/Sandbox 路径
    std::wstring realPath, sandboxPath;
    // 注意：这里传入 currentNtPath 避免 GetRegPaths 内部再次调用 GetPathFromHandle
    // 我们需要稍微修改 GetRegPaths 或者在这里手动处理 为了性能 建议复用 currentNtPath
    // 这里为了代码改动最小化 我们假设 GetRegPaths 会再次获取路径 或者我们手动实现路径判断逻辑
    // 为了稳妥 我们先用 currentNtPath 进行缓存校验

    RegContext* ctx = nullptr;
    bool needsBuild = false;

    // 3. 检查缓存并校验身份
    {
        std::unique_lock<std::shared_mutex> lock(g_RegContextMutex); // 使用写锁 因为可能需要删除过期缓存
        auto it = g_RegContextMap.find(KeyHandle);

        if (it != g_RegContextMap.end()) {
            // [关键修复] 检查缓存的路径与当前句柄路径是否一致 (忽略大小写)
            if (_wcsicmp(it->second->FullPath.c_str(), currentNtPath.c_str()) != 0) {
                // 句柄被复用了！旧缓存是脏数据 必须清除
                delete it->second;
                g_RegContextMap.erase(it);
                needsBuild = true;
            } else {
                ctx = it->second;
                if (!ctx->KeysInitialized) needsBuild = true;
            }
        } else {
            needsBuild = true;
        }

        // 如果需要构建 先占位
        if (needsBuild && ctx == nullptr) {
            ctx = new RegContext();
            ctx->FullPath = currentNtPath; // [关键] 绑定当前路径
            g_RegContextMap[KeyHandle] = ctx;
        }
    }

    // 4. 构建合并列表 (无锁操作)
    if (needsBuild) {
        if (GetRegPaths(KeyHandle, realPath, sandboxPath)) {
            std::map<std::wstring, CachedRegKey> mergedKeys;

            // A. 枚举真实路径
            EnumerateKeysToMap(realPath, mergedKeys);

            // B. HKCR 特殊合并 (HKLM\Software\Classes + HKCU\Software\Classes)
            if (realPath.length() >= 34 && _wcsnicmp(realPath.c_str(), L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes", 34) == 0) {
                std::wstring subPath = realPath.substr(34);
                std::wstring userClassesPath = g_CurrentUserSidPath + L"\\Software\\Classes" + subPath;
                EnumerateKeysToMap(userClassesPath, mergedKeys);
            }

            // C. 枚举沙盒路径 (沙盒版本覆盖真实版本)
            EnumerateKeysToMap(sandboxPath, mergedKeys);

            // [修正] D. 过滤带魔数时间戳的子键
            // 注意：这里变量名必须是 mergedKeys (Map<wstring, CachedRegKey>)
            for (auto it = mergedKeys.begin(); it != mergedKeys.end(); ) {
                // 检查 CachedRegKey 中的 LastWriteTime
                if (IsDeleteMark(it->second.LastWriteTime)) {
                    it = mergedKeys.erase(it); // 从列表中移除
                } else {
                    ++it;
                }
            }

            // E. 更新上下文
            std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
            auto it = g_RegContextMap.find(KeyHandle);
            // [修复] 使用 _wcsicmp 忽略大小写比较 防止因大小写不同导致缓存不更新
            if (it != g_RegContextMap.end() && _wcsicmp(it->second->FullPath.c_str(), currentNtPath.c_str()) == 0) {
                ctx = it->second;
                ctx->SubKeys.clear();
                for (auto& pair : mergedKeys) ctx->SubKeys.push_back(pair.second);
                ctx->KeysInitialized = true;
            }
        } else {
            std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
            auto it = g_RegContextMap.find(KeyHandle);
            if (it != g_RegContextMap.end()) {
                delete it->second;
                g_RegContextMap.erase(it);
                return fpNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
            }
        }
    }

    // 5. 从缓存读取数据
    std::shared_lock<std::shared_mutex> lock(g_RegContextMutex);

    // 再次校验 ctx 有效性
    auto it = g_RegContextMap.find(KeyHandle);
    if (it == g_RegContextMap.end() || _wcsicmp(it->second->FullPath.c_str(), currentNtPath.c_str()) != 0) {
        // 极端并发情况：缓存被删除了
        return fpNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
    }
    ctx = it->second;

    if (Index >= ctx->SubKeys.size()) return STATUS_NO_MORE_ENTRIES;

    const CachedRegKey& entry = ctx->SubKeys[Index];

    ULONG nameBytes = (ULONG)(entry.Name.length() * sizeof(WCHAR));
    ULONG classBytes = (ULONG)(entry.Class.length() * sizeof(WCHAR));
    ULONG requiredSize = 0;

    switch (KeyInformationClass) {
        case KeyBasicInformation: requiredSize = FIELD_OFFSET(KEY_BASIC_INFORMATION, Name) + nameBytes; break;
        case KeyNodeInformation:  requiredSize = FIELD_OFFSET(KEY_NODE_INFORMATION, Name) + nameBytes + classBytes; break;
        case KeyFullInformation:  requiredSize = FIELD_OFFSET(KEY_FULL_INFORMATION, Class) + classBytes; break;
        case KeyNameInformation:  requiredSize = FIELD_OFFSET(KEY_NAME_INFORMATION, Name) + nameBytes; break;
        default: return fpNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
    }

    if (ResultLength) *ResultLength = requiredSize;
    if (Length < requiredSize) return STATUS_BUFFER_OVERFLOW;

    memset(KeyInformation, 0, Length);

    if (KeyInformationClass == KeyBasicInformation) {
        PKEY_BASIC_INFORMATION info = (PKEY_BASIC_INFORMATION)KeyInformation;
        info->LastWriteTime = entry.LastWriteTime;
        info->TitleIndex = entry.TitleIndex;
        info->NameLength = nameBytes;
        memcpy(info->Name, entry.Name.c_str(), nameBytes);
    }
    else if (KeyInformationClass == KeyNodeInformation) {
        PKEY_NODE_INFORMATION info = (PKEY_NODE_INFORMATION)KeyInformation;
        info->LastWriteTime = entry.LastWriteTime;
        info->TitleIndex = entry.TitleIndex;
        info->NameLength = nameBytes;
        info->ClassLength = classBytes;
        info->ClassOffset = FIELD_OFFSET(KEY_NODE_INFORMATION, Name) + nameBytes;
        memcpy(info->Name, entry.Name.c_str(), nameBytes);
        if (classBytes > 0) memcpy((BYTE*)info + info->ClassOffset, entry.Class.c_str(), classBytes);
    }
    else if (KeyInformationClass == KeyFullInformation) {
        PKEY_FULL_INFORMATION info = (PKEY_FULL_INFORMATION)KeyInformation;
        info->LastWriteTime = entry.LastWriteTime;
        info->TitleIndex = entry.TitleIndex;
        info->ClassLength = classBytes;
        info->ClassOffset = FIELD_OFFSET(KEY_FULL_INFORMATION, Class);
        info->SubKeys = (ULONG)ctx->SubKeys.size();
        info->Values = (ULONG)ctx->Values.size();
        if (classBytes > 0) memcpy(info->Class, entry.Class.c_str(), classBytes);
    }
    else if (KeyInformationClass == KeyNameInformation) {
        PKEY_NAME_INFORMATION info = (PKEY_NAME_INFORMATION)KeyInformation;
        info->NameLength = nameBytes;
        memcpy(info->Name, entry.Name.c_str(), nameBytes);
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI Detour_NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    if (g_IsInHook || !g_HookReg) return fpNtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
    RecursionGuard guard;

    // 1. 校验身份
    std::wstring currentNtPath = GetPathFromHandle(KeyHandle);
    if (currentNtPath.empty()) return fpNtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

    RegContext* ctx = nullptr;
    bool needsBuild = false;

    {
        std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
        auto it = g_RegContextMap.find(KeyHandle);
        if (it != g_RegContextMap.end()) {
            // [关键修复] 忽略大小写比较
            if (_wcsicmp(it->second->FullPath.c_str(), currentNtPath.c_str()) != 0) {
                delete it->second;
                g_RegContextMap.erase(it);
                needsBuild = true;
            } else {
                ctx = it->second;
                if (!ctx->ValuesInitialized) needsBuild = true;
            }
        } else {
            needsBuild = true;
        }

        if (needsBuild && ctx == nullptr) {
            ctx = new RegContext();
            ctx->FullPath = currentNtPath;
            g_RegContextMap[KeyHandle] = ctx;
        }
    }

    if (needsBuild) {
        std::wstring realPath, sandboxPath;
        if (GetRegPaths(KeyHandle, realPath, sandboxPath)) {
            std::map<std::wstring, CachedRegValue> mergedValues;
            EnumerateValuesToMap(realPath, mergedValues);
            EnumerateValuesToMap(sandboxPath, mergedValues);

            // [新增] 过滤惰性 CoW 的值墓碑
            for (auto it = mergedValues.begin(); it != mergedValues.end(); ) {
                if (it->second.Type == YAPBOX_VALUE_TOMBSTONE_TYPE) {
                    it = mergedValues.erase(it);
                } else {
                    ++it;
                }
            }

            std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
            auto it = g_RegContextMap.find(KeyHandle);
            // [修复] 使用 _wcsicmp 忽略大小写比较 防止因大小写不同导致缓存不更新
            if (it != g_RegContextMap.end() && _wcsicmp(it->second->FullPath.c_str(), currentNtPath.c_str()) == 0) {
                ctx = it->second;
                ctx->Values.clear();
                for (auto& pair : mergedValues) ctx->Values.push_back(pair.second);
                ctx->ValuesInitialized = true;
            }
        } else {
            std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
            auto it = g_RegContextMap.find(KeyHandle);
            if (it != g_RegContextMap.end()) {
                delete it->second;
                g_RegContextMap.erase(it);
            }
            return fpNtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
        }
    }

    std::shared_lock<std::shared_mutex> lock(g_RegContextMutex);
    auto it = g_RegContextMap.find(KeyHandle);
    if (it == g_RegContextMap.end() || _wcsicmp(it->second->FullPath.c_str(), currentNtPath.c_str()) != 0) {
        return fpNtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
    }
    ctx = it->second;

    if (Index >= ctx->Values.size()) return STATUS_NO_MORE_ENTRIES;

    const CachedRegValue& entry = ctx->Values[Index];
    ULONG nameBytes = (ULONG)(entry.Name.length() * sizeof(WCHAR));
    ULONG dataBytes = (ULONG)entry.Data.size();
    ULONG requiredSize = 0;

    // [关键修改] 计算对齐后的 DataOffset
    ULONG dataOffset = 0;

    switch (KeyValueInformationClass) {
        case KeyValueBasicInformation:
            requiredSize = FIELD_OFFSET(KEY_VALUE_BASIC_INFORMATION, Name) + nameBytes;
            break;
        case KeyValueFullInformation:
            // 计算 Name 结束后的偏移
            dataOffset = FIELD_OFFSET(KEY_VALUE_FULL_INFORMATION, Name) + nameBytes;
            // [修复] 强制 4 字节对齐 (DataOffset 必须是 4 的倍数)
            dataOffset = (dataOffset + 3) & ~3;
            // 总大小 = 对齐后的偏移 + 数据大小
            requiredSize = dataOffset + dataBytes;
            break;
        case KeyValuePartialInformation:
            requiredSize = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + dataBytes;
            break;
        default:
            return fpNtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
    }

    if (ResultLength) *ResultLength = requiredSize;
    if (Length < requiredSize) return STATUS_BUFFER_OVERFLOW;

    memset(KeyValueInformation, 0, Length);

    if (KeyValueInformationClass == KeyValueBasicInformation) {
        PKEY_VALUE_BASIC_INFORMATION info = (PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation;
        info->TitleIndex = entry.TitleIndex;
        info->Type = entry.Type;
        info->NameLength = nameBytes;
        memcpy(info->Name, entry.Name.c_str(), nameBytes);
    }
    else if (KeyValueInformationClass == KeyValueFullInformation) {
        PKEY_VALUE_FULL_INFORMATION info = (PKEY_VALUE_FULL_INFORMATION)KeyValueInformation;
        info->TitleIndex = entry.TitleIndex;
        info->Type = entry.Type;
        info->NameLength = nameBytes;
        info->DataLength = dataBytes;
        // 使用对齐后的偏移
        info->DataOffset = dataOffset;

        memcpy(info->Name, entry.Name.c_str(), nameBytes);

        if (dataBytes > 0) {
            // 确保写入位置在缓冲区范围内
            if (Length >= dataOffset + dataBytes) {
                memcpy((BYTE*)info + dataOffset, entry.Data.data(), dataBytes);
            }
        }
    }
    else if (KeyValueInformationClass == KeyValuePartialInformation) {
        PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)KeyValueInformation;
        info->TitleIndex = entry.TitleIndex;
        info->Type = entry.Type;
        info->DataLength = dataBytes;
        if (dataBytes > 0) memcpy(info->Data, entry.Data.data(), dataBytes);
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI Detour_NtDeleteKey(HANDLE KeyHandle) {
    if (g_IsInHook) return fpNtDeleteKey(KeyHandle);
    RecursionGuard guard;

    // 1. 获取路径判断是否在沙盒内
    std::wstring path = GetPathFromHandle(KeyHandle);
    bool isSandboxKey = false;
    if (!g_RegMountPathNt.empty() && _wcsnicmp(path.c_str(), g_RegMountPathNt.c_str(), g_RegMountPathNt.length()) == 0) {
        isSandboxKey = true;
    }

    // 2. 如果是沙盒内的键 执行“逻辑删除”
    if (isSandboxKey) {
        // 检查是否有子键 (如果有子键 标准行为是返回 STATUS_CANNOT_DELETE)
        // 这里为了简化 假设调用者已经递归删除了子键 或者我们只标记当前键
        // Sandboxie 的逻辑是：如果还有物理子键 不能标记父键删除
        // 但为了修复你的问题 我们先实现最简单的标记逻辑

        // 尝试设置时间戳标记为删除
        NTSTATUS status = SetKeyLastWriteTime(KeyHandle, true);

        if (status == STATUS_ACCESS_DENIED) {
            // 如果句柄没有 KEY_SET_VALUE 权限 尝试重新打开
            HANDLE hWrite = NULL;
            OBJECT_ATTRIBUTES oa;
            UNICODE_STRING emptyStr;
            RtlInitUnicodeString(&emptyStr, L"");
            InitializeObjectAttributes(&oa, &emptyStr, OBJ_CASE_INSENSITIVE, KeyHandle, NULL);

            if (NT_SUCCESS(fpNtOpenKey(&hWrite, KEY_SET_VALUE, &oa))) {
                status = SetKeyLastWriteTime(hWrite, true);
                fpNtClose(hWrite);
            }
        }

        // 成功标记后 清除缓存并返回成功
        if (NT_SUCCESS(status)) {
            // [新增] 清除该键的非墓碑值 (保留值墓碑以屏蔽真实注册表)
            CleanNonTombstoneValues(KeyHandle);
            // [新增] 递归清除子键中的非墓碑值
            CleanNonTombstoneValuesRecursive(path);
            InvalidateParentRegContext(path);
            return STATUS_SUCCESS;
        }
    }

    // 3. 如果是真实注册表路径（通过重定向逻辑） 需要在沙盒创建墓碑
    // (这部分逻辑保持你原有的结构 但创建出来的键要立即打上时间戳标记)
    if (g_HookReg && g_hAppHive && !isSandboxKey) {
        std::wstring relPath;
        if (ShouldRedirectReg(path, relPath)) {
            EnsureRegPathExistsRelative(relPath);

            HANDLE hSandbox = NULL;
            UNICODE_STRING usRel;
            OBJECT_ATTRIBUTES oaSandbox;
            RtlInitUnicodeString(&usRel, relPath.c_str());
            InitializeObjectAttributes(&oaSandbox, &usRel, OBJ_CASE_INSENSITIVE, (HANDLE)g_hAppHive, NULL);

            ULONG disposition;
            // 创建或打开沙盒键
            if (NT_SUCCESS(fpNtCreateKey(&hSandbox, KEY_ALL_ACCESS, &oaSandbox, 0, NULL, 0, &disposition))) {
                // [新增] 清除已有非墓碑值 (如果沙盒键已存在)
                CleanNonTombstoneValues(hSandbox);
                // 标记为删除
                SetKeyLastWriteTime(hSandbox, true);
                fpNtClose(hSandbox);

                std::wstring sandboxPath = g_RegMountPathNt + L"\\" + relPath;
                // [新增] 递归清除子键中的非墓碑值
                CleanNonTombstoneValuesRecursive(sandboxPath);
                InvalidateParentRegContext(sandboxPath);
                return STATUS_SUCCESS;
            }
        }
    }

    return fpNtDeleteKey(KeyHandle);
}

// --- [新增] 惰性 CoW 核心：拦截写入 ---
NTSTATUS NTAPI Detour_NtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize) {
    if (g_IsInHook || !g_HookReg) return fpNtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
    RecursionGuard guard;

    NTSTATUS status = fpNtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);

    // 如果返回拒绝访问 可能是程序拿着只读的真实句柄尝试写入
    // 我们需要提权重新打开该键（这会触发 Detour_NtOpenKey 重定向到沙盒影子键）
    if (status == STATUS_ACCESS_DENIED) {
        OBJECT_ATTRIBUTES oa;
        UNICODE_STRING emptyStr;
        RtlInitUnicodeString(&emptyStr, L"");
        InitializeObjectAttributes(&oa, &emptyStr, OBJ_CASE_INSENSITIVE, KeyHandle, NULL);

        HANDLE hTemp = NULL;
        if (NT_SUCCESS(Detour_NtOpenKey(&hTemp, KEY_WRITE, &oa))) {
            status = fpNtSetValueKey(hTemp, ValueName, TitleIndex, Type, Data, DataSize);
            fpNtClose(hTemp);
        }
    }

    // 写入成功后 使该键的枚举缓存失效
    if (NT_SUCCESS(status)) {
        std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
        auto it = g_RegContextMap.find(KeyHandle);
        if (it != g_RegContextMap.end()) {
            it->second->ValuesInitialized = false;
            it->second->Values.clear();
        }
    }
    return status;
}

// --- [新增] 惰性 CoW 核心：拦截删除 ---
NTSTATUS NTAPI Detour_NtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName) {
    if (g_IsInHook || !g_HookReg) return fpNtDeleteValueKey(KeyHandle, ValueName);
    RecursionGuard guard;

    NTSTATUS status = fpNtDeleteValueKey(KeyHandle, ValueName);

    HANDLE hWrite = KeyHandle;
    HANDLE hTemp = NULL;

    // 尝试提权打开
    if (status == STATUS_ACCESS_DENIED) {
        OBJECT_ATTRIBUTES oa;
        UNICODE_STRING emptyStr;
        RtlInitUnicodeString(&emptyStr, L"");
        InitializeObjectAttributes(&oa, &emptyStr, OBJ_CASE_INSENSITIVE, KeyHandle, NULL);
        if (NT_SUCCESS(Detour_NtOpenKey(&hTemp, KEY_WRITE, &oa))) {
            hWrite = hTemp;
            status = STATUS_SUCCESS; // 提权成功
        }
    }

    // 检查当前操作的句柄是否在沙盒内
    bool isSandboxHandle = false;
    std::wstring path = GetPathFromHandle(hWrite);
    if (!g_RegMountPathNt.empty() && _wcsnicmp(path.c_str(), g_RegMountPathNt.c_str(), g_RegMountPathNt.length()) == 0) {
        isSandboxHandle = true;
    }

    if (isSandboxHandle) {
        // 沙盒内：写入墓碑屏蔽真实注册表
        fpNtSetValueKey(hWrite, ValueName, 0, YAPBOX_VALUE_TOMBSTONE_TYPE, NULL, 0);
        status = STATUS_SUCCESS;
    } else if (hTemp) {
        // 真实注册表（白名单）：提权后执行真正的删除
        status = fpNtDeleteValueKey(hTemp, ValueName);
    }

    if (hTemp) fpNtClose(hTemp);

    // 更新缓存
    if (NT_SUCCESS(status)) {
        std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
        auto it = g_RegContextMap.find(KeyHandle);
        if (it != g_RegContextMap.end()) {
            it->second->ValuesInitialized = false;
            it->second->Values.clear();
        }
    }
    return status;
}

NTSTATUS NTAPI Detour_NtCreateKeyTransacted(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class,
    ULONG CreateOptions,
    HANDLE TransactionHandle,
    PULONG Disposition)
{
    if (g_IsInHook || !g_hAppHive || g_CurrentUserSidPath.empty()) {
        return fpNtCreateKeyTransacted(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, TransactionHandle, Disposition);
    }
    RecursionGuard guard;

    std::wstring fullNtPath = ResolveRegPathFromAttr(ObjectAttributes);

    // --- 1. 白名单检查 ---
    std::wstring realPathCandidate;
    bool isSandboxPath = false;
    if (!g_RegMountPathNt.empty() && _wcsnicmp(fullNtPath.c_str(), g_RegMountPathNt.c_str(), g_RegMountPathNt.length()) == 0) {
        isSandboxPath = true;
        GetRealFromSandboxPath(fullNtPath, realPathCandidate);
    } else {
        realPathCandidate = fullNtPath;
    }

    // ========== [新增] WOW64 路径重定向修正 ==========
    std::wstring fixedRealPath = FixRegPathWow64(realPathCandidate, DesiredAccess);
    if (fixedRealPath != realPathCandidate) {
        realPathCandidate = fixedRealPath;
        if (!isSandboxPath) {
            fullNtPath = fixedRealPath;
        } else {
            // 如果是沙盒路径 且真实路径因为 WOW64 发生了改变 (例如插入了 Wow6432Node)
            // 需要重新计算沙盒路径 fullNtPath
            std::wstring relPath;
            if (ShouldRedirectReg(realPathCandidate, relPath)) {
                fullNtPath = g_RegMountPathNt + L"\\" + relPath;
            }
        }
    }

    if (!realPathCandidate.empty() && IsSystemCriticalRegPath(realPathCandidate)) {
        UNICODE_STRING usReal;
        RtlInitUnicodeString(&usReal, realPathCandidate.c_str());
        OBJECT_ATTRIBUTES oaReal = *ObjectAttributes;
        oaReal.ObjectName = &usReal;
        oaReal.RootDirectory = NULL;

        NTSTATUS status = fpNtCreateKeyTransacted(KeyHandle, DesiredAccess, &oaReal, TitleIndex, Class, CreateOptions, TransactionHandle, Disposition);
        if (status == STATUS_ACCESS_DENIED) {
            ACCESS_MASK readOnlyAccess = DesiredAccess & (KEY_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | READ_CONTROL);
            if (readOnlyAccess == 0) readOnlyAccess = KEY_READ;
            status = fpNtOpenKeyTransacted(KeyHandle, readOnlyAccess, &oaReal, TransactionHandle);
            if (NT_SUCCESS(status) && Disposition) *Disposition = REG_OPENED_EXISTING_KEY;
        }
        return status;
    }

    // --- 2. 重定向逻辑 ---
    std::wstring relPath;
    if (ShouldRedirectReg(fullNtPath, relPath)) {
        EnsureRegPathExistsRelative(relPath);
        std::wstring targetSandboxFull = g_RegMountPathNt + L"\\" + relPath;

        UNICODE_STRING uStr;
        RtlInitUnicodeString(&uStr, relPath.c_str());
        OBJECT_ATTRIBUTES oaModified = *ObjectAttributes;
        oaModified.ObjectName = &uStr;
        oaModified.RootDirectory = (HANDLE)g_hAppHive;

        // 尝试创建/打开沙盒键 (带事务)
        NTSTATUS status = fpNtCreateKeyTransacted(KeyHandle, DesiredAccess, &oaModified, TitleIndex, Class, CreateOptions, TransactionHandle, Disposition);

        // ========== [新增] 降权处理 (移植自 Sandboxie Key_NtCreateKeyImpl) ==========
        if (status == STATUS_ACCESS_DENIED && IsRestrictedToken()) {
            // 降低目标键及其父键的完整性级别
            SetLowLabelKeyByName(targetSandboxFull);
            size_t pos = targetSandboxFull.rfind(L'\\');
            if (pos != std::wstring::npos) {
                SetLowLabelKeyByName(targetSandboxFull.substr(0, pos));
            }
            // 重试 (注意：必须包含 TransactionHandle 参数)
            status = fpNtCreateKeyTransacted(KeyHandle, DesiredAccess, &oaModified, TitleIndex, Class, CreateOptions, TransactionHandle, Disposition);
        }

        if (NT_SUCCESS(status)) {
			// [新增] 预防式降权：如果当前是沙盒路径 且是新创建的键
			// 无论当前进程是什么权限 都尝试将新键设为 Low IL
			// 这样后续的 Low IL 进程（如 Chrome内核）也能访问它
			if (isSandboxPath && (Disposition && *Disposition == REG_CREATED_NEW_KEY)) {
				// 只有当当前进程有权修改 DACL/SACL 时 (Medium/High) 才能成功
				// 如果当前已经是 Low 它创建出来的本来就是 Low 这里失败也没关系
				SetLowLabelKeyByName(targetSandboxFull); // 或者使用句柄版本 SetLowLabelKeyByHandle(*KeyHandle)
			}

            // [维护操作] 使用非事务句柄进行墓碑复活和初始化
            HANDLE hMaintenance = NULL;
            OBJECT_ATTRIBUTES oaMaint;
            UNICODE_STRING usMaint;
            RtlInitUnicodeString(&usMaint, targetSandboxFull.c_str());
            InitializeObjectAttributes(&oaMaint, &usMaint, OBJ_CASE_INSENSITIVE, NULL, NULL);

            NTSTATUS maintStatus = fpNtOpenKey(&hMaintenance, KEY_ALL_ACCESS, &oaMaint);
            if (!NT_SUCCESS(maintStatus)) {
                maintStatus = fpNtOpenKey(&hMaintenance, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_ENUMERATE_SUB_KEYS, &oaMaint);
            }

            if (NT_SUCCESS(maintStatus)) {
                bool isNewKey = false;

                if (IsKeyMarkedDeleted(hMaintenance)) {
                    // === 复活 (Resurrection) ===
                    SetKeyLastWriteTime(hMaintenance, false);
                    ClearSandboxKeyValues(hMaintenance);
                    if (Disposition) *Disposition = REG_CREATED_NEW_KEY;
                    isNewKey = true;
                }
                else {
                    if (Disposition && *Disposition == REG_CREATED_NEW_KEY) {
                        isNewKey = true;
                    }
                }

                // 惰性 CoW 初始化：屏蔽真实值
                if (isNewKey) {
                    HANDLE hRealCheck = NULL;
                    OBJECT_ATTRIBUTES oaRealCheck;
                    UNICODE_STRING usRealCheck;
                    RtlInitUnicodeString(&usRealCheck, fullNtPath.c_str());
                    InitializeObjectAttributes(&oaRealCheck, &usRealCheck, OBJ_CASE_INSENSITIVE, NULL, NULL);

                    // 打开真实键 (非事务 只读检查)
                    if (NT_SUCCESS(fpNtOpenKey(&hRealCheck, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &oaRealCheck))) {
                        ULONG idx = 0, vlen = 0;
                        BYTE staticValBuf[4096];
                        BYTE dummyByte = 0;

                        while (true) {
                            NTSTATUS st = fpNtEnumerateValueKey(hRealCheck, idx, KeyValueBasicInformation, staticValBuf, sizeof(staticValBuf), &vlen);
                            std::vector<BYTE> dynamicValBuf;
                            PKEY_VALUE_BASIC_INFORMATION vinfo = (PKEY_VALUE_BASIC_INFORMATION)staticValBuf;

                            if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL) {
                                try { dynamicValBuf.resize(vlen); } catch(...) { break; }
                                st = fpNtEnumerateValueKey(hRealCheck, idx, KeyValueBasicInformation, dynamicValBuf.data(), vlen, &vlen);
                                if (!NT_SUCCESS(st)) break;
                                vinfo = (PKEY_VALUE_BASIC_INFORMATION)dynamicValBuf.data();
                            } else if (!NT_SUCCESS(st)) {
                                break;
                            }

                            UNICODE_STRING vName;
                            vName.Buffer = vinfo->Name;
                            vName.Length = (USHORT)vinfo->NameLength;
                            vName.MaximumLength = (USHORT)vinfo->NameLength;

                            fpNtSetValueKey(hMaintenance, &vName, 0, YAPBOX_VALUE_TOMBSTONE_TYPE, &dummyByte, 0);
                            idx++;
                        }
                        fpNtClose(hRealCheck);
                    }
                }
                fpNtClose(hMaintenance);
            }

            InvalidateParentRegContext(targetSandboxFull);

            // 更新 Context
            HANDLE hReal = NULL;
            OBJECT_ATTRIBUTES oaReal;
            UNICODE_STRING usReal;
            RtlInitUnicodeString(&usReal, fullNtPath.c_str());
            InitializeObjectAttributes(&oaReal, &usReal, OBJ_CASE_INSENSITIVE, NULL, NULL);
            fpNtOpenKey(&hReal, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &oaReal);

            std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
            auto it = g_RegContextMap.find(*KeyHandle);
            if (it != g_RegContextMap.end()) {
                if (it->second->hRealKey) fpNtClose(it->second->hRealKey);
                it->second->hRealKey = hReal;
                it->second->FullPath = targetSandboxFull;
                it->second->KeysInitialized = false;
                it->second->ValuesInitialized = false;
                it->second->SubKeys.clear();
                it->second->Values.clear();
            } else {
                RegContext* ctx = new RegContext();
                ctx->FullPath = targetSandboxFull;
                ctx->hRealKey = hReal;
                g_RegContextMap[*KeyHandle] = ctx;
            }
        }
        return status;
    }

    // --- 3. 非重定向路径 ---
    NTSTATUS status = fpNtCreateKeyTransacted(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, TransactionHandle, Disposition);

    if (NT_SUCCESS(status)) {
        if (isSandboxPath) {
             HANDLE hMaint = NULL;
             OBJECT_ATTRIBUTES oaM;
             UNICODE_STRING usM;
             RtlInitUnicodeString(&usM, fullNtPath.c_str());
             InitializeObjectAttributes(&oaM, &usM, OBJ_CASE_INSENSITIVE, NULL, NULL);

             if (NT_SUCCESS(fpNtOpenKey(&hMaint, KEY_ALL_ACCESS, &oaM))) {
                 bool needValueTombstones = false;
                 if (IsKeyMarkedDeleted(hMaint)) {
                    SetKeyLastWriteTime(hMaint, false);
                    ClearSandboxKeyValues(hMaint);
                    if (Disposition) *Disposition = REG_CREATED_NEW_KEY;
                    InvalidateParentRegContext(fullNtPath);
                    needValueTombstones = true;
                 }
                 else if (Disposition && *Disposition == REG_CREATED_NEW_KEY) {
                    needValueTombstones = true;
                 }

                 if (needValueTombstones) {
                    std::wstring realPathForTombstone;
                    if (GetRealFromSandboxPath(fullNtPath, realPathForTombstone)) {
                        HANDLE hRealCheck = NULL;
                        OBJECT_ATTRIBUTES oaRealCheck;
                        UNICODE_STRING usRealCheck;
                        RtlInitUnicodeString(&usRealCheck, realPathForTombstone.c_str());
                        InitializeObjectAttributes(&oaRealCheck, &usRealCheck, OBJ_CASE_INSENSITIVE, NULL, NULL);
                        if (NT_SUCCESS(fpNtOpenKey(&hRealCheck, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &oaRealCheck))) {
                            ULONG idx = 0, vlen = 0;
                            BYTE staticValBuf[4096];
                            BYTE dummyByte = 0;
                            while (true) {
                                NTSTATUS st = fpNtEnumerateValueKey(hRealCheck, idx, KeyValueBasicInformation, staticValBuf, sizeof(staticValBuf), &vlen);
                                std::vector<BYTE> dynamicValBuf;
                                PKEY_VALUE_BASIC_INFORMATION vinfo = (PKEY_VALUE_BASIC_INFORMATION)staticValBuf;
                                if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL) {
                                    try { dynamicValBuf.resize(vlen); } catch(...) { break; }
                                    st = fpNtEnumerateValueKey(hRealCheck, idx, KeyValueBasicInformation, dynamicValBuf.data(), vlen, &vlen);
                                    if (!NT_SUCCESS(st)) break;
                                    vinfo = (PKEY_VALUE_BASIC_INFORMATION)dynamicValBuf.data();
                                } else if (!NT_SUCCESS(st)) {
                                    break;
                                }
                                UNICODE_STRING vName;
                                vName.Buffer = vinfo->Name;
                                vName.Length = (USHORT)vinfo->NameLength;
                                vName.MaximumLength = (USHORT)vinfo->NameLength;
                                fpNtSetValueKey(hMaint, &vName, 0, YAPBOX_VALUE_TOMBSTONE_TYPE, &dummyByte, 0);
                                idx++;
                            }
                            fpNtClose(hRealCheck);
                        }
                    }
                 }
                 fpNtClose(hMaint);
             }
        }

        std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
        auto it = g_RegContextMap.find(*KeyHandle);
        if (it == g_RegContextMap.end()) {
            RegContext* ctx = new RegContext();
            ctx->FullPath = fullNtPath;
            ctx->hRealKey = NULL;
            g_RegContextMap[*KeyHandle] = ctx;
        }
    }

    return status;
}

NTSTATUS NTAPI Detour_NtOpenKeyTransacted(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE TransactionHandle) {
    if (g_IsInHook || !g_hAppHive || g_CurrentUserSidPath.empty()) return fpNtOpenKeyTransacted(KeyHandle, DesiredAccess, ObjectAttributes, TransactionHandle);
    RecursionGuard guard;

    std::wstring fullNtPath = ResolveRegPathFromAttr(ObjectAttributes);
    std::wstring realPathCandidate;
    bool isSandboxPath = false;

    if (!g_RegMountPathNt.empty() && _wcsnicmp(fullNtPath.c_str(), g_RegMountPathNt.c_str(), g_RegMountPathNt.length()) == 0) {
        isSandboxPath = true;
        GetRealFromSandboxPath(fullNtPath, realPathCandidate);
    } else {
        realPathCandidate = fullNtPath;
    }

    // ========== [新增] WOW64 路径重定向修正 ==========
    std::wstring fixedRealPath = FixRegPathWow64(realPathCandidate, DesiredAccess);
    if (fixedRealPath != realPathCandidate) {
        realPathCandidate = fixedRealPath;
        if (!isSandboxPath) {
            fullNtPath = fixedRealPath;
        } else {
            // 如果是沙盒路径 且真实路径因为 WOW64 发生了改变 (例如插入了 Wow6432Node)
            // 需要重新计算沙盒路径 fullNtPath
            std::wstring relPath;
            if (ShouldRedirectReg(realPathCandidate, relPath)) {
                fullNtPath = g_RegMountPathNt + L"\\" + relPath;
            }
        }
    }

    // 白名单直通
    if (!realPathCandidate.empty() && IsSystemCriticalRegPath(realPathCandidate)) {
        UNICODE_STRING usReal;
        RtlInitUnicodeString(&usReal, realPathCandidate.c_str());
        OBJECT_ATTRIBUTES oaReal = *ObjectAttributes;
        oaReal.ObjectName = &usReal;
        oaReal.RootDirectory = NULL;
        return fpNtOpenKeyTransacted(KeyHandle, DesiredAccess, &oaReal, TransactionHandle);
    }

    // 重定向逻辑
    OBJECT_ATTRIBUTES oaModified = *ObjectAttributes;
    UNICODE_STRING usRedirected;
    std::wstring relPath;
    bool isRedirectedRoot = false;

    if (!isSandboxPath && ShouldRedirectReg(fullNtPath, relPath)) {
        RtlInitUnicodeString(&usRedirected, relPath.c_str());
        oaModified.ObjectName = &usRedirected;
        oaModified.RootDirectory = (HANDLE)g_hAppHive;
        isRedirectedRoot = true;
    }

    // 尝试打开 (带事务)
    NTSTATUS status = fpNtOpenKeyTransacted(KeyHandle, DesiredAccess, &oaModified, TransactionHandle);

    if (NT_SUCCESS(status)) {
        std::wstring openedPath = GetPathFromHandle(*KeyHandle);
        if (!openedPath.empty() && _wcsnicmp(openedPath.c_str(), g_RegMountPathNt.c_str(), g_RegMountPathNt.length()) == 0) {
            if (IsKeyMarkedDeleted(*KeyHandle)) {
                fpNtClose(*KeyHandle);
                *KeyHandle = NULL;
                status = STATUS_OBJECT_NAME_NOT_FOUND;
            }
        }
    }

    // 回退逻辑 (Fallback)
    if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
        std::wstring realPathForCheck;
        bool canCheckReal = false;

        if (isRedirectedRoot) {
            realPathForCheck = fullNtPath;
            canCheckReal = true;
        } else if (GetRealFromSandboxPath(fullNtPath, realPathForCheck)) {
            canCheckReal = true;
        }

        if (canCheckReal) {
            HANDLE hRealCheck = NULL;
            OBJECT_ATTRIBUTES oaReal;
            UNICODE_STRING usReal;
            RtlInitUnicodeString(&usReal, realPathForCheck.c_str());
            InitializeObjectAttributes(&oaReal, &usReal, OBJ_CASE_INSENSITIVE, NULL, NULL);

            ACCESS_MASK fallbackAccess = DesiredAccess & ~(KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | DELETE | WRITE_DAC | WRITE_OWNER);
            if (fallbackAccess == 0) fallbackAccess = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS;

            // 检查真实键 (非事务 只读)
            if (NT_SUCCESS(fpNtOpenKey(&hRealCheck, fallbackAccess, &oaReal))) {
                if (IS_REG_WRITE_ACCESS(DesiredAccess)) {
                    // 写权限请求：执行 Copy-on-Write
                    std::wstring relPathToCreate;
                    if (isRedirectedRoot) {
                        relPathToCreate = relPath;
                    } else {
                        relPathToCreate = fullNtPath.substr(g_RegMountPathNt.length());
                        if (!relPathToCreate.empty() && relPathToCreate[0] == L'\\') relPathToCreate = relPathToCreate.substr(1);
                    }

                    EnsureRegPathExistsRelative(relPathToCreate);

                    HANDLE hNewKey = NULL;
                    UNICODE_STRING usCreate;
                    OBJECT_ATTRIBUTES oaCreate;
                    RtlInitUnicodeString(&usCreate, relPathToCreate.c_str());
                    InitializeObjectAttributes(&oaCreate, &usCreate, OBJ_CASE_INSENSITIVE, (HANDLE)g_hAppHive, NULL);

                    ULONG disposition;
                    // 创建影子键 (带事务)
                    if (NT_SUCCESS(fpNtCreateKeyTransacted(&hNewKey, KEY_READ | KEY_WRITE, &oaCreate, 0, NULL, 0, TransactionHandle, &disposition))) {
                        fpNtClose(hNewKey);
                        status = fpNtOpenKeyTransacted(KeyHandle, DesiredAccess, &oaModified, TransactionHandle);
                    }
                } else {
                    // 只读请求：返回真实句柄 (非事务)
                    *KeyHandle = hRealCheck;
                    status = STATUS_SUCCESS;

                    std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
                    auto it = g_RegContextMap.find(*KeyHandle);
                    if (it != g_RegContextMap.end()) {
                        if (it->second->hRealKey) fpNtClose(it->second->hRealKey);
                        it->second->hRealKey = NULL;
                        it->second->FullPath = realPathForCheck;
                        it->second->KeysInitialized = false;
                        it->second->ValuesInitialized = false;
                        it->second->SubKeys.clear();
                        it->second->Values.clear();
                    } else {
                        RegContext* ctx = new RegContext();
                        ctx->hRealKey = NULL;
                        ctx->FullPath = realPathForCheck;
                        ctx->KeysInitialized = false;
                        ctx->ValuesInitialized = false;
                        g_RegContextMap[*KeyHandle] = ctx;
                    }
                    return status;
                }
                fpNtClose(hRealCheck);
            }
        }
    }

    // 更新上下文缓存
    if (NT_SUCCESS(status)) {
        std::wstring realPathForCheck;
        bool canCheckReal = false;
        if (isRedirectedRoot) {
            realPathForCheck = fullNtPath;
            canCheckReal = true;
        } else if (GetRealFromSandboxPath(fullNtPath, realPathForCheck)) {
            canCheckReal = true;
        }

        HANDLE hRealTarget = NULL;
        if (canCheckReal) {
            OBJECT_ATTRIBUTES oaReal;
            UNICODE_STRING usReal;
            RtlInitUnicodeString(&usReal, realPathForCheck.c_str());
            InitializeObjectAttributes(&oaReal, &usReal, OBJ_CASE_INSENSITIVE, NULL, NULL);
            fpNtOpenKey(&hRealTarget, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &oaReal);
        }

        std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
        auto it = g_RegContextMap.find(*KeyHandle);
        if (it != g_RegContextMap.end()) {
            if (it->second->hRealKey) fpNtClose(it->second->hRealKey);
            it->second->hRealKey = hRealTarget;
            it->second->FullPath = isRedirectedRoot ? (g_RegMountPathNt + L"\\" + relPath) : fullNtPath;
            it->second->KeysInitialized = false;
            it->second->ValuesInitialized = false;
            it->second->SubKeys.clear();
            it->second->Values.clear();
        } else {
            RegContext* ctx = new RegContext();
            ctx->hRealKey = hRealTarget;
            ctx->FullPath = isRedirectedRoot ? (g_RegMountPathNt + L"\\" + relPath) : fullNtPath;
            g_RegContextMap[*KeyHandle] = ctx;
        }
    }

    return status;
}

// --- [新增] 现代软件多值查询 Hook (复用单值查询逻辑以支持墓碑和回退) ---
NTSTATUS NTAPI Detour_NtQueryMultipleValueKey(
    HANDLE KeyHandle,
    PKEY_VALUE_ENTRY ValueEntries,
    ULONG EntryCount,
    PVOID ValueBuffer,
    PULONG BufferLength,
    PULONG RequiredBufferLength
) {
    if (g_IsInHook || !g_HookReg) return fpNtQueryMultipleValueKey(KeyHandle, ValueEntries, EntryCount, ValueBuffer, BufferLength, RequiredBufferLength);
    RecursionGuard guard;

    ULONG totalRequiredSize = 0;
    NTSTATUS finalStatus = STATUS_SUCCESS;
    ULONG currentOffset = 0;

    std::vector<BYTE> tempBuf(4096);

    for (ULONG i = 0; i < EntryCount; i++) {
        PKEY_VALUE_ENTRY entry = &ValueEntries[i];

        ULONG resultLength = 0;
        // 复用 Detour_NtQueryValueKey 自动处理墓碑值、真实注册表回退和 FakeACP
        NTSTATUS status = Detour_NtQueryValueKey(
            KeyHandle,
            entry->ValueName,
            KeyValuePartialInformation,
            tempBuf.data(),
            (ULONG)tempBuf.size(),
            &resultLength
        );

        if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL) {
            tempBuf.resize(resultLength);
            status = Detour_NtQueryValueKey(
                KeyHandle,
                entry->ValueName,
                KeyValuePartialInformation,
                tempBuf.data(),
                (ULONG)tempBuf.size(),
                &resultLength
            );
        }

        if (NT_SUCCESS(status)) {
            PKEY_VALUE_PARTIAL_INFORMATION partialInfo = (PKEY_VALUE_PARTIAL_INFORMATION)tempBuf.data();

            entry->Type = partialInfo->Type;
            entry->DataLength = partialInfo->DataLength;

            if (BufferLength && currentOffset + partialInfo->DataLength <= *BufferLength) {
                entry->DataOffset = currentOffset;
                if (ValueBuffer) {
                    memcpy((PUCHAR)ValueBuffer + currentOffset, partialInfo->Data, partialInfo->DataLength);
                }
                currentOffset += partialInfo->DataLength;

                // 强制 4 字节对齐
                currentOffset = (currentOffset + 3) & ~3;
            } else {
                finalStatus = STATUS_BUFFER_OVERFLOW;
            }
            // 累加所需大小 包括对齐
            totalRequiredSize += partialInfo->DataLength;
            totalRequiredSize = (totalRequiredSize + 3) & ~3;
        } else {
            // 如果任何一个值找不到 整体返回 STATUS_OBJECT_NAME_NOT_FOUND
            finalStatus = STATUS_OBJECT_NAME_NOT_FOUND;
            entry->DataLength = 0;
            entry->DataOffset = 0;
            entry->Type = 0;
        }
    }

    if (RequiredBufferLength) {
        *RequiredBufferLength = totalRequiredSize;
    }

    return finalStatus;
}

// --- [新增] 注册表变更通知 Hook (解决回退真实句柄无法收到沙盒变更的问题) ---
NTSTATUS NTAPI Detour_NtNotifyChangeKey(
    HANDLE KeyHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG CompletionFilter,
    BOOLEAN WatchTree,
    PVOID Buffer,
    ULONG BufferSize,
    BOOLEAN Asynchronous
) {
    if (g_IsInHook || !g_HookReg) return fpNtNotifyChangeKey(KeyHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, CompletionFilter, WatchTree, Buffer, BufferSize, Asynchronous);
    RecursionGuard guard;

    HANDLE hTargetKey = KeyHandle;
    std::wstring relPath;
    std::wstring path = GetPathFromHandle(KeyHandle);

    // 如果当前句柄指向真实注册表 且属于应重定向的路径 说明它是只读回退句柄
    // 我们需要将其重定向到沙盒影子键 以便程序能收到沙盒内的变更通知
    if (!path.empty() && ShouldRedirectReg(path, relPath)) {
        std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
        auto it = g_RegContextMap.find(KeyHandle);
        if (it != g_RegContextMap.end()) {
            if (!it->second->hMonitorKey) {
                EnsureRegPathExistsRelative(relPath);
                std::wstring sandboxPath = g_RegMountPathNt + L"\\" + relPath;
                OBJECT_ATTRIBUTES oa;
                UNICODE_STRING us;
                RtlInitUnicodeString(&us, sandboxPath.c_str());
                InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

                HANDLE hMonitor = NULL;
                if (NT_SUCCESS(fpNtOpenKey(&hMonitor, KEY_NOTIFY, &oa))) {
                    it->second->hMonitorKey = hMonitor;
                } else {
                    ULONG disp;
                    if (NT_SUCCESS(fpNtCreateKey(&hMonitor, KEY_NOTIFY, &oa, 0, NULL, 0, &disp))) {
                        it->second->hMonitorKey = hMonitor;
                    }
                }
            }
            if (it->second->hMonitorKey) {
                hTargetKey = it->second->hMonitorKey;
            }
        }
    }

    return fpNtNotifyChangeKey(hTargetKey, Event, ApcRoutine, ApcContext, IoStatusBlock, CompletionFilter, WatchTree, Buffer, BufferSize, Asynchronous);
}

NTSTATUS NTAPI Detour_NtNotifyChangeMultipleKeys(
    HANDLE MasterKeyHandle,
    ULONG Count,
    POBJECT_ATTRIBUTES SlaveObjects,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG CompletionFilter,
    BOOLEAN WatchTree,
    PVOID Buffer,
    ULONG BufferSize,
    BOOLEAN Asynchronous
) {
    if (g_IsInHook || !g_HookReg) return fpNtNotifyChangeMultipleKeys(MasterKeyHandle, Count, SlaveObjects, Event, ApcRoutine, ApcContext, IoStatusBlock, CompletionFilter, WatchTree, Buffer, BufferSize, Asynchronous);
    RecursionGuard guard;

    HANDLE hTargetKey = MasterKeyHandle;
    std::wstring relPath;
    std::wstring path = GetPathFromHandle(MasterKeyHandle);

    if (!path.empty() && ShouldRedirectReg(path, relPath)) {
        std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
        auto it = g_RegContextMap.find(MasterKeyHandle);
        if (it != g_RegContextMap.end()) {
            if (!it->second->hMonitorKey) {
                EnsureRegPathExistsRelative(relPath);
                std::wstring sandboxPath = g_RegMountPathNt + L"\\" + relPath;
                OBJECT_ATTRIBUTES oa;
                UNICODE_STRING us;
                RtlInitUnicodeString(&us, sandboxPath.c_str());
                InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

                HANDLE hMonitor = NULL;
                if (NT_SUCCESS(fpNtOpenKey(&hMonitor, KEY_NOTIFY, &oa))) {
                    it->second->hMonitorKey = hMonitor;
                } else {
                    ULONG disp;
                    if (NT_SUCCESS(fpNtCreateKey(&hMonitor, KEY_NOTIFY, &oa, 0, NULL, 0, &disp))) {
                        it->second->hMonitorKey = hMonitor;
                    }
                }
            }
            if (it->second->hMonitorKey) {
                hTargetKey = it->second->hMonitorKey;
            }
        }
    }

    return fpNtNotifyChangeMultipleKeys(hTargetKey, Count, SlaveObjects, Event, ApcRoutine, ApcContext, IoStatusBlock, CompletionFilter, WatchTree, Buffer, BufferSize, Asynchronous);
}

// [新增] 使用 NT API 枚举目录以获取真实 FileId
void EnumerateFilesNt(const std::wstring& ntPath, bool isSandbox, std::map<std::wstring, CachedDirEntry>& outMap) {
    HANDLE hDir = INVALID_HANDLE_VALUE;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uStr;
    IO_STATUS_BLOCK iosb;

    RtlInitUnicodeString(&uStr, ntPath.c_str());
    InitializeObjectAttributes(&oa, &uStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // 打开目录
    NTSTATUS status = fpNtOpenFile(&hDir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

    if (!NT_SUCCESS(status)) return;

    const size_t bufSize = 4096;
    std::vector<BYTE> buffer(bufSize);
    bool firstQuery = true;

    // [新增] 预先计算路径前缀 用于子项可见性检查
    std::wstring pathPrefix = ntPath;
    if (pathPrefix.back() != L'\\') pathPrefix += L"\\";

    while (true) {
        status = fpNtQueryDirectoryFile(hDir, NULL, NULL, NULL, &iosb, buffer.data(), (ULONG)bufSize,
                                        FileIdBothDirectoryInformation, FALSE, NULL, firstQuery);
        firstQuery = false;

        if (status == STATUS_NO_MORE_FILES) break;
        if (!NT_SUCCESS(status)) break;

        PFILE_ID_BOTH_DIR_INFORMATION info = (PFILE_ID_BOTH_DIR_INFORMATION)buffer.data();
        while (true) {
            if (info->FileNameLength > 0) {
                std::wstring fileName(info->FileName, info->FileNameLength / sizeof(wchar_t));

                if (fileName != L"." && fileName != L"..") {

                    // [新增] 核心修复：Mode 3 下对真实目录的子项进行二次过滤
                    bool isVisible = true;
                    if (g_HookMode == 3 && !isSandbox) {
                        std::wstring fullChildPath = pathPrefix + fileName;
                        if (!IsPathVisible(fullChildPath)) {
                            isVisible = false;
                        }
                    }

                    if (isVisible) {
                        CachedDirEntry entry;
                        entry.FileName = fileName;
                        if (info->ShortNameLength > 0) {
                            entry.ShortName = std::wstring(info->ShortName, info->ShortNameLength / sizeof(wchar_t));
                        }
                        entry.FileAttributes = info->FileAttributes;
                        entry.CreationTime = info->CreationTime;
                        entry.LastAccessTime = info->LastAccessTime;
                        entry.LastWriteTime = info->LastWriteTime;
                        entry.ChangeTime = info->ChangeTime;
                        entry.EndOfFile = info->EndOfFile;
                        entry.AllocationSize = info->AllocationSize;
                        entry.FileId = info->FileId;

                        if (isSandbox) {
                            ToggleFileIdScramble(&entry.FileId);
                        }

                        std::wstring key = fileName;
                        std::transform(key.begin(), key.end(), key.begin(), towlower);
                        outMap[key] = entry;
                    }
                }
            }

            if (info->NextEntryOffset == 0) break;
            info = (PFILE_ID_BOTH_DIR_INFORMATION)((BYTE*)info + info->NextEntryOffset);
        }
    }
    fpNtClose(hDir);
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

// [新增] 生成简单的 FileId (基于文件名哈希)
LARGE_INTEGER GenerateFileId(const std::wstring& name) {
    LARGE_INTEGER id;
    std::hash<std::wstring> hasher;
    // 简单的哈希 确保非零
    size_t h = hasher(name);
    id.QuadPart = (LONGLONG)(h == 0 ? 1 : h);
    return id;
}

// 核心：构建合并后的文件列表
void BuildMergedDirectoryList(const std::wstring& realNtPath, const std::wstring& sandboxNtPath, std::vector<CachedDirEntry>& outList) {
    std::map<std::wstring, CachedDirEntry> mergedMap;

    // 1. 扫描真实目录
    if (!realNtPath.empty()) {
        if (g_HookMode != 3 || IsPathVisible(realNtPath)) {

            // --- 智能 WOW64 重定向控制 (保持原有逻辑) ---
            PVOID oldRedirectionValue = NULL;
            BOOL isWow64 = FALSE;
            bool needDisable = false;

            IsWow64Process(GetCurrentProcess(), &isWow64);
            if (isWow64) {
                // 简单判断：如果包含 System32 则尝试禁用重定向以读取原生内容
                if (ContainsCaseInsensitive(realNtPath, L"System32")) {
                    needDisable = true;
                }
            }

            if (needDisable) {
                Wow64DisableWow64FsRedirection(&oldRedirectionValue);
            }

            EnumerateFilesNt(realNtPath, false, mergedMap);

            if (needDisable) {
                Wow64RevertWow64FsRedirection(oldRedirectionValue);
            }
        }
    }

    // 2. 扫描沙盒目录
    if (!sandboxNtPath.empty()) {
        EnumerateFilesNt(sandboxNtPath, true, mergedMap);
    }

    // 3. 扫描沙盒内的 Sysnative 目录 (仅 32 位进程)
    BOOL isWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &isWow64);

    if (isWow64 && !sandboxNtPath.empty()) {
        // 查找 System32 (不区分大小写)
        const wchar_t* pSys32 = StrStrIW(sandboxNtPath.c_str(), L"\\System32");
        if (pSys32) {
            std::wstring sysnativePath = sandboxNtPath;
            size_t pos = pSys32 - sandboxNtPath.c_str();
            sysnativePath.replace(pos + 1, 8, L"Sysnative");

            // 枚举 Sysnative (视为沙盒内容 混淆 ID)
            EnumerateFilesNt(sysnativePath, true, mergedMap);
        }
    }

    // 4. 添加 . 和 ..
    // 判断是否为根目录 (例如 \??\C: 或 \??\C:\)
    bool isRoot = false;
    if (realNtPath.length() <= 7 && realNtPath.find(L"\\??\\") == 0 && realNtPath.find(L":") != std::wstring::npos) {
        // 简单检查：如果是盘符根目录
        if (realNtPath.back() == L':' || realNtPath.back() == L'\\') isRoot = true;
    }

    if (!isRoot) {
        CachedDirEntry dotEntry = {};
        dotEntry.FileName = L".";
        dotEntry.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        // . 和 .. 的 ID 通常由文件系统动态生成 这里可以留空或生成假 ID
        dotEntry.FileId = GenerateFileId(L".");
        outList.push_back(dotEntry);

        CachedDirEntry dotDotEntry = {};
        dotDotEntry.FileName = L"..";
        dotDotEntry.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        dotDotEntry.FileId = GenerateFileId(L"..");
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

// [新增] 初始化管道前缀 (在 InitHookThread 中调用)
void InitPipeVirtualization() {
    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

    // 生成唯一前缀 格式: YapBox_<SessionId>_
    // 这样不同 Session 的沙盒不会冲突 且与真实管道区分开
    wchar_t buf[64];
    swprintf_s(buf, L"YapBox_%08x_", sessionId);
    g_PipePrefix = buf;
}

// [新增] 计算虚拟化管道路径
// 输入: \Device\NamedPipe\MyPipe
// 输出: \Device\NamedPipe\YapBox_00000001_MyPipe
bool GetBoxedPipePath(const std::wstring& fullNtPath, std::wstring& outBoxedPath) {
    const std::wstring pipeDevice = L"\\Device\\NamedPipe\\";

    // 检查是否为命名管道路径
    if (fullNtPath.size() > pipeDevice.size() &&
        _wcsnicmp(fullNtPath.c_str(), pipeDevice.c_str(), pipeDevice.size()) == 0) {

        std::wstring pipeName = fullNtPath.substr(pipeDevice.size());

        // 检查是否已经被虚拟化 (防止重复添加前缀)
        if (pipeName.find(g_PipePrefix) == 0) return false;

        // 构造虚拟化路径
        outBoxedPath = pipeDevice + g_PipePrefix + pipeName;
        return true;
    }
    return false;
}

// [新增] 虚拟光驱路径重定向辅助类 (RAII)
class VirtualCdRedirector {
public:
    VirtualCdRedirector(POBJECT_ATTRIBUTES attr) : m_attr(attr) {
        if (g_VirtualCdDrive != 0 && m_attr && m_attr->ObjectName) {
            // 检查路径是否以虚拟盘符前缀开头 (例如 \??\M:)
            if (m_attr->ObjectName->Length >= g_VirtualCdNtPrefix.length() * sizeof(wchar_t)) {
                if (_wcsnicmp(m_attr->ObjectName->Buffer, g_VirtualCdNtPrefix.c_str(), g_VirtualCdNtPrefix.length()) == 0) {

                    // 构造重定向后的路径: \??\M:\Setup.exe -> \??\Z:\Other\ISO\Setup.exe
                    std::wstring originalPath(m_attr->ObjectName->Buffer, m_attr->ObjectName->Length / sizeof(wchar_t));
                    m_newPath = g_HookCdNtPath + originalPath.substr(g_VirtualCdNtPrefix.length());

                    // 初始化新的 UNICODE_STRING
                    // 注意：RtlInitUnicodeString 使用 m_newPath.c_str() 必须确保 m_newPath 在对象生命周期内有效
                    RtlInitUnicodeString(&m_newStr, m_newPath.c_str());

                    // 备份原始值
                    m_oldName = m_attr->ObjectName;
                    m_oldRoot = m_attr->RootDirectory;

                    // 替换为新路径 (绝对路径 忽略 RootDirectory)
                    m_attr->ObjectName = &m_newStr;
                    m_attr->RootDirectory = NULL;
                    m_redirected = true;
                }
            }
        }
    }

    ~VirtualCdRedirector() {
        if (m_redirected) {
            // 还原原始值
            m_attr->ObjectName = m_oldName;
            m_attr->RootDirectory = m_oldRoot;
        }
    }

private:
    POBJECT_ATTRIBUTES m_attr;
    std::wstring m_newPath;
    UNICODE_STRING m_newStr;
    PUNICODE_STRING m_oldName = nullptr;
    HANDLE m_oldRoot = NULL;
    bool m_redirected = false;
};

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

    // [修改] 使用辅助类处理虚拟光驱重定向 (\??\M: -> \??\Z:\ISO)
    VirtualCdRedirector cdRedirect(ObjectAttributes);

    // [新增] 处理按 ID 打开 (FILE_OPEN_BY_FILE_ID)
    // 移植自 file.c: File_GetName_FromFileId
    if (CreateOptions & FILE_OPEN_BY_FILE_ID) {
        // 这种模式下 RootDirectory 必须存在 且 ObjectName 是一个 8 字节的 File ID
        if (ObjectAttributes && ObjectAttributes->RootDirectory && ObjectAttributes->ObjectName) {

            // 检查父目录句柄是否在沙盒内
            if (IsHandleInSandbox(ObjectAttributes->RootDirectory)) {

                // 如果父目录在沙盒内 说明传入的 ID 很可能是我们之前混淆过的
                // 我们需要将其还原 (Unscramble) 才能让系统找到真实文件

                if (ObjectAttributes->ObjectName->Length == sizeof(LARGE_INTEGER)) {
                    // 1. 复制 ObjectAttributes (避免修改调用者的只读内存)
                    OBJECT_ATTRIBUTES oa = *ObjectAttributes;
                    UNICODE_STRING objName = *ObjectAttributes->ObjectName;
                    LARGE_INTEGER fileId;

                    // 2. 复制并还原 ID
                    memcpy(&fileId, objName.Buffer, sizeof(LARGE_INTEGER));
                    ToggleFileIdScramble(&fileId);

                    // 3. 指向还原后的 ID
                    objName.Buffer = (PWSTR)&fileId;
                    oa.ObjectName = &objName;

                    // 4. 调用原始函数
                    return fpNtCreateFile(FileHandle, DesiredAccess, &oa, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
                }
            }
        }
        // 如果不是沙盒内的 ID 打开 直接透传
        return fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
    }

    // 1. 路径解析与规范化 (后续原有逻辑)
    std::wstring rawNtPath = ResolvePathFromAttr(ObjectAttributes);
    std::wstring fullNtPath = NormalizeNtPath(rawNtPath);

    // [新增] 命名管道客户端虚拟化
    std::wstring boxedPipePath;
    if (GetBoxedPipePath(fullNtPath, boxedPipePath)) {
        // 这是一个管道路径 我们需要决定是连接到沙盒内的虚拟管道 还是直通系统管道

        // 1. 检查沙盒内是否存在该虚拟管道
        // 使用 NtQueryAttributesFile 探测 避免产生连接副作用
        OBJECT_ATTRIBUTES oaPipe;
        UNICODE_STRING usPipe;
        FILE_BASIC_INFORMATION basicInfo;

        RtlInitUnicodeString(&usPipe, boxedPipePath.c_str());
        InitializeObjectAttributes(&oaPipe, &usPipe, OBJ_CASE_INSENSITIVE, NULL, NULL);

        // 注意：对于管道 NtQueryAttributesFile 可能返回 STATUS_SUCCESS 或其他状态
        // 只要不是 Object Name Not Found 就说明管道存在
        NTSTATUS probeStatus = fpNtQueryAttributesFile(&oaPipe, &basicInfo);

        if (probeStatus != STATUS_OBJECT_NAME_NOT_FOUND && probeStatus != STATUS_OBJECT_PATH_NOT_FOUND) {
            // 沙盒内存在同名管道 (由本沙盒内的进程创建) 优先连接它
            UNICODE_STRING uStr;
            RtlInitUnicodeString(&uStr, boxedPipePath.c_str());

            PUNICODE_STRING oldName = ObjectAttributes->ObjectName;
            HANDLE oldRoot = ObjectAttributes->RootDirectory;
            ObjectAttributes->ObjectName = &uStr;
            ObjectAttributes->RootDirectory = NULL;

            NTSTATUS status = fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

            ObjectAttributes->ObjectName = oldName;
            ObjectAttributes->RootDirectory = oldRoot;

            DebugLog(L"Pipe: Connected to Virtualized Pipe %s", boxedPipePath.c_str());
            return status;
        }
        // 如果沙盒内不存在 则放行 允许连接到真实的系统管道 (如 RPC, SCM 等)
    }

    // 兼容性补丁区域 (Pre-Call)

    // [MSI & TiWorker] 移除 ACCESS_SYSTEM_SECURITY
    if (g_CurrentProcessType == ProcType_Msi_Installer || g_CurrentProcessType == ProcType_TiWorker) {
        if (DesiredAccess & ACCESS_SYSTEM_SECURITY) {
            // TiWorker 全局移除 MSI 仅针对 .msi 文件移除
            if (g_CurrentProcessType == ProcType_TiWorker ||
               (fullNtPath.length() > 4 && _wcsicmp(fullNtPath.c_str() + fullNtPath.length() - 4, L".msi") == 0)) {
                DesiredAccess &= ~ACCESS_SYSTEM_SECURITY;
                DebugLog(L"Compat: Stripped ACCESS_SYSTEM_SECURITY for %s", fullNtPath.c_str());
            }
        }
    }

    // [Firefox] 移除插件 EXE 的 GENERIC_WRITE
    if (g_CurrentProcessType == ProcType_Mozilla_Firefox) {
        if ((DesiredAccess & GENERIC_WRITE) && fullNtPath.length() > 4 &&
            _wcsicmp(fullNtPath.c_str() + fullNtPath.length() - 4, L".exe") == 0) {
            DesiredAccess &= ~GENERIC_WRITE;
            DebugLog(L"Compat: Firefox - Stripped GENERIC_WRITE");
        }
    }

    // [Explorer] 移除只读文件的写属性请求
    if (g_CurrentProcessType == ProcType_Explorer && CreateDisposition == FILE_OPEN) {
        if ((DesiredAccess & FILE_WRITE_ATTRIBUTES) && !(DesiredAccess & (FILE_WRITE_DATA | DELETE))) {
             DesiredAccess &= ~FILE_WRITE_ATTRIBUTES;
        }
    }

    // [Outlook] OICE_ 临时文件安全描述符处理
    if (g_CurrentProcessType == ProcType_Office_Outlook && fullNtPath.find(L"\\OICE_") != std::wstring::npos) {
        if (ObjectAttributes && ObjectAttributes->SecurityDescriptor) {
            ObjectAttributes->SecurityDescriptor = NULL;
            DebugLog(L"Compat: Outlook - Cleared SecurityDescriptor");
        }
    }

    // [SystemDB] 强制写权限以触发 CoW (针对被锁定的数据库文件)
    if (g_CurrentProcessType == ProcType_SvcHost || g_CurrentProcessType == ProcType_DllHost) {
        bool isLockedDb = ContainsCaseInsensitive(fullNtPath, L"catdb") ||
                          ContainsCaseInsensitive(fullNtPath, L"DataStore.edb") ||
                          ContainsCaseInsensitive(fullNtPath, L"WebCache");
        if (isLockedDb && !(DesiredAccess & (GENERIC_WRITE | FILE_WRITE_DATA))) {
            DesiredAccess |= FILE_GENERIC_WRITE;
            DebugLog(L"Compat: SystemDB - Forced Write Access to trigger migration");
        }
    }

    // 重定向逻辑

    std::wstring targetNtPath;

    if (ShouldRedirect(fullNtPath, targetNtPath)) {
        bool isDirectory = (CreateOptions & FILE_DIRECTORY_FILE) != 0;
        // 判断是否为写操作 (包含显式写权限或破坏性创建标志)
        bool isWrite = (DesiredAccess & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA));
        if (CreateDisposition == FILE_CREATE || CreateDisposition == FILE_SUPERSEDE || CreateDisposition == FILE_OVERWRITE || CreateDisposition == FILE_OVERWRITE_IF || CreateDisposition == FILE_OPEN_IF) {
            isWrite = true;
        }

        bool sandboxExists = NtPathExists(targetNtPath);
        bool realExists = NtPathExists(fullNtPath);

        // [Mode 3] 可见性检查：如果真实文件存在但被隐藏 视为不存在
        if (g_HookMode == 3 && realExists) {
            if (!IsPathVisible(fullNtPath)) {
                realExists = false;
            }
        }

        bool shouldRedirect = false;

        if (isDirectory && !isWrite) {
            // 目录只读访问
            if (!realExists && sandboxExists) {
                shouldRedirect = true;
            } else if (realExists) {
                // 真实存在且可见 直接打开真实目录
                // 目录内容合并由 NtQueryDirectoryFile 处理
                shouldRedirect = false;
            } else {
                // 都不存在 重定向到沙盒以报错
                shouldRedirect = true;
            }
        } else if (isWrite) {
            // 写操作
            if (sandboxExists) {
                shouldRedirect = true;
            } else if (realExists) {
                // 真实存在但沙盒没有 -> 执行写时复制 (CoW)
                bool isDeleteOnClose = (CreateOptions & FILE_DELETE_ON_CLOSE) != 0;

                // [修改] 处理 CoW 返回值
                int cowResult = PerformCopyOnWrite(fullNtPath, targetNtPath, !isDeleteOnClose);

                if (cowResult == 0) {
                    // 成功
                    shouldRedirect = true;
                } else if (cowResult == 2) {
                    // [新增] 大小超限 直接拒绝访问
                    return STATUS_ACCESS_DENIED;
                } else {
                    // 迁移失败 (可能是文件被锁)
                    // 强制重定向 让 NtCreateFile 在沙盒路径上失败 (Object Not Found)
                    shouldRedirect = true;
                }
            } else {
                // 都不存在 (新建文件)
                shouldRedirect = true;
            }
        } else {
            // 文件只读访问
            if (sandboxExists) {
                shouldRedirect = true;
            } else if (realExists) {
                shouldRedirect = false;
            } else {
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

            // 如果是写操作或创建操作 确保沙盒父目录存在
            if (isWrite || CreateDisposition == FILE_CREATE || CreateDisposition == FILE_OPEN_IF || CreateDisposition == FILE_OVERWRITE_IF || CreateDisposition == FILE_SUPERSEDE) {
                EnsureDirectoryExistsNT(targetNtPath.c_str());
            }

            NTSTATUS status = fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

            ObjectAttributes->ObjectName = oldName;
            ObjectAttributes->RootDirectory = oldRoot;
            return status;
        }
    }

    // 调用原始函数
    NTSTATUS status = fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

    // 兼容性补丁区域 (Post-Call / Retry)

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

    // [MSI] 记录 Config.Msi 访问失败
    if (status == STATUS_ACCESS_DENIED && g_CurrentProcessType == ProcType_Msi_Installer && fullNtPath.find(L"\\Config.Msi") != std::wstring::npos) {
        DebugLog(L"Compat: MSI Config.Msi access denied. Installation might fail.");
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

    // [新增] 虚拟光驱重定向 (虽然光驱通常只读 但为了兼容性加上)
    VirtualCdRedirector cdRedirect(ObjectAttributes);

    std::wstring rawNtPath = ResolvePathFromAttr(ObjectAttributes);

    if (rawNtPath.find(L"\\Device\\") == 0) {
        rawNtPath = DevicePathToNtPath(rawNtPath);
    }

    // [修改] 增加路径规范化 确保删除操作也能正确识别短文件名和链接
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

NTSTATUS NTAPI Detour_NtSetInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
) {
    if (g_IsInHook) return fpNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    RecursionGuard guard;

    // 1. 处理重命名 (Rename)
    if (FileInformationClass == FileRenameInformation || FileInformationClass == FileRenameInformationEx) {

        // ---------------------------------------------------------
        // A. 目录全量迁移 (Merge before Rename)
        // ---------------------------------------------------------
        IO_STATUS_BLOCK queryIosb;
        FILE_STANDARD_INFORMATION stdInfo;
        if (NT_SUCCESS(fpNtQueryInformationFile(FileHandle, &queryIosb, &stdInfo, sizeof(stdInfo), FileStandardInformation))) {
            if (stdInfo.Directory) {
                std::wstring realDosPath, sandboxDosPath;
                if (GetRealAndSandboxPaths(FileHandle, realDosPath, sandboxDosPath)) {
                    // 如果句柄指向沙盒路径且真实路径也存在 说明这是一个“分层”的目录
                    if (GetFileAttributesW(realDosPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                        DebugLog(L"Rename: Merging directory content before rename...");
                        // 执行递归合并：将 Real 中的遗留文件复制到 Sandbox
                        CopyDirectoryTree(realDosPath, sandboxDosPath);
                    }
                }
            }
        }

        PFILE_RENAME_INFORMATION pRename = (PFILE_RENAME_INFORMATION)FileInformation;
        std::wstring targetName(pRename->FileName, pRename->FileNameLength / sizeof(wchar_t));

        // 检查目标路径是否是绝对路径 (以 \ 开头)
        if (targetName.length() > 0 && targetName[0] == L'\\') {

            std::wstring fullTargetNt = NormalizeNtPath(targetName);
            std::wstring redirectedTargetNt;

            // 检查目标路径是否需要重定向
            if (ShouldRedirect(fullTargetNt, redirectedTargetNt)) {

                // ---------------------------------------------------------
                // B. 修复移动到仅真实存在目录时的报错 (Auto-Create Destination Directory)
                // ---------------------------------------------------------
                std::wstring sandboxTargetDos = NtPathToDosPath(redirectedTargetNt);
                wchar_t sandboxDir[MAX_PATH];
                if (wcscpy_s(sandboxDir, MAX_PATH, sandboxTargetDos.c_str()) == 0) {
                    PathRemoveFileSpecW(sandboxDir); // 获取沙盒目标父目录

                    // 1. 检查沙盒父目录是否存在
                    if (GetFileAttributesW(sandboxDir) == INVALID_FILE_ATTRIBUTES) {

                        // 2. 获取真实目标父目录
                        std::wstring realTargetDos = NtPathToDosPath(fullTargetNt);
                        wchar_t realDir[MAX_PATH];
                        if (wcscpy_s(realDir, MAX_PATH, realTargetDos.c_str()) == 0) {
                            PathRemoveFileSpecW(realDir); // 获取真实目标父目录

                            // 3. 检查真实父目录是否存在
                            DWORD realAttr = GetFileAttributesW(realDir);
                            if (realAttr != INVALID_FILE_ATTRIBUTES && (realAttr & FILE_ATTRIBUTE_DIRECTORY)) {

                                // 4. 真实存在但沙盒不存在 -> 迁移目录结构
                                DebugLog(L"Rename: Creating missing destination directory %s", sandboxDir);
                                // 使用带同步功能的递归创建 (如果已移植) 或普通递归创建
                                RecursiveCreatePathWithSync(sandboxDir);

                                // 5. 同步目录属性 (双重保险)
                                CopyFileAttributesAndStripReadOnly(realDir, sandboxDir);
                                CopyFileTimestamps(realDir, sandboxDir);
                            }
                        }
                    }
                }

                // ---------------------------------------------------------
                // C. 构造新的重命名结构体
                // ---------------------------------------------------------
                ULONG newSize = Length + (ULONG)(redirectedTargetNt.length() * sizeof(wchar_t)) + 128;
                PFILE_RENAME_INFORMATION pNewRename = (PFILE_RENAME_INFORMATION)new(char[newSize]);

                if (pNewRename) {
                    memset(pNewRename, 0, newSize);

                    // 复制头部信息
                    pNewRename->ReplaceIfExists = pRename->ReplaceIfExists;
                    pNewRename->RootDirectory = pRename->RootDirectory;

                    if (FileInformationClass == FileRenameInformationEx) {
                         ((PFILE_DISPOSITION_INFORMATION_EX)pNewRename)->Flags = ((PFILE_DISPOSITION_INFORMATION_EX)pRename)->Flags;
                    }

                    // 填入重定向后的沙盒路径
                    pNewRename->FileNameLength = (ULONG)(redirectedTargetNt.length() * sizeof(wchar_t));
                    memcpy(pNewRename->FileName, redirectedTargetNt.c_str(), pNewRename->FileNameLength);

                    // 调用原始函数
                    NTSTATUS status = fpNtSetInformationFile(FileHandle, IoStatusBlock, pNewRename, newSize, FileInformationClass);

                    delete[] (char*)pNewRename;
                    return status;
                }
            }
        }
    }

    // 2. 处理硬链接 (Hard Link)
    if (FileInformationClass == FileLinkInformation || FileInformationClass == (FILE_INFORMATION_CLASS)65 /*FileLinkInformationEx*/) {

        PFILE_LINK_INFORMATION pLink = (PFILE_LINK_INFORMATION)FileInformation;
        std::wstring targetName(pLink->FileName, pLink->FileNameLength / sizeof(wchar_t));

        if (targetName.length() > 0 && targetName[0] == L'\\') {

            std::wstring fullTargetNt = NormalizeNtPath(targetName);
            std::wstring redirectedTargetNt;

            if (ShouldRedirect(fullTargetNt, redirectedTargetNt)) {

                // 1. 构造新的 Link 结构体
                ULONG newSize = Length + (ULONG)(redirectedTargetNt.length() * sizeof(wchar_t)) + 128;
                PFILE_LINK_INFORMATION pNewLink = (PFILE_LINK_INFORMATION)new(char[newSize]);

                if (pNewLink) {
                    memset(pNewLink, 0, newSize);

                    // 复制头部信息 (兼容 Ex 结构)
                    *(ULONG*)pNewLink = *(ULONG*)pLink;

                    pNewLink->RootDirectory = pLink->RootDirectory;
                    pNewLink->FileNameLength = (ULONG)(redirectedTargetNt.length() * sizeof(wchar_t));
                    memcpy(pNewLink->FileName, redirectedTargetNt.c_str(), pNewLink->FileNameLength);

                    // 2. 检查源文件是否需要迁移 (CoW)
                    HANDLE hOpHandle = FileHandle;
                    bool closeHandle = false;

                    if (!IsHandleInSandbox(FileHandle)) {
                        std::wstring rawPath = GetPathFromHandle(FileHandle);
                        std::wstring sourceNtPath = DevicePathToNtPath(rawPath);
                        std::wstring sourceSandboxNt;

                        if (ShouldRedirect(sourceNtPath, sourceSandboxNt)) {
                            // [修改] 处理 CoW 返回值
                            int cowResult = PerformCopyOnWrite(sourceNtPath, sourceSandboxNt);

                            if (cowResult == 2) {
                                // [新增] 大小超限
                                delete[] (char*)pNewLink;
                                return STATUS_ACCESS_DENIED;
                            }

                            if (cowResult == 0) {
                                std::wstring sourceSandboxDos = NtPathToDosPath(sourceSandboxNt);
                                HANDLE hSandboxed = CreateFileW(sourceSandboxDos.c_str(),
                                    FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

                                if (hSandboxed != INVALID_HANDLE_VALUE) {
                                    hOpHandle = hSandboxed;
                                    closeHandle = true;
                                    DebugLog(L"HardLink: Source migrated to %s", sourceSandboxDos.c_str());
                                }
                            }
                        }
                    }

                    // 3. 调用原始函数
                    NTSTATUS status = fpNtSetInformationFile(hOpHandle, IoStatusBlock, pNewLink, newSize, FileInformationClass);

                    if (closeHandle) CloseHandle(hOpHandle);
                    delete[] (char*)pNewLink;
                    return status;
                }
            }
        }
    }

    // [拦截] FileHardLinkInformation (强制程序使用 CopyFile)
    if (FileInformationClass == (FILE_INFORMATION_CLASS)46 /*FileHardLinkInformation*/) {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    // 3. 处理删除 (Delete)
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

    // 获取路径
    std::wstring rawPath = GetPathFromHandle(FileHandle);
    if (rawPath.empty()) {
        return fpNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    }

    // 路径标准化
    std::wstring ntPath = DevicePathToNtPath(rawPath);
    std::wstring targetPath;

    // 检查是否需要重定向
    if (!ShouldRedirect(ntPath, targetPath)) {
        return fpNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    }

    // 判断目标位置
    std::wstring sandboxRootNt = L"\\??\\";
    sandboxRootNt += g_SandboxRoot;

    // 检查句柄是否已经指向沙盒内的文件
    bool isHandleInSandbox = ContainsCaseInsensitive(ntPath, sandboxRootNt);

    // --- 分支 A: 句柄指向沙盒内的文件 ---
    if (isHandleInSandbox) {
        // 直接调用原始函数进行物理删除
        return fpNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    }

    // --- 分支 B: 句柄指向真实文件 (尚未 CoW) ---
    else {
        std::wstring realDosPath = NtPathToDosPath(ntPath);
        DWORD realAttrs = GetFileAttributesW(realDosPath.c_str());

        if (realAttrs != INVALID_FILE_ATTRIBUTES) {
            // 真实文件存在 但我们不能删除它
            // 在纯用户模式下 我们无法完美隐藏它（除非使用墓碑机制）
            // 这里返回伪造的成功 欺骗程序文件已删除
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

    // [新增] 虚拟光驱重定向
    VirtualCdRedirector cdRedirect(ObjectAttributes);

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

    // [新增] 虚拟光驱重定向
    VirtualCdRedirector cdRedirect(ObjectAttributes);

    // 1. 路径解析与规范化 (处理短文件名、Symlink)
    std::wstring rawNtPath = ResolvePathFromAttr(ObjectAttributes);
    std::wstring fullNtPath = NormalizeNtPath(rawNtPath);
    std::wstring targetNtPath;

    // 2. 重定向逻辑
    if (ShouldRedirect(fullNtPath, targetNtPath)) {
        UNICODE_STRING uStr;
        RtlInitUnicodeString(&uStr, targetNtPath.c_str());
        PUNICODE_STRING oldName = ObjectAttributes->ObjectName;
        HANDLE oldRoot = ObjectAttributes->RootDirectory;
        ObjectAttributes->ObjectName = &uStr;
        ObjectAttributes->RootDirectory = NULL;

        // 尝试查询沙盒路径
        NTSTATUS status = fpNtQueryFullAttributesFile(ObjectAttributes, FileInformation);

        ObjectAttributes->ObjectName = oldName;
        ObjectAttributes->RootDirectory = oldRoot;

        // 如果沙盒中存在 直接返回
        if (status == STATUS_SUCCESS) return status;

        // [Mode 3] 隐藏检查：如果沙盒没有 且真实路径被策略隐藏 则返回未找到
        if (g_HookMode == 3) {
            if (!IsPathVisible(fullNtPath)) {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
        }
    }

    // 3. 调用原始函数查询真实路径
    NTSTATUS status = fpNtQueryFullAttributesFile(ObjectAttributes, FileInformation);

    // 4. [兼容性补丁] MSI Config.Msi 修复
    // MSI 安装程序必须能够看到 Config.Msi 目录 如果不存在则尝试创建
    if (status == STATUS_OBJECT_NAME_NOT_FOUND && g_CurrentProcessType == ProcType_Msi_Installer) {
        if (fullNtPath.length() >= 11 &&
            _wcsicmp(fullNtPath.c_str() + fullNtPath.length() - 11, L"\\Config.Msi") == 0) {

            std::wstring dosPath = NtPathToDosPath(fullNtPath);
            if (!dosPath.empty()) {
                // 尝试创建目录 (CreateDirectory 会自动处理权限 如果失败则无法修复)
                if (CreateDirectoryW(dosPath.c_str(), NULL)) {
                    DebugLog(L"Compat: MSI - Created missing Config.Msi at %s", dosPath.c_str());
                    // 创建成功后重试查询
                    status = fpNtQueryFullAttributesFile(ObjectAttributes, FileInformation);
                }
            }
        }
    }

    return status;
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
        // [修改] 直接传递 NT 路径 不再转换为 DOS 路径
        // BuildMergedDirectoryList 内部已改为使用 NT API
        BuildMergedDirectoryList(ntDirPath, targetPath, localEntries);
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

        // [修改] 使用 entry 中存储的真实/混淆后的 FileId
        LARGE_INTEGER fileId = entry.FileId;

        // 兜底：如果 ID 为 0 (异常情况) 回退到哈希生成
        if (fileId.QuadPart == 0) {
             fileId = GenerateFileId(entry.FileName);
        }

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

NTSTATUS NTAPI Detour_NtQueryObject(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG Length,
    PULONG ReturnLength
) {
    // 1. 调用原始函数
    NTSTATUS status = fpNtQueryObject(Handle, ObjectInformationClass, ObjectInformation, Length, ReturnLength);

    // 2. 仅处理成功且为 ObjectNameInformation (1) 的情况
    // 注意：ObjectAllInformation (3) 返回的是全局类型统计 不包含当前对象的路径 因此无需伪装
    if (NT_SUCCESS(status) && ObjectInformationClass == ObjectNameInformation && ObjectInformation) {

        POBJECT_NAME_INFORMATION pNameInfo = (POBJECT_NAME_INFORMATION)ObjectInformation;

        // 确保缓冲区包含有效的 Name 结构且 Name 不为空
        if (pNameInfo->Name.Buffer && pNameInfo->Name.Length > 0) {

            std::wstring currentPath(pNameInfo->Name.Buffer, pNameInfo->Name.Length / sizeof(wchar_t));
            std::wstring spoofedPath;
            bool needSpoof = false;

            // ---------------------------------------------------------
            // A. 注册表对象伪装 (配合 g_RegMountPathNt)
            // ---------------------------------------------------------
            if (!g_RegMountPathNt.empty() &&
                _wcsnicmp(currentPath.c_str(), g_RegMountPathNt.c_str(), g_RegMountPathNt.length()) == 0) {

                // 反推真实路径
                std::wstring realRegPath;
                if (GetRealFromSandboxPath(currentPath, realRegPath)) {
                    spoofedPath = realRegPath;
                    needSpoof = true;
                }
            }
            // ---------------------------------------------------------
            // B. 文件对象伪装 (配合 g_SandboxDevicePath)
            // ---------------------------------------------------------
            else if (!g_SandboxDevicePath.empty() &&
                     currentPath.size() > g_SandboxDevicePath.size() &&
                     _wcsnicmp(currentPath.c_str(), g_SandboxDevicePath.c_str(), g_SandboxDevicePath.size()) == 0) {

                size_t devLen = g_SandboxDevicePath.size();
                // 检查格式 ...\C\...
                if (currentPath[devLen] == L'\\' && currentPath.length() > devLen + 2 && currentPath[devLen + 2] == L'\\') {
                    wchar_t driveLetter = currentPath[devLen + 1];
                    std::wstring realDevicePrefix = GetDevicePathByDrive(driveLetter);

                    if (!realDevicePrefix.empty()) {
                        spoofedPath = realDevicePrefix + currentPath.substr(devLen + 3);
                        needSpoof = true;
                    }
                }
            }

            // ---------------------------------------------------------
            // C. 执行伪装并修正 ReturnLength
            // ---------------------------------------------------------
            if (needSpoof && !spoofedPath.empty()) {
                USHORT newByteLength = (USHORT)(spoofedPath.length() * sizeof(wchar_t));

                // 检查缓冲区是否足够 (通常伪装后的路径比沙盒路径短 所以是安全的)
                if (newByteLength <= pNameInfo->Name.MaximumLength) {

                    // 1. 覆盖路径数据
                    memcpy(pNameInfo->Name.Buffer, spoofedPath.c_str(), newByteLength);
                    pNameInfo->Name.Length = newByteLength;

                    // 2. 确保 NULL 结尾 (安全防御)
                    if (newByteLength + sizeof(wchar_t) <= pNameInfo->Name.MaximumLength) {
                        pNameInfo->Name.Buffer[spoofedPath.length()] = L'\0';
                    }

                    // 3. [关键] 修正 ReturnLength
                    // 很多程序(如.NET)会检查 ReturnLength 是否与实际数据匹配
                    if (ReturnLength) {
                        // 计算实际需要的总大小：结构体头 + 字符串长度 + NULL结尾
                        ULONG actualSize = sizeof(OBJECT_NAME_INFORMATION) + newByteLength + sizeof(wchar_t);
                        *ReturnLength = actualSize;
                    }
                }
            }
        }
    }

    return status;
}

NTSTATUS NTAPI Detour_NtQueryInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
) {
    if (g_IsInHook) return fpNtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    RecursionGuard guard;

    // 1. 调用原始函数
    NTSTATUS status = fpNtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);

    if (NT_SUCCESS(status)) {

        // [新增] File ID 混淆逻辑
        PLARGE_INTEGER pFileId = NULL;

        if (FileInformationClass == FileInternalInformation) {
            if (Length >= sizeof(FILE_INTERNAL_INFORMATION)) {
                pFileId = &((PFILE_INTERNAL_INFORMATION)FileInformation)->IndexNumber;
            }
        }
        else if (FileInformationClass == FileAllInformation) {
            if (Length >= sizeof(FILE_ALL_INFORMATION)) {
                pFileId = &((PFILE_ALL_INFORMATION)FileInformation)->InternalInformation.IndexNumber;
            }
        }

        // 如果获取到了 ID 指针 且文件位于沙盒内 则进行混淆
        if (pFileId && IsHandleInSandbox(FileHandle)) {
            ToggleFileIdScramble(pFileId);
        }

        // [原有] 文件名欺骗逻辑
        PFILE_NAME_INFORMATION pNameInfo = NULL;
        if (FileInformationClass == (FILE_INFORMATION_CLASS)9 /*FileNameInformation*/) {
            pNameInfo = (PFILE_NAME_INFORMATION)FileInformation;
        }
        else if (FileInformationClass == (FILE_INFORMATION_CLASS)18 /*FileAllInformation*/) {
            pNameInfo = &((PFILE_ALL_INFORMATION)FileInformation)->NameInformation;
        }

        if (pNameInfo && pNameInfo->FileNameLength > 0) {
            std::wstring currentPath(pNameInfo->FileName, pNameInfo->FileNameLength / sizeof(wchar_t));
            if (!g_SandboxRelativePath.empty() &&
                currentPath.size() > g_SandboxRelativePath.size() &&
                _wcsnicmp(currentPath.c_str(), g_SandboxRelativePath.c_str(), g_SandboxRelativePath.size()) == 0) {

                size_t relLen = g_SandboxRelativePath.size();
                if (currentPath[relLen] == L'\\' && currentPath[relLen + 2] == L'\\') {
                    std::wstring spoofedPath = currentPath.substr(relLen + 2);
                    memcpy(pNameInfo->FileName, spoofedPath.c_str(), spoofedPath.length() * sizeof(wchar_t));
                    pNameInfo->FileNameLength = (ULONG)(spoofedPath.length() * sizeof(wchar_t));
                }
            }
        }
    }

    return status;
}

// --- [新增] UI 语言 Hook ---
LANGID WINAPI Detour_GetUserDefaultUILanguage(void) {
    return g_FakeLangID ? g_FakeLangID : fpGetUserDefaultUILanguage();
}

LANGID WINAPI Detour_GetSystemDefaultUILanguage(void) {
    return g_FakeLangID ? g_FakeLangID : fpGetSystemDefaultUILanguage();
}

// --- [新增] 字体枚举 Hook (解决字体选择乱码) ---

// 代理回调上下文
struct EnumFontContext {
    FONTENUMPROCW originalProc;
    LPARAM originalLParam;
};

// 代理回调函数
int CALLBACK ProxyEnumFontFamExProc(const LOGFONTW* lpelfe, const TEXTMETRICW* lpntme, DWORD FontType, LPARAM lParam) {
    EnumFontContext* ctx = (EnumFontContext*)lParam;

    // 欺骗程序：告诉它这个字体支持我们伪造的字符集
    // 即使系统字体实际上不支持 很多程序只要看到 CharSet 匹配就会尝试使用
    // 而 Windows 的字体链接机制通常能兜底显示正确的字符
    if (g_FakeCharSet != 0) {
        LOGFONTW spoofedLF = *lpelfe;
        spoofedLF.lfCharSet = g_FakeCharSet;

        // 如果是 TEXTMETRIC (TrueType) 也修改
        TEXTMETRICW spoofedTM = *lpntme;
        spoofedTM.tmCharSet = g_FakeCharSet;

        return ctx->originalProc(&spoofedLF, &spoofedTM, FontType, ctx->originalLParam);
    }

    return ctx->originalProc(lpelfe, lpntme, FontType, ctx->originalLParam);
}

int WINAPI Detour_EnumFontFamiliesExW(HDC hdc, LPLOGFONTW lpLogfont, FONTENUMPROCW lpEnumFontFamExProc, LPARAM lParam, DWORD dwFlags) {
    if (g_FakeCharSet != 0) {
        // 修改输入请求：强制请求目标字符集的字体
        LOGFONTW spoofedRequest = *lpLogfont;
        spoofedRequest.lfCharSet = g_FakeCharSet;

        // 挂钩回调
        EnumFontContext ctx;
        ctx.originalProc = lpEnumFontFamExProc;
        ctx.originalLParam = lParam;

        return fpEnumFontFamiliesExW(hdc, &spoofedRequest, ProxyEnumFontFamExProc, (LPARAM)&ctx, dwFlags);
    }
    return fpEnumFontFamiliesExW(hdc, lpLogfont, lpEnumFontFamExProc, lParam, dwFlags);
}

// EnumFontsW 和 EnumFontFamiliesW 逻辑类似 通常现代程序用 Ex 为了保险可以一并挂钩
int WINAPI Detour_EnumFontFamiliesW(HDC hdc, LPCWSTR lpszFamily, FONTENUMPROCW lpEnumFontFamProc, LPARAM lParam) {
    if (g_FakeCharSet != 0) {
        EnumFontContext ctx;
        ctx.originalProc = lpEnumFontFamProc;
        ctx.originalLParam = lParam;
        return fpEnumFontFamiliesW(hdc, lpszFamily, ProxyEnumFontFamExProc, (LPARAM)&ctx);
    }
    return fpEnumFontFamiliesW(hdc, lpszFamily, lpEnumFontFamProc, lParam);
}

// [新增] Hook NtCreateNamedPipeFile (用于创建管道服务端)
NTSTATUS NTAPI Detour_NtCreateNamedPipeFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, ULONG NamedPipeType, ULONG ReadMode,
    ULONG CompletionMode, ULONG MaximumInstances, ULONG InboundQuota, ULONG OutboundQuota, PLARGE_INTEGER DefaultTimeout)
{
    if (g_IsInHook) return fpNtCreateNamedPipeFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, NamedPipeType, ReadMode, CompletionMode, MaximumInstances, InboundQuota, OutboundQuota, DefaultTimeout);
    RecursionGuard guard;

    std::wstring rawNtPath = ResolvePathFromAttr(ObjectAttributes);
    std::wstring boxedPath;

    // 如果是创建管道 强制重定向到虚拟化名称
    // 这样沙盒内创建的管道对外部不可见 且不会与系统服务冲突
    if (GetBoxedPipePath(rawNtPath, boxedPath)) {
        UNICODE_STRING uStr;
        RtlInitUnicodeString(&uStr, boxedPath.c_str());

        PUNICODE_STRING oldName = ObjectAttributes->ObjectName;
        HANDLE oldRoot = ObjectAttributes->RootDirectory;

        // 替换为绝对路径 忽略 RootDirectory
        ObjectAttributes->ObjectName = &uStr;
        ObjectAttributes->RootDirectory = NULL;

        NTSTATUS status = fpNtCreateNamedPipeFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, NamedPipeType, ReadMode, CompletionMode, MaximumInstances, InboundQuota, OutboundQuota, DefaultTimeout);

        ObjectAttributes->ObjectName = oldName;
        ObjectAttributes->RootDirectory = oldRoot;

        if (NT_SUCCESS(status)) {
            DebugLog(L"Pipe: Virtualized Server %s -> %s", rawNtPath.c_str(), boxedPath.c_str());
        }
        return status;
    }

    return fpNtCreateNamedPipeFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, NamedPipeType, ReadMode, CompletionMode, MaximumInstances, InboundQuota, OutboundQuota, DefaultTimeout);
}

// [新增] 拦截 GetLogicalDrives (位掩码)
DWORD WINAPI Detour_GetLogicalDrives(void) {
    DWORD drives = fpGetLogicalDrives();
    if (g_VirtualCdDrive != 0) {
        // 将虚拟盘符对应的位设为 1 (A=0, B=1, ...)
        drives |= (1 << (g_VirtualCdDrive - L'A'));
    }
    return drives;
}

// [新增] 拦截 GetLogicalDriveStringsW (字符串列表)
DWORD WINAPI Detour_GetLogicalDriveStringsW(DWORD nBufferLength, LPWSTR lpBuffer) {
    // 1. 调用原始函数
    DWORD ret = fpGetLogicalDriveStringsW(nBufferLength, lpBuffer);

    if (g_VirtualCdDrive != 0 && lpBuffer) {
        // 检查缓冲区是否足够容纳额外的 "M:\" (4个字符)
        // ret 是不包含末尾双NULL的长度
        if (ret + 4 <= nBufferLength) {
            // 移动指针到末尾 (跳过现有的驱动器字符串)
            LPWSTR pEnd = lpBuffer + ret;

            // 构造新驱动器字符串 "M:\"
            pEnd[0] = g_VirtualCdDrive;
            pEnd[1] = L':';
            pEnd[2] = L'\\';
            pEnd[3] = L'\0'; // 字符串结束符
            pEnd[4] = L'\0'; // 列表结束符 (双NULL)

            return ret + 4;
        }
    }
    return ret;
}

// [修改] 拦截 GetDriveTypeW (合并了虚拟盘符和路径匹配逻辑)
UINT WINAPI Detour_GetDriveTypeW(LPCWSTR lpRootPathName) {
    if (!lpRootPathName) return DRIVE_UNKNOWN;

    // 1. 检查是否为虚拟盘符 (例如 "M:", "M:\")
    if (g_VirtualCdDrive != 0) {
        if (towupper(lpRootPathName[0]) == g_VirtualCdDrive && lpRootPathName[1] == L':') {
            return DRIVE_CDROM;
        }
    }

    // 2. 检查是否为指定的伪装路径 (兼容旧逻辑)
    if (!g_HookCdPath.empty()) {
        std::wstring queryPath = lpRootPathName;
        // 检查完全匹配
        if (_wcsnicmp(queryPath.c_str(), g_HookCdPath.c_str(), queryPath.length()) == 0) {
             return DRIVE_CDROM;
        }
        // 检查是否查询的是伪装目录所在的盘符根目录
        if (g_HookCdPath.length() >= 3 && queryPath.length() >= 3) {
            if (towupper(g_HookCdPath[0]) == towupper(queryPath[0]) &&
                g_HookCdPath[1] == L':' && queryPath[1] == L':') {
                return DRIVE_CDROM;
            }
        }
    }
    return fpGetDriveTypeW(lpRootPathName);
}

// [修改] Detour_NtQueryVolumeInformationFile (合并了 VolumeID 和 CD 伪装逻辑)
NTSTATUS NTAPI Detour_NtQueryVolumeInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FsInformation,
    ULONG Length,
    FS_INFORMATION_CLASS FsInformationClass
) {
    // 1. 调用原始函数
    NTSTATUS status = fpNtQueryVolumeInformationFile(FileHandle, IoStatusBlock, FsInformation, Length, FsInformationClass);

    if (!NT_SUCCESS(status)) return status;

    // 获取句柄对应的路径
    std::wstring rawPath = GetPathFromHandle(FileHandle);
    if (rawPath.empty()) return status;
    std::wstring ntPath = DevicePathToNtPath(rawPath);

    // 逻辑 A: 修改卷序列号 (hookvolumeid)
    if (g_HookVolumeId && FsInformationClass == FileFsVolumeInformation) {
        bool shouldFake = false;
        if (!g_SystemDriveNt.empty() && (ntPath.find(g_SystemDriveNt) == 0)) shouldFake = true;
        else if (!g_LauncherDriveNt.empty() && (ntPath.find(g_LauncherDriveNt) == 0)) shouldFake = true;

        if (shouldFake) {
            PFILE_FS_VOLUME_INFORMATION info = (PFILE_FS_VOLUME_INFORMATION)FsInformation;
            info->VolumeSerialNumber = g_FakeVolumeSerial;
        }
    }

    // 逻辑 B: 伪装光驱属性 (hookcd)
    if (!g_HookCdPath.empty()) {
        // 检查是否在伪装路径内
        std::wstring hookCdNtPrefix = L"\\??\\" + g_HookCdPath;
        bool isTarget = false;
        if (ntPath.size() >= hookCdNtPrefix.size() &&
            _wcsnicmp(ntPath.c_str(), hookCdNtPrefix.c_str(), hookCdNtPrefix.size()) == 0) {
            isTarget = true;
        }

        // 或者是虚拟盘符
        if (!isTarget && g_VirtualCdDrive != 0) {
             // 检查路径是否包含虚拟盘符前缀 (例如 \??\M:\...)
             if (ntPath.size() >= g_VirtualCdNtPrefix.size() &&
                 _wcsnicmp(ntPath.c_str(), g_VirtualCdNtPrefix.c_str(), g_VirtualCdNtPrefix.size()) == 0) {
                 isTarget = true;
             }
        }

        if (isTarget) {
            // 伪装设备类型为光驱
            if (FsInformationClass == FileFsDeviceInformation) {
                if (Length >= sizeof(FILE_FS_DEVICE_INFORMATION)) {
                    PFILE_FS_DEVICE_INFORMATION info = (PFILE_FS_DEVICE_INFORMATION)FsInformation;
                    info->DeviceType = FILE_DEVICE_CD_ROM;
                    info->Characteristics |= (FILE_READ_ONLY_DEVICE | FILE_REMOVABLE_MEDIA);
                }
            }
            // 伪装文件系统名称为 CDFS
            else if (FsInformationClass == FileFsAttributeInformation) {
                if (Length >= sizeof(FILE_FS_ATTRIBUTE_INFORMATION)) {
                    PFILE_FS_ATTRIBUTE_INFORMATION info = (PFILE_FS_ATTRIBUTE_INFORMATION)FsInformation;

                    const wchar_t* fsName = L"CDFS";
                    size_t fsNameLen = wcslen(fsName) * sizeof(wchar_t);

                    if (Length >= FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName) + fsNameLen) {
                        info->FileSystemAttributes |= FILE_READ_ONLY_VOLUME;
                        info->FileSystemNameLength = (ULONG)fsNameLen;
                        memcpy(info->FileSystemName, fsName, fsNameLen);
                    }
                }
            }
        }
    }

    return status;
}

NTSTATUS NTAPI Detour_NtClose(HANDLE Handle) {
    // 清理 DirContext
    {
        std::unique_lock<std::shared_mutex> lock(g_DirContextMutex);
        auto it = g_DirContextMap.find(Handle);
        if (it != g_DirContextMap.end()) {
            delete it->second;
            g_DirContextMap.erase(it);
        }
    }

    // 清理 RegContext
    {
        std::unique_lock<std::shared_mutex> lock(g_RegContextMutex);
        auto it = g_RegContextMap.find(Handle);
        if (it != g_RegContextMap.end()) {
            // [新增] 关闭缓存的真实句柄
            if (it->second->hRealKey) {
                fpNtClose(it->second->hRealKey);
            }
            // [新增] 关闭监视句柄
            if (it->second->hMonitorKey) {
                fpNtClose(it->second->hMonitorKey);
            }
            delete it->second;
            g_RegContextMap.erase(it);
        }
    }

    return fpNtClose(Handle);
}

// --- 字体替换 Hook 实现 ---

// 辅助：执行字体名称替换
void OverrideLogFontName(LPWSTR faceName) {
    if (!g_OverrideFontName.empty()) {
        // 安全拷贝字体名称
        wcsncpy_s(faceName, LF_FACESIZE, g_OverrideFontName.c_str(), _TRUNCATE);
    }
}

// [修改] 更新字体 Hook 以强制字符集
HFONT WINAPI Detour_CreateFontIndirectW(const LOGFONTW* lplf) {
    // 如果没有启用字体替换且没有启用区域伪造 直接返回
    if (g_OverrideFontName.empty() && g_FakeCharSet == 0) return fpCreateFontIndirectW(lplf);

    LOGFONTW newLf = *lplf;

    // 1. 字体名称替换
    if (!g_OverrideFontName.empty()) {
        OverrideLogFontName(newLf.lfFaceName);
    }

    // 2. [新增] 强制字符集 (解决乱码的关键)
    // 如果程序请求默认字符集 强制改为目标语言字符集
    if (g_FakeCharSet != 0) {
        if (newLf.lfCharSet == DEFAULT_CHARSET || newLf.lfCharSet == ANSI_CHARSET) {
            newLf.lfCharSet = g_FakeCharSet;
        }
    }

    return fpCreateFontIndirectW(&newLf);
}

HFONT WINAPI Detour_CreateFontIndirectExW(const ENUMLOGFONTEXDVW* lpelf) {
    if (g_OverrideFontName.empty() && g_FakeCharSet == 0) return fpCreateFontIndirectExW(lpelf);

    ENUMLOGFONTEXDVW newElf = *lpelf;

    if (!g_OverrideFontName.empty()) {
        OverrideLogFontName(newElf.elfEnumLogfontEx.elfLogFont.lfFaceName);
    }

    // [新增] 强制字符集
    if (g_FakeCharSet != 0) {
        if (newElf.elfEnumLogfontEx.elfLogFont.lfCharSet == DEFAULT_CHARSET ||
            newElf.elfEnumLogfontEx.elfLogFont.lfCharSet == ANSI_CHARSET) {
            newElf.elfEnumLogfontEx.elfLogFont.lfCharSet = g_FakeCharSet;
        }
    }

    return fpCreateFontIndirectExW(&newElf);
}

// [新增] GetStockObject 挂钩
HGDIOBJ WINAPI Detour_GetStockObject(int i) {
    // 拦截特定的老旧系统字体 ID
    switch (i) {
    case OEM_FIXED_FONT:
    case ANSI_FIXED_FONT:
    case ANSI_VAR_FONT:
    case SYSTEM_FONT:
    case DEVICE_DEFAULT_FONT:
    case SYSTEM_FIXED_FONT:
        // 如果我们成功创建了替换字体 则返回它
        if (g_hNewGSOFont) {
            return g_hNewGSOFont;
        }
        break;
    }
    return fpGetStockObject(i);
}

// GDI+ 字体创建 Hook
// [修改] 使用 WINAPI 代替 stdcall
GpStatus WINAPI Detour_GdipCreateFontFamilyFromName(const WCHAR* name, GpFontCollection* fontCollection, GpFontFamily** fontFamily) {
    if (!g_OverrideFontName.empty()) {
        // 直接使用覆盖的字体名称调用原始函数
        return fpGdipCreateFontFamilyFromName(g_OverrideFontName.c_str(), fontCollection, fontFamily);
    }
    return fpGdipCreateFontFamilyFromName(name, fontCollection, fontFamily);
}

// --- [新增] 区域伪造 Hook 实现 ---

UINT WINAPI Detour_GetACP(void) {
    return g_FakeACP ? g_FakeACP : fpGetACP();
}

UINT WINAPI Detour_GetOEMCP(void) {
    return g_FakeACP ? g_FakeACP : fpGetOEMCP(); // 通常 OEMCP 与 ACP 保持一致以避免兼容性问题
}

LCID WINAPI Detour_GetUserDefaultLCID(void) {
    return g_FakeLCID ? g_FakeLCID : fpGetUserDefaultLCID();
}

LCID WINAPI Detour_GetSystemDefaultLCID(void) {
    return g_FakeLCID ? g_FakeLCID : fpGetSystemDefaultLCID();
}

LCID WINAPI Detour_GetThreadLocale(void) {
    return g_FakeLCID ? g_FakeLCID : fpGetThreadLocale();
}

LANGID WINAPI Detour_GetUserDefaultLangID(void) {
    return g_FakeLCID ? LANGIDFROMLCID(g_FakeLCID) : fpGetUserDefaultLangID();
}

LANGID WINAPI Detour_GetSystemDefaultLangID(void) {
    return g_FakeLCID ? LANGIDFROMLCID(g_FakeLCID) : fpGetSystemDefaultLangID();
}

// 拦截 GetLocaleInfoW 以确保返回正确的代码页信息 (例如 CP_ACP)
int WINAPI Detour_GetLocaleInfoW(LCID Locale, LCTYPE LCType, LPWSTR lpLCData, int cchData) {
    // 如果查询的是当前伪造的 Locale 且查询的是代码页
    if (g_FakeLCID && (Locale == g_FakeLCID || Locale == LOCALE_USER_DEFAULT || Locale == LOCALE_SYSTEM_DEFAULT)) {
        if ((LCType & ~LOCALE_NOUSEROVERRIDE) == LOCALE_IDEFAULTANSICODEPAGE ||
            (LCType & ~LOCALE_NOUSEROVERRIDE) == LOCALE_IDEFAULTCODEPAGE) {

            if (cchData == 0) return 6; // 返回所需长度 (最多5位数字+NULL)

            if (lpLCData && cchData > 0) {
                return swprintf_s(lpLCData, cchData, L"%u", g_FakeACP) > 0 ? (int)wcslen(lpLCData) + 1 : 0;
            }
        }
    }
    return fpGetLocaleInfoW(Locale, LCType, lpLCData, cchData);
}

// --- [新增] 核心防乱码 Hook ---

// 拦截 ANSI -> Unicode 转换
int WINAPI Detour_MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar) {
    // 如果程序请求使用系统默认 ANSI 代码页 强制替换为我们伪造的代码页
    if (g_FakeACP && (CodePage == CP_ACP || CodePage == CP_THREAD_ACP || CodePage == CP_OEMCP)) {
        CodePage = g_FakeACP;
    }
    return fpMultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
}

// 拦截 Unicode -> ANSI 转换
int WINAPI Detour_WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar) {
    if (g_FakeACP && (CodePage == CP_ACP || CodePage == CP_THREAD_ACP || CodePage == CP_OEMCP)) {
        CodePage = g_FakeACP;
    }
    return fpWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
}

// --- [新增] Ntdll 字符串转换 Hook (底层核心) ---
// 很多程序内部使用这个函数而不是 MultiByteToWideChar
NTSTATUS NTAPI Detour_RtlMultiByteToUnicodeN(PWCH UnicodeString, ULONG MaxBytesInUnicodeString, PULONG BytesInUnicodeString, PCSTR MultiByteString, ULONG BytesInMultiByteString) {
    // 这里的逻辑稍微复杂 因为 Rtl 函数不接受 CodePage 参数 它默认使用系统当前 ANSI 代码页
    // 我们必须手动实现转换 强制使用 g_FakeACP

    if (g_FakeACP != 0) {
        int wLen = 0;
        // 计算所需长度
        // 注意：MaxBytesInUnicodeString 是字节数 不是字符数
        int maxChars = MaxBytesInUnicodeString / sizeof(WCHAR);

        // 如果只查询长度 (UnicodeString == NULL)
        if (!UnicodeString) {
            wLen = MultiByteToWideChar(g_FakeACP, 0, MultiByteString, BytesInMultiByteString, NULL, 0);
            if (BytesInUnicodeString) *BytesInUnicodeString = wLen * sizeof(WCHAR);
            return STATUS_SUCCESS;
        }

        // 执行转换
        wLen = MultiByteToWideChar(g_FakeACP, 0, MultiByteString, BytesInMultiByteString, UnicodeString, maxChars);

        if (BytesInUnicodeString) *BytesInUnicodeString = wLen * sizeof(WCHAR);
        return STATUS_SUCCESS;
    }

    return fpRtlMultiByteToUnicodeN(UnicodeString, MaxBytesInUnicodeString, BytesInUnicodeString, MultiByteString, BytesInMultiByteString);
}

NTSTATUS NTAPI Detour_RtlUnicodeToMultiByteN(PCHAR MultiByteString, ULONG MaxBytesInMultiByteString, PULONG BytesInMultiByteString, PCWSTR UnicodeString, ULONG BytesInUnicodeString) {
    if (g_FakeACP != 0) {
        int aLen = 0;
        int charsInUnicode = BytesInUnicodeString / sizeof(WCHAR);

        if (!MultiByteString) {
            aLen = WideCharToMultiByte(g_FakeACP, 0, UnicodeString, charsInUnicode, NULL, 0, NULL, NULL);
            if (BytesInMultiByteString) *BytesInMultiByteString = aLen;
            return STATUS_SUCCESS;
        }

        aLen = WideCharToMultiByte(g_FakeACP, 0, UnicodeString, charsInUnicode, MultiByteString, MaxBytesInMultiByteString, NULL, NULL);

        if (BytesInMultiByteString) *BytesInMultiByteString = aLen;
        return STATUS_SUCCESS;
    }

    return fpRtlUnicodeToMultiByteN(MultiByteString, MaxBytesInMultiByteString, BytesInMultiByteString, UnicodeString, BytesInUnicodeString);
}

// --- [新增] ANSI 字体创建 Hook (解决字体名乱码) ---
HFONT WINAPI Detour_CreateFontIndirectA(const LOGFONTA* lplf) {
    if (g_FakeACP == 0) return fpCreateFontIndirectA(lplf);

    // 1. 将 LOGFONTA 转换为 LOGFONTW
    // 关键点：使用 g_FakeACP 进行转换！
    // 如果不 Hook 这里 系统会用 CP_ACP (如 936) 转换 Shift-JIS 名字 结果就是乱码
    LOGFONTW lfw = { 0 };

    lfw.lfHeight = lplf->lfHeight;
    lfw.lfWidth = lplf->lfWidth;
    lfw.lfEscapement = lplf->lfEscapement;
    lfw.lfOrientation = lplf->lfOrientation;
    lfw.lfWeight = lplf->lfWeight;
    lfw.lfItalic = lplf->lfItalic;
    lfw.lfUnderline = lplf->lfUnderline;
    lfw.lfStrikeOut = lplf->lfStrikeOut;
    lfw.lfCharSet = lplf->lfCharSet;
    lfw.lfOutPrecision = lplf->lfOutPrecision;
    lfw.lfClipPrecision = lplf->lfClipPrecision;
    lfw.lfQuality = lplf->lfQuality;
    lfw.lfPitchAndFamily = lplf->lfPitchAndFamily;

    // 使用伪造的代码页转换字体名称
    MultiByteToWideChar(g_FakeACP, 0, lplf->lfFaceName, -1, lfw.lfFaceName, LF_FACESIZE);

    // 2. 强制字符集 (双重保险)
    if (g_FakeCharSet != 0) {
        if (lfw.lfCharSet == DEFAULT_CHARSET || lfw.lfCharSet == ANSI_CHARSET) {
            lfw.lfCharSet = g_FakeCharSet;
        }
    }

    // 3. 字体名称替换 (如果配置了 hookfont)
    if (!g_OverrideFontName.empty()) {
        OverrideLogFontName(lfw.lfFaceName);
    }

    // 4. 调用 Wide 版本 (它已经被我们 Hook 了 或者直接调用原始的)
    // 这里直接调用 CreateFontIndirectW 系统会自动处理
    return CreateFontIndirectW(&lfw);
}

HFONT WINAPI Detour_CreateFontA(int cHeight, int cWidth, int cEscapement, int cOrientation, int cWeight, DWORD bItalic, DWORD bUnderline, DWORD bStrikeOut, DWORD iCharSet, DWORD iOutPrecision, DWORD iClipPrecision, DWORD iQuality, DWORD iPitchAndFamily, LPCSTR pszFaceName) {
    // 构造 LOGFONTA 并转发给 Detour_CreateFontIndirectA
    LOGFONTA lfa;
    lfa.lfHeight = cHeight;
    lfa.lfWidth = cWidth;
    lfa.lfEscapement = cEscapement;
    lfa.lfOrientation = cOrientation;
    lfa.lfWeight = cWeight;
    lfa.lfItalic = (BYTE)bItalic;
    lfa.lfUnderline = (BYTE)bUnderline;
    lfa.lfStrikeOut = (BYTE)bStrikeOut;
    lfa.lfCharSet = (BYTE)iCharSet;
    lfa.lfOutPrecision = (BYTE)iOutPrecision;
    lfa.lfClipPrecision = (BYTE)iClipPrecision;
    lfa.lfQuality = (BYTE)iQuality;
    lfa.lfPitchAndFamily = (BYTE)iPitchAndFamily;

    if (pszFaceName) {
        strncpy_s(lfa.lfFaceName, pszFaceName, LF_FACESIZE - 1);
    } else {
        lfa.lfFaceName[0] = 0;
    }

    return Detour_CreateFontIndirectA(&lfa);
}

// --- [新增] 注册表 ANSI <-> Unicode 转换辅助 ---

// 使用伪造的代码页将 ANSI 路径转换为 Unicode
std::wstring SpoofAnsiToWide(LPCSTR ansiStr) {
    if (!ansiStr) return L"";
    UINT cp = g_FakeACP ? g_FakeACP : CP_ACP;
    int len = MultiByteToWideChar(cp, 0, ansiStr, -1, NULL, 0);
    if (len <= 0) return L"";
    std::vector<wchar_t> buf(len);
    MultiByteToWideChar(cp, 0, ansiStr, -1, buf.data(), len);
    return std::wstring(buf.data());
}

// 使用伪造的代码页将 Unicode 转换回 ANSI (用于 QueryValue 返回数据)
std::string SpoofWideToAnsi(LPCWSTR wideStr, int len = -1) {
    if (!wideStr) return "";
    UINT cp = g_FakeACP ? g_FakeACP : CP_ACP;
    int aLen = WideCharToMultiByte(cp, 0, wideStr, len, NULL, 0, NULL, NULL);
    if (aLen <= 0) return "";
    std::vector<char> buf(aLen + 1); // +1 安全起见
    WideCharToMultiByte(cp, 0, wideStr, len, buf.data(), aLen, NULL, NULL);
    if (len == -1) buf[aLen] = 0; // 确保 NULL 结尾
    return std::string(buf.data(), aLen); // 注意这里构造 string 的长度
}

// --- [新增] ANSI 注册表 Hook 实现 ---

LSTATUS WINAPI Detour_RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
    if (g_FakeACP != 0) {
        // 1. 将 Shift-JIS 路径转为 Unicode
        std::wstring wSubKey = SpoofAnsiToWide(lpSubKey);
        // 2. 调用 Unicode API
        return RegOpenKeyExW(hKey, wSubKey.c_str(), ulOptions, samDesired, phkResult);
    }
    return fpRegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

LSTATUS WINAPI Detour_RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition) {
    if (g_FakeACP != 0) {
        std::wstring wSubKey = SpoofAnsiToWide(lpSubKey);
        std::wstring wClass = SpoofAnsiToWide(lpClass);
        return RegCreateKeyExW(hKey, wSubKey.c_str(), Reserved, lpClass ? (LPWSTR)wClass.c_str() : NULL, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
    }
    return fpRegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
}

LSTATUS WINAPI Detour_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) {
    if (g_FakeACP != 0) {
        std::wstring wValueName = SpoofAnsiToWide(lpValueName);
        DWORD type = 0;
        DWORD wSize = 0;

        // 1. 先查询 Unicode 数据大小
        LSTATUS status = RegQueryValueExW(hKey, wValueName.c_str(), lpReserved, &type, NULL, &wSize);
        if (status != ERROR_SUCCESS) return status;

        // 2. 如果是字符串类型 需要转码
        if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
            std::vector<BYTE> wData(wSize);
            status = RegQueryValueExW(hKey, wValueName.c_str(), lpReserved, &type, wData.data(), &wSize);
            if (status != ERROR_SUCCESS) return status;

            // 转回 Shift-JIS
            std::string aData = SpoofWideToAnsi((LPCWSTR)wData.data(), wSize / sizeof(wchar_t)); // 包含 NULL

            if (lpType) *lpType = type;

            if (lpcbData) {
                if (!lpData) {
                    *lpcbData = (DWORD)aData.size();
                    return ERROR_SUCCESS;
                }
                if (*lpcbData < aData.size()) {
                    *lpcbData = (DWORD)aData.size();
                    return ERROR_MORE_DATA;
                }
                memcpy(lpData, aData.data(), aData.size());
                *lpcbData = (DWORD)aData.size();
            }
            return ERROR_SUCCESS;
        }
        else {
            // 非字符串直接透传 (但需要调用 W 版)
            return RegQueryValueExW(hKey, wValueName.c_str(), lpReserved, lpType, lpData, lpcbData);
        }
    }
    return fpRegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

LSTATUS WINAPI Detour_RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData) {
    if (g_FakeACP != 0) {
        std::wstring wValueName = SpoofAnsiToWide(lpValueName);

        if (dwType == REG_SZ || dwType == REG_EXPAND_SZ || dwType == REG_MULTI_SZ) {
            // 将写入的 Shift-JIS 内容转为 Unicode
            std::wstring wData = SpoofAnsiToWide((LPCSTR)lpData);
            // 注意：cbData 是字节数 RegSetValueExW 需要字节数 (len * 2)
            return RegSetValueExW(hKey, wValueName.c_str(), Reserved, dwType, (const BYTE*)wData.c_str(), (DWORD)(wData.length() + 1) * sizeof(wchar_t));
        } else {
            return RegSetValueExW(hKey, wValueName.c_str(), Reserved, dwType, lpData, cbData);
        }
    }
    return fpRegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

LSTATUS WINAPI Detour_RegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey) {
    if (g_FakeACP != 0) {
        std::wstring wSubKey = SpoofAnsiToWide(lpSubKey);
        return RegDeleteKeyW(hKey, wSubKey.c_str());
    }
    return fpRegDeleteKeyA(hKey, lpSubKey);
}

LSTATUS WINAPI Detour_RegDeleteValueA(HKEY hKey, LPCSTR lpValueName) {
    if (g_FakeACP != 0) {
        std::wstring wValueName = SpoofAnsiToWide(lpValueName);
        return RegDeleteValueW(hKey, wValueName.c_str());
    }
    return fpRegDeleteValueA(hKey, lpValueName);
}

// --- [新增] 窗口标题乱码修复 Hook ---

HWND WINAPI Detour_CreateWindowExA(
    DWORD dwExStyle,
    LPCSTR lpClassName,
    LPCSTR lpWindowName,
    DWORD dwStyle,
    int X,
    int Y,
    int nWidth,
    int nHeight,
    HWND hWndParent,
    HMENU hMenu,
    HINSTANCE hInstance,
    LPVOID lpParam
) {
    if (g_FakeACP != 0) {
        // 1. 转码窗口标题 (WindowName)
        std::wstring wWindowName = SpoofAnsiToWide(lpWindowName);

        // 2. 转码窗口类名 (ClassName) - 注意类名可能是 ATOM
        std::wstring wClassName;
        LPCWSTR lpWClass = NULL;

        if (IS_ATOM(lpClassName)) {
            lpWClass = (LPCWSTR)lpClassName; // ATOM 直接透传
        } else {
            wClassName = SpoofAnsiToWide(lpClassName);
            lpWClass = wClassName.c_str();
        }

        // 3. 调用 Unicode 版本 API (CreateWindowExW)
        // 这样 Windows 接收到的就是正确的 Unicode 字符 不会乱码
        return CreateWindowExW(
            dwExStyle,
            lpWClass,
            wWindowName.c_str(),
            dwStyle,
            X, Y, nWidth, nHeight,
            hWndParent,
            hMenu,
            hInstance,
            lpParam
        );
    }
    return fpCreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

int WINAPI Detour_GetWindowTextA(HWND hWnd, LPSTR lpString, int nMaxCount) {
    if (g_FakeACP != 0 && nMaxCount > 0) {
        // 1. 获取 Unicode 标题
        int wLen = GetWindowTextLengthW(hWnd);
        if (wLen == 0) {
            if (lpString) lpString[0] = 0;
            return 0;
        }

        std::vector<wchar_t> wBuf(wLen + 1);
        GetWindowTextW(hWnd, wBuf.data(), wLen + 1);

        // 2. 转回 Shift-JIS (欺骗程序它读到的是 ANSI)
        std::string aStr = SpoofWideToAnsi(wBuf.data());

        // 3. 复制到缓冲区
        int copyLen = min((int)aStr.length(), nMaxCount - 1);
        memcpy(lpString, aStr.c_str(), copyLen);
        lpString[copyLen] = 0;

        return copyLen;
    }
    return fpGetWindowTextA(hWnd, lpString, nMaxCount);
}

// 拦截默认窗口过程 处理 WM_SETTEXT 消息
LRESULT WINAPI Detour_DefWindowProcA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    if (g_FakeACP != 0) {
        // 当消息到达这里时 lParam 依然是 Shift-JIS 编码
        // 我们在这里将其转为 Unicode 并交给 Unicode 版的 DefWindowProc 进行绘制
        if (Msg == WM_SETTEXT && lParam != 0) {
            std::wstring wText = SpoofAnsiToWide((LPCSTR)lParam);
            return DefWindowProcW(hWnd, Msg, wParam, (LPARAM)wText.c_str());
        }

        // 处理获取标题
        if (Msg == WM_GETTEXT && lParam != 0 && wParam > 0) {
            std::vector<wchar_t> wBuf(wParam + 1);
            LRESULT wResult = DefWindowProcW(hWnd, Msg, wParam, (LPARAM)wBuf.data());

            std::string aStr = SpoofWideToAnsi(wBuf.data());
            size_t copyLen = min((size_t)wParam - 1, aStr.length());
            memcpy((void*)lParam, aStr.c_str(), copyLen);
            ((char*)lParam)[copyLen] = 0;
            return copyLen;
        }
    }
    return fpDefWindowProcA(hWnd, Msg, wParam, lParam);
}

// --- [新增] SendMessageA 专用处理逻辑 (移植自 Locale Remulator) ---

// 处理输入字符串的消息 (如 WM_SETTEXT, LB_ADDSTRING)
// 将 ANSI(Shift-JIS) 转为 Unicode 后转发给 SendMessageW
LRESULT Handle_AnsiInString(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    if (lParam == 0) return SendMessageW(hWnd, Msg, wParam, 0);

    std::wstring wStr = SpoofAnsiToWide((LPCSTR)lParam);
    return SendMessageW(hWnd, Msg, wParam, (LPARAM)wStr.c_str());
}

// 处理输出字符串的消息 (如 WM_GETTEXT)
// 调用 W 版获取 Unicode 再转回 ANSI(Shift-JIS) 写入缓冲区
LRESULT Handle_AnsiOutString(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    if (lParam == 0 || wParam == 0) return 0;

    // 1. 准备 Unicode 缓冲区
    // wParam 通常是缓冲区大小 (字符数)
    std::vector<wchar_t> wBuf(wParam + 1, 0);

    // 2. 调用 W 版 API
    LRESULT wResult = SendMessageW(hWnd, Msg, wParam, (LPARAM)wBuf.data());

    // 3. 转回 ANSI
    std::string aStr = SpoofWideToAnsi(wBuf.data());

    // 4. 写入用户缓冲区 (注意截断)
    size_t copyLen = min((size_t)wParam - 1, aStr.length());
    if (copyLen > 0) {
        memcpy((void*)lParam, aStr.c_str(), copyLen);
    }
    ((char*)lParam)[copyLen] = 0; // 确保 NULL 结尾

    return copyLen;
}

// 处理 ListBox/ComboBox 获取文本 (LB_GETTEXT, CB_GETLBTEXT)
// 这些消息的 wParam 是索引 lParam 是缓冲区 且不传递缓冲区大小(危险!)
// 需要先获取长度 分配 Unicode 缓冲区 获取内容 再转码
LRESULT Handle_ListGetText(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    if (lParam == 0) return 0;

    // 确定对应的获取长度消息
    UINT msgGetLen = (Msg == LB_GETTEXT) ? LB_GETTEXTLEN : CB_GETLBTEXTLEN;

    // 1. 获取 Unicode 长度
    LRESULT wLen = SendMessageW(hWnd, msgGetLen, wParam, 0);
    if (wLen == LB_ERR || wLen == CB_ERR) return wLen;

    // 2. 分配 Unicode 缓冲区
    std::vector<wchar_t> wBuf(wLen + 1, 0);

    // 3. 获取 Unicode 文本
    SendMessageW(hWnd, Msg, wParam, (LPARAM)wBuf.data());

    // 4. 转回 ANSI
    std::string aStr = SpoofWideToAnsi(wBuf.data());

    // 5. 写入用户缓冲区 (假设用户已分配足够空间 这是 Win32 API 的约定)
    strcpy((char*)lParam, aStr.c_str());

    return aStr.length();
}

// 处理获取文本长度的消息 (WM_GETTEXTLENGTH, LB_GETTEXTLEN)
// 获取 Unicode 长度 -> 转为 ANSI 后的字节数
LRESULT Handle_GetTextLength(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    // 1. 获取 Unicode 长度
    LRESULT wLen = SendMessageW(hWnd, Msg, wParam, lParam);
    if (wLen <= 0) return wLen;

    // 2. 获取实际内容以计算 ANSI 长度
    // 注意：对于 LB/CB wParam 是索引；对于 WM wParam 通常忽略
    UINT msgGetText = 0;
    if (Msg == LB_GETTEXTLEN) msgGetText = LB_GETTEXT;
    else if (Msg == CB_GETLBTEXTLEN) msgGetText = CB_GETLBTEXT;
    else msgGetText = WM_GETTEXT;

    std::vector<wchar_t> wBuf(wLen + 1, 0);

    if (msgGetText == WM_GETTEXT) {
        SendMessageW(hWnd, msgGetText, wLen + 1, (LPARAM)wBuf.data());
    } else {
        SendMessageW(hWnd, msgGetText, wParam, (LPARAM)wBuf.data());
    }

    // 3. 计算转码后的长度
    int aLen = WideCharToMultiByte(g_FakeACP ? g_FakeACP : CP_ACP, 0, wBuf.data(), -1, NULL, 0, NULL, NULL);
    return (aLen > 0) ? aLen - 1 : 0;
}

// 处理窗口创建消息 (WM_CREATE, WM_NCCREATE)
// 需要转换 CREATESTRUCTA 结构体中的类名和窗口名
LRESULT Handle_CreateStruct(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    if (lParam == 0) return SendMessageW(hWnd, Msg, wParam, lParam);

    LPCREATESTRUCTA pCsA = (LPCREATESTRUCTA)lParam;

    // 构造 W 版结构体
    CREATESTRUCTW csW = { 0 };
    // 复制基本成员
    csW.lpCreateParams = pCsA->lpCreateParams;
    csW.hInstance = pCsA->hInstance;
    csW.hMenu = pCsA->hMenu;
    csW.hwndParent = pCsA->hwndParent;
    csW.cy = pCsA->cy;
    csW.cx = pCsA->cx;
    csW.y = pCsA->y;
    csW.x = pCsA->x;
    csW.style = pCsA->style;
    csW.dwExStyle = pCsA->dwExStyle;

    // 转换字符串 (注意类名可能是 ATOM)
    std::wstring wName, wClass;

    if (pCsA->lpszName) {
        wName = SpoofAnsiToWide(pCsA->lpszName);
        csW.lpszName = wName.c_str();
    }

    if (IS_ATOM(pCsA->lpszClass)) {
        csW.lpszClass = (LPCWSTR)pCsA->lpszClass;
    } else if (pCsA->lpszClass) {
        wClass = SpoofAnsiToWide(pCsA->lpszClass);
        csW.lpszClass = wClass.c_str();
    }

    return SendMessageW(hWnd, Msg, wParam, (LPARAM)&csW);
}

// 处理 MDI 子窗口创建 (WM_MDICREATE)
LRESULT Handle_MdiCreateStruct(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    if (lParam == 0) return SendMessageW(hWnd, Msg, wParam, lParam);

    LPMDICREATESTRUCTA pMdiA = (LPMDICREATESTRUCTA)lParam;
    MDICREATESTRUCTW mdiW = { 0 };

    mdiW.hOwner = pMdiA->hOwner;
    mdiW.x = pMdiA->x;
    mdiW.y = pMdiA->y;
    mdiW.cx = pMdiA->cx;
    mdiW.cy = pMdiA->cy;
    mdiW.style = pMdiA->style;
    mdiW.lParam = pMdiA->lParam;

    std::wstring wClass, wTitle;

    if (IS_ATOM(pMdiA->szClass)) {
        mdiW.szClass = (LPCWSTR)pMdiA->szClass;
    } else if (pMdiA->szClass) {
        wClass = SpoofAnsiToWide(pMdiA->szClass);
        mdiW.szClass = wClass.c_str();
    }

    if (pMdiA->szTitle) {
        wTitle = SpoofAnsiToWide(pMdiA->szTitle);
        mdiW.szTitle = wTitle.c_str();
    }

    return SendMessageW(hWnd, Msg, wParam, (LPARAM)&mdiW);
}

// --- [新增] SendMessageA Hook (解决标题栏/控件乱码) ---
LRESULT WINAPI Detour_SendMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    // 如果没有启用区域伪造 直接调用原始函数
    if (g_FakeACP == 0) {
        return fpSendMessageA(hWnd, Msg, wParam, lParam);
    }

    switch (Msg) {
        // --- 1. 输入字符串类消息 (ANSI -> Unicode) ---
        case WM_SETTEXT:
        case WM_SETTINGCHANGE:
        case WM_DEVMODECHANGE:
        case EM_REPLACESEL:
        // ListBox
        case LB_ADDSTRING:
        case LB_INSERTSTRING:
        case LB_SELECTSTRING:
        case LB_FINDSTRING:
        case LB_FINDSTRINGEXACT:
        case LB_DIR:
        // ComboBox
        case CB_ADDSTRING:
        case CB_INSERTSTRING:
        case CB_SELECTSTRING:
        case CB_FINDSTRING:
        case CB_FINDSTRINGEXACT:
        case CB_DIR:
        {
            return Handle_AnsiInString(hWnd, Msg, wParam, lParam);
        }

        // --- 2. 输出字符串类消息 (Unicode -> ANSI) ---
        case WM_GETTEXT:
        case WM_ASKCBFORMATNAME:
        {
            return Handle_AnsiOutString(hWnd, Msg, wParam, lParam);
        }

        // --- 3. 列表框获取文本 (特殊处理) ---
        case LB_GETTEXT:
        case CB_GETLBTEXT:
        {
            return Handle_ListGetText(hWnd, Msg, wParam, lParam);
        }

        // --- 4. 获取长度类消息 ---
        case WM_GETTEXTLENGTH:
        case LB_GETTEXTLEN:
        case CB_GETLBTEXTLEN:
        {
            return Handle_GetTextLength(hWnd, Msg, wParam, lParam);
        }

        // --- 5. 窗口创建类消息 ---
        case WM_CREATE:
        case WM_NCCREATE:
        {
            return Handle_CreateStruct(hWnd, Msg, wParam, lParam);
        }
        case WM_MDICREATE:
        {
            return Handle_MdiCreateStruct(hWnd, Msg, wParam, lParam);
        }
    }

    // 其他消息直接透传
    return fpSendMessageA(hWnd, Msg, wParam, lParam);
}

// --- [新增] 强制退出 Hook (解决进程残留) ---

void WINAPI Detour_ExitProcess(UINT uExitCode) {
    // 这里的关键是使用 TerminateProcess 而不是 ExitProcess
    // ExitProcess 会尝试通知所有 DLL (DLL_PROCESS_DETACH) 并等待线程结束 容易导致死锁
    // TerminateProcess 是内核级强制查杀 瞬间结束 不留后患
    TerminateProcess(GetCurrentProcess(), uExitCode);
}

NTSTATUS NTAPI Detour_NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
    // 如果程序尝试结束自己
    if (!ProcessHandle || ProcessHandle == GetCurrentProcess()) {
        TerminateProcess(GetCurrentProcess(), 0); // 强制退出
        return STATUS_SUCCESS; // 实际上永远不会执行到这里
    }
    return fpNtTerminateProcess(ProcessHandle, ExitStatus);
}

// --- [新增] ANSI 字体枚举 Hook (补充) ---
// 某些游戏使用 ANSI 版枚举字体 如果不 Hook 传入的 Shift-JIS 字体名会被错误解析

int WINAPI Detour_EnumFontFamiliesExA(HDC hdc, LPLOGFONTA lpLogfont, FONTENUMPROCA lpEnumFontFamExProc, LPARAM lParam, DWORD dwFlags) {
    if (g_FakeCharSet != 0 && lpLogfont) {
        // 强制修改请求的字符集
        if (lpLogfont->lfCharSet == DEFAULT_CHARSET || lpLogfont->lfCharSet == ANSI_CHARSET) {
            // 我们不能直接修改 const 指针指向的内容 所以复制一份
            LOGFONTA newLf = *lpLogfont;
            newLf.lfCharSet = g_FakeCharSet;
            return fpEnumFontFamiliesExA(hdc, &newLf, lpEnumFontFamExProc, lParam, dwFlags);
        }
    }
    return fpEnumFontFamiliesExA(hdc, lpLogfont, lpEnumFontFamExProc, lParam, dwFlags);
}

int WINAPI Detour_EnumFontFamiliesA(HDC hdc, LPCSTR lpszFamily, FONTENUMPROCA lpEnumFontFamProc, LPARAM lParam) {
    // EnumFontFamiliesA 比较古老 通常没有 CharSet 参数 直接透传即可
    // 如果需要更严格的控制 可以转码后调用 W 版 但通常没必要
    return fpEnumFontFamiliesA(hdc, lpszFamily, lpEnumFontFamProc, lParam);
}

// --- [新增] 代码页信息 Hook (模拟底层 NLS 缓存修改) ---

BOOL WINAPI Detour_GetCPInfo(UINT CodePage, LPCPINFO lpCPInfo) {
    // 如果程序查询系统默认代码页 将其重定向到我们伪造的代码页
    if (g_FakeACP != 0) {
        if (CodePage == CP_ACP || CodePage == CP_OEMCP || CodePage == CP_THREAD_ACP) {
            CodePage = g_FakeACP;
        }
    }
    return fpGetCPInfo(CodePage, lpCPInfo);
}

BOOL WINAPI Detour_GetCPInfoExW(UINT CodePage, DWORD dwFlags, LPCPINFOEXW lpCPInfoEx) {
    if (g_FakeACP != 0) {
        if (CodePage == CP_ACP || CodePage == CP_OEMCP || CodePage == CP_THREAD_ACP) {
            CodePage = g_FakeACP;
        }
    }
    return fpGetCPInfoExW(CodePage, dwFlags, lpCPInfoEx);
}

BOOL WINAPI Detour_IsValidCodePage(UINT CodePage) {
    // 确保程序询问“伪造的代码页是否有效”时返回真
    if (g_FakeACP != 0 && CodePage == g_FakeACP) {
        return TRUE;
    }
    return fpIsValidCodePage(CodePage);
}

// --- [新增] 从注册表加载时区信息 ---
bool LoadTimeZoneFromRegistry(const std::wstring& timeZoneName) {
    std::wstring keyPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\" + timeZoneName;
    HKEY hKey;

    // 打开 HKLM 下的时区键
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        DebugLog(L"TimeZone: Failed to open registry key for '%s'", timeZoneName.c_str());
        return false;
    }

    DWORD type, size;
    REG_TZI_FORMAT tziBin = { 0 };

    // 1. 读取 TZI 二进制数据
    size = sizeof(tziBin);
    if (RegQueryValueExW(hKey, L"TZI", NULL, &type, (LPBYTE)&tziBin, &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }

    // 2. 读取显示名称 (Std / Dlt)
    wchar_t stdName[32] = { 0 };
    wchar_t dltName[32] = { 0 };

    size = sizeof(stdName);
    RegQueryValueExW(hKey, L"Std", NULL, NULL, (LPBYTE)stdName, &size);

    size = sizeof(dltName);
    RegQueryValueExW(hKey, L"Dlt", NULL, NULL, (LPBYTE)dltName, &size);

    RegCloseKey(hKey);

    // 3. 填充全局结构
    ZeroMemory(&g_FakeDTZI, sizeof(g_FakeDTZI));
    g_FakeDTZI.Bias = tziBin.Bias;
    g_FakeDTZI.StandardBias = tziBin.StandardBias;
    g_FakeDTZI.DaylightBias = tziBin.DaylightBias;
    g_FakeDTZI.StandardDate = tziBin.StandardDate;
    g_FakeDTZI.DaylightDate = tziBin.DaylightDate;

    wcscpy_s(g_FakeDTZI.StandardName, stdName);
    wcscpy_s(g_FakeDTZI.DaylightName, dltName);
    // TimeZoneKeyName 设为请求的名称
    wcscpy_s(g_FakeDTZI.TimeZoneKeyName, timeZoneName.c_str());

    // 禁用动态夏令时 (通常老游戏不需要 且简化处理)
    g_FakeDTZI.DynamicDaylightTimeDisabled = TRUE;

    return true;
}

// --- [新增] 时区 Hook 实现 ---

DWORD WINAPI Detour_GetTimeZoneInformation(LPTIME_ZONE_INFORMATION lpTimeZoneInformation) {
    if (g_EnableTimeZoneHook && lpTimeZoneInformation) {
        // 将 Dynamic 结构转为普通结构
        lpTimeZoneInformation->Bias = g_FakeDTZI.Bias;
        wcscpy_s(lpTimeZoneInformation->StandardName, g_FakeDTZI.StandardName);
        lpTimeZoneInformation->StandardDate = g_FakeDTZI.StandardDate;
        lpTimeZoneInformation->StandardBias = g_FakeDTZI.StandardBias;
        wcscpy_s(lpTimeZoneInformation->DaylightName, g_FakeDTZI.DaylightName);
        lpTimeZoneInformation->DaylightDate = g_FakeDTZI.DaylightDate;
        lpTimeZoneInformation->DaylightBias = g_FakeDTZI.DaylightBias;

        return TIME_ZONE_ID_STANDARD; // 假装当前处于标准时间
    }
    return fpGetTimeZoneInformation(lpTimeZoneInformation);
}

DWORD WINAPI Detour_GetDynamicTimeZoneInformation(PDYNAMIC_TIME_ZONE_INFORMATION pTimeZoneInformation) {
    if (g_EnableTimeZoneHook && pTimeZoneInformation) {
        *pTimeZoneInformation = g_FakeDTZI;
        return TIME_ZONE_ID_STANDARD;
    }
    return fpGetDynamicTimeZoneInformation(pTimeZoneInformation);
}

// 拦截 Ntdll 的系统信息查询 (很多底层库使用此 API 获取时区)
NTSTATUS NTAPI Detour_NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    // 1. 处理时区伪造 (SystemCurrentTimeZoneInformation = 44)
    if (g_EnableTimeZoneHook && (int)SystemInformationClass == 44) {
        if (SystemInformation && SystemInformationLength >= sizeof(RTL_TIME_ZONE_INFORMATION)) {
            // RTL_TIME_ZONE_INFORMATION 结构与 TIME_ZONE_INFORMATION 几乎一致
            LPTIME_ZONE_INFORMATION pTzi = (LPTIME_ZONE_INFORMATION)SystemInformation;

            pTzi->Bias = g_FakeDTZI.Bias;
            wcscpy_s(pTzi->StandardName, g_FakeDTZI.StandardName);
            pTzi->StandardDate = g_FakeDTZI.StandardDate;
            pTzi->StandardBias = g_FakeDTZI.StandardBias;
            wcscpy_s(pTzi->DaylightName, g_FakeDTZI.DaylightName);
            pTzi->DaylightDate = g_FakeDTZI.DaylightDate;
            pTzi->DaylightBias = g_FakeDTZI.DaylightBias;

            if (ReturnLength) *ReturnLength = sizeof(RTL_TIME_ZONE_INFORMATION);
            return STATUS_SUCCESS;
        }
    }

    // 2. 调用原始函数获取其他信息
    NTSTATUS status = fpNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    // 3. 处理时间伪造 (SystemTimeOfDayInformation = 3)
    if (NT_SUCCESS(status) && g_EnableTimeHook && SystemInformation && (int)SystemInformationClass == 3 && !g_InTimeHook) {
        if (SystemInformationLength >= sizeof(YAP_SYSTEM_TIMEOFDAY_INFORMATION)) {
            PYAP_SYSTEM_TIMEOFDAY_INFORMATION pInfo = (PYAP_SYSTEM_TIMEOFDAY_INFORMATION)SystemInformation;
            pInfo->CurrentTime.QuadPart += g_TimeOffset;
            pInfo->BootTime.QuadPart += g_TimeOffset; // 视情况启用
        }
    }

    return fpNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

// --- [新增] 资源加载 Hook ---
NTSTATUS NTAPI Detour_LdrResSearchResource(
    PVOID DllHandle,
    PULONG_PTR ResourceIdPath,
    ULONG ResourceIdPathLength,
    ULONG Flags,
    PVOID* Resource,
    PULONG Size,
    PVOID Reserve1,
    PVOID Reserve2
) {
    // 如果启用了区域伪造 且正在查找 RT_VERSION (版本信息) 或其他资源
    if (g_FakeLangID != 0 && ResourceIdPath && ResourceIdPathLength >= 3) {
        // ResourceIdPath[0] = Type, [1] = Name, [2] = Language

        // 强制修改请求的语言 ID 为我们伪造的语言 (例如 0x0411)
        // 注意：ResourceIdPath 是调用者栈上的数组 直接修改可能会影响调用者
        // 但通常 LdrResSearchResource 是只读读取的为了安全 我们可以复制一份

        // 这里采用简化的直接修改策略 因为在 Ntdll 内部通常是安全的
        // 只有当指定了特定语言时才修改 (如果由系统默认查找 通常 ResourceIdPath[2] 为 0)
        if (ResourceIdPath[2] != 0) {
             ResourceIdPath[2] = g_FakeLangID;
        }
    }

    NTSTATUS status = fpLdrResSearchResource(DllHandle, ResourceIdPath, ResourceIdPathLength, Flags, Resource, Size, Reserve1, Reserve2);

    // LE 还有一个 ReplaceMUIVersionLocaleInfo 的逻辑 用于修改版本信息中的语言
    // 这对于某些检查 EXE 版本的安装程序很有用 但对于运行游戏通常不是必须的

    return status;
}

// --- [新增] 时间伪造 Hook 实现 ---

// 辅助：FILETIME 加减运算
void AddTimeOffset(LPFILETIME lpFt) {
    if (lpFt && g_EnableTimeHook) {
        ULARGE_INTEGER uli;
        uli.LowPart = lpFt->dwLowDateTime;
        uli.HighPart = lpFt->dwHighDateTime;
        uli.QuadPart += g_TimeOffset;
        lpFt->dwLowDateTime = uli.LowPart;
        lpFt->dwHighDateTime = uli.HighPart;
    }
}

// 辅助：SYSTEMTIME 转 FILETIME
void SystemTimeToFileTimeHelper(const SYSTEMTIME* st, FILETIME* ft) {
    SystemTimeToFileTime(st, ft);
}

// 辅助：FILETIME 转 SYSTEMTIME
void FileTimeToSystemTimeHelper(const FILETIME* ft, SYSTEMTIME* st) {
    FileTimeToSystemTime(ft, st);
}

VOID WINAPI Detour_GetSystemTime(LPSYSTEMTIME lpSystemTime) {
    // [关键修复] 如果已经在 Hook 链中（例如被其他 API 调用） 直接透传 不重复修改
    if (g_InTimeHook) {
        fpGetSystemTime(lpSystemTime);
        return;
    }

    {
        TimeRecursionGuard guard;
        fpGetSystemTime(lpSystemTime);
    }

    if (g_EnableTimeHook && lpSystemTime) {
        FILETIME ft;
        SystemTimeToFileTimeHelper(lpSystemTime, &ft);
        AddTimeOffset(&ft);
        FileTimeToSystemTimeHelper(&ft, lpSystemTime);
    }
}

VOID WINAPI Detour_GetLocalTime(LPSYSTEMTIME lpSystemTime) {
    if (g_InTimeHook) {
        fpGetLocalTime(lpSystemTime);
        return;
    }

    {
        TimeRecursionGuard guard;
        fpGetLocalTime(lpSystemTime);
    }

    if (g_EnableTimeHook && lpSystemTime) {
        FILETIME ft;
        SystemTimeToFileTimeHelper(lpSystemTime, &ft);
        AddTimeOffset(&ft);
        FileTimeToSystemTimeHelper(&ft, lpSystemTime);
    }
}

VOID WINAPI Detour_GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime) {
    if (g_InTimeHook) {
        fpGetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
        return;
    }

    {
        TimeRecursionGuard guard;
        fpGetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
    }
    AddTimeOffset(lpSystemTimeAsFileTime);
}

VOID WINAPI Detour_GetSystemTimePreciseAsFileTime(LPFILETIME lpSystemTimeAsFileTime) {
    if (!fpGetSystemTimePreciseAsFileTime) return;

    if (g_InTimeHook) {
        fpGetSystemTimePreciseAsFileTime(lpSystemTimeAsFileTime);
        return;
    }

    {
        TimeRecursionGuard guard;
        fpGetSystemTimePreciseAsFileTime(lpSystemTimeAsFileTime);
    }
    AddTimeOffset(lpSystemTimeAsFileTime);
}

// 拦截底层系统调用 NtQuerySystemTime
NTSTATUS NTAPI Detour_NtQuerySystemTime(PLARGE_INTEGER SystemTime) {
    NTSTATUS status = fpNtQuerySystemTime(SystemTime);

    // [修改] 增加 !g_InTimeHook 检查
    // 只有当不是由高层 Hook 调用时 才在这里修改时间
    if (NT_SUCCESS(status) && g_EnableTimeHook && SystemTime && !g_InTimeHook) {
        SystemTime->QuadPart += g_TimeOffset;
    }
    return status;
}

NTSTATUS NTAPI Detour_NtQuerySystemInformation_Time(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    // 调用原始函数
    NTSTATUS status = fpNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    // SystemTimeOfDayInformation = 3
    if (NT_SUCCESS(status) && g_EnableTimeHook && SystemInformation && (int)SystemInformationClass == 3) {
        if (SystemInformationLength >= sizeof(YAP_SYSTEM_TIMEOFDAY_INFORMATION)) {
            PYAP_SYSTEM_TIMEOFDAY_INFORMATION pInfo = (PYAP_SYSTEM_TIMEOFDAY_INFORMATION)SystemInformation;

            // 修改当前时间
            pInfo->CurrentTime.QuadPart += g_TimeOffset;

            // 可选：修改启动时间 (BootTime)
            // 如果程序通过 BootTime + TickCount 计算时间 也需要偏移 BootTime
            pInfo->BootTime.QuadPart += g_TimeOffset;
        }
    }

    return status;
}

// --- KernelBase 专用 Detour 函数 ---
VOID WINAPI Detour_GetSystemTime_KB(LPSYSTEMTIME lpSystemTime) {
    if (g_InTimeHook) {
        fpGetSystemTime_KB(lpSystemTime);
        return;
    }

    {
        TimeRecursionGuard guard;
        fpGetSystemTime_KB(lpSystemTime);
    }

    if (g_EnableTimeHook && lpSystemTime) {
        FILETIME ft;
        SystemTimeToFileTimeHelper(lpSystemTime, &ft);
        AddTimeOffset(&ft);
        FileTimeToSystemTimeHelper(&ft, lpSystemTime);
    }
}

VOID WINAPI Detour_GetLocalTime_KB(LPSYSTEMTIME lpSystemTime) {
    if (g_InTimeHook) {
        fpGetLocalTime_KB(lpSystemTime);
        return;
    }

    {
        TimeRecursionGuard guard;
        fpGetLocalTime_KB(lpSystemTime);
    }

    if (g_EnableTimeHook && lpSystemTime) {
        FILETIME ft;
        SystemTimeToFileTimeHelper(lpSystemTime, &ft);
        AddTimeOffset(&ft);
        FileTimeToSystemTimeHelper(&ft, lpSystemTime);
    }
}

VOID WINAPI Detour_GetSystemTimeAsFileTime_KB(LPFILETIME lpSystemTimeAsFileTime) {
    if (g_InTimeHook) {
        fpGetSystemTimeAsFileTime_KB(lpSystemTimeAsFileTime);
        return;
    }

    {
        TimeRecursionGuard guard;
        fpGetSystemTimeAsFileTime_KB(lpSystemTimeAsFileTime);
    }
    AddTimeOffset(lpSystemTimeAsFileTime);
}

VOID WINAPI Detour_GetSystemTimePreciseAsFileTime_KB(LPFILETIME lpSystemTimeAsFileTime) {
    if (!fpGetSystemTimePreciseAsFileTime_KB) return;

    if (g_InTimeHook) {
        fpGetSystemTimePreciseAsFileTime_KB(lpSystemTimeAsFileTime);
        return;
    }

    {
        TimeRecursionGuard guard;
        fpGetSystemTimePreciseAsFileTime_KB(lpSystemTimeAsFileTime);
    }
    AddTimeOffset(lpSystemTimeAsFileTime);
}

// --- [新增] 底层退出 Hook (解决进程残留) ---

// Ntdll 级别的退出函数 比 ExitProcess 更底层
void NTAPI Detour_RtlExitUserProcess(NTSTATUS Status) {
    // 强制终止当前进程 不等待任何线程清理
    TerminateProcess(GetCurrentProcess(), Status);
}

// 看门狗线程：防止 PostQuitMessage 后主循环卡死
DWORD WINAPI SuicideWatchdog(LPVOID) {
    Sleep(2000); // 给主程序 2 秒时间正常退出
    TerminateProcess(GetCurrentProcess(), 0); // 2秒后强制杀进程
    return 0;
}

void WINAPI Detour_PostQuitMessage(int nExitCode) {
    // 当程序请求退出消息循环时 启动一个看门狗线程
    // 如果程序在 2 秒内没有通过正常途径退出 看门狗会强制杀死它
    HANDLE hThread = CreateThread(NULL, 0, SuicideWatchdog, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);

    fpPostQuitMessage(nExitCode);
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

    // [新增] 去除前导空格 防止解析错误
    size_t firstNonSpace = cmd.find_first_not_of(L' ');
    if (firstNonSpace != std::wstring::npos && firstNonSpace > 0) {
        cmd = cmd.substr(firstNonSpace);
    }

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

// 声明伪变量 用于获取当前模块(DLL)的句柄 这是 MSVC 的标准用法
EXTERN_C IMAGE_DOS_HEADER __ImageBase;

// 获取当前 DLL 所在的目录 (不含文件名)
std::wstring GetCurrentDllDir() {
    wchar_t path[MAX_PATH];
    // 使用 &__ImageBase 获取当前 DLL 的句柄 而不是 NULL (EXE)
    if (GetModuleFileNameW((HINSTANCE)&__ImageBase, path, MAX_PATH) == 0) {
        return L"";
    }
    PathRemoveFileSpecW(path);
    return std::wstring(path);
}

// 检查 PE 文件架构 (32/64)
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
                if (ReadFile(hFile, &ntHeaders32, sizeof(ntHeaders32), &bytesRead, NULL) && bytesRead == sizeof(ntHeaders32)) {
                    if (ntHeaders32.Signature == IMAGE_NT_SIGNATURE) {
                        if (ntHeaders32.FileHeader.Machine == IMAGE_FILE_MACHINE_I386) arch = 32;
                        else if (ntHeaders32.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) arch = 64;
                    }
                }
            }
        }
    }
    CloseHandle(hFile);
    return arch;
}

// 直接在当前线程执行注入 (无 IPC 无外部进程)
bool InjectDllDirectly(HANDLE hProcess, const std::wstring& dllPath) {
    if (dllPath.empty()) return false;

    // 获取 LoadLibraryW 地址 (Kernel32 在所有进程中的基址通常相同)
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return false;
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibrary) return false;

    // 在目标进程分配内存
    size_t size = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMem) return false;

    // 写入 DLL 路径
    if (!WriteProcessMemory(hProcess, pRemoteMem, dllPath.c_str(), size, NULL)) {
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        return false;
    }

    // 创建远程线程
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMem, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE); // 等待注入完成
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        return true;
    }

    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    return false;
}

// [新增] 调用外部注入器 (用于跨架构注入)
bool RunExternalInjector(DWORD targetPid, const std::wstring& dllPath, const std::wstring& injectorPath) {
    if (GetFileAttributesW(injectorPath.c_str()) == INVALID_FILE_ATTRIBUTES) return false;

    // 构造命令行: "Injector.exe" <PID> "DLLPath"
    std::wstring cmdLine = L"\"" + injectorPath + L"\" " + std::to_wstring(targetPid) + L" \"" + dllPath + L"\"";

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // 隐藏窗口

    if (CreateProcessW(NULL, &cmdLine[0], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        // 等待注入器结束 (通常很快)
        WaitForSingleObject(pi.hProcess, 5000);

        DWORD exitCode = 1;
        GetExitCodeProcess(pi.hProcess, &exitCode);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return (exitCode == 0);
    }
    return false;
}

// [新增] 跨架构注入并等待握手
bool InjectCrossArchAndWait(DWORD targetPid, const std::wstring& dllPath, const std::wstring& injectorPath) {
    // 1. 创建握手事件 (与 Launcher 逻辑一致)
    std::wstring eventName = GetReadyEventName(targetPid);
    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, eventName.c_str());

    // 2. 执行注入
    bool success = RunExternalInjector(targetPid, dllPath, injectorPath);

    // 3. 等待 Hook 初始化完成
    if (success && hEvent) {
        WaitForSingleObject(hEvent, 3000); // 最多等 3 秒
    }

    if (hEvent) CloseHandle(hEvent);
    return success;
}

// --- 具体钩子实现 ---

// [核心移植] 统一的底层进程创建拦截
BOOL WINAPI Detour_CreateProcessInternalW(
    HANDLE hToken,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    PHANDLE hNewToken
) {
    if (g_IsInHook) {
        return fpCreateProcessInternalW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);
    }
    RecursionGuard guard;
    DWORD lastErr = GetLastError();

    // 1. 路径重定向逻辑 (Portable Mode)
    std::wstring exePathW = lpApplicationName ? lpApplicationName : L"";
    std::wstring cmdLineW = lpCommandLine ? lpCommandLine : L"";

    std::wstring targetExe = GetTargetExePath(exePathW.c_str(), (LPWSTR)cmdLineW.c_str());
    std::wstring redirectedExe = TryRedirectDosPath(targetExe.c_str(), false);

    std::wstring curDirW = lpCurrentDirectory ? lpCurrentDirectory : L"";
    std::wstring redirectedDir = TryRedirectDosPath(curDirW.c_str(), true);

    // 2. Chromium 命令行智能处理
    std::vector<std::wstring> extraArgs;
    if (!cmdLineW.empty()) {
        cmdLineW = CmdUtils::ProcessAndReassemble(cmdLineW, extraArgs);
    }

    // 3. 准备最终参数
    LPCWSTR finalAppName = redirectedExe.empty() ? lpApplicationName : redirectedExe.c_str();
    LPCWSTR finalCurDir = redirectedDir.empty() ? lpCurrentDirectory : redirectedDir.c_str();

    std::vector<wchar_t> wideCmdBuffer;
    LPWSTR finalCmdLinePtr = lpCommandLine;
    if (!cmdLineW.empty()) {
        wideCmdBuffer.assign(cmdLineW.begin(), cmdLineW.end());
        wideCmdBuffer.push_back(L'\0');
        finalCmdLinePtr = wideCmdBuffer.data();
    }

    if (!redirectedExe.empty()) DebugLog(L"CreateProcessInternalW Redirect EXE: %s -> %s", targetExe.c_str(), redirectedExe.c_str());
    if (!redirectedDir.empty()) DebugLog(L"CreateProcessInternalW Redirect DIR: %s -> %s", curDirW.c_str(), redirectedDir.c_str());

    // 4.[移植 Sandboxie 特性] 修复强制挂起时的安全描述符 (Owner) 冲突 BUG
    // 如果调用者指定了 Owner，强制附加 CREATE_SUSPENDED 会导致 STATUS_INVALID_OWNER 错误
    PVOID SaveOwnerProcess = nullptr;
    PVOID SaveOwnerThread = nullptr;

    if (lpProcessAttributes && lpProcessAttributes->lpSecurityDescriptor) {
        SECURITY_DESCRIPTOR* sd = (SECURITY_DESCRIPTOR*)lpProcessAttributes->lpSecurityDescriptor;
        if (sd->Control & SE_SELF_RELATIVE) {
            SaveOwnerProcess = (PVOID)(ULONG_PTR)((SECURITY_DESCRIPTOR_RELATIVE*)sd)->Owner;
            if (SaveOwnerProcess) ((SECURITY_DESCRIPTOR_RELATIVE*)sd)->Owner = 0;
        } else {
            SaveOwnerProcess = sd->Owner;
            if (SaveOwnerProcess) sd->Owner = NULL;
        }
    }
    if (lpThreadAttributes && lpThreadAttributes->lpSecurityDescriptor) {
        SECURITY_DESCRIPTOR* sd = (SECURITY_DESCRIPTOR*)lpThreadAttributes->lpSecurityDescriptor;
        if (sd->Control & SE_SELF_RELATIVE) {
            SaveOwnerThread = (PVOID)(ULONG_PTR)((SECURITY_DESCRIPTOR_RELATIVE*)sd)->Owner;
            if (SaveOwnerThread) ((SECURITY_DESCRIPTOR_RELATIVE*)sd)->Owner = 0;
        } else {
            SaveOwnerThread = sd->Owner;
            if (SaveOwnerThread) sd->Owner = NULL;
        }
    }

    // 5. 准备注入相关的标志位
    PROCESS_INFORMATION localPI = { 0 };
    LPPROCESS_INFORMATION pPI = lpProcessInformation ? lpProcessInformation : &localPI;

    BOOL callerWantedSuspended = (dwCreationFlags & CREATE_SUSPENDED);
    DWORD newCreationFlags = dwCreationFlags | CREATE_SUSPENDED;

    // 6. 调用底层真实 API
    BOOL result = fpCreateProcessInternalW(
        hToken, finalAppName, finalCmdLinePtr,
        lpProcessAttributes, lpThreadAttributes, bInheritHandles,
        newCreationFlags, lpEnvironment, finalCurDir,
        lpStartupInfo, pPI, hNewToken
    );

    // 7. [移植 Sandboxie 特性] 恢复安全描述符的 Owner
    if (SaveOwnerProcess) {
        SECURITY_DESCRIPTOR* sd = (SECURITY_DESCRIPTOR*)lpProcessAttributes->lpSecurityDescriptor;
        if (sd->Control & SE_SELF_RELATIVE) ((SECURITY_DESCRIPTOR_RELATIVE*)sd)->Owner = (DWORD)(ULONG_PTR)SaveOwnerProcess;
        else sd->Owner = SaveOwnerProcess;
    }
    if (SaveOwnerThread) {
        SECURITY_DESCRIPTOR* sd = (SECURITY_DESCRIPTOR*)lpThreadAttributes->lpSecurityDescriptor;
        if (sd->Control & SE_SELF_RELATIVE) ((SECURITY_DESCRIPTOR_RELATIVE*)sd)->Owner = (DWORD)(ULONG_PTR)SaveOwnerThread;
        else sd->Owner = SaveOwnerThread;
    }

    // 8. 注入与恢复逻辑 (保留你原有的优秀跨架构注入逻辑)
    if (result) {
        if (ShouldHookChildProcess(targetExe)) {
            
            // [新增] 过滤 WerFault.exe (Windows 错误报告)，防止注入崩溃导致的无限死循环
            if (wcsstr(targetExe.c_str(), L"WerFault.exe") != nullptr) {
                if (!callerWantedSuspended) ResumeThread(pPI->hThread);
                if (!lpProcessInformation) { CloseHandle(localPI.hProcess); CloseHandle(localPI.hThread); }
                SetLastError(lastErr);
                return result;
            }

            #ifdef _WIN64
            int currentArch = 64;
            #else
            int currentArch = 32;
            #endif

            int targetArch = GetPeArchitecture(targetExe);
            if (targetArch == 0) targetArch = currentArch;

            std::wstring dllDir = GetCurrentDllDir();
            std::wstring targetDllPath;
            if (!dllDir.empty()) {
                targetDllPath = (targetArch == 64) ? (dllDir + L"\\YapHook64.dll") : (dllDir + L"\\YapHook32.dll");
            }
            std::wstring injectorPath = dllDir + L"\\YapInjector32.exe";
            bool injected = false;

            // --- 策略 A: 同架构直接注入 ---
            if (currentArch == targetArch && !targetDllPath.empty() && GetFileAttributesW(targetDllPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                if (InjectDllDirectly(pPI->hProcess, targetDllPath)) {
                    injected = true;
                    std::wstring eventName = GetReadyEventName(pPI->dwProcessId);
                    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, eventName.c_str());
                    if (hEvent) { WaitForSingleObject(hEvent, 5000); CloseHandle(hEvent); }

                    for (const auto& extraDll : g_ExtraDlls) {
                        if (GetFileAttributesW(extraDll.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
                        int dllArch = GetPeArchitecture(extraDll);
                        if (dllArch != 0 && dllArch != targetArch) continue;
                        InjectDllDirectly(pPI->hProcess, extraDll);
                    }
                }
            }

            // --- 策略 B: 异架构直接调用注入器 (64->32) ---
            if (!injected && currentArch == 64 && targetArch == 32 && !targetDllPath.empty() && GetFileAttributesW(injectorPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                if (InjectCrossArchAndWait(pPI->dwProcessId, targetDllPath, injectorPath)) {
                    injected = true;
                    for (const auto& extraDll : g_ExtraDlls) {
                        if (GetFileAttributesW(extraDll.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
                        int dllArch = GetPeArchitecture(extraDll);
                        if (dllArch != 0 && dllArch != targetArch) continue;
                        RunExternalInjector(pPI->dwProcessId, extraDll, injectorPath);
                    }
                }
            }

            // --- 策略 C: IPC 回退 ---
            if (!injected) {
                RequestInjectionFromLauncher(pPI->dwProcessId);
                std::wstring eventName = GetReadyEventName(pPI->dwProcessId);
                HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, eventName.c_str());
                if (hEvent) { WaitForSingleObject(hEvent, 5000); CloseHandle(hEvent); }
            }
        }

        if (!callerWantedSuspended) {
            ResumeThread(pPI->hThread);
        }

        if (!lpProcessInformation) {
            CloseHandle(localPI.hProcess);
            CloseHandle(localPI.hThread);
        }
    }

    SetLastError(lastErr);
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
        if (ShouldHookChildProcess(targetExe)) {
            RequestInjectionFromLauncher(pPI->dwProcessId);
        } else {
            DebugLog(L"ChildHook: Skipped %s (Not in whitelist)", targetExe.c_str());
        }

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
        if (ShouldHookChildProcess(targetExe)) {
            RequestInjectionFromLauncher(pPI->dwProcessId);
        } else {
            DebugLog(L"ChildHook: Skipped %s (Not in whitelist)", targetExe.c_str());
        }

        if (!callerWantedSuspended) ResumeThread(pPI->hThread);
        if (!lpProcessInformation) { CloseHandle(localPI.hProcess); CloseHandle(localPI.hThread); }
    }
    return result;
}

DWORD WINAPI Detour_GetFinalPathNameByHandleW(HANDLE hFile, LPWSTR lpszFilePath, DWORD cchFilePath, DWORD dwFlags) {
    if (g_IsInHook) return fpGetFinalPathNameByHandleW(hFile, lpszFilePath, cchFilePath, dwFlags);
    RecursionGuard guard;

    DWORD lastErr = GetLastError();

    // 1. 调用原始函数获取真实路径 (例如 \\?\Z:\Sandbox\C\New)
    DWORD result = fpGetFinalPathNameByHandleW(hFile, lpszFilePath, cchFilePath, dwFlags);

    if (result > 0 && result < cchFilePath) {

        // 2. 检查是否包含沙盒根目录
        // g_SandboxRoot 格式如 Z:\Sandbox
        // GetFinalPathNameByHandleW 返回格式通常是 \\?\Z:\Sandbox\...

        std::wstring finalPath = lpszFilePath;

        // 构造匹配前缀: \\?\ + g_SandboxRoot
        std::wstring sandboxPrefix = L"\\\\?\\" + std::wstring(g_SandboxRoot);

        // 不区分大小写比较
        if (finalPath.size() >= sandboxPrefix.size() &&
            _wcsnicmp(finalPath.c_str(), sandboxPrefix.c_str(), sandboxPrefix.size()) == 0) {

            // 3. 执行反向映射 (去除沙盒前缀)
            // 原始: \\?\Z:\Sandbox\C\New
            // 目标: \\?\C:\New

            // 提取相对路径: \C\New
            std::wstring relPath = finalPath.substr(sandboxPrefix.size());

            // 处理盘符结构
            // 如果 relPath 是 \C\New 我们需要把它变成 C:\New
            if (relPath.length() >= 2 && relPath[0] == L'\\') {

                std::wstring driveLetter(1, relPath[1]); // C
                std::wstring remaining = relPath.substr(2); // \New

                std::wstring spoofedPath = L"\\\\?\\" + driveLetter + L":" + remaining;

                // 4. 写回缓冲区
                if (spoofedPath.length() < cchFilePath) {
                    wcscpy_s(lpszFilePath, cchFilePath, spoofedPath.c_str());
                    result = (DWORD)spoofedPath.length();
                }
            }
        }
    }

    SetLastError(lastErr);
    return result;
}

// [新增] 拦截 ShellExecuteExW
BOOL WINAPI Detour_ShellExecuteExW(SHELLEXECUTEINFOW* pExecInfo) {
    if (g_IsInHook) return fpShellExecuteExW(pExecInfo);
    RecursionGuard guard;

    ULONG originalMask = pExecInfo->fMask;
    pExecInfo->fMask |= SEE_MASK_NOCLOSEPROCESS;

    BOOL result = fpShellExecuteExW(pExecInfo);

    if (result && pExecInfo->hProcess) {
        DWORD pid = GetProcessId(pExecInfo->hProcess);

        std::wstring targetExe = L"";
        if (pExecInfo->lpFile) {
            targetExe = pExecInfo->lpFile;
        }

        if (ShouldHookChildProcess(targetExe)) {
            // 1. 请求注入 (这会导致进程被挂起)
            RequestInjectionFromLauncher(pid);
            DebugLog(L"ShellExecute: Injected PID %d (%s)", pid, targetExe.c_str());

            // 2. [新增] 注入完成后 强制恢复进程
            // 注入器为了安全注入 会将进程挂起 (SuspendCount + 1)
            // 我们必须将其恢复 否则进程将一直挂起
            if (fpNtResumeProcess) {
                fpNtResumeProcess(pExecInfo->hProcess);
            }
        }

        if (!(originalMask & SEE_MASK_NOCLOSEPROCESS)) {
            CloseHandle(pExecInfo->hProcess);
            pExecInfo->hProcess = NULL;
            pExecInfo->fMask = originalMask;
        }
    }

    return result;
}

// --- [新增] WinExec Hook (兼容老旧启动器) ---
UINT WINAPI Detour_WinExec(LPCSTR lpCmdLine, UINT uCmdShow) {
    // 构造 STARTUPINFO 模拟 WinExec 的行为
    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = (WORD)uCmdShow;

    // WinExec 的 lpCmdLine 可能是只读的 但 CreateProcess 需要可写的
    // 所以我们复制一份
    std::string cmdLine = lpCmdLine ? lpCmdLine : "";

    // 关键点：调用 CreateProcessA
    // 如果 g_HookChild 开启 这会触发 Detour_CreateProcessA 从而实现注入和转区
    // 如果 g_HookChild 关闭 这会调用系统 API 行为与原 WinExec 一致
    if (CreateProcessA(NULL, (LPSTR)cmdLine.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 33; // WinExec 成功时返回 > 31 的值
    }

    return 0; // 失败
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
    if (g_BlockNetwork > 0) { // Mode 1 or 2
        std::wstring nameW = AnsiToWide(name);

        // 允许 localhost
        if (_wcsicmp(nameW.c_str(), L"localhost") == 0) {
            return fpGethostbyname(name);
        }

        // 如果是 IP 字符串 放行
        if (IsIpAddressString(nameW.c_str())) {
             return fpGethostbyname(name);
        }

        // Mode 2: 拦截所有域名
        if (g_BlockNetwork == 2) {
            WSASetLastError(WSAHOST_NOT_FOUND);
            return NULL;
        }

        // Mode 1: 默认拦截非 IP 字符串 (因为无法预知解析结果)
        // 如果需要支持内网旧版域名解析 这里需要放行 但为了安全默认拦截
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

    // Mode 2: 拦截所有 DNS 解析
    if (g_BlockNetwork == 2) {
        // 1. 如果是 IP 字符串 放行 (GetAddrInfoW 会将其转换为 sockaddr 不涉及网络查询)
        if (IsIpAddressString(pNodeName)) {
            return fpGetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
        }

        // 2. 允许 localhost (本地回环通常不走 DNS 但为了保险起见放行)
        if (pNodeName && _wcsicmp(pNodeName, L"localhost") == 0) {
             return fpGetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
        }

        // 3. 拦截其他所有域名 (包括内网域名)
        // 返回 EAI_FAIL (不可恢复的错误) 或 EAI_NONAME
        return EAI_FAIL;
    }

    // Mode 1 (或 0): 始终放行 DNS 解析
    // Mode 1 依赖 connect/sendto 拦截解析后的 IP
    return fpGetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
}

// 拦截 ConnectEx
BOOL PASCAL Detour_ConnectEx(
    SOCKET s,
    const struct sockaddr* name,
    int namelen,
    PVOID lpSendBuffer,
    DWORD dwSendDataLength,
    LPDWORD lpdwBytesSent,
    LPOVERLAPPED lpOverlapped
) {
    // 检查是否为内网 IP
    if (IsIntranetAddress(name)) {
        // 如果是内网 调用真实的 ConnectEx
        return fpConnectEx_Real(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
    }

    // 如果是外网 拦截
    WSASetLastError(WSAEACCES);
    return FALSE;
}

// 拦截 WSAIoctl 以劫持 ConnectEx 的获取
int WSAAPI Detour_WSAIoctl(
    SOCKET s,
    DWORD dwIoControlCode,
    LPVOID lpvInBuffer,
    DWORD cbInBuffer,
    LPVOID lpvOutBuffer,
    DWORD cbOutBuffer,
    LPDWORD lpcbBytesReturned,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    // 1. 调用原始函数
    int result = fpWSAIoctl(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine);

    // 2. 检查是否成功 且是否在请求扩展函数指针
    if (result == 0 && dwIoControlCode == SIO_GET_EXTENSION_FUNCTION_POINTER) {
        if (cbInBuffer >= sizeof(GUID) && lpvInBuffer != NULL && lpvOutBuffer != NULL && cbOutBuffer >= sizeof(PVOID)) {

            GUID* pGuid = (GUID*)lpvInBuffer;

            // 3. 检查请求的是否为 ConnectEx
            if (IsEqualGUID(*pGuid, g_GuidConnectEx)) {
                // 保存真实的 ConnectEx 地址 (仅保存一次)
                if (fpConnectEx_Real == NULL) {
                    fpConnectEx_Real = *(LPFN_CONNECTEX*)lpvOutBuffer;
                }

                // 4. 将返回缓冲区中的地址替换为我们的 Detour 函数
                *(void**)lpvOutBuffer = (void*)Detour_ConnectEx;

                // DebugLog(L"Network: Hijacked ConnectEx pointer via WSAIoctl");
            }
        }
    }

    return result;
}

BOOL WSAAPI Detour_WSAConnectByNameW(SOCKET s, LPWSTR nodename, LPWSTR servicename, LPDWORD LocalAddressLength, LPSOCKADDR LocalAddress, LPDWORD RemoteAddressLength, LPSOCKADDR RemoteAddress, LPDWORD Timeout, const struct timeval* Reserved, LPWSAOVERLAPPED Overlapped) {
    // 这里的逻辑比较复杂 因为 RemoteAddress 是输出参数
    // 简单策略：如果启用了阻断 直接检查 nodename 是否为内网主机
    if (g_BlockNetwork) {
        if (!IsIntranetHost(nodename)) {
            WSASetLastError(WSAEACCES);
            return FALSE;
        }
    }
    return fpWSAConnectByNameW(s, nodename, servicename, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, Timeout, Reserved, Overlapped);
}

// [新增] 拦截 WSAConnectByList
BOOL WSAAPI Detour_WSAConnectByList(
    SOCKET s,
    PSOCKET_ADDRESS_LIST SocketAddressList,
    LPDWORD LocalAddressLength,
    LPSOCKADDR LocalAddress,
    LPDWORD RemoteAddressLength,
    LPSOCKADDR RemoteAddress,
    const struct timeval* timeout,
    LPWSAOVERLAPPED Reserved
) {
    // 如果开启了网络拦截
    if (g_BlockNetwork && SocketAddressList) {
        // 遍历所有候选地址
        for (int i = 0; i < SocketAddressList->iAddressCount; i++) {
            LPSOCKADDR pAddr = SocketAddressList->Address[i].lpSockaddr;

            // 只要发现有一个地址不是内网地址 就拒绝整个连接请求
            // 这是最安全的策略 防止程序尝试连接列表中的公网 IP
            if (!IsIntranetAddress(pAddr)) {
                WSASetLastError(WSAEACCES);
                return FALSE;
            }
        }
    }

    // 如果所有地址都是内网地址（或未开启拦截） 则放行
    return fpWSAConnectByList(s, SocketAddressList, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, Reserved);
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
    // [新增] 初始化管道前缀
    InitPipeVirtualization();
    // [新增] 启用特权以支持短文件名设置
    EnableRestorePrivilege();

    // [关键修复] 提前获取 ntdll 句柄和所有通用函数指针
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        fpNtResumeProcess = (P_NtResumeProcess)GetProcAddress(hNtdll, "NtResumeProcess");
        // 无论何种模式 都初始化 NtQueryObject 因为路径解析依赖它
        fpNtQueryObject = (P_NtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");

        // [修复] 无论何种模式 都初始化 NtClose
        fpNtClose = (P_NtClose)GetProcAddress(hNtdll, "NtClose");
    }

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

    // 读取 YAP_HOOK_REG 配置
    wchar_t regBuffer[64] = { 0 };
    if (GetEnvironmentVariableW(L"YAP_HOOK_REG", regBuffer, 64) > 0) {
        g_HookReg = (_wtoi(regBuffer) == 1);
    }

    if (g_HookReg && hNtdll) {
        // 1. 获取 RtlFormatCurrentUserKeyPath 函数地址
        fpRtlFormatCurrentUserKeyPath = (P_RtlFormatCurrentUserKeyPath)GetProcAddress(hNtdll, "RtlFormatCurrentUserKeyPath");

        if (fpRtlFormatCurrentUserKeyPath) {
            UNICODE_STRING userKeyPath;
            if (NT_SUCCESS(fpRtlFormatCurrentUserKeyPath(&userKeyPath))) {
                g_CurrentUserSidPath.assign(userKeyPath.Buffer, userKeyPath.Length / sizeof(WCHAR));
                DebugLog(L"RegHook: CurrentUser = %s", g_CurrentUserSidPath.c_str());
            }
        }

        // 2. [修改] 连接到由启动器挂载的注册表键
        // 不再使用 RegLoadAppKey 而是打开已挂载的键
        // 启动器会将挂载点名称写入 YAP_HOOK_REGPATH 环境变量
        wchar_t mountPointBuf[256] = { 0 };
        if (GetEnvironmentVariableW(L"YAP_HOOK_REGPATH", mountPointBuf, 256) > 0) {
            // 构造 NT 路径: \REGISTRY\USER\<MountPointName>
            std::wstring mountPath = L"\\REGISTRY\\USER\\" + std::wstring(mountPointBuf);

            UNICODE_STRING uStr;
            RtlInitUnicodeString(&uStr, mountPath.c_str());

            OBJECT_ATTRIBUTES oa;
            InitializeObjectAttributes(&oa, &uStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

            // 使用 NtOpenKey 打开挂载点
            // 需要 MAXIMUM_ALLOWED 或 KEY_ALL_ACCESS 以便后续创建子键
            NTSTATUS status = 0;
            // 尝试获取 NtOpenKey 指针 (如果尚未获取)
            if (!fpNtOpenKey) fpNtOpenKey = (P_NtOpenKey)GetProcAddress(hNtdll, "NtOpenKey");

            if (fpNtOpenKey) {
                status = fpNtOpenKey(reinterpret_cast<PHANDLE>(&g_hAppHive), KEY_ALL_ACCESS, &oa);
            } else {
                status = STATUS_NOT_SUPPORTED;
            }

            if (NT_SUCCESS(status)) {
                // [新增] 保存挂载点路径供后续判断使用
                g_RegMountPathNt = mountPath;
                DebugLog(L"RegHook: Connected to mounted hive at %s", mountPath.c_str());
                // 注意：Hive 的初始化（创建 Machine/User 子键）现在由启动器在创建 Hive 文件时完成
            } else {
                DebugLog(L"RegHook: Failed to open mounted hive %s, status %x", mountPath.c_str(), status);
                g_hAppHive = NULL;
            }
        } else {
             DebugLog(L"RegHook: YAP_HOOK_REGPATH not set, registry redirection disabled.");
             g_hAppHive = NULL;
        }
    }

    // [新增] 读取子进程挂钩配置
    wchar_t childBuffer[64];
    if (GetEnvironmentVariableW(L"YAP_HOOK_CHILD", childBuffer, 64) > 0) {
        int val = _wtoi(childBuffer);
        // hookchild=0 表示不挂钩子进程
        if (val == 0) {
            g_HookChild = false;
        }
    }

    // [新增] 初始化子进程白名单
    InitChildHookWhitelist();

    // [新增] 读取第三方 DLL 列表
    wchar_t extraDllsBuf[4096];
    if (GetEnvironmentVariableW(L"YAP_EXTRA_DLL", extraDllsBuf, 4096) > 0) {
        wchar_t* ctx = NULL;
        wchar_t* token = wcstok_s(extraDllsBuf, L"|", &ctx);
        while (token) {
            g_ExtraDlls.push_back(token);
            token = wcstok_s(NULL, L"|", &ctx);
        }
    }

    // [新增] 读取 hookcopysize 配置
    wchar_t copySizeBuf[64];
    if (GetEnvironmentVariableW(L"YAP_HOOK_COPY_SIZE", copySizeBuf, 64) > 0) {
        long long mb = _wtoi64(copySizeBuf);
        if (mb > 0) {
            g_HookCopySizeLimit = mb * 1024 * 1024; // 转换为字节
        }
    }

    // [新增] 读取网络拦截开关
    wchar_t netBuffer[64];
    if (GetEnvironmentVariableW(L"YAP_HOOK_NET", netBuffer, 64) > 0) {
        g_BlockNetwork = _wtoi(netBuffer);
    }

    // [新增] 读取 hookvolumeid 配置
    wchar_t volIdBuf[64];
    if (GetEnvironmentVariableW(L"YAP_HOOK_VOLUME_ID", volIdBuf, 64) > 0) {
        std::wstring volIdStr = volIdBuf;
        // 移除 '-' (例如 1234-5678 -> 12345678)
        size_t dashPos = volIdStr.find(L'-');
        if (dashPos != std::wstring::npos) {
            volIdStr.erase(dashPos, 1);
        }

        // 解析十六进制
        wchar_t* endPtr;
        g_FakeVolumeSerial = wcstoul(volIdStr.c_str(), &endPtr, 16);

        if (g_FakeVolumeSerial != 0) {
            g_HookVolumeId = true;
            DebugLog(L"VolumeID: Configured to %08X", g_FakeVolumeSerial);
        }
    }

    // [新增] 读取 hookcd 配置
    wchar_t cdBuffer[MAX_PATH];
    if (GetEnvironmentVariableW(L"YAP_HOOK_CD", cdBuffer, MAX_PATH) > 0) {
        g_HookCdPath = cdBuffer;
        if (!g_HookCdPath.empty() && g_HookCdPath.back() == L'\\') {
            g_HookCdPath.pop_back();
        }

        g_HookCdNtPath = L"\\??\\" + g_HookCdPath;

        // [新增] 获取真实路径的设备路径 (用于反向匹配)
        // g_HookCdPath = Z:\Other\ISO
        // 需要解析 Z: -> \Device\HarddiskVolume1
        if (g_HookCdPath.length() >= 2 && g_HookCdPath[1] == L':') {
            wchar_t driveStr[] = { g_HookCdPath[0], L':', L'\0' };
            wchar_t devBuf[MAX_PATH];
            if (QueryDosDeviceW(driveStr, devBuf, MAX_PATH)) {
                g_HookCdDevicePath = devBuf; // \Device\HarddiskVolume1
                if (g_HookCdPath.length() > 2) {
                    g_HookCdDevicePath += g_HookCdPath.substr(2); // + \Other\ISO
                }
            }
        }

        // 寻找未使用的盘符 (从 Z 倒序查找 或者从 D 顺序查找)
        DWORD drives = GetLogicalDrives();
        // 从 'E' 开始查找 (跳过 A, B, C, D)
        for (wchar_t drive = L'E'; drive <= L'Z'; ++drive) {
            if ((drives & (1 << (drive - L'A'))) == 0) {
                g_VirtualCdDrive = drive;
                break;
            }
        }

        // 如果找不到 尝试 D
        if (g_VirtualCdDrive == 0 && (drives & (1 << (L'D' - L'A'))) == 0) {
            g_VirtualCdDrive = L'D';
        }

        if (g_VirtualCdDrive != 0) {
            g_VirtualCdNtPrefix = L"\\??\\";
            g_VirtualCdNtPrefix += g_VirtualCdDrive;
            g_VirtualCdNtPrefix += L":";

            DebugLog(L"CDHook: Mapped Virtual Drive %c: -> %s", g_VirtualCdDrive, g_HookCdPath.c_str());
        } else {
            DebugLog(L"CDHook: Failed to find unused drive letter!");
        }
    }

    // [新增] 读取 hookfont 配置
    wchar_t fontBuffer[MAX_PATH];
    if (GetEnvironmentVariableW(L"YAP_HOOK_FONT", fontBuffer, MAX_PATH) > 0) {
        std::wstring fontConfig = fontBuffer;

        // 检查是否为文件 (简单的判断：包含反斜杠 或 文件存在)
        bool isFile = (fontConfig.find(L'\\') != std::wstring::npos) ||
                      (GetFileAttributesW(fontConfig.c_str()) != INVALID_FILE_ATTRIBUTES);

        if (isFile) {
            // 如果是文件 尝试加载并读取名称
            std::wstring loadedName = LoadCustomFontFile(fontConfig);
            if (!loadedName.empty()) {
                g_OverrideFontName = loadedName;
            } else {
                // 加载失败 回退：也许用户输入的只是一个带斜杠的字体名？(极少见)
                // 或者文件路径错误保留原值尝试作为名称使用 或者置空
                // 这里选择保留原值 万一它就是个名字
                g_OverrideFontName = fontConfig;
            }
        } else {
            // 不是文件 直接作为字体名称
            g_OverrideFontName = fontConfig;
        }

        if (!g_OverrideFontName.empty()) {
            DebugLog(L"FontHook: Override font set to '%s'", g_OverrideFontName.c_str());
        }
    }

    // --- [修改] 读取 hooklocale 配置 ---
    wchar_t localeBuffer[64];
    if (GetEnvironmentVariableW(L"YAP_HOOK_LOCALE", localeBuffer, 64) > 0) {
        int cp = _wtoi(localeBuffer);
        if (cp > 0) {
            g_FakeACP = (UINT)cp;

            // [新增] 生成注册表伪造所需的字符串
            g_FakeACPStr = std::to_wstring(g_FakeACP);
            g_FakeOEMCPStr = g_FakeACPStr;

            const wchar_t* autoTimeZone = nullptr;

            // 根据代码页映射 LCID, CharSet, LangID 和 TimeZone
            switch (cp) {
            case 932: // 日语
                g_FakeLCID = 0x0411;
                g_FakeLangID = 0x0411;
                g_FakeCharSet = 128; // SHIFTJIS_CHARSET
                autoTimeZone = L"Tokyo Standard Time"; // UTC+9
                break;
            case 936: // 简体中文
                g_FakeLCID = 0x0804;
                g_FakeLangID = 0x0804;
                g_FakeCharSet = 134; // GB2312_CHARSET
                autoTimeZone = L"China Standard Time"; // UTC+8
                break;
            case 949: // 韩语
                g_FakeLCID = 0x0412;
                g_FakeLangID = 0x0412;
                g_FakeCharSet = 129; // HANGEUL_CHARSET
                autoTimeZone = L"Korea Standard Time"; // UTC+9
                break;
            case 950: // 繁体中文
                g_FakeLCID = 0x0404;
                g_FakeLangID = 0x0404;
                g_FakeCharSet = 136; // CHINESEBIG5_CHARSET
                autoTimeZone = L"Taipei Standard Time"; // UTC+8
                break;
            case 1250: // 中欧 (捷克/波兰等)
                g_FakeLCID = 0x0405; // cs-CZ
                g_FakeLangID = 0x0405;
                g_FakeCharSet = 238; // EASTEUROPE_CHARSET
                autoTimeZone = L"Central Europe Standard Time"; // UTC+1
                break;
            case 1251: // 俄语
                g_FakeLCID = 0x0419;
                g_FakeLangID = 0x0419;
                g_FakeCharSet = 204; // RUSSIAN_CHARSET
                autoTimeZone = L"Russian Standard Time"; // UTC+3 (Moscow)
                break;
            case 1252: // 西欧 (英语/法语/德语等)
                g_FakeLCID = 0x0409; // en-US
                g_FakeLangID = 0x0409;
                g_FakeCharSet = 0;   // ANSI_CHARSET
                // 西欧常用时区 这里选巴黎/马德里/柏林作为代表
                autoTimeZone = L"Romance Standard Time"; // UTC+1
                break;
            default:
                g_FakeLCID = 0x0409;
                g_FakeLangID = 0x0409;
                g_FakeCharSet = 0;
                break;
            }

            // 设置线程 Locale
            if (g_FakeLCID != 0) {
                SetThreadLocale(g_FakeLCID);
            }

            // [新增] 自动加载对应的时区
            if (autoTimeZone != nullptr) {
                if (LoadTimeZoneFromRegistry(autoTimeZone)) {
                    g_EnableTimeZoneHook = true;
                    DebugLog(L"LocaleHook: Auto-set TimeZone to '%s'", autoTimeZone);
                }
            }

            DebugLog(L"LocaleHook: Spoofing CP=%s, LCID=%04X, CharSet=%u", g_FakeACPStr.c_str(), g_FakeLCID, g_FakeCharSet);
        }
    }

    // --- [新增] 读取 hooktime 配置 ---
    wchar_t timeBuffer[64];
    if (GetEnvironmentVariableW(L"YAP_HOOK_TIME", timeBuffer, 64) > 0) {
        int year = 0, month = 0, day = 0, hour = -1, minute = -1;

        // 尝试解析 "YYYY/MM/DD :: HH:MM"
        // swscanf_s 返回成功匹配的字段数量
        int fields = swscanf_s(timeBuffer, L"%d/%d/%d :: %d:%d", &year, &month, &day, &hour, &minute);

        if (fields >= 3) {
            // 1. 获取当前真实 UTC 时间 (用于计算基准)
            SYSTEMTIME realUtcSt;
            GetSystemTime(&realUtcSt);
            FILETIME realUtcFt;
            SystemTimeToFileTime(&realUtcSt, &realUtcFt);
            ULARGE_INTEGER realUtcUli;
            realUtcUli.LowPart = realUtcFt.dwLowDateTime;
            realUtcUli.HighPart = realUtcFt.dwHighDateTime;

            // 2. 获取当前真实 Local 时间 (用于填充未指定的时间部分)
            SYSTEMTIME realLocalSt;
            GetLocalTime(&realLocalSt);

            // 3. 构造目标 Local 时间
            SYSTEMTIME targetLocalSt = realLocalSt; // 默认继承当前的 Local 时/分/秒/毫秒
            targetLocalSt.wYear = (WORD)year;
            targetLocalSt.wMonth = (WORD)month;
            targetLocalSt.wDay = (WORD)day;

            // 如果指定了具体时间 则覆盖
            if (fields >= 5 && hour >= 0 && minute >= 0) {
                targetLocalSt.wHour = (WORD)hour;
                targetLocalSt.wMinute = (WORD)minute;
                targetLocalSt.wSecond = 0;
                targetLocalSt.wMilliseconds = 0;
            }

            // 4. 将目标 Local 时间转换为目标 UTC 时间
            // 关键修正：使用 TzSpecificLocalTimeToSystemTime 将用户配置的本地时间转为 UTC
            SYSTEMTIME targetUtcSt;
            if (TzSpecificLocalTimeToSystemTime(NULL, &targetLocalSt, &targetUtcSt)) {
                FILETIME targetUtcFt;
                SystemTimeToFileTime(&targetUtcSt, &targetUtcFt);
                ULARGE_INTEGER targetUtcUli;
                targetUtcUli.LowPart = targetUtcFt.dwLowDateTime;
                targetUtcUli.HighPart = targetUtcFt.dwHighDateTime;

                // 5. 计算偏移量：目标 UTC - 真实 UTC
                // 这样 Hook 后的 GetSystemTime 返回的是正确的伪造 UTC 时间
                // 应用程序再通过 GetLocalTime (+8小时) 就能得到正确的本地时间
                g_TimeOffset = (long long)(targetUtcUli.QuadPart - realUtcUli.QuadPart);
                g_EnableTimeHook = true;

                DebugLog(L"TimeHook: Enabled. Target Local: %04d/%02d/%02d %02d:%02d, Offset: %lld",
                    targetLocalSt.wYear, targetLocalSt.wMonth, targetLocalSt.wDay,
                    targetLocalSt.wHour, targetLocalSt.wMinute, g_TimeOffset);
            } else {
                DebugLog(L"TimeHook: TzSpecificLocalTimeToSystemTime failed.");
            }
        }
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

    InitSpoofing();

    DebugLog(L"Hook Initialized. Mode: %d, Root: %s", g_HookMode, g_SandboxRoot);

    // 7. 初始化 MinHook
    if (MH_Initialize() != MH_OK) return 0;

    // =======================================================
    // 分组挂钩逻辑
    // =======================================================

    // [修改] 公共基础 Hook：NtQueryObject
    // 只要启用了 文件重定向 OR 虚拟盘符 OR 注册表重定向
    // 就必须挂钩 NtQueryObject 以进行路径伪装 (防止通过句柄反查到沙盒路径)
    if (hNtdll && (g_HookMode > 0 || g_VirtualCdDrive != 0 || g_HookReg)) {
        void* pNtQueryObject = (void*)GetProcAddress(hNtdll, "NtQueryObject");
        if (pNtQueryObject) {
            // MH_CreateHook 会自动更新 fpNtQueryObject 为跳板地址(Trampoline)
            // 这样 GetPathFromHandle 内部调用 fpNtQueryObject 时依然能正常工作
            MH_CreateHook(pNtQueryObject, &Detour_NtQueryObject, reinterpret_cast<LPVOID*>(&fpNtQueryObject));
        }
    }

    // --- 组 A: 文件系统 Hook ---
    if (hNtdll) {
        // [修改] 启用文件重定向挂钩的条件
        // 1. hookfile > 0 (常规重定向)
        // 2. hookcd 启用了虚拟盘符 (需要重定向 M: -> Z:)
        if (g_HookMode > 0 || g_VirtualCdDrive != 0) {
            MH_CreateHook(GetProcAddress(hNtdll, "NtCreateFile"), &Detour_NtCreateFile, reinterpret_cast<LPVOID*>(&fpNtCreateFile));
            MH_CreateHook(GetProcAddress(hNtdll, "NtOpenFile"), &Detour_NtOpenFile, reinterpret_cast<LPVOID*>(&fpNtOpenFile));
            MH_CreateHook(GetProcAddress(hNtdll, "NtQueryAttributesFile"), &Detour_NtQueryAttributesFile, reinterpret_cast<LPVOID*>(&fpNtQueryAttributesFile));
            MH_CreateHook(GetProcAddress(hNtdll, "NtQueryFullAttributesFile"), &Detour_NtQueryFullAttributesFile, reinterpret_cast<LPVOID*>(&fpNtQueryFullAttributesFile));
            // 下面这些通常只在 hookfile 启用时才需要 但为了保险起见也可以挂钩
            MH_CreateHook(GetProcAddress(hNtdll, "NtQueryInformationFile"), &Detour_NtQueryInformationFile, reinterpret_cast<LPVOID*>(&fpNtQueryInformationFile));
            MH_CreateHook(GetProcAddress(hNtdll, "NtQueryDirectoryFile"), &Detour_NtQueryDirectoryFile, reinterpret_cast<LPVOID*>(&fpNtQueryDirectoryFile));
            MH_CreateHook(GetProcAddress(hNtdll, "NtSetInformationFile"), &Detour_NtSetInformationFile, reinterpret_cast<LPVOID*>(&fpNtSetInformationFile));
            MH_CreateHook(GetProcAddress(hNtdll, "NtDeleteFile"), &Detour_NtDeleteFile, reinterpret_cast<LPVOID*>(&fpNtDeleteFile));
            MH_CreateHook(GetProcAddress(hNtdll, "NtClose"), &Detour_NtClose, reinterpret_cast<LPVOID*>(&fpNtClose));

            // [新增] 挂钩 NtCreateNamedPipeFile
            void* pNtCreateNamedPipeFile = (void*)GetProcAddress(hNtdll, "NtCreateNamedPipeFile");
            if (pNtCreateNamedPipeFile) {
                MH_CreateHook(pNtCreateNamedPipeFile, &Detour_NtCreateNamedPipeFile, reinterpret_cast<LPVOID*>(&fpNtCreateNamedPipeFile));
            }

            void* pNtQueryDirectoryFileEx = (void*)GetProcAddress(hNtdll, "NtQueryDirectoryFileEx");
            if (pNtQueryDirectoryFileEx) {
                MH_CreateHook(pNtQueryDirectoryFileEx, &Detour_NtQueryDirectoryFileEx, reinterpret_cast<LPVOID*>(&fpNtQueryDirectoryFileEx));
            }

            HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
            if (hKernel32) {
                // 1. 路径欺骗挂钩 (原有)
                void* pGetFinalPathNameByHandleW = (void*)GetProcAddress(hKernel32, "GetFinalPathNameByHandleW");
                if (pGetFinalPathNameByHandleW) {
                    MH_CreateHook(pGetFinalPathNameByHandleW, &Detour_GetFinalPathNameByHandleW, reinterpret_cast<LPVOID*>(&fpGetFinalPathNameByHandleW));
                }

                // 2. 驱动器枚举与类型挂钩 (新增 用于 hookcd)
                // 只要 hookcd 启用 (无论是否分配了虚拟盘符 GetDriveTypeW 都需要挂钩以处理路径匹配)
                if (!g_HookCdPath.empty()) {
                    void* pGetDriveTypeW = (void*)GetProcAddress(hKernel32, "GetDriveTypeW");
                    if (pGetDriveTypeW) MH_CreateHook(pGetDriveTypeW, &Detour_GetDriveTypeW, reinterpret_cast<LPVOID*>(&fpGetDriveTypeW));
                }

                // 3. 虚拟盘符专用挂钩 (仅当分配了虚拟盘符时)
                if (g_VirtualCdDrive != 0) {
                    void* pGetLogicalDrives = (void*)GetProcAddress(hKernel32, "GetLogicalDrives");
                    if (pGetLogicalDrives) MH_CreateHook(pGetLogicalDrives, &Detour_GetLogicalDrives, reinterpret_cast<LPVOID*>(&fpGetLogicalDrives));

                    void* pGetLogicalDriveStringsW = (void*)GetProcAddress(hKernel32, "GetLogicalDriveStringsW");
                    if (pGetLogicalDriveStringsW) MH_CreateHook(pGetLogicalDriveStringsW, &Detour_GetLogicalDriveStringsW, reinterpret_cast<LPVOID*>(&fpGetLogicalDriveStringsW));
                }
            }
        }

        // 3. 卷序列号挂钩 (独立控制)
        if (g_HookVolumeId || !g_HookCdPath.empty()) {
            void* pNtQueryVolumeInformationFile = (void*)GetProcAddress(hNtdll, "NtQueryVolumeInformationFile");
            if (pNtQueryVolumeInformationFile) {
                MH_CreateHook(pNtQueryVolumeInformationFile, &Detour_NtQueryVolumeInformationFile, reinterpret_cast<LPVOID*>(&fpNtQueryVolumeInformationFile));
            }
        }
    }

    // --- 组 B: 进程创建 Hook (只要启用了任意功能 就需要挂钩以实现子进程注入) ---
    if (g_HookChild) {
        
        // [核心修改] 动态获取并挂钩 CreateProcessInternalW
        // 优先从 kernelbase.dll 获取 (Win7+)，失败则从 kernel32.dll 获取 (XP)
        HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
        if (!hKernelBase) hKernelBase = GetModuleHandleW(L"kernel32.dll");
        
        if (hKernelBase) {
            void* pCreateProcessInternalW = (void*)GetProcAddress(hKernelBase, "CreateProcessInternalW");
            if (pCreateProcessInternalW) {
                MH_CreateHook(pCreateProcessInternalW, &Detour_CreateProcessInternalW, reinterpret_cast<LPVOID*>(&fpCreateProcessInternalW));
            }
        }

        // 挂钩 WinExec (老旧程序兼容)
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (hKernel32) {
            void* pWinExec = (void*)GetProcAddress(hKernel32, "WinExec");
            if (pWinExec) {
                MH_CreateHook(pWinExec, &Detour_WinExec, reinterpret_cast<LPVOID*>(&fpWinExec));
            }
        }

        // 挂钩 ShellExecuteExW
        HMODULE hShell32 = LoadLibraryW(L"shell32.dll");
        if (hShell32) {
            void* pShellExecuteExW = (void*)GetProcAddress(hShell32, "ShellExecuteExW");
            if (pShellExecuteExW) {
                MH_CreateHook(pShellExecuteExW, &Detour_ShellExecuteExW, reinterpret_cast<LPVOID*>(&fpShellExecuteExW));
            }
        }

        // 注意：CreateProcessWithTokenW 和 CreateProcessWithLogonW 依然需要保留！
        // 因为这两个 API 内部是通过 RPC 调用 Secondary Logon 服务 (seclogon) 来跨 Session 创建进程的，
        // 它们并不一定会在当前进程内调用 CreateProcessInternalW。
        HMODULE hAdvapi32 = LoadLibraryW(L"advapi32.dll");
        if (hAdvapi32) {
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
            void* pWSAIoctl = (void*)GetProcAddress(hWinsock, "WSAIoctl");
            void* pWSAConnectByNameW = (void*)GetProcAddress(hWinsock, "WSAConnectByNameW");
            void* pWSAConnectByList = (void*)GetProcAddress(hWinsock, "WSAConnectByList");

            if (pWSAConnectByList) {
                MH_CreateHook(pWSAConnectByList, &Detour_WSAConnectByList, reinterpret_cast<LPVOID*>(&fpWSAConnectByList));
            }
            if (pWSAConnectByNameW) MH_CreateHook(pWSAConnectByNameW, &Detour_WSAConnectByNameW, reinterpret_cast<LPVOID*>(&fpWSAConnectByNameW));
            if (pWSAIoctl) MH_CreateHook(pWSAIoctl, &Detour_WSAIoctl, reinterpret_cast<LPVOID*>(&fpWSAIoctl));
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

    // --- 组 D: 字体 Hook (仅当 hookfont 有值时启用) ---
    if (!g_OverrideFontName.empty()) {
        HMODULE hGdi32 = LoadLibraryW(L"gdi32.dll");
        if (hGdi32) {
            // 1. 挂钩 CreateFontIndirect 系列
            void* pCreateFontIndirectW = (void*)GetProcAddress(hGdi32, "CreateFontIndirectW");
            if (pCreateFontIndirectW) MH_CreateHook(pCreateFontIndirectW, &Detour_CreateFontIndirectW, reinterpret_cast<LPVOID*>(&fpCreateFontIndirectW));

            void* pCreateFontIndirectExW = (void*)GetProcAddress(hGdi32, "CreateFontIndirectExW");
            if (pCreateFontIndirectExW) MH_CreateHook(pCreateFontIndirectExW, &Detour_CreateFontIndirectExW, reinterpret_cast<LPVOID*>(&fpCreateFontIndirectExW));

            // 2. [新增] 准备 GetStockObject 的替换字体
            // 获取系统当前的非客户区指标（包含标准的界面字体 如 Segoe UI 或 Microsoft YaHei）
            NONCLIENTMETRICSW ncm = { sizeof(NONCLIENTMETRICSW) };
            // 注意：在不同 Windows 版本下 sizeof 可能不同 通常这样写兼容性尚可
            if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) {
                // 使用 hookfont 指定的名称覆盖系统默认名称
                wcsncpy_s(ncm.lfMessageFont.lfFaceName, LF_FACESIZE, g_OverrideFontName.c_str(), _TRUNCATE);

                // 创建替换用的字体对象
                g_hNewGSOFont = CreateFontIndirectW(&ncm.lfMessageFont);
            }

            // 3. [新增] 挂钩 GetStockObject
            void* pGetStockObject = (void*)GetProcAddress(hGdi32, "GetStockObject");
            if (pGetStockObject) {
                MH_CreateHook(pGetStockObject, &Detour_GetStockObject, reinterpret_cast<LPVOID*>(&fpGetStockObject));
            }
        }

        // GDI+ Hook ... (保持不变)
        HMODULE hGdiPlus = GetModuleHandleW(L"gdiplus.dll");
        if (!hGdiPlus) hGdiPlus = LoadLibraryW(L"gdiplus.dll");

        if (hGdiPlus) {
            void* pGdipCreateFontFamilyFromName = (void*)GetProcAddress(hGdiPlus, "GdipCreateFontFamilyFromName");
            if (pGdipCreateFontFamilyFromName) {
                MH_CreateHook(pGdipCreateFontFamilyFromName, &Detour_GdipCreateFontFamilyFromName, reinterpret_cast<LPVOID*>(&fpGdipCreateFontFamilyFromName));
            }
        }
    }

    // --- [新增] 组 E: 区域语言 Hook (仅当 hooklocale 有值时启用) ---
    if (g_FakeACP != 0) {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll"); // 确保获取 ntdll
        HMODULE hGdi32 = GetModuleHandleW(L"gdi32.dll");
        if (hKernel32) {
            // 基础信息查询
            MH_CreateHook(GetProcAddress(hKernel32, "GetACP"), &Detour_GetACP, reinterpret_cast<LPVOID*>(&fpGetACP));
            MH_CreateHook(GetProcAddress(hKernel32, "GetOEMCP"), &Detour_GetOEMCP, reinterpret_cast<LPVOID*>(&fpGetOEMCP));
            MH_CreateHook(GetProcAddress(hKernel32, "GetUserDefaultLCID"), &Detour_GetUserDefaultLCID, reinterpret_cast<LPVOID*>(&fpGetUserDefaultLCID));
            MH_CreateHook(GetProcAddress(hKernel32, "GetSystemDefaultLCID"), &Detour_GetSystemDefaultLCID, reinterpret_cast<LPVOID*>(&fpGetSystemDefaultLCID));
            MH_CreateHook(GetProcAddress(hKernel32, "GetThreadLocale"), &Detour_GetThreadLocale, reinterpret_cast<LPVOID*>(&fpGetThreadLocale));
            MH_CreateHook(GetProcAddress(hKernel32, "GetUserDefaultLangID"), &Detour_GetUserDefaultLangID, reinterpret_cast<LPVOID*>(&fpGetUserDefaultLangID));
            MH_CreateHook(GetProcAddress(hKernel32, "GetSystemDefaultLangID"), &Detour_GetSystemDefaultLangID, reinterpret_cast<LPVOID*>(&fpGetSystemDefaultLangID));
            MH_CreateHook(GetProcAddress(hKernel32, "GetLocaleInfoW"), &Detour_GetLocaleInfoW, reinterpret_cast<LPVOID*>(&fpGetLocaleInfoW));
            MH_CreateHook(GetProcAddress(hKernel32, "MultiByteToWideChar"), &Detour_MultiByteToWideChar, reinterpret_cast<LPVOID*>(&fpMultiByteToWideChar));
            MH_CreateHook(GetProcAddress(hKernel32, "WideCharToMultiByte"), &Detour_WideCharToMultiByte, reinterpret_cast<LPVOID*>(&fpWideCharToMultiByte));

            // [新增] UI 语言 Hook
            MH_CreateHook(GetProcAddress(hKernel32, "GetUserDefaultUILanguage"), &Detour_GetUserDefaultUILanguage, reinterpret_cast<LPVOID*>(&fpGetUserDefaultUILanguage));
            MH_CreateHook(GetProcAddress(hKernel32, "GetSystemDefaultUILanguage"), &Detour_GetSystemDefaultUILanguage, reinterpret_cast<LPVOID*>(&fpGetSystemDefaultUILanguage));
        }

        if (hNtdll) {
            MH_CreateHook(GetProcAddress(hNtdll, "RtlMultiByteToUnicodeN"), &Detour_RtlMultiByteToUnicodeN, reinterpret_cast<LPVOID*>(&fpRtlMultiByteToUnicodeN));
            MH_CreateHook(GetProcAddress(hNtdll, "RtlUnicodeToMultiByteN"), &Detour_RtlUnicodeToMultiByteN, reinterpret_cast<LPVOID*>(&fpRtlUnicodeToMultiByteN));
        }

        // [新增] 资源加载 Hook
        if (hNtdll) {
            void* pLdrResSearchResource = (void*)GetProcAddress(hNtdll, "LdrResSearchResource");
            if (pLdrResSearchResource) {
                MH_CreateHook(pLdrResSearchResource, &Detour_LdrResSearchResource, reinterpret_cast<LPVOID*>(&fpLdrResSearchResource));
            }
        }

        // [新增] 字体枚举 Hook
        if (hGdi32) {
            void* pEnumFontFamiliesExW = (void*)GetProcAddress(hGdi32, "EnumFontFamiliesExW");
            if (pEnumFontFamiliesExW) MH_CreateHook(pEnumFontFamiliesExW, &Detour_EnumFontFamiliesExW, reinterpret_cast<LPVOID*>(&fpEnumFontFamiliesExW));

            void* pEnumFontFamiliesW = (void*)GetProcAddress(hGdi32, "EnumFontFamiliesW");
            if (pEnumFontFamiliesW) MH_CreateHook(pEnumFontFamiliesW, &Detour_EnumFontFamiliesW, reinterpret_cast<LPVOID*>(&fpEnumFontFamiliesW));

            // [新增] ANSI 字体 Hook
            MH_CreateHook(GetProcAddress(hGdi32, "CreateFontIndirectA"), &Detour_CreateFontIndirectA, reinterpret_cast<LPVOID*>(&fpCreateFontIndirectA));
            MH_CreateHook(GetProcAddress(hGdi32, "CreateFontA"), &Detour_CreateFontA, reinterpret_cast<LPVOID*>(&fpCreateFontA));
        }
    }

    // --- [新增] 组 F: ANSI 注册表 Hook (解决路径乱码) ---
    if (g_FakeACP != 0) {
        HMODULE hAdvapi32 = LoadLibraryW(L"advapi32.dll");
        if (hAdvapi32) {
            MH_CreateHook(GetProcAddress(hAdvapi32, "RegOpenKeyExA"), &Detour_RegOpenKeyExA, reinterpret_cast<LPVOID*>(&fpRegOpenKeyExA));
            MH_CreateHook(GetProcAddress(hAdvapi32, "RegCreateKeyExA"), &Detour_RegCreateKeyExA, reinterpret_cast<LPVOID*>(&fpRegCreateKeyExA));
            MH_CreateHook(GetProcAddress(hAdvapi32, "RegQueryValueExA"), &Detour_RegQueryValueExA, reinterpret_cast<LPVOID*>(&fpRegQueryValueExA));
            MH_CreateHook(GetProcAddress(hAdvapi32, "RegSetValueExA"), &Detour_RegSetValueExA, reinterpret_cast<LPVOID*>(&fpRegSetValueExA));
            MH_CreateHook(GetProcAddress(hAdvapi32, "RegDeleteKeyA"), &Detour_RegDeleteKeyA, reinterpret_cast<LPVOID*>(&fpRegDeleteKeyA));
            MH_CreateHook(GetProcAddress(hAdvapi32, "RegDeleteValueA"), &Detour_RegDeleteValueA, reinterpret_cast<LPVOID*>(&fpRegDeleteValueA));

            // 很多旧程序使用 RegOpenKeyA (它是 RegOpenKeyExA 的包装 但也需要 Hook)
            // 注意：RegOpenKeyA 在 advapi32 中通常直接导出
            void* pRegOpenKeyA = (void*)GetProcAddress(hAdvapi32, "RegOpenKeyA");
            if (pRegOpenKeyA) {
                // 我们可以直接重定向到 Detour_RegOpenKeyExA 的逻辑 或者简单地实现一个 Detour_RegOpenKeyA
                // 这里为了简单 假设程序主要用 Ex 如果用了非 Ex 通常也会被上面的 Ex 捕获（如果它是通过 Ex 实现的）
                // 但为了保险 建议也 Hook 它
                // 由于参数不同 这里暂不展开 通常 Ex 足够覆盖 95% 的情况
            }
        }
    }

    // --- [新增] 组 G: User32 窗口 Hook (解决标题栏乱码) ---
    if (g_FakeACP != 0) {
        HMODULE hUser32 = LoadLibraryW(L"user32.dll");
        if (hUser32) {
            MH_CreateHook(GetProcAddress(hUser32, "CreateWindowExA"), &Detour_CreateWindowExA, reinterpret_cast<LPVOID*>(&fpCreateWindowExA));
            MH_CreateHook(GetProcAddress(hUser32, "GetWindowTextA"), &Detour_GetWindowTextA, reinterpret_cast<LPVOID*>(&fpGetWindowTextA));
            MH_CreateHook(GetProcAddress(hUser32, "DefWindowProcA"), &Detour_DefWindowProcA, reinterpret_cast<LPVOID*>(&fpDefWindowProcA));
        }
    }

    // --- [新增] 组 H: 消息与退出 Hook (解决残留和剩余乱码) ---
    if (g_FakeACP != 0) {
        HMODULE hUser32 = LoadLibraryW(L"user32.dll");
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        HMODULE hGdi32 = GetModuleHandleW(L"gdi32.dll");

        if (hUser32) {
            MH_CreateHook(GetProcAddress(hUser32, "SendMessageA"), &Detour_SendMessageA, reinterpret_cast<LPVOID*>(&fpSendMessageA));

            // 拦截退出消息 启动看门狗
            MH_CreateHook(GetProcAddress(hUser32, "PostQuitMessage"), &Detour_PostQuitMessage, reinterpret_cast<LPVOID*>(&fpPostQuitMessage));
        }

        if (hKernel32) {
            MH_CreateHook(GetProcAddress(hKernel32, "ExitProcess"), &Detour_ExitProcess, reinterpret_cast<LPVOID*>(&fpExitProcess));
        }

        if (hNtdll) {
            MH_CreateHook(GetProcAddress(hNtdll, "NtTerminateProcess"), &Detour_NtTerminateProcess, reinterpret_cast<LPVOID*>(&fpNtTerminateProcess));

            // 拦截最底层的用户态退出函数
            MH_CreateHook(GetProcAddress(hNtdll, "RtlExitUserProcess"), &Detour_RtlExitUserProcess, reinterpret_cast<LPVOID*>(&fpRtlExitUserProcess));
        }

        if (hGdi32) {
             MH_CreateHook(GetProcAddress(hGdi32, "EnumFontFamiliesExA"), &Detour_EnumFontFamiliesExA, reinterpret_cast<LPVOID*>(&fpEnumFontFamiliesExA));
             MH_CreateHook(GetProcAddress(hGdi32, "EnumFontFamiliesA"), &Detour_EnumFontFamiliesA, reinterpret_cast<LPVOID*>(&fpEnumFontFamiliesA));
        }
    }

    // --- [新增] 组 I: 时区 Hook ---
    if (g_EnableTimeZoneHook) {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

        if (hKernel32) {
            MH_CreateHook(GetProcAddress(hKernel32, "GetTimeZoneInformation"), &Detour_GetTimeZoneInformation, reinterpret_cast<LPVOID*>(&fpGetTimeZoneInformation));
            // GetDynamicTimeZoneInformation 在 XP 上可能不存在 需要判断
            void* pGetDynamic = (void*)GetProcAddress(hKernel32, "GetDynamicTimeZoneInformation");
            if (pGetDynamic) {
                MH_CreateHook(pGetDynamic, &Detour_GetDynamicTimeZoneInformation, reinterpret_cast<LPVOID*>(&fpGetDynamicTimeZoneInformation));
            }
        }

        if (hNtdll) {
            // 如果之前没有 Hook NtQuerySystemInformation 这里 Hook
            // 如果之前在其他组已经 Hook 了 需要合并逻辑 (通常建议只 Hook 一次 在 Detour 函数里分发)
            // 假设这是第一次 Hook：
            if (fpNtQuerySystemInformation == NULL) {
                 MH_CreateHook(GetProcAddress(hNtdll, "NtQuerySystemInformation"), &Detour_NtQuerySystemInformation, reinterpret_cast<LPVOID*>(&fpNtQuerySystemInformation));
            }
        }
    }

    // --- [新增] 组 J: NLS 代码页信息 Hook ---
    if (g_FakeACP != 0) {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (hKernel32) {
            // 拦截代码页属性查询 确保返回 Shift-JIS (932) 的特征
            // 例如：MaxCharSize=2, LeadByte 范围等
            MH_CreateHook(GetProcAddress(hKernel32, "GetCPInfo"), &Detour_GetCPInfo, reinterpret_cast<LPVOID*>(&fpGetCPInfo));
            MH_CreateHook(GetProcAddress(hKernel32, "GetCPInfoExW"), &Detour_GetCPInfoExW, reinterpret_cast<LPVOID*>(&fpGetCPInfoExW));
            MH_CreateHook(GetProcAddress(hKernel32, "IsValidCodePage"), &Detour_IsValidCodePage, reinterpret_cast<LPVOID*>(&fpIsValidCodePage));
        }
    }

    // --- [新增] 组 K: 时间 Hook ---
    if (g_EnableTimeHook) {
        // 1. Hook Kernel32 (标准路径)
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (hKernel32) {
            MH_CreateHook(GetProcAddress(hKernel32, "GetSystemTime"), &Detour_GetSystemTime, reinterpret_cast<LPVOID*>(&fpGetSystemTime));
            MH_CreateHook(GetProcAddress(hKernel32, "GetLocalTime"), &Detour_GetLocalTime, reinterpret_cast<LPVOID*>(&fpGetLocalTime));
            MH_CreateHook(GetProcAddress(hKernel32, "GetSystemTimeAsFileTime"), &Detour_GetSystemTimeAsFileTime, reinterpret_cast<LPVOID*>(&fpGetSystemTimeAsFileTime));

            void* pGetPrecise = (void*)GetProcAddress(hKernel32, "GetSystemTimePreciseAsFileTime");
            if (pGetPrecise) {
                MH_CreateHook(pGetPrecise, &Detour_GetSystemTimePreciseAsFileTime, reinterpret_cast<LPVOID*>(&fpGetSystemTimePreciseAsFileTime));
            }
        }

        // 2. Hook KernelBase (底层路径 防止绕过 Kernel32)
        HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
        if (hKernelBase) {
            // 注意：使用 _KB 后缀的函数指针和 Detour 函数 防止与 Kernel32 冲突
            MH_CreateHook(GetProcAddress(hKernelBase, "GetSystemTime"), &Detour_GetSystemTime_KB, reinterpret_cast<LPVOID*>(&fpGetSystemTime_KB));
            MH_CreateHook(GetProcAddress(hKernelBase, "GetLocalTime"), &Detour_GetLocalTime_KB, reinterpret_cast<LPVOID*>(&fpGetLocalTime_KB));
            MH_CreateHook(GetProcAddress(hKernelBase, "GetSystemTimeAsFileTime"), &Detour_GetSystemTimeAsFileTime_KB, reinterpret_cast<LPVOID*>(&fpGetSystemTimeAsFileTime_KB));

            void* pGetPreciseKB = (void*)GetProcAddress(hKernelBase, "GetSystemTimePreciseAsFileTime");
            if (pGetPreciseKB) {
                MH_CreateHook(pGetPreciseKB, &Detour_GetSystemTimePreciseAsFileTime_KB, reinterpret_cast<LPVOID*>(&fpGetSystemTimePreciseAsFileTime_KB));
            }
        }

        // 3. Hook Ntdll (NtQuerySystemTime - 最底层系统调用)
        // 很多 CRT 时间函数(如 time, _ftime) 和 GetSystemTime 最终都会调用它
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            void* pNtQuerySystemTime = (void*)GetProcAddress(hNtdll, "NtQuerySystemTime");
            if (pNtQuerySystemTime) {
                MH_CreateHook(pNtQuerySystemTime, &Detour_NtQuerySystemTime, reinterpret_cast<LPVOID*>(&fpNtQuerySystemTime));
            }
        }
    }

    // --- 组 L: 注册表重定向 Hook (仅当 YAP_HOOK_REG=1 时启用) ---
    if (g_HookReg && hNtdll) {
        void* pNtCreateKey      = (void*)GetProcAddress(hNtdll, "NtCreateKey");
        void* pNtOpenKey        = (void*)GetProcAddress(hNtdll, "NtOpenKey");
        void* pNtOpenKeyEx      = (void*)GetProcAddress(hNtdll, "NtOpenKeyEx");
        void* pNtDeleteKey      = (void*)GetProcAddress(hNtdll, "NtDeleteKey");
        void* pNtRenameKey = (void*)GetProcAddress(hNtdll, "NtRenameKey");
        void* pNtSetValueKey = (void*)GetProcAddress(hNtdll, "NtSetValueKey");
        void* pNtDeleteValueKey = (void*)GetProcAddress(hNtdll, "NtDeleteValueKey");

        fpNtQueryKey = (P_NtQueryKey)GetProcAddress(hNtdll, "NtQueryKey");
        fpNtSetInformationKey = (P_NtSetInformationKey)GetProcAddress(hNtdll, "NtSetInformationKey");

        if (pNtSetValueKey) MH_CreateHook(pNtSetValueKey, &Detour_NtSetValueKey, reinterpret_cast<LPVOID*>(&fpNtSetValueKey));
        if (pNtDeleteValueKey) MH_CreateHook(pNtDeleteValueKey, &Detour_NtDeleteValueKey, reinterpret_cast<LPVOID*>(&fpNtDeleteValueKey));
        if (pNtCreateKey)     MH_CreateHook(pNtCreateKey,     &Detour_NtCreateKey,     reinterpret_cast<LPVOID*>(&fpNtCreateKey));
        if (pNtOpenKey)       MH_CreateHook(pNtOpenKey,       &Detour_NtOpenKey,       reinterpret_cast<LPVOID*>(&fpNtOpenKey));
        if (pNtOpenKeyEx)     MH_CreateHook(pNtOpenKeyEx,     &Detour_NtOpenKeyEx,     reinterpret_cast<LPVOID*>(&fpNtOpenKeyEx));
        if (pNtDeleteKey)     MH_CreateHook(pNtDeleteKey,     &Detour_NtDeleteKey,     reinterpret_cast<LPVOID*>(&fpNtDeleteKey));
        if (pNtRenameKey) MH_CreateHook(pNtRenameKey, &Detour_NtRenameKey, reinterpret_cast<LPVOID*>(&fpNtRenameKey));

        void* pNtEnumerateKey = (void*)GetProcAddress(hNtdll, "NtEnumerateKey");
        if (pNtEnumerateKey) {
            MH_CreateHook(pNtEnumerateKey, &Detour_NtEnumerateKey, reinterpret_cast<LPVOID*>(&fpNtEnumerateKey));
        }

        void* pNtEnumerateValueKey = (void*)GetProcAddress(hNtdll, "NtEnumerateValueKey");
        if (pNtEnumerateValueKey) {
            MH_CreateHook(pNtEnumerateValueKey, &Detour_NtEnumerateValueKey, reinterpret_cast<LPVOID*>(&fpNtEnumerateValueKey));
        }

        // [新增] 注册表多值查询与变更通知 Hook
        void* pNtQueryMultipleValueKey = (void*)GetProcAddress(hNtdll, "NtQueryMultipleValueKey");
        if (pNtQueryMultipleValueKey) {
            MH_CreateHook(pNtQueryMultipleValueKey, &Detour_NtQueryMultipleValueKey, reinterpret_cast<LPVOID*>(&fpNtQueryMultipleValueKey));
        }

        void* pNtNotifyChangeKey = (void*)GetProcAddress(hNtdll, "NtNotifyChangeKey");
        if (pNtNotifyChangeKey) {
            MH_CreateHook(pNtNotifyChangeKey, &Detour_NtNotifyChangeKey, reinterpret_cast<LPVOID*>(&fpNtNotifyChangeKey));
        }

        void* pNtNotifyChangeMultipleKeys = (void*)GetProcAddress(hNtdll, "NtNotifyChangeMultipleKeys");
        if (pNtNotifyChangeMultipleKeys) {
            MH_CreateHook(pNtNotifyChangeMultipleKeys, &Detour_NtNotifyChangeMultipleKeys, reinterpret_cast<LPVOID*>(&fpNtNotifyChangeMultipleKeys));
        }

        // [新增] 事务注册表 Hook
        void* pNtCreateKeyTransacted = (void*)GetProcAddress(hNtdll, "NtCreateKeyTransacted");
        if (pNtCreateKeyTransacted) {
            MH_CreateHook(pNtCreateKeyTransacted, &Detour_NtCreateKeyTransacted, reinterpret_cast<LPVOID*>(&fpNtCreateKeyTransacted));
        }

        void* pNtOpenKeyTransacted = (void*)GetProcAddress(hNtdll, "NtOpenKeyTransacted");
        if (pNtOpenKeyTransacted) {
            MH_CreateHook(pNtOpenKeyTransacted, &Detour_NtOpenKeyTransacted, reinterpret_cast<LPVOID*>(&fpNtOpenKeyTransacted));
        }
    }

    // --- [新增] 组 M: 共享注册表查询 Hook (统一处理) ---
    // 只要启用了 区域伪装(FakeACP) 或者 注册表重定向(HookReg) 就需要挂钩 NtQueryValueKey
    if ((g_FakeACP != 0 || g_HookReg) && hNtdll) {
        // 防止重复挂钩的防御性检查
        if (fpNtQueryValueKey == NULL) {
            void* pNtQueryValueKey = (void*)GetProcAddress(hNtdll, "NtQueryValueKey");
            if (pNtQueryValueKey) {
                MH_CreateHook(pNtQueryValueKey, &Detour_NtQueryValueKey, reinterpret_cast<LPVOID*>(&fpNtQueryValueKey));
            }
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