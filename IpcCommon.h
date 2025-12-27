#pragma once
#include <windows.h>
#include <string>

// 管道名称前缀
static const wchar_t* const kPipeNamePrefix = L"\\\\.\\pipe\\YapLauncherPipe_";

// 事件名称前缀 (用于同步初始化)
static const wchar_t* const kEventNamePrefix = L"Local\\YapReadyEvent_";

// 共享内存名称前缀 (用于传递配置给环境被净化的子进程)
static const wchar_t* const kSharedMemPrefix = L"Local\\YapConfig_";

// 通信消息结构
struct IpcMessage {
    DWORD targetPid;
    wchar_t workDir[MAX_PATH];
};

// 响应消息
struct IpcResponse {
    bool success;
    DWORD error;
};

// 共享配置结构 (Launcher -> Child Hook)
struct HookConfig {
    wchar_t hookPath[MAX_PATH];
    wchar_t pipeName[MAX_PATH];
    wchar_t launcherDir[MAX_PATH]; // [新增] 传递启动器目录用于日志
};

// 辅助：生成事件名称
static std::wstring GetReadyEventName(DWORD pid) {
    return kEventNamePrefix + std::to_wstring(pid);
}

// 辅助：生成共享内存名称
static std::wstring GetConfigMapName(DWORD pid) {
    return kSharedMemPrefix + std::to_wstring(pid);
}