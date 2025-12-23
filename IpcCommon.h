#pragma once
#include <windows.h>
#include <string>

// 管道名称前缀
static const wchar_t* const kPipeNamePrefix = L"\\\\.\\pipe\\YapLauncherPipe_";

// 事件名称前缀 (用于同步初始化)
static const wchar_t* const kEventNamePrefix = L"Local\\YapReadyEvent_";

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

// 辅助：生成事件名称
static std::wstring GetReadyEventName(DWORD pid) {
    return kEventNamePrefix + std::to_wstring(pid);
}