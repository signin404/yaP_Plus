// IpcCommon.h
#pragma once
#include <windows.h>

// 管道名称前缀
static const wchar_t* const kPipeNamePrefix = L"\\\\.\\pipe\\YapLauncherPipe_";

// 通信消息结构
struct IpcMessage {
    DWORD targetPid;           // 目标进程 ID
    wchar_t workDir[MAX_PATH]; // 预留
};

// 响应消息
struct IpcResponse {
    bool success;
    DWORD error;
};