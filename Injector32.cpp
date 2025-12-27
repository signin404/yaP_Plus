// Injector32.cpp
// 编译选项: Release, x86, 静态链接 CRT (/MT)
#include <windows.h>
#include <iostream>
#include <string>
#include <tlhelp32.h>

// 简单的日志输出 方便调试（实际使用可去除）
void Log(const wchar_t* msg) {
    // OutputDebugStringW(msg);
}

bool Inject(DWORD pid, const std::wstring& dllPath) {
    Log(L"Injector32: Opening process...");
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    // 获取 LoadLibraryW 地址
    // 因为这是 32位 进程 GetModuleHandle 获取的是 32位 kernel32
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        CloseHandle(hProcess);
        return false;
    }
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibrary) {
        CloseHandle(hProcess);
        return false;
    }

    // 分配内存
    size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMem) {
        CloseHandle(hProcess);
        return false;
    }

    // 写入路径
    if (!WriteProcessMemory(hProcess, pRemoteMem, dllPath.c_str(), pathSize, NULL)) {
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // 创建远程线程
    Log(L"Injector32: Creating remote thread...");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMem, 0, NULL);

    if (!hThread) {
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // 等待注入完成
    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return (exitCode != 0); // LoadLibrary 返回非零表示成功
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) return 1;

    DWORD pid = _wtoi(argv[1]);
    std::wstring dllPath = argv[2];

    if (Inject(pid, dllPath)) {
        return 0; // 成功
    } else {
        return 1; // 失败
    }
}