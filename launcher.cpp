#include <windows.h>
#include <string>
#include <vector>
#include <shlwapi.h> // For Path functions
#include <tlhelp32.h> // For CreateToolhelp32Snapshot
#include <iostream>

#pragma comment(lib, "Shlwapi.lib") // Link against Shlwapi.lib for path functions
#pragma comment(lib, "User32.lib")  // Link against User32.lib for MessageBoxW

// Function to check if any of the specified processes are running (no changes needed here)
bool AreWaitProcessesRunning(const std::vector<std::wstring>& waitProcesses) {
    if (waitProcesses.empty()) {
        return false;
    }
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            for (const auto& processName : waitProcesses) {
                if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return false;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    // 1. Get INI file path
    wchar_t launcherPath[MAX_PATH];
    GetModuleFileNameW(NULL, launcherPath, MAX_PATH);
    std::wstring iniPath = launcherPath;
    size_t pos = iniPath.find_last_of(L".");
    if (pos != std::wstring::npos) {
        iniPath.replace(pos, std::wstring::npos, L".ini");
    }

    // 2. Read configuration from INI file (raw values)
    wchar_t appPathRaw[MAX_PATH];
    wchar_t commandLine[2048];
    wchar_t workDirRaw[MAX_PATH];
    
    GetPrivateProfileStringW(L"Settings", L"application", L"", appPathRaw, MAX_PATH, iniPath.c_str());
    GetPrivateProfileStringW(L"Settings", L"commandline", L"", commandLine, 2048, iniPath.c_str());
    GetPrivateProfileStringW(L"Settings", L"workdir", L"", workDirRaw, MAX_PATH, iniPath.c_str());
    int checkTime = GetPrivateProfileIntW(L"Settings", L"checktime", 10, iniPath.c_str());

    if (wcslen(appPathRaw) == 0) {
        MessageBoxW(NULL, L"INI配置文件中未找到或未设置 'application' 路径。", L"配置错误", MB_ICONERROR);
        return 1;
    }

    // 3. Process paths: convert to absolute and validate
    
    // Convert application path to absolute path
    wchar_t absoluteAppPath[MAX_PATH];
    if (GetFullPathNameW(appPathRaw, MAX_PATH, absoluteAppPath, NULL) == 0) {
        MessageBoxW(NULL, L"转换应用程序路径为绝对路径失败。", L"路径错误", MB_ICONERROR);
        return 1;
    }

    // Determine the application's own directory
    wchar_t appDir[MAX_PATH];
    wcscpy_s(appDir, absoluteAppPath);
    PathRemoveFileSpecW(appDir);

    // Determine the final working directory
    std::wstring finalWorkDir;
    if (wcslen(workDirRaw) > 0) {
        wchar_t absoluteWorkDir[MAX_PATH];
        GetFullPathNameW(workDirRaw, MAX_PATH, absoluteWorkDir, NULL);
        
        // Check if the specified working directory exists
        if (PathFileExistsW(absoluteWorkDir)) {
            finalWorkDir = absoluteWorkDir; // Use it if it exists
        } else {
            finalWorkDir = appDir; // Fallback to app's directory if it doesn't exist
        }
    } else {
        finalWorkDir = appDir; // Default to app's directory if not set
    }

    // 4. Prepare for CreateProcess
    std::wstring fullCommandLine = L"\"" + std::wstring(absoluteAppPath) + L"\" " + std::wstring(commandLine);
    wchar_t commandLineBuffer[3000];
    wcscpy_s(commandLineBuffer, fullCommandLine.c_str());

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // 5. Create the process with absolute paths
    bool success = CreateProcessW(
        NULL,
        commandLineBuffer,
        NULL, NULL, FALSE, 0, NULL,
        finalWorkDir.c_str(), // Use the validated, absolute working directory
        &si, &pi
    );

    if (!success) {
        std::wstring errorMsg = L"启动程序失败: \n" + std::wstring(absoluteAppPath);
        MessageBoxW(NULL, errorMsg.c_str(), L"启动错误", MB_ICONERROR);
        return 1;
    }

    // 6. Wait for processes to exit (no changes needed here)
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    std::vector<std::wstring> waitProcesses;
    wchar_t waitProcessBuffer[MAX_PATH];
    for (int i = 1; ; ++i) {
        std::wstring key = L"waitprocess" + std::to_wstring(i);
        GetPrivateProfileStringW(L"Settings", key.c_str(), L"", waitProcessBuffer, MAX_PATH, iniPath.c_str());
        if (wcslen(waitProcessBuffer) == 0) break;
        waitProcesses.push_back(waitProcessBuffer);
    }

    if (!waitProcesses.empty()) {
        Sleep(3000);
        while (AreWaitProcessesRunning(waitProcesses)) {
            Sleep(checkTime * 1000);
        }
    }

    return 0;
}