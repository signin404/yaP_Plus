#include <windows.h>
#include <string>
#include <vector>
#include <shlwapi.h> // For PathRemoveFileSpecW
#include <tlhelp32.h> // For CreateToolhelp32Snapshot
#include <iostream>

#pragma comment(lib, "Shlwapi.lib") // Link against Shlwapi.lib for path functions

// Function to check if any of the specified processes are running
bool AreWaitProcessesRunning(const std::vector<std::wstring>& waitProcesses) {
    if (waitProcesses.empty()) {
        return false;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false; // Cannot check, assume they are not running
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            for (const auto& processName : waitProcesses) {
                if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                    CloseHandle(hSnapshot);
                    return true; // Found a process that we need to wait for
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return false; // None of the wait processes were found
}


int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    // 1. Get the path of the launcher executable to find the INI file
    wchar_t launcherPath[MAX_PATH];
    GetModuleFileNameW(NULL, launcherPath, MAX_PATH);

    std::wstring iniPath = launcherPath;
    size_t pos = iniPath.find_last_of(L".");
    if (pos != std::wstring::npos) {
        iniPath.replace(pos, std::wstring::npos, L".ini");
    }

    // 2. Read configuration from INI file
    wchar_t appPath[MAX_PATH];
    wchar_t commandLine[2048];
    wchar_t workDir[MAX_PATH];
    
    GetPrivateProfileStringW(L"Settings", L"application", L"", appPath, MAX_PATH, iniPath.c_str());
    GetPrivateProfileStringW(L"Settings", L"commandline", L"", commandLine, 2048, iniPath.c_str());
    GetPrivateProfileStringW(L"Settings", L"workdir", L"", workDir, MAX_PATH, iniPath.c_str());
    int checkTime = GetPrivateProfileIntW(L"Settings", L"checktime", 10, iniPath.c_str());

    if (std::wstring(appPath).empty()) {
        MessageBoxW(NULL, L"INI配置文件中未找到或未设置 'application' 路径。", L"配置错误", MB_ICONERROR);
        return 1;
    }

    // Read all waitprocess entries
    std::vector<std::wstring> waitProcesses;
    wchar_t waitProcessBuffer[MAX_PATH];
    for (int i = 1; ; ++i) {
        std::wstring key = L"waitprocess" + std::to_wstring(i);
        GetPrivateProfileStringW(L"Settings", key.c_str(), L"", waitProcessBuffer, MAX_PATH, iniPath.c_str());
        if (wcslen(waitProcessBuffer) == 0) {
            break; // No more waitprocess entries
        }
        waitProcesses.push_back(waitProcessBuffer);
    }

    // 3. Prepare paths and arguments for CreateProcess
    // Automatically add quotes around the application path
    std::wstring fullCommandLine = L"\"" + std::wstring(appPath) + L"\" " + std::wstring(commandLine);
    wchar_t commandLineBuffer[3000]; // CreateProcessW requires a mutable buffer
    wcscpy_s(commandLineBuffer, fullCommandLine.c_str());

    // If workdir is not set, default to the application's directory
    std::wstring finalWorkDir = workDir;
    if (finalWorkDir.empty()) {
        wchar_t appDir[MAX_PATH];
        wcscpy_s(appDir, appPath);
        PathRemoveFileSpecW(appDir); // Removes the filename part, leaving the directory
        finalWorkDir = appDir;
    }

    // 4. Create the process
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    bool success = CreateProcessW(
        NULL,                   // Use command line for module name
        commandLineBuffer,      // Command line (mutable)
        NULL,                   // Process handle not inheritable
        NULL,                   // Thread handle not inheritable
        FALSE,                  // Set handle inheritance to FALSE
        0,                      // No creation flags
        NULL,                   // Use parent's environment block
        finalWorkDir.empty() ? NULL : finalWorkDir.c_str(), // Starting directory
        &si,                    // Pointer to STARTUPINFO structure
        &pi                     // Pointer to PROCESS_INFORMATION structure
    );

    if (!success) {
        MessageBoxW(NULL, (L"启动程序失败: " + std::wstring(appPath)).c_str(), L"启动错误", MB_ICONERROR);
        return 1;
    }

    // 5. Wait for the main application to exit
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Close process and thread handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // 6. Handle waiting for other processes if any are specified
    if (!waitProcesses.empty()) {
        // Initial 3-second delay
        Sleep(3000);

        // Loop until all wait processes have exited
        while (AreWaitProcessesRunning(waitProcesses)) {
            Sleep(checkTime * 1000); // Wait for the specified interval
        }
    }

    return 0;
}