#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <atomic>
#include <thread>
#include <shlwapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "ntdll.lib") // For NtResumeProcess/NtSuspendProcess

// --- Function pointer types for NTDLL functions ---
typedef LONG (NTAPI *pfnNtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG (NTAPI *pfnNtResumeProcess)(IN HANDLE ProcessHandle);

// --- Global function pointers ---
pfnNtSuspendProcess g_NtSuspendProcess = nullptr;
pfnNtResumeProcess g_NtResumeProcess = nullptr;


// --- Custom INI Reader (No changes) ---
std::wstring trim(const std::wstring& s) {
    const std::wstring WHITESPACE = L" \t\n\r\f\v";
    size_t first = s.find_first_not_of(WHITESPACE);
    if (std::wstring::npos == first) return L"";
    size_t last = s.find_last_not_of(WHITESPACE);
    return s.substr(first, (last - first + 1));
}

std::wstring GetValueFromIniContent(const std::wstring& content, const std::wstring& section, const std::wstring& key) {
    std::wstringstream stream(content);
    std::wstring line;
    std::wstring currentSection;
    std::wstring searchKey = trim(key);
    std::wstring searchSection = L"[" + trim(section) + L"]";
    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty() || line[0] == L';' || line[0] == L'#') continue;
        if (line[0] == L'[' && line.back() == L']') {
            currentSection = line;
            continue;
        }
        if (_wcsicmp(currentSection.c_str(), searchSection.c_str()) == 0) {
            size_t delimiterPos = line.find(L'=');
            if (delimiterPos != std::wstring::npos) {
                std::wstring currentKey = trim(line.substr(0, delimiterPos));
                if (_wcsicmp(currentKey.c_str(), searchKey.c_str()) == 0) {
                    return trim(line.substr(delimiterPos + 1));
                }
            }
        }
    }
    return L"";
}

std::vector<std::wstring> GetMultiValueFromIniContent(const std::wstring& content, const std::wstring& section, const std::wstring& key) {
    std::vector<std::wstring> values;
    std::wstringstream stream(content);
    std::wstring line;
    std::wstring currentSection;
    std::wstring searchKey = trim(key);
    std::wstring searchSection = L"[" + trim(section) + L"]";
    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty() || line[0] == L';' || line[0] == L'#') continue;
        if (line[0] == L'[' && line.back() == L']') {
            currentSection = line;
            continue;
        }
        if (_wcsicmp(currentSection.c_str(), searchSection.c_str()) == 0) {
            size_t delimiterPos = line.find(L'=');
            if (delimiterPos != std::wstring::npos) {
                std::wstring currentKey = trim(line.substr(0, delimiterPos));
                if (_wcsicmp(currentKey.c_str(), searchKey.c_str()) == 0) {
                    values.push_back(trim(line.substr(delimiterPos + 1)));
                }
            }
        }
    }
    return values;
}

bool ReadFileToWString(const std::wstring& path, std::wstring& out_content) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    if (buffer.empty()) {
        out_content = L"";
        return true;
    }
    if (buffer.size() >= 2 && buffer[0] == (char)0xFF && buffer[1] == (char)0xFE) {
        out_content = std::wstring(reinterpret_cast<wchar_t*>(&buffer[2]), (buffer.size() / 2) - 1);
    } else if (buffer.size() >= 3 && buffer[0] == (char)0xEF && buffer[1] == (char)0xBB && buffer[2] == (char)0xBF) {
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, &buffer[3], (int)buffer.size() - 3, NULL, 0);
        out_content.resize(size_needed);
        MultiByteToWideChar(CP_UTF8, 0, &buffer[3], (int)buffer.size() - 3, &out_content[0], size_needed);
    } else {
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, &buffer[0], (int)buffer.size(), NULL, 0);
        out_content.resize(size_needed);
        MultiByteToWideChar(CP_UTF8, 0, &buffer[0], (int)buffer.size(), &out_content[0], size_needed);
    }
    return true;
}
// --- End of Custom INI Reader ---


// --- Process Management Functions ---

bool AreWaitProcessesRunning(const std::vector<std::wstring>& waitProcesses) {
    if (waitProcesses.empty()) return false;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
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

// Gets the process name for a given Process ID (PID).
std::wstring GetProcessNameByPid(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return L"";

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                CloseHandle(hSnapshot);
                return pe32.szExeFile;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return L"";
}

// Suspends or resumes all running instances of the specified processes.
void SetAllProcessesState(const std::vector<std::wstring>& processList, bool suspend) {
    if (processList.empty() || !g_NtSuspendProcess || !g_NtResumeProcess) return;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            for (const auto& processName : processList) {
                if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        if (suspend) {
                            g_NtSuspendProcess(hProcess);
                        } else {
                            g_NtResumeProcess(hProcess);
                        }
                        CloseHandle(hProcess);
                    }
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
}

// --- Foreground Monitoring Thread ---
struct MonitorThreadData {
    std::atomic<bool>* shouldStop;
    int checkInterval;
    std::wstring foregroundAppName;
    std::vector<std::wstring> suspendProcesses;
};

DWORD WINAPI ForegroundMonitorThread(LPVOID lpParam) {
    MonitorThreadData* data = static_cast<MonitorThreadData*>(lpParam);
    bool areProcessesSuspended = false;

    while (!*(data->shouldStop)) {
        HWND hForegroundWnd = GetForegroundWindow();
        if (hForegroundWnd) {
            DWORD foregroundPid = 0;
            GetWindowThreadProcessId(hForegroundWnd, &foregroundPid);
            std::wstring foregroundProcessName = GetProcessNameByPid(foregroundPid);

            if (_wcsicmp(foregroundProcessName.c_str(), data->foregroundAppName.c_str()) == 0) {
                // Target process is in the foreground
                if (!areProcessesSuspended) {
                    SetAllProcessesState(data->suspendProcesses, true); // Suspend
                    areProcessesSuspended = true;
                }
            } else {
                // Target process is NOT in the foreground
                if (areProcessesSuspended) {
                    SetAllProcessesState(data->suspendProcesses, false); // Resume
                    areProcessesSuspended = false;
                }
            }
        }
        Sleep(data->checkInterval * 1000);
    }
    return 0;
}


// Helper function to launch the main application.
void LaunchApplication(const std::wstring& iniContent) {
    std::wstring appPathRaw = GetValueFromIniContent(iniContent, L"Settings", L"application");
    if (appPathRaw.empty()) return;

    wchar_t absoluteAppPath[MAX_PATH];
    GetFullPathNameW(appPathRaw.c_str(), MAX_PATH, absoluteAppPath, NULL);

    wchar_t appDir[MAX_PATH];
    wcscpy_s(appDir, absoluteAppPath);
    PathRemoveFileSpecW(appDir);

    std::wstring workDirRaw = GetValueFromIniContent(iniContent, L"Settings", L"workdir");
    std::wstring finalWorkDir;
    if (!workDirRaw.empty()) {
        wchar_t absoluteWorkDir[MAX_PATH];
        GetFullPathNameW(workDirRaw.c_str(), MAX_PATH, absoluteWorkDir, NULL);
        if (PathFileExistsW(absoluteWorkDir)) finalWorkDir = absoluteWorkDir;
        else finalWorkDir = appDir;
    } else {
        finalWorkDir = appDir;
    }

    std::wstring commandLine = GetValueFromIniContent(iniContent, L"Settings", L"commandline");
    std::wstring fullCommandLine = L"\"" + std::wstring(absoluteAppPath) + L"\" " + commandLine;
    wchar_t commandLineBuffer[4096];
    wcscpy_s(commandLineBuffer, fullCommandLine.c_str());

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (CreateProcessW(NULL, commandLineBuffer, NULL, NULL, FALSE, 0, NULL, finalWorkDir.c_str(), &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}


int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    // --- Load NTDLL functions dynamically ---
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        g_NtSuspendProcess = (pfnNtSuspendProcess)GetProcAddress(hNtdll, "NtSuspendProcess");
        g_NtResumeProcess = (pfnNtResumeProcess)GetProcAddress(hNtdll, "NtResumeProcess");
    }

    wchar_t launcherFullPath[MAX_PATH];
    GetModuleFileNameW(NULL, launcherFullPath, MAX_PATH);
    
    std::wstring iniPath = launcherFullPath;
    size_t pos = iniPath.find_last_of(L".");
    if (pos != std::wstring::npos) {
        iniPath.replace(pos, std::wstring::npos, L".ini");
    }
    std::wstring iniContent;
    ReadFileToWString(iniPath, iniContent);

    wchar_t launcherBaseName[MAX_PATH];
    wcscpy_s(launcherBaseName, PathFindFileNameW(launcherFullPath));
    PathRemoveExtensionW(launcherBaseName);

    std::wstring appPathRaw = GetValueFromIniContent(iniContent, L"Settings", L"application");
    wchar_t appBaseName[MAX_PATH] = L"";
    if (!appPathRaw.empty()) {
        wcscpy_s(appBaseName, PathFindFileNameW(appPathRaw.c_str()));
        PathRemoveExtensionW(appBaseName);
    }

    std::wstring mutexName = L"Global\\" + std::wstring(launcherBaseName) + L"_" + std::wstring(appBaseName);

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = FALSE;

    HANDLE hMutex = CreateMutexW(&sa, TRUE, mutexName.c_str());
    bool isFirstInstance = (GetLastError() != ERROR_ALREADY_EXISTS);

    if (isFirstInstance) {
        // --- MASTER INSTANCE LOGIC ---
        if (appPathRaw.empty()) {
            MessageBoxW(NULL, L"INI配置文件中未找到或未设置 'application' 路径。", L"配置错误", MB_ICONERROR);
            CloseHandle(hMutex);
            return 1;
        }
        
        // --- Foreground Monitoring Setup ---
        HANDLE hMonitorThread = NULL;
        MonitorThreadData threadData;
        std::atomic<bool> stopMonitor(false);
        
        std::wstring foregroundAppName = GetValueFromIniContent(iniContent, L"Settings", L"foreground");
        if (!foregroundAppName.empty()) {
            threadData.shouldStop = &stopMonitor;
            threadData.foregroundAppName = foregroundAppName;
            threadData.suspendProcesses = GetMultiValueFromIniContent(iniContent, L"Settings", L"suspend");
            
            std::wstring fgCheckStr = GetValueFromIniContent(iniContent, L"Settings", L"foregroundcheck");
            threadData.checkInterval = fgCheckStr.empty() ? 1 : _wtoi(fgCheckStr.c_str());
            if (threadData.checkInterval <= 0) threadData.checkInterval = 1;

            if (!threadData.suspendProcesses.empty()) {
                hMonitorThread = CreateThread(NULL, 0, ForegroundMonitorThread, &threadData, 0, NULL);
            }
        }

        // --- Main Application Launch ---
        wchar_t absoluteAppPath[MAX_PATH];
        GetFullPathNameW(appPathRaw.c_str(), MAX_PATH, absoluteAppPath, NULL);
        
        wchar_t appDir[MAX_PATH];
        wcscpy_s(appDir, absoluteAppPath);
        PathRemoveFileSpecW(appDir);
        
        std::wstring workDirRaw = GetValueFromIniContent(iniContent, L"Settings", L"workdir");
        std::wstring finalWorkDir;
        if (!workDirRaw.empty()) {
            wchar_t absoluteWorkDir[MAX_PATH];
            GetFullPathNameW(workDirRaw.c_str(), MAX_PATH, absoluteWorkDir, NULL);
            if (PathFileExistsW(absoluteWorkDir)) finalWorkDir = absoluteWorkDir;
            else finalWorkDir = appDir;
        } else {
            finalWorkDir = appDir;
        }

        std::wstring commandLine = GetValueFromIniContent(iniContent, L"Settings", L"commandline");
        std::wstring fullCommandLine = L"\"" + std::wstring(absoluteAppPath) + L"\" " + commandLine;
        wchar_t commandLineBuffer[4096];
        wcscpy_s(commandLineBuffer, fullCommandLine.c_str());

        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        if (!CreateProcessW(NULL, commandLineBuffer, NULL, NULL, FALSE, 0, NULL, finalWorkDir.c_str(), &si, &pi)) {
            MessageBoxW(NULL, (L"启动程序失败: \n" + std::wstring(absoluteAppPath)).c_str(), L"启动错误", MB_ICONERROR);
            if (hMonitorThread) {
                stopMonitor = true;
                WaitForSingleObject(hMonitorThread, 2000);
                CloseHandle(hMonitorThread);
            }
            CloseHandle(hMutex);
            return 1;
        }

        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        // --- Wait Process Logic ---
        std::vector<std::wstring> waitProcesses = GetMultiValueFromIniContent(iniContent, L"Settings", L"waitprocess");
        std::wstring multipleValue = GetValueFromIniContent(iniContent, L"Settings", L"multiple");
        if (multipleValue == L"1") {
            const wchar_t* appFilename = PathFindFileNameW(absoluteAppPath);
            if (appFilename && wcslen(appFilename) > 0) {
                waitProcesses.push_back(appFilename);
            }
        }
        
        if (!waitProcesses.empty()) {
            std::wstring waitCheckStr = GetValueFromIniContent(iniContent, L"Settings", L"waitcheck");
            int waitCheck = waitCheckStr.empty() ? 10 : _wtoi(waitCheckStr.c_str());
            if (waitCheck <= 0) waitCheck = 10;
            
            Sleep(3000);
            while (AreWaitProcessesRunning(waitProcesses)) {
                Sleep(waitCheck * 1000);
            }
        }

        // --- CRITICAL CLEANUP ---
        if (hMonitorThread) {
            stopMonitor = true; // Signal thread to stop
            WaitForSingleObject(hMonitorThread, 2000); // Wait for it to exit
            CloseHandle(hMonitorThread);
            // Ensure all processes are resumed before we exit
            SetAllProcessesState(threadData.suspendProcesses, false);
        }

        CloseHandle(hMutex);

    } else {
        // --- SUBSEQUENT INSTANCE LOGIC ---
        CloseHandle(hMutex);

        std::wstring multipleValue = GetValueFromIniContent(iniContent, L"Settings", L"multiple");
        if (multipleValue == L"1") {
            LaunchApplication(iniContent);
        }
    }

    return 0;
}