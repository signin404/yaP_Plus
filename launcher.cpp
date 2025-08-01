#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <atomic>
#include <thread>
#include <utility> // For std::pair
#include <shlwapi.h>
#include <tlhelp32.h>
#include <shellapi.h> // Header for SHFileOperationW
#include <shlobj.h>   // For SHGetKnownFolderPath and KNOWNFOLDERID

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib") // <-- The final, definitive fix is here

// --- Function pointer types for NTDLL functions ---
typedef LONG (NTAPI *pfnNtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG (NTAPI *pfnNtResumeProcess)(IN HANDLE ProcessHandle);
pfnNtSuspendProcess g_NtSuspendProcess = nullptr;
pfnNtResumeProcess g_NtResumeProcess = nullptr;


// --- Path and INI Parsing Utilities ---
std::wstring trim(const std::wstring& s) {
    const std::wstring WHITESPACE = L" \t\n\r\f\v";
    size_t first = s.find_first_not_of(WHITESPACE);
    if (std::wstring::npos == first) return L"";
    size_t last = s.find_last_not_of(WHITESPACE);
    return s.substr(first, (last - first + 1));
}

// --- NEW: Path Variable Expansion ---
std::wstring GetKnownFolderPath(const KNOWNFOLDERID& rfid) {
    PWSTR pszPath = nullptr;
    HRESULT hr = SHGetKnownFolderPath(rfid, 0, NULL, &pszPath);
    if (SUCCEEDED(hr)) {
        std::wstring path = pszPath;
        CoTaskMemFree(pszPath);
        return path;
    }
    return L"";
}

std::wstring ExpandPathVariables(std::wstring path) {
    static const std::vector<std::pair<std::wstring, KNOWNFOLDERID>> replacements = {
        {L"{Local}", FOLDERID_LocalAppData},
        {L"{LocalLow}", FOLDERID_LocalAppDataLow},
        {L"{Roaming}", FOLDERID_RoamingAppData},
        {L"{Documents}", FOLDERID_Documents},
        {L"{ProgramData}", FOLDERID_ProgramData},
        {L"{SavedGames}", FOLDERID_SavedGames},
        {L"{PublicDocuments}", FOLDERID_PublicDocuments}
    };

    for (const auto& rep : replacements) {
        size_t start_pos = path.find(rep.first);
        if (start_pos != std::wstring::npos) {
            std::wstring expanded = GetKnownFolderPath(rep.second);
            if (!expanded.empty()) {
                path.replace(start_pos, rep.first.length(), expanded);
            }
        }
    }
    return path;
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
                        if (suspend) g_NtSuspendProcess(hProcess);
                        else g_NtResumeProcess(hProcess);
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
                if (!areProcessesSuspended) {
                    SetAllProcessesState(data->suspendProcesses, true);
                    areProcessesSuspended = true;
                }
            } else {
                if (areProcessesSuspended) {
                    SetAllProcessesState(data->suspendProcesses, false);
                    areProcessesSuspended = false;
                }
            }
        }
        Sleep(data->checkInterval * 1000);
    }
    return 0;
}

// --- Backup Functionality ---
std::pair<std::wstring, std::wstring> ParseBackupEntry(const std::wstring& entry) {
    size_t separatorPos = entry.find(L"::");
    if (separatorPos == std::wstring::npos) {
        return {};
    }
    std::wstring dest = ExpandPathVariables(trim(entry.substr(0, separatorPos)));
    std::wstring src = ExpandPathVariables(trim(entry.substr(separatorPos + 2)));
    if (dest.empty() || src.empty()) {
        return {};
    }
    return {dest, src};
}

void PerformDirectoryBackup(const std::wstring& dest, const std::wstring& src) {
    if (!PathFileExistsW(src.c_str())) return;

    std::wstring backupDest = dest + L"_Backup";
    bool oldVersionExists = PathFileExistsW(dest.c_str());

    if (oldVersionExists) {
        MoveFileW(dest.c_str(), backupDest.c_str());
    }

    wchar_t srcPath[MAX_PATH * 2] = {0};
    wcscpy_s(srcPath, src.c_str());
    srcPath[src.length() + 1] = L'\0';

    wchar_t destPath[MAX_PATH * 2] = {0};
    wcscpy_s(destPath, dest.c_str());
    destPath[dest.length() + 1] = L'\0';

    SHFILEOPSTRUCTW sfos = {0};
    sfos.wFunc = FO_COPY;
    sfos.pFrom = srcPath;
    sfos.pTo = destPath;
    sfos.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT | FOF_NOCONFIRMMKDIR;

    int result = SHFileOperationW(&sfos);
    if (result == 0 && oldVersionExists) {
        wchar_t backupPath[MAX_PATH * 2] = {0};
        wcscpy_s(backupPath, backupDest.c_str());
        backupPath[backupDest.length() + 1] = L'\0';

        SHFILEOPSTRUCTW delSfos = {0};
        delSfos.wFunc = FO_DELETE;
        delSfos.pFrom = backupPath;
        delSfos.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
        SHFileOperationW(&delSfos);
    }
}

void PerformFileBackup(const std::wstring& dest, const std::wstring& src) {
    if (!PathFileExistsW(src.c_str())) return;

    std::wstring backupDest = dest + L"_Backup";
    bool oldVersionExists = PathFileExistsW(dest.c_str());

    if (oldVersionExists) {
        MoveFileW(dest.c_str(), backupDest.c_str());
    }

    if (CopyFileW(src.c_str(), dest.c_str(), FALSE)) {
        if (oldVersionExists) {
            DeleteFileW(backupDest.c_str());
        }
    }
}

struct BackupThreadData {
    std::atomic<bool>* shouldStop;
    std::atomic<bool>* isWorking;
    int backupInterval;
    std::vector<std::pair<std::wstring, std::wstring>> backupDirs;
    std::vector<std::pair<std::wstring, std::wstring>> backupFiles;
};

DWORD WINAPI BackupWorkerThread(LPVOID lpParam) {
    BackupThreadData* data = static_cast<BackupThreadData*>(lpParam);
    while (!*(data->shouldStop)) {
        Sleep(data->backupInterval);
        if (*(data->shouldStop)) break;

        *(data->isWorking) = true;

        for (const auto& pair : data->backupDirs) {
            PerformDirectoryBackup(pair.first, pair.second);
        }
        for (const auto& pair : data->backupFiles) {
            PerformFileBackup(pair.first, pair.second);
        }

        *(data->isWorking) = false;
    }
    return 0;
}

// --- Main Application Logic ---
void LaunchApplication(const std::wstring& iniContent) {
    std::wstring appPathRaw = ExpandPathVariables(GetValueFromIniContent(iniContent, L"Settings", L"application"));
    if (appPathRaw.empty()) return;

    wchar_t absoluteAppPath[MAX_PATH];
    GetFullPathNameW(appPathRaw.c_str(), MAX_PATH, absoluteAppPath, NULL);
    wchar_t appDir[MAX_PATH];
    wcscpy_s(appDir, absoluteAppPath);
    PathRemoveFileSpecW(appDir);
    
    std::wstring workDirRaw = ExpandPathVariables(GetValueFromIniContent(iniContent, L"Settings", L"workdir"));
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
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        g_NtSuspendProcess = (pfnNtSuspendProcess)GetProcAddress(hNtdll, "NtSuspendProcess");
        g_NtResumeProcess = (pfnNtResumeProcess)GetProcAddress(hNtdll, "NtResumeProcess");
    }

    wchar_t launcherFullPath[MAX_PATH];
    GetModuleFileNameW(NULL, launcherFullPath, MAX_PATH);
    std::wstring iniPath = launcherFullPath;
    size_t pos = iniPath.find_last_of(L".");
    if (pos != std::wstring::npos) iniPath.replace(pos, std::wstring::npos, L".ini");
    std::wstring iniContent;
    ReadFileToWString(iniPath, iniContent);

    wchar_t launcherBaseName[MAX_PATH];
    wcscpy_s(launcherBaseName, PathFindFileNameW(launcherFullPath));
    PathRemoveExtensionW(launcherBaseName);
    
    std::wstring appPathRaw = ExpandPathVariables(GetValueFromIniContent(iniContent, L"Settings", L"application"));
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
        
        // --- Setup Threads ---
        HANDLE hMonitorThread = NULL;
        MonitorThreadData monitorData;
        std::atomic<bool> stopMonitor(false);
        HANDLE hBackupThread = NULL;
        BackupThreadData backupData;
        std::atomic<bool> stopBackup(false);
        std::atomic<bool> isBackupWorking(false);

        // Foreground Monitor Setup
        std::wstring foregroundAppName = GetValueFromIniContent(iniContent, L"Settings", L"foreground");
        if (!foregroundAppName.empty()) {
            monitorData.shouldStop = &stopMonitor;
            monitorData.foregroundAppName = foregroundAppName;
            monitorData.suspendProcesses = GetMultiValueFromIniContent(iniContent, L"Settings", L"suspend");
            std::wstring fgCheckStr = GetValueFromIniContent(iniContent, L"Settings", L"foregroundcheck");
            monitorData.checkInterval = fgCheckStr.empty() ? 1 : _wtoi(fgCheckStr.c_str());
            if (monitorData.checkInterval <= 0) monitorData.checkInterval = 1;
            if (!monitorData.suspendProcesses.empty()) {
                hMonitorThread = CreateThread(NULL, 0, ForegroundMonitorThread, &monitorData, 0, NULL);
            }
        }

        // Backup Thread Setup
        std::wstring backupTimeStr = GetValueFromIniContent(iniContent, L"Settings", L"backuptime");
        int backupTime = backupTimeStr.empty() ? 0 : _wtoi(backupTimeStr.c_str());
        if (backupTime > 0) {
            backupData.shouldStop = &stopBackup;
            backupData.isWorking = &isBackupWorking;
            backupData.backupInterval = backupTime * 60 * 1000;
            
            auto dirEntries = GetMultiValueFromIniContent(iniContent, L"Settings", L"backupdir");
            for(const auto& entry : dirEntries) backupData.backupDirs.push_back(ParseBackupEntry(entry));
            
            auto fileEntries = GetMultiValueFromIniContent(iniContent, L"Settings", L"backupfile");
            for(const auto& entry : fileEntries) backupData.backupFiles.push_back(ParseBackupEntry(entry));

            if (!backupData.backupDirs.empty() || !backupData.backupFiles.empty()) {
                hBackupThread = CreateThread(NULL, 0, BackupWorkerThread, &backupData, 0, NULL);
            }
        }

        // --- Main Application Launch ---
        wchar_t absoluteAppPath[MAX_PATH];
        GetFullPathNameW(appPathRaw.c_str(), MAX_PATH, absoluteAppPath, NULL);
        STARTUPINFOW si; PROCESS_INFORMATION pi; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si); ZeroMemory(&pi, sizeof(pi));
        std::wstring fullCommandLine = L"\"" + std::wstring(absoluteAppPath) + L"\" " + GetValueFromIniContent(iniContent, L"Settings", L"commandline");
        wchar_t commandLineBuffer[4096]; wcscpy_s(commandLineBuffer, fullCommandLine.c_str());
        
        std::wstring workDirRaw = ExpandPathVariables(GetValueFromIniContent(iniContent, L"Settings", L"workdir"));
        wchar_t appDir[MAX_PATH]; wcscpy_s(appDir, absoluteAppPath); PathRemoveFileSpecW(appDir);
        std::wstring finalWorkDir;
        if (!workDirRaw.empty()) {
            wchar_t absoluteWorkDir[MAX_PATH]; GetFullPathNameW(workDirRaw.c_str(), MAX_PATH, absoluteWorkDir, NULL);
            if (PathFileExistsW(absoluteWorkDir)) finalWorkDir = absoluteWorkDir; else finalWorkDir = appDir;
        } else { finalWorkDir = appDir; }

        if (!CreateProcessW(NULL, commandLineBuffer, NULL, NULL, FALSE, 0, NULL, finalWorkDir.c_str(), &si, &pi)) {
            MessageBoxW(NULL, (L"启动程序失败: \n" + std::wstring(absoluteAppPath)).c_str(), L"启动错误", MB_ICONERROR);
            if (hMonitorThread) { stopMonitor = true; WaitForSingleObject(hMonitorThread, 1500); CloseHandle(hMonitorThread); }
            if (hBackupThread) { stopBackup = true; while(isBackupWorking) Sleep(100); WaitForSingleObject(hBackupThread, 1500); CloseHandle(hBackupThread); }
            CloseHandle(hMutex);
            return 1;
        }
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        // --- Wait Process Logic ---
        std::vector<std::wstring> waitProcesses = GetMultiValueFromIniContent(iniContent, L"Settings", L"waitprocess");
        if (GetValueFromIniContent(iniContent, L"Settings", L"multiple") == L"1") {
            const wchar_t* appFilename = PathFindFileNameW(absoluteAppPath);
            if (appFilename && wcslen(appFilename) > 0) waitProcesses.push_back(appFilename);
        }
        if (!waitProcesses.empty()) {
            std::wstring waitCheckStr = GetValueFromIniContent(iniContent, L"Settings", L"waitcheck");
            int waitCheck = waitCheckStr.empty() ? 10 : _wtoi(waitCheckStr.c_str());
            if (waitCheck <= 0) waitCheck = 10;
            Sleep(3000);
            while (AreWaitProcessesRunning(waitProcesses)) Sleep(waitCheck * 1000);
        }

        // --- CRITICAL CLEANUP ---
        if (hMonitorThread) {
            stopMonitor = true;
            WaitForSingleObject(hMonitorThread, 1500);
            CloseHandle(hMonitorThread);
            SetAllProcessesState(monitorData.suspendProcesses, false);
        }
        if (hBackupThread) {
            stopBackup = true;
            while (isBackupWorking) Sleep(100);
            WaitForSingleObject(hBackupThread, 1500);
            CloseHandle(hBackupThread);
        }
        CloseHandle(hMutex);

    } else {
        // --- SUBSEQUENT INSTANCE LOGIC ---
        CloseHandle(hMutex);
        if (GetValueFromIniContent(iniContent, L"Settings", L"multiple") == L"1") {
            LaunchApplication(iniContent);
        }
    }
    return 0;
}