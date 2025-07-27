#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <shlwapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "User32.lib")

// --- Start of Custom INI Reader ---

// Helper function to trim whitespace from both ends of a string
std::wstring trim(const std::wstring& s) {
    const std::wstring WHITESPACE = L" \t\n\r\f\v";
    size_t first = s.find_first_not_of(WHITESPACE);
    if (std::wstring::npos == first) {
        return L"";
    }
    size_t last = s.find_last_not_of(WHITESPACE);
    return s.substr(first, (last - first + 1));
}

// Custom INI parser that works on a string containing the file content
std::wstring GetValueFromIniContent(const std::wstring& content, const std::wstring& section, const std::wstring& key) {
    std::wstringstream stream(content);
    std::wstring line;
    std::wstring currentSection;
    std::wstring searchKey = trim(key);
    std::wstring searchSection = L"[" + trim(section) + L"]";

    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty() || line[0] == L';' || line[0] == L'#') {
            continue;
        }

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
    return L""; // Not found
}

// Reads a file into a wstring, auto-detecting encoding (UTF-8, UTF-16)
bool ReadFileToWString(const std::wstring& path, std::wstring& out_content) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    if (buffer.size() < 2) { // Not enough data for BOM
        if (buffer.empty()) {
            out_content = L"";
            return true;
        }
        // Assume UTF-8 if no BOM
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, &buffer[0], (int)buffer.size(), NULL, 0);
        out_content.resize(size_needed);
        MultiByteToWideChar(CP_UTF8, 0, &buffer[0], (int)buffer.size(), &out_content[0], size_needed);
        return true;
    }

    // Check for BOMs
    if (buffer[0] == (char)0xFF && buffer[1] == (char)0xFE) { // UTF-16 LE
        out_content = std::wstring(reinterpret_cast<wchar_t*>(&buffer[2]), (buffer.size() / 2) - 1);
    } else if (buffer[0] == (char)0xFE && buffer[1] == (char)0xFF) { // UTF-16 BE (needs byte swap)
        for (size_t i = 2; i < buffer.size(); i += 2) {
            out_content += static_cast<wchar_t>((buffer[i] << 8) | buffer[i + 1]);
        }
    } else if (buffer.size() >= 3 && buffer[0] == (char)0xEF && buffer[1] == (char)0xBB && buffer[2] == (char)0xBF) { // UTF-8 with BOM
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, &buffer[3], (int)buffer.size() - 3, NULL, 0);
        out_content.resize(size_needed);
        MultiByteToWideChar(CP_UTF8, 0, &buffer[3], (int)buffer.size() - 3, &out_content[0], size_needed);
    } else { // No BOM, assume UTF-8
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, &buffer[0], (int)buffer.size(), NULL, 0);
        out_content.resize(size_needed);
        MultiByteToWideChar(CP_UTF8, 0, &buffer[0], (int)buffer.size(), &out_content[0], size_needed);
    }
    return true;
}

// --- End of Custom INI Reader ---

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

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    // 1. Get INI file path
    wchar_t launcherPath[MAX_PATH];
    GetModuleFileNameW(NULL, launcherPath, MAX_PATH);
    std::wstring iniPath = launcherPath;
    size_t pos = iniPath.find_last_of(L".");
    if (pos != std::wstring::npos) {
        iniPath.replace(pos, std::wstring::npos, L".ini");
    }

    // 2. Read INI file using the custom reader
    std::wstring iniContent;
    if (!ReadFileToWString(iniPath, iniContent)) {
        MessageBoxW(NULL, (L"无法读取INI文件: " + iniPath).c_str(), L"文件错误", MB_ICONERROR);
        return 1;
    }

    // 3. Get values from the INI content
    std::wstring appPathRaw = GetValueFromIniContent(iniContent, L"Settings", L"application");
    std::wstring commandLine = GetValueFromIniContent(iniContent, L"Settings", L"commandline");
    std::wstring workDirRaw = GetValueFromIniContent(iniContent, L"Settings", L"workdir");
    std::wstring checkTimeString = GetValueFromIniContent(iniContent, L"Settings", L"checktime");
    int checkTime = checkTimeString.empty() ? 10 : _wtoi(checkTimeString.c_str());
    if (checkTime <= 0) checkTime = 10;

    if (appPathRaw.empty()) {
        MessageBoxW(NULL, L"INI配置文件中未找到或未设置 'application' 路径。", L"配置错误", MB_ICONERROR);
        return 1;
    }
    
    // 4. Process paths: convert to absolute and validate
    wchar_t absoluteAppPath[MAX_PATH];
    if (GetFullPathNameW(appPathRaw.c_str(), MAX_PATH, absoluteAppPath, NULL) == 0) {
        MessageBoxW(NULL, L"转换应用程序路径为绝对路径失败。", L"路径错误", MB_ICONERROR);
        return 1;
    }

    wchar_t appDir[MAX_PATH];
    wcscpy_s(appDir, absoluteAppPath);
    PathRemoveFileSpecW(appDir);

    std::wstring finalWorkDir;
    if (!workDirRaw.empty()) {
        wchar_t absoluteWorkDir[MAX_PATH];
        GetFullPathNameW(workDirRaw.c_str(), MAX_PATH, absoluteWorkDir, NULL);
        if (PathFileExistsW(absoluteWorkDir)) {
            finalWorkDir = absoluteWorkDir;
        } else {
            finalWorkDir = appDir;
        }
    } else {
        finalWorkDir = appDir;
    }

    // 5. Prepare for CreateProcess
    std::wstring fullCommandLine = L"\"" + std::wstring(absoluteAppPath) + L"\" " + commandLine;
    wchar_t commandLineBuffer[4096];
    wcscpy_s(commandLineBuffer, fullCommandLine.c_str());

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // 6. Create the process
    if (!CreateProcessW(NULL, commandLineBuffer, NULL, NULL, FALSE, 0, NULL, finalWorkDir.c_str(), &si, &pi)) {
        std::wstring errorMsg = L"启动程序失败: \n" + std::wstring(absoluteAppPath);
        MessageBoxW(NULL, errorMsg.c_str(), L"启动错误", MB_ICONERROR);
        return 1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // 7. Handle wait processes
    std::vector<std::wstring> waitProcesses;
    for (int i = 1; ; ++i) {
        std::wstring key = L"waitprocess" + std::to_wstring(i);
        std::wstring process = GetValueFromIniContent(iniContent, L"Settings", key);
        if (process.empty()) break;
        waitProcesses.push_back(process);
    }

    if (!waitProcesses.empty()) {
        Sleep(3000);
        while (AreWaitProcessesRunning(waitProcesses)) {
            Sleep(checkTime * 1000);
        }
    }

    return 0;
}