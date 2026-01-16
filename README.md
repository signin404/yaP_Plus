English | [中文](./README_zh-CN.md)

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/signin404/yaP_Plus)
[![zread](https://img.shields.io/badge/Ask_Zread-_.svg?style=flat&color=00b0aa&labelColor=000000&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTQuOTYxNTYgMS42MDAxSDIuMjQxNTZDMS44ODgxIDEuNjAwMSAxLjYwMTU2IDEuODg2NjQgMS42MDE1NiAyLjI0MDFWNC45NjAxQzEuNjAxNTYgNS4zMTM1NiAxLjg4ODEgNS42MDAxIDIuMjQxNTYgNS42MDAxSDQuOTYxNTZDNS4zMTUwMiA1LjYwMDEgNS42MDE1NiA1LjMxMzU2IDUuNjAxNTYgNC45NjAxVjIuMjQwMUM1LjYwMTU2IDEuODg2NjQgNS4zMTUwMiAxLjYwMDEgNC45NjE1NiAxLjYwMDFaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00Ljk2MTU2IDEwLjM5OTlIMi4yNDE1NkMxLjg4ODEgMTAuMzk5OSAxLjYwMTU2IDEwLjY4NjQgMS42MDE1NiAxMS4wMzk5VjEzLjc1OTlDMS42MDE1NiAxNC4xMTM0IDEuODg4MSAxNC4zOTk5IDIuMjQxNTYgMTQuMzk5OUg0Ljk2MTU2QzUuMzE1MDIgMTQuMzk5OSA1LjYwMTU2IDE0LjExMzQgNS42MDE1NiAxMy43NTk5VjExLjAzOTlDNS42MDE1NiAxMC42ODY0IDUuMzE1MDIgMTAuMzk5OSA0Ljk2MTU2IDEwLjM5OTlaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik0xMy43NTg0IDEuNjAwMUgxMS4wMzg0QzEwLjY4NSAxLjYwMDEgMTAuMzk4NCAxLjg4NjY0IDEwLjM5ODQgMi4yNDAxVjQuOTYwMUMxMC4zOTg0IDUuMzEzNTYgMTAuNjg1IDUuNjAwMSAxMS4wMzg0IDUuNjAwMUgxMy43NTg0QzE0LjExMTkgNS42MDAxIDE0LjM5ODQgNS4zMTM1NiAxNC4zOTg0IDQuOTYwMVYyLjI0MDFDMTQuMzk4NCAxLjg4NjY0IDE0LjExMTkgMS42MDAxIDEzLjc1ODQgMS42MDAxWiIgZmlsbD0iI2ZmZiIvPgo8cGF0aCBkPSJNNCAxMkwxMiA0TDQgMTJaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00IDEyTDEyIDQiIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSIxLjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIvPgo8L3N2Zz4K&logoColor=ffffff)](https://zread.ai/signin404/yaP_Plus)

# yaP Plus
[yaP](https://yap.rolandtoth.hu) (yet another Portablizer) Reimplementation

Just copy and paste to create portable software.

[Quick Guide](https://github.com/signin404/yaP_Plus/discussions/50)

## Feature
- [x] Save directory/file
- [x] Delete directory/file
- [x] Restore directory/file
- [x] Copy or move directory/file
- [x] Save registry key/value
- [x] Delete registry key/value
- [x] Restore registry key/value
- [x] Create directory/file
- [x] Create registry key/value
- [x] Create symbolic link
- [x] Write INI
- [x] Text replacement
- [x] Line text replacement
- [x] Run file
- [x] Terminate process
- [x] Run multiple instances
- [x] Import registry
- [x] Register or unregister DLL
- [x] Set directory/file attributes
- [x] Set command line
- [x] Set working directory
- [x] Set up environment/user variables
- [x] Environment/user variable string replacement
- [x] Delayed execution
- [x] Delayed automatic cleanup

* Plus
- [x] Unicode support
- [x] Wait for process
- [x] Scheduled backup
- [x] Create hard links
- [x] Create firewall rules
- [x] Hide console program window
- [x] Detect foreground and suspend background processes
- [x] File write format encoding detection
- [x] Exception exit solutions
- [x] Full directory traversal with hard links
- [x] Hard/Symbolic Link Single-Level Directory Traversal
- [x] Check the parent process or path and terminate the process
- [x] Traverse subdirectories and delete files/directories
- [x] (Experimental) Hook Redirect File Operations
- [x] (Experimental) Hook Forged volume serial number
- [x] (Experimental) Hook to prevent network connection
- [x] (Experimental) Injecting a third-party DLL

## Unported Features
* !admin
* !dotnet
* !java
* !online
* !os
* clip
* ->regkey
* ->regvalue
* date
* iniread
* message
* nowait
* quit
* regexport
* regmerge
* systemrefresh

## Comparison of Portable Solutions

### Hooking

*   **Compatibility:** Low
*   **Performance Overhead:** Low
*   **Isolation Level:** Medium
*   **Core Principle:** Achieves redirection by hooking (intercepting) API calls.
*   **Pros:**
    *   Negligible performance loss.
*   **Cons:**
    *   The more complex the software or the more hooks are used, the higher the probability of conflicts.
    *   Incompatible software or plugins require targeted fixes.
    *   The ongoing maintenance workload is high.

### Launcher

*   **Compatibility:** High
*   **Performance Overhead:** None
*   **Isolation Level:** None
*   **Core Principle:** Writes configuration before the application runs and cleans it up after exit.
*   **Pros:**
    *   Almost universally compatible, except for some software that loads drivers.
*   **Cons:**
    *   Not suitable for "badly-behaved" software.
    *   Software that requires drivers might not be applicable.
    *   If the software doesn't support symbolic links and the configuration file is large, it could result in excessive data writes.
*   **Software using this solution:**
    *   [PortableApps.com Launcher](https://portableapps.com/apps/development/portableapps.com_launcher)
    *   [PortableApps Compiler & Management](https://github.com/daemondevin/pac-man)
    *   [X-Launcher](https://www.winpenpack.com/en/download.php?view.15) | [x64](https://www.portablefreeware.com/index.php?id=3134)
    *   [AutoRun LWMenu](https://github.com/lwcorp/lwmenu)
    *   [PortableXE](https://github.com/LMLK-seal/PortableXE)

### Virtualization

*   **Compatibility:** Medium
*   **Performance Overhead:** High
*   **Isolation Level:** High
*   **Core Principle:** Creates a virtual container (sandbox) and runs the software within it.
*   **Pros:**
    *   Suitable for badly-behaved or lightweight software that does not require high performance.
*   **Cons:**
    *   **Packaging & Size:** Requires packaging all of the application's files, which are then extracted at runtime, potentially leading to a much larger file size.
    *   **Inconvenient Maintenance:** Installing or uninstalling game mods requires repackaging the entire application.
    *   **Compatibility Issues:** Game plugins that rely on hooking may not be compatible with the virtualized environment.
    *   **Performance Bottleneck:** The performance overhead from the translation/virtualization layer is significant, making it unsuitable for gaming or other high-performance software.
*   **Software using this solution:**
    *   [Turbo Studio](https://turbo.net/studio)
    *   VMware ThinApp
    *   [Enigma Virtual Box](https://enigmaprotector.com/en/aboutvb.html)

### Self-extracting file

*   **Compatibility:** High
*   **Performance Overhead:** None
*   **Isolation Level:** None
*   **Core Principle:** Run after releasing the software and configuration to the temporary directory (%TEMP%), and delete afterward.
*   **Pros:**
    *   Easy to make—just package the software and configuration directly.
*   **Cons:**
    *   Unable to process the registry.
    *   Software configurations changed at runtime cannot be saved.
    *   Files need to be released again every time it runs.
*   **Software using this solution:**
    *   [PortableR](https://github.com/Shuunen/portabler)
    *   [Single-file creation tool](http://wuyou.net/forum.php?mod=viewthread&tid=437991)
