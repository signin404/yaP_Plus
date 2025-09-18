English | [中文](./README_zh-CN.md)

# yaP Plus
yet another Portablizer [(yaP)](https://yap.rolandtoth.hu) Reimplementation

Just copy and paste to create portable software.

## New Feature
* Unicode support  
* Wait for process  
* Scheduled backup  
* Create hard links  
* Create firewall rules  
* Hide console program window  
* Detect foreground and suspend background processes  
* File write format encoding detection  
* Exception exit solutions

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
    *   PortableApps.com Launcher
    *   X-Launcher
    *   AutoRun LWMenu

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
    *   Turbo Studio
    *   VMware ThinApp
    *   Enigma Virtual Box
