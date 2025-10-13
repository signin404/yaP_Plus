[English](./README.md) | 中文

# yaP Plus
[yaP](https://yap.rolandtoth.hu) (yet another Portablizer) 的重新实现

复制粘贴即可制作便携软件

## 功能
- [x] 目录保存
- [x] 目录删除
- [x] 目录还原
- [x] 目录复制/移动
- [x] 文件保存
- [x] 文件删除
- [x] 文件还原
- [x] 文件复制/移动
- [x] 注册表项保存
- [x] 注册表项删除
- [x] 注册表项还原
- [x] 注册表值保存
- [x] 注册表值删除
- [x] 注册表值还原
- [x] 创建目录
- [x] 创建文件
- [x] 创建符号链接
- [x] 创建注册表项
- [x] 创建注册表值
- [x] 写入INI
- [x] 文本替换
- [x] 文本行替换
- [x] 运行文件
- [x] 终止进程
- [x] 多实例运行
- [x] 注册表导入
- [x] 注册或注销DLL
- [x] 设置目录/文件属性
- [x] 设置命令行
- [x] 设置工作目录
- [x] 设置环境变量
- [x] 设置用户变量
- [x] 用户/环境变量字符串替换
- [x] 延迟执行
- [x] 延迟自动清理

* Plus
- [x] Unicode支持
- [x] 等待进程
- [x] 定时备份
- [x] 创建硬链接
- [x] 创建防火墙规则
- [x] 隐藏控制台程序窗口
- [x] 检测前台并挂起后台
- [x] 文件写入格式编码检测
- [x] 异常退出解决方案
- [x] 硬链接完整目录遍历
- [x] 硬/符号链接单层目录遍历

## 未移植功能
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

## 便携化方案对比

### 挂钩

*   **兼容性:** 低
*   **性能损耗:** 低
*   **隔离程度:** 中
*   **核心原理:** 通过挂钩系统 API 接口 实现文件或注册表操作的重定向
*   **优点:**
    *   性能损耗可忽略不计
*   **缺点:**
    *   软件越复杂或挂钩越多 冲突概率呈指数级增高
    *   对于不兼容的软件或插件 需要进行针对性的修复
    *   持续维护的工作量巨大

### 启动器

*   **兼容性:** 高
*   **性能损耗:** 无
*   **隔离程度:** 无
*   **核心原理:** 运行前写入配置 退出后删除或还原
*   **优点:**
    *   除了少数需要加载驱动的软件 几乎是通用方案
*   **缺点:**
    *   不适合行为不良的软件
    *   需要加载驱动的软件可能不适用
    *   如果软件不支持符号链接且配置文件很大 会导致大量写入
*   **使用此方案的软件:**
    *   [PortableApps.com Launcher](https://portableapps.com/apps/development/portableapps.com_launcher)
    *   [X-Launcher](https://www.winpenpack.com/en/download.php?view.15) | [x64](https://www.portablefreeware.com/index.php?id=3134)
    *   [AutoRun LWMenu](https://github.com/lwcorp/lwmenu)

### 虚拟化

*   **兼容性:** 中
*   **性能损耗:** 高
*   **隔离程度:** 高
*   **核心原理:** 创建一个虚拟化容器让软件在其中运行 与真实系统隔离
*   **优点:**
    *   适合行为不良、轻量级且不需要高性能的软件
*   **缺点:**
    *   **打包与体积:** 需要先将软件的所有文件打包 运行时再释放 导致文件体积翻倍
    *   **维护不便:** 安装或卸载游戏模组等插件 都需要对整个软件包重新打包
    *   **兼容性问题:** 需要挂钩的游戏插件可能无法在虚拟化环境中正常工作
    *   **性能瓶颈:** 虚拟化转译带来的性能损耗不可忽视 因此**不适合游戏或对性能要求高的软件**
*   **使用此方案的软件:**
    *   [Turbo Studio](https://turbo.net/studio)
    *   VMware ThinApp
    *   [Enigma Virtual Box](https://enigmaprotector.com/en/aboutvb.html)

### 自解压文件

*   **兼容性:** 高
*   **性能损耗:** 无
*   **隔离程度:** 无
*   **核心原理:** 将软件和配置释放到临时目录(%TEMP%)后运行 退出后删除
*   **优点:**
    *   制作简单 只需将软件和配置直接打包即可
*   **缺点:**
    *   无法处理注册表
    *   运行时更改的软件配置无法被保存
    *   每次运行都需要重新释放
*   **使用此方案的软件:**
    *   [PortableR](https://github.com/Shuunen/portabler)
    *   [单文件制作工具](http://wuyou.net/forum.php?mod=viewthread&tid=437991)
