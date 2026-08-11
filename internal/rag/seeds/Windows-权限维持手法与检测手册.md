# Windows 权限维持手法与检测手册

> 攻击者在 Windows 靶机上常用注册表、服务、计划任务、WMI、启动文件夹做持久化。本手册按「启动项 → 服务 → 计划任务 → WMI → 账号 → 登录脚本」排查并清理。

## 一、注册表启动项（Run 键）

```powershell
# 当前用户 + 所有用户
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
# 一次启动键
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"
# 检测特征：指向 temp/AppData/ProgramData 的可执行
```

## 二、服务型后门

```powershell
# 可疑服务（路径指向非系统目录/随机名）
Get-WmiObject Win32_Service | Where-Object { $_.PathName -match 'Temp|AppData|ProgramData|C:\\Users' } |
  Select Name, State, StartMode, PathName
# 新安装服务事件（7045）
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} -MaxEvents 20 | Select TimeCreated, Message
# 停用/删除可疑服务
sc stop <服务名>; sc delete <服务名>
```

## 三、计划任务

```powershell
schtasks /query /fo LIST /v | Out-File C:\evidence\tasks.txt
# 重点看任务指向的程序路径与触发条件
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |
  Where-Object { $_.Actions.Execute -match 'Temp|AppData|powershell|cmd' }
# 删除恶意任务
schtasks /Delete /TN "<任务名>" /F
```

## 四、WMI 事件订阅（隐蔽持久化）

```powershell
# WMI 永久事件订阅（无文件痕迹，攻击者常用）
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
# 发现可疑即删除（记录名称后删）
```

## 五、启动文件夹与登录脚本

```powershell
# 启动文件夹
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
# 组策略登录脚本（GP 后门）
gpedit.msc   # 计算机配置→Windows设置→脚本(启动/关机)
# 登录/注销脚本注册表
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
reg query "HKCU\Environment" /v UserInitMprLogonScript
```

## 六、账号与隐藏用户

```powershell
# 管理员组成员
net localgroup Administrators
# 隐藏账号（$ 结尾）
Get-LocalUser | Select Name, Enabled, PasswordRequired
Get-WmiObject Win32_UserAccount | Where-Object { $_.Name -like '*$' }
# 最近创建用户事件
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720} | Select TimeCreated, Message
# 锁定/删除后门账号
net user <账号> /active:no
net localgroup Administrators <账号> /delete
```

## 七、其他隐蔽手法

| 手法 | 检测 |
|------|------|
| DLL 劫持/搜索顺序劫持 | 检查程序同目录被注入 DLL、`Get-Process -Module` |
| 映像劫持 | `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"` |
| AppInit_DLLs | `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs` |
| 受信任的安装程序伪装 | 可疑路径下的 `WindowsUpdate.exe` 等伪装 |
| 内存马（无文件） | PowerShell 事件 4104、进程命令行审计 |

## 八、清理顺序与取证

1. **取证先行**：`reg export` 可疑键、`schtasks /query /xml` 导出、`cp` 可疑文件到 C:\evidence。
2. **从根源清理**：删 Run 键 → 删服务 → 删计划任务 → 删 WMI 订阅 → 锁账号。
3. **验证无复现**：重启后再次全量排查启动项与服务，确认后门未自愈。
4. **配套证据**：配合「Windows 事件日志」手册的 7045/4698/4720 事件写入溯源报告。
