# Windows 加固清单（Server 2016 + Win10 Pro Sec）

> 覆盖 AWD 靶机群 Windows 系统：Windows_Server_2016、Win10-Pro_Sec。命令在管理员 PowerShell 执行，改动前先记录原始配置。

## Windows Administrator 重命名与 Guest 禁用
- 重命名 Administrator：`Rename-LocalUser -Name "Administrator" -NewName "admin_tf2026"`
- 禁用 Guest：`Disable-LocalUser -Name "Guest"`
- 查看本地用户：`Get-LocalUser`

## Windows 密码策略与锁定策略
- 密码策略（命令行）：`net accounts /minpwlen:12 /maxpwage:90 /minpwage:1`；查看：`net accounts`
- 图形界面：`secpol.msc` → 账户策略 → 密码策略 / 账户锁定策略（如 5 次失败锁定 30 分钟）

## Windows UAC 加固
- `secpol.msc` → 本地策略 → 安全选项：启用「内置管理员账户的管理员批准模式」；注册表方式：`Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1`

## Windows RDP 加固：修改 3389 端口
- 改端口：`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -Value 33489`
- 重启远程桌面服务：`Restart-Service TermService -Force`；同步放行新端口：`netsh advfirewall firewall add rule name="rdp33489" dir=in action=allow protocol=TCP localport=33489`

## Windows RDP NLA 网络级认证
- 注册表开启：`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1`
- 组策略：`gpedit.msc` → 计算机配置 → 管理模板 → Windows 组件 → 远程桌面服务 → 远程桌面会话主机 → 安全 → 要求使用网络级别身份验证 → 已启用；验证：mstsc 连接时先要求输入凭据

## Windows RDP 仅允许指定用户
- 加入远程桌面用户组：`Add-LocalGroupMember -Group "Remote Desktop Users" -Member "用户名"`
- 移除：`Remove-LocalGroupMember -Group "Remote Desktop Users" -Member "用户名"`
- 查看组成员：`Get-LocalGroupMember "Remote Desktop Users"`

## WinRM 认证与 TrustedHosts 清理
- 查看配置：`winrm get winrm/config`
- 清理 TrustedHosts：`winrm set winrm/config/client @{TrustedHosts=""}`
- 不需要则关闭服务：`Stop-Service WinRM; Set-Service WinRM -StartupType Disabled`；检查监听 5985：`netstat -ano | findstr 5985`

## WinRM 防火墙规则
- 查看组规则：`Get-NetFirewallRule -DisplayGroup "Windows Remote Management"`；禁用整组放行规则：`Set-NetFirewallRule -DisplayGroup "Windows Remote Management" -Enabled False`
- 仅放行本机子网 5985：`New-NetFirewallRule -DisplayName "WinRM-Local" -Direction Inbound -Protocol TCP -LocalPort 5985 -RemoteAddress 192.168.1.0/24 -Action Allow`

## Windows netsh advfirewall 防火墙基础
- 开启防火墙：`netsh advfirewall set allprofiles state on`
- 默认入站阻止、出站允许：`netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound`
- 查看规则：`netsh advfirewall firewall show rule name=all`

## Windows 防火墙放行/封禁端口
- 放行 80：`netsh advfirewall firewall add rule name="allow80" dir=in action=allow protocol=TCP localport=80`；封禁 4444：`netsh advfirewall firewall add rule name="block4444" dir=in action=block protocol=TCP localport=4444`
- 删除规则：`netsh advfirewall firewall delete rule name="allow80"`

## Windows 防火墙开启日志
- 设置日志路径：`netsh advfirewall set allprofiles logging filename C:\Windows\System32\LogFiles\Firewall\pfirewall.log`；记录丢弃与允许：`netsh advfirewall set allprofiles logging droppedconnections enable` 与 `allowedconnections enable`
- 查看日志：`Get-Content C:\Windows\System32\LogFiles\Firewall\pfirewall.log -Tail 50`

## Windows 补丁更新
- Server 2016 命令行：输入 `sconfig`，选 6 安装更新
- 手动触发检测：`wuauclt /detectnow`（Win10 可用 `UsoClient StartScan`）
- 查看已装补丁：`Get-HotFix | Sort InstalledOn`

## Windows 关闭 SMBv1
- 注册表关闭：`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0`
- 卸载功能：`Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart`
- 验证状态：`Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`

## Windows 服务最小化
- 列出运行中服务：`Get-Service | Where-Object Status -eq "Running"`
- 停止并禁用可疑/多余服务：`Stop-Service 服务名; Set-Service 服务名 -StartupType Disabled`；sc 方式：`sc config 服务名 start= disabled`（注意 start= 后有空格）
- 重点检查：Telnet、FTP、RemoteRegistry（远程注册表）

## Windows 安全日志审计（4625 登录失败 / 4688 进程创建）
- 开启登录失败审计：`auditpol /set /subcategory:"Logon" /failure:enable`（中文系统子类名为「登录」）
- 开启进程创建审计：`auditpol /set /subcategory:"Process Creation" /success:enable`（中文系统为「进程创建」）
- 查看策略：`auditpol /get /category:*`；事件 ID：4624 成功登录、4625 登录失败、4688 进程创建

## Windows 事件日志保留策略
- 设置安全日志 1GB 且自动覆盖：`wevtutil sl Security /ms:1073741824 /rt:true /ab:true`
- 查看配置：`wevtutil gl Security`
- 清除日志（慎重，仅加固完成后）：`wevtutil cl Security`

## Windows 后门排查：计划任务
- 查看全部任务详情：`schtasks /query /fo LIST /v`
- 简洁查看：`schtasks /query /fo TABLE`
- 删除可疑任务：`schtasks /delete /tn "任务名" /f`

## Windows 后门排查：启动项
- 查注册表 Run 键：`reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` 与 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`、`...\RunOnce`
- 查启动文件夹：`Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"`、`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`
- 汇总：`Get-CimInstance Win32_StartupCommand | Select Name,Command,Location`

## Windows 后门排查：服务
- 列出全部服务：`sc query state= all`
- 查可疑路径服务：`Get-CimInstance win32_service | Select Name,State,StartMode,PathName | Where-Object PathName -match "temp|tmp|ProgramData"`
- 查看服务具体配置：`sc qc 服务名`

## Windows 可疑用户排查
- 查看所有本地用户：`Get-LocalUser`
- 查看管理员组成员：`Get-LocalGroupMember Administrators`
- 禁用可疑用户：`Disable-LocalUser 用户名`；删除：`Remove-LocalUser 用户名`

## Windows 会话查看 qwinsta
- 查看本机会话：`qwinsta`（或 `query session`）
- 查看登录用户明细：`quser`
- 踢掉可疑会话：`rwinsta 会话ID`

## Windows 进程排查
- tasklist 列出：`tasklist /v`
- 详查含路径：`Get-Process | Select Id,ProcessName,Path | Sort Id`
- 找可疑命令行：`Get-CimInstance Win32_Process | Select ProcessId,Name,CommandLine | Where-Object CommandLine -match "powershell.*enc|temp|down"`

## Windows 监听端口排查
- 查看监听端口与 PID：`netstat -ano | findstr LISTENING`
- PID 反查进程：`tasklist /fi "PID eq PID号"` 或 `Get-Process -Id PID号 | Select ProcessName,Path`
- 反向外连：`netstat -ano | findstr ESTABLISHED` 后对可疑外连 PID 定位进程
