# Windows 全版本加固与应急手册（Win7 / Win8 / Win10 / Win11）

> 覆盖 Windows 7 SP1、Windows 8/8.1、Windows 10（1507~22H2）、Windows 11（21H2~24H2）。
> Win7 自带 PowerShell 2.0，Win10 1809+ 为 5.1/7；Win11 已移除 wmic。命令均已做兼容回退，先备份再改动。

## 版本与内置工具差异速查
- Win7/8.1：`wmic` 可用；PowerShell 2.0/4.0（`Get-WmiObject` 可用，`Get-CimInstance` 不可用）
- Win10 1803+：内置 `tar`、`curl`、`ss` 等价物（`Get-NetTCPConnection`）
- Win11 22H2+：**wmic 已移除**，一律改用 `Get-CimInstance` / `Get-WmiObject`
- 通用兼容命令基线：`netstat -ano`、`net user`、`net localgroup administrators`、`net accounts`、`reg query`、`schtasks /query /fo LIST`、`netsh advfirewall` 在 Win7~Win11 全部可用

## 用户账号与权限应急
- 列出全部用户：`net user`；管理员组成员：`net localgroup administrators`
- 锁定可疑账号：`net user 用户名 /active:no`；改密：`net user 用户名 新密码`
- 隐藏/克隆账号识别：`wmic useraccount list brief`（Win7/10）或
  `powershell -NoProfile -Command "Get-CimInstance Win32_UserAccount -ErrorAction SilentlyContinue | Select Name,SID,Disabled,LocalAccount"`（Win11 兼容回退）
- 排查 UID/SID 500 管理员克隆：比对 `Get-LocalUser`（Win10+）与注册表 SAM 映射

## 启动项与持久化后门排查
- 注册表 Run 键：
  `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"`、
  `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"`、
  `reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"`
- 全部启动项（Win11 兼容）：
  `powershell -NoProfile -Command "Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Select Caption,Command"`
  回退：`wmic startup get Caption,Command`（Win7/10）
- 计划任务：`schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`，重点看以管理员/系统身份运行且指向 Temp、AppData 的项
- 服务排查：`powershell -NoProfile -Command "Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {$_.PathName -like '*Temp*' -or $_.PathName -like '*AppData*'} | Select Name,State,PathName"`（Win7 回退 Get-WmiObject）

## 网络连接与后门排查
- 监听端口与 PID：`netstat -ano | findstr LISTENING`
- 外联连接：`netstat -ano | findstr ESTABLISHED`；用 `tasklist /fi "PID eq 进程号"` 反查进程
- Win10+ 增强：`powershell -NoProfile -Command "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess"`
- 重点端口：4444 / 5555 / 6666 / 7777 / 8888 / 9999 / 31337 / 8080 / 7001

## 进程与 WebShell 排查
- 可疑进程（AppData/Temp 路径）：`powershell -NoProfile -Command "Get-Process | Where-Object {$_.Path -like 'C:\Users\*\AppData\*' -or $_.Path -like '*\Temp\*'} | Select Name,Id,Path"`
- IIS 站点目录 WebShell（Win7~Win11）：
  `powershell -NoProfile -Command "Get-ChildItem C:\inetpub\wwwroot -Recurse -Include *.asp,*.aspx,*.php,*.jsp -ErrorAction SilentlyContinue | Select-String -Pattern 'eval|execute|base64|cmd' -List | Select Path"`
- 杀进程：`taskkill /F /PID 进程号`；杀指定名称：`taskkill /F /IM 名字.exe`

## 防火墙（netsh advfirewall，Win7~Win11 通用）
- 查看状态：`netsh advfirewall show allprofiles state`
- 启用：`netsh advfirewall set allprofiles state on`
- 封禁 IP：`netsh advfirewall firewall add rule name="block_ip" dir=in action=block remoteip=IP`
- 封禁端口：`netsh advfirewall firewall add rule name="block_4444" dir=in protocol=TCP localport=4444 action=block`
- 放行端口：`netsh advfirewall firewall add rule name="allow_80" dir=in protocol=TCP localport=80 action=allow`
- 删除规则：`netsh advfirewall firewall delete rule name="block_ip"`
- 默认入站拒绝：`netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound`

## 密码策略（net accounts，Win7~Win11 通用）
- 查看：`net accounts`；最小密码长度 8：`net accounts /minpwlen:8`
- 密码最长 90 天：`net accounts /maxpwage:90`；最短 7 天：`net accounts /minpwage:7`
- 锁定阈值 5 次 30 分钟：`net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30`

## 登录审计与事件日志
- 查看 Security 日志 4625（登录失败，需管理员）：
  `powershell -NoProfile -Command "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 10 -ErrorAction SilentlyContinue | Select TimeCreated,Message | Format-List"`
- 最近登录会话：`net session`
- 系统日志快速筛查：`wevtutil qe System /c:50 /rd:true /f:text`

## 加固后验证
- 复扫启动项/任务/服务为空、netstat 无异常外联、防火墙状态为 ON
- 业务可用性验证：IIS 站点访问、SSH/WinRM 连接、远程桌面 3389 是否仍可达
- 变更备份：加固前用 `reg export HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run run.bak.reg` 备份注册表
