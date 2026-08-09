# Windows 事件日志与取证分析手册

> Windows 靶机（Win7/Server 系列）排查依赖事件日志与系统痕迹。本手册按「登录事件 → 进程创建 → 服务/计划任务 → 文件痕迹 → 持久化」逐层排查，PowerShell 命令均需管理员权限。

## 一、关键事件 ID 对照表

| 事件 ID | 日志 | 含义 |
|--------|------|------|
| 4624 | Security | 成功登录 |
| 4625 | Security | 登录失败（爆破特征） |
| 4634 / 4647 | Security | 注销 / 主动注销 |
| 4672 | Security | 授予特殊权限（管理员登录） |
| 4688 | Security | 进程创建（开启审核后可用） |
| 4720/4722/4725 | Security | 创建用户 / 启用 / 禁用账户 |
| 4728/4732 | Security | 加入组成员 |
| 1102 | Security | 审核日志被清除（攻击痕迹） |
| 7045 | System | 安装服务（服务型后门特征） |
| 4698 | Security | 创建计划任务 |
| 4104 | PowerShell | PS 脚本块记录（开启后） |

## 二、登录与爆破排查

```powershell
# 最近 20 条成功登录（含来源 IP：事件属性 18 为源地址）
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 20 |
  ForEach-Object { [PSCustomObject]@{Time=$_.TimeCreated; User=$_.Properties[5].Value; IP=$_.Properties[18].Value} }

# 登录失败 Top 来源 IP（爆破源）
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} |
  ForEach-Object { $_.Properties[18].Value } | Group-Object | Sort-Object Count -Descending | Select -First 10

# 成功登录的异常来源（非本机/非管理 IP 的 4624）
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} |
  Where-Object { $_.Properties[18].Value -notmatch '^(127\.|192\.168\.|::1)' } |
  Select-Object -First 20 TimeCreated, @{n='IP';e={$_.Properties[18].Value}}
```

## 三、账户与权限后门

```powershell
# 新建/删除/改密账户
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720} | Select TimeCreated, @{n='User';e={$_.Properties[0].Value}}
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4726}

# 管理员组成员（对照基线看是否多出人）
net localgroup Administrators
# 隐藏账户（$ 结尾 / RID 500 同名）
Get-WmiObject Win32_UserAccount | Select Name, SID, LocalAccount
# 最近创建的本地用户
Get-LocalUser | Sort-Object -Property LastLogon
```

## 四、服务与计划任务后门

```powershell
# 新增服务（7045 事件，服务型木马特征）
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} | Select TimeCreated, Message

# 当前服务里可疑的（指向非系统目录/随机名）
Get-WmiObject Win32_Service | Where-Object { $_.PathName -match 'tmp|temp|AppData|ProgramData' } |
  Select Name, PathName

# 计划任务
schtasks /query /fo LIST /v | findstr /i "任务名 程序路径"
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4698} | Select TimeCreated, Message
```

## 五、文件与启动项痕迹

```powershell
# 启动项（注册表 Run 键 + 启动文件夹）
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
# 可疑文件（最近创建的可执行/脚本）
Get-ChildItem C:\ -Recurse -Include *.exe,*.bat,*.ps1,*.vbs -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) } | Select FullName
```

## 六、日志被清除的判断

```powershell
# 安全日志被清（1102 事件本身会留记录）
Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102}
# 日志文件大小异常/被 truncate
wevtutil gl Security | findstr /i "maxSize"
```

## 七、取证要点

1. **先保全**：`wevtutil epl Security C:\evidence\Security.evtx` 导出事件日志再分析。
2. **时间线**：把 4624/4625/4720/7045 事件按时间排序，还原「爆破→登录→建号→装服务」攻击链。
3. **配合文件系统**：`dir /a` 看隐藏文件、`wmic process get CommandLine` 看残留进程命令行，与事件日志互相印证后写入报告。
