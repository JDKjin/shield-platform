# 解题 / 溯源 Writeup 模板

综合防御赛中，应急处置、运行配置类题目需达到指定效果后提交 Writeup，经裁判审核得分。以下模板可用于统一输出。

## 一、题目信息
- 题目名称 / 编号：
- 场景类型（发电 / 电网 / 油气）：
- 涉及资产（IP / 端口 / 服务 / 应用）：
- 题目分值：

## 二、攻击研判
- 攻击来源（红队 / 自动化脚本 / 历史流量回放）：
- 攻击手法（如 SQL 注入、Webshell 上传、Modbus 写线圈）：
- 攻击时间线（关键时间戳）：

## 三、攻击链溯源
- 初始访问：
- 漏洞利用点：
- 权限提升：
- 权限维持（后门）：
- 横向移动：
- 影响范围：

## 四、应急处置与加固
- 处置动作（隔离文件 / 封禁 IP / 改口令 / 关端口 / 补丁）：
- 加固前后对比（配置 diff / 截图）：
- 业务可用性验证（服务是否正常）：

## 五、证据与结论
- 关键日志 / 截图索引：
- 是否彻底消除入口（防止同方式再次失分）：
- 结论与建议：

## 提交注意
- 人工评分项：报告质量直接决定能否拿分，不能只操作不写文档
- 时间线、IOC、证据三者要能互相印证
- 比赛结束前通过平台提交整体解题报告，组委会审核后确定最终得分

## 补强篇：完整 Writeup 示例与取证命令速查（GUI / 无头双路径）

### 一、完整示例 Writeup（Linux Web 服务器被植入 webshell）

> 新手可直接对照本示例填写，所有时间、IP、命令均为示例，请按实际环境替换。

```
================================================================
题目名称：Web 服务器应急响应 - webshell 排查与处置
题目编号：IR-2024-007
场景类型：发电 - 监控 Web 站点
涉及资产：10.10.3.21 / TCP 80 8080 / nginx 1.18 + PHP 7.2 / CentOS 7.9
题目分值：100
================================================================

一、题目信息
- 题目名称 / 编号：Web 服务器应急响应 - webshell 排查与处置 / IR-2024-007
- 场景类型（发电 / 电网 / 油气）：发电 - 监控 Web 站点
- 涉及资产（IP / 端口 / 服务 / 应用）：
    外网入口：10.10.3.21
    开放端口：TCP 22(SSH) / TCP 80(nginx) / TCP 8080(tomcat)
    应用：电力监控系统前台 portal v2.3
    数据库：本地 MariaDB 5.5.68
- 题目分值：100

二、攻击研判
- 攻击来源：红队（IP 203.0.113.45），通过公网 SSH 暴力破解 + Web 上传组合攻击
- 攻击手法：
    1) SSH 暴力破解弱口令（root/123456）
    2) 上传 PHP webshell /var/www/html/uploads/shell.php
    3) 通过 webshell 执行 whoami / id / cat /etc/passwd
- 攻击时间线（关键时间戳）：
    2024-08-11 02:13:07  攻击者首次 SSH 失败登录（Failed password）
    2024-08-11 02:13:42  SSH 登录成功（Accepted password for root）
    2024-08-11 02:15:11  webshell 文件 shell.php 创建（stat 显示）
    2024-08-11 02:16:30  webshell 执行 whoami，返回 www-data
    2024-08-11 02:18:55  攻击者下载 /etc/passwd
    2024-08-11 02:22:10  攻击者 IP 断开

三、攻击链溯源
- 初始访问：SSH 暴力破解 root/123456 成功
- 漏洞利用点：uploads 目录未限制 PHP 执行 + SSH 弱口令
- 权限提升：通过 webshell 调用 sudo（root 已登录，直接获得 root 权限上下文）
- 权限维持（后门）：/var/www/html/uploads/shell.php 内容为 eval($_POST['cmd'])
- 横向移动：未发现（仅本机）
- 影响范围：仅 10.10.3.21，未扩散至内网 10.10.3.0/24 其他主机

四、应急处置与加固
- 处置动作：
    1) 立即隔离主机：iptables -A INPUT -s 203.0.113.45 -j DROP
    2) 删除 webshell：rm -f /var/www/html/uploads/shell.php
    3) 修改 root 口令：passwd root（新口令长度≥12，含大小写数字符号）
    4) 禁用 root SSH 登录：sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart sshd
    5) 关闭 uploads 目录 PHP 执行：在 nginx 配置增加 location ~* /uploads/.*\.(php|php5)$ { deny all; }
    6) 安装 fail2ban：yum install -y fail2ban && systemctl enable --now fail2ban
- 加固前后对比：
    加固前：PermitRootLogin yes；uploads 目录可执行 PHP；无 SSH 失败登录封禁
    加固后：PermitRootLogin no；uploads 目录 deny all PHP；fail2ban 5 次失败封禁 1 小时
    配置 diff 截图：evidence/screenshots/20240811-0230-ssh-hardening-diff.png
- 业务可用性验证：
    curl -I http://10.10.3.21/  返回 200 OK
    curl -I http://10.10.3.21/uploads/shell.php  返回 403 Forbidden
    业务前台页面正常访问，监控数据上传正常

五、证据与结论
- 关键日志 / 截图索引：
    1) /var/log/secure  SSH 暴力破解与登录成功日志
    2) /var/log/nginx/access.log  webshell 访问记录
    3) stat /var/www/html/uploads/shell.php  文件时间戳
    4) evidence/screenshots/20240811-0225-webshell-content.png  webshell 内容截图
    5) evidence/screenshots/20240811-0230-ssh-hardening-diff.png  加固前后对比
    6) evidence/pcap/20240811-0213-ssh-brute.pcap  抓包文件
    7) evidence/ioc/ioc.txt  webshell MD5 列表
- 是否彻底消除入口：是
    - SSH 弱口令已改，root 禁止远程登录
    - uploads 目录禁止 PHP 执行，webshell 已删除
    - fail2ban 已启用，5 次失败即封禁
- 结论与建议：
    1) 本次失陷根因为 root SSH 弱口令 + uploads 目录未禁用 PHP 执行
    2) 已完成应急处置，攻击链彻底切断
    3) 建议：全量审计 /var/www 下所有 .php 文件，排查是否还有其他后门
    4) 建议：将 SSH 默认端口 22 改为非标准端口，并启用密钥登录
    5) 建议：定期备份 nginx access.log 与 secure 日志，至少保留 90 天

================================================================
```

### 二、Linux 取证命令模板（CentOS 7 / Ubuntu 20.04 通用）

> 说明：以下命令在 CentOS 7（/var/log/secure）与 Ubuntu 20.04（/var/log/auth.log）路径不同，请按发行版替换日志路径。

#### 2.1 SSH 暴力破解排查

```bash
# CentOS 7 - 查看所有 SSH 失败登录
grep "Failed password" /var/log/secure

# Ubuntu 20.04 - 查看所有 SSH 失败登录
grep "Failed password" /var/log/auth.log

# 统计失败登录次数最多的 IP（CentOS 7）
grep "Failed password" /var/log/secure | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# 统计失败登录次数最多的 IP（Ubuntu 20.04）
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# 查看 SSH 成功登录记录（CentOS 7）
grep "Accepted password" /var/log/secure

# 查看 SSH 成功登录记录（Ubuntu 20.04）
grep "Accepted password" /var/log/auth.log
```

#### 2.2 系统日志排查

```bash
# 查看最近 1 小时系统日志
journalctl --since "1h ago"

# 查看指定时间段系统日志
journalctl --since "2024-08-11 02:00:00" --until "2024-08-11 03:00:00"

# 查看 SSH 服务日志（最近 100 条）
journalctl -u sshd -n 100 --no-pager

# 查看最近登录用户
last -n 20

# 查看登录失败记录
lastb -n 20
```

#### 2.3 Webshell 文件排查

```bash
# 查看指定 webshell 文件的时间戳（创建 / 修改 / 访问）
stat /var/www/html/uploads/shell.php

# 查找 /var/www 下比 /tmp/marker 更新的 PHP 文件（先 touch /tmp/marker 建立基准）
find /var/www -name "*.php" -newer /tmp/marker

# 查找 /var/www 下最近 3 天修改的 PHP 文件
find /var/www -name "*.php" -mtime -3

# 在 web 根目录递归搜索常见 webshell 危险函数
grep -rnE "eval|assert|system|exec|passthru|shell_exec|popen|proc_open" /var/www/html/

# 查找包含 base64_decode 的可疑 PHP 文件
grep -rn "base64_decode" /var/www/html/ --include="*.php"

# 查找包含 $_POST 直接传给执行函数的文件
grep -rnE '\$_(POST|GET|REQUEST|COOKIE)\s*\[' /var/www/html/ --include="*.php"
```

#### 2.4 网络连接排查

```bash
# 查看所有已建立的 TCP 连接及对应进程
ss -antp | grep ESTABLISHED

# 查看所有监听端口及进程
ss -antp | grep LISTEN

# 查看所有网络连接（含进程名 / PID / 用户）
lsof -i -P

# 查看指定端口占用（如 8080）
lsof -i :8080

# 查看指定 PID 的所有网络连接
lsof -p <PID> -i
```

#### 2.5 进程与文件排查

```bash
# 查看所有进程（含完整命令行）
ps auxwwf

# 查看指定 PID 的进程信息
ps -ef | grep <PID>

# 查看指定 PID 的工作目录与可执行文件
ls -l /proc/<PID>/cwd
ls -l /proc/<PID>/exe

# 查找最近 3 天修改的所有文件（全盘）
find / -type f -mtime -3 -ls > /tmp/recent_files.txt

# 查找 SUID 文件（提权排查）
find / -perm -4000 -type f 2>/dev/null

# 查看计划任务（后门排查）
crontab -l
cat /etc/crontab
ls -la /etc/cron.*/
```

### 三、Windows Server 2016 取证命令对照

> 说明：Windows Server 2016 使用 PowerShell 5.1，以下命令均在管理员 PowerShell 中执行。

#### 3.1 安全日志排查（对应 Linux SSH 日志）

```powershell
# 使用 wevtutil 查询安全日志（事件 ID 4625 = 登录失败）
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:50 /rd:true /f:text

# 使用 Get-WinEvent 查询登录失败事件（更易读）
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50 | Format-List TimeCreated, Id, Message

# 查询登录成功事件（事件 ID 4624）
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 50 | Format-List TimeCreated, Id, Message

# 统计登录失败次数最多的源 IP
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} | ForEach-Object { $_.Properties[19].Value } | Group-Object | Sort-Object Count -Descending | Select-Object -First 20
```

#### 3.2 Webshell 文件排查（对应 Linux find/grep）

```powershell
# 查找 IIS 根目录下所有 .asp 文件（含子目录）
Get-ChildItem C:\inetpub\wwwroot -Filter *.asp -Recurse

# 查找最近 3 天修改的 .asp / .aspx 文件
Get-ChildItem C:\inetpub\wwwroot -Include *.asp,*.aspx -Recurse | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-3) }

# 查看指定文件的创建时间、修改时间、访问时间
Get-Item C:\inetpub\wwwroot\uploads\shell.asp | Select CreationTime, LastWriteTime, LastAccessTime, FullName

# 在 IIS 根目录搜索包含危险函数的 asp 文件
Select-String -Path C:\inetpub\wwwroot\*.asp -Pattern "Execute|Eval|WScript.Shell|cmd.exe" -SimpleMatch

# 在 IIS 根目录递归搜索包含危险函数的 aspx 文件
Get-ChildItem C:\inetpub\wwwroot -Filter *.aspx -Recurse | Select-String -Pattern "eval|exec|cmd" | Select Path, LineNumber, Line
```

#### 3.3 网络连接排查（对应 Linux ss/lsof）

```powershell
# 查看所有已建立的 TCP 连接及对应进程
Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

# 查看所有监听端口
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess

# 查看指定 PID 对应的进程名
Get-Process -Id <PID>

# 查看所有进程及路径
Get-Process | Select-Object Id, ProcessName, Path | Format-Table -AutoSize
```

#### 3.4 IIS 日志排查（对应 Linux nginx access.log）

```powershell
# IIS 默认日志路径（Windows Server 2016）
# C:\inetpub\logs\LogFiles\W3SVC1\

# 查询 IIS 日志中包含 POST 上传的记录
Select-String -Path C:\inetpub\logs\LogFiles\W3SVC1\*.log -Pattern "POST"

# 查询 IIS 日志中访问 uploads 目录的记录
Select-String -Path C:\inetpub\logs\LogFiles\W3SVC1\*.log -Pattern "/uploads/"

# 查询 IIS 日志中返回 200 且为 .asp 的记录
Select-String -Path C:\inetpub\logs\LogFiles\W3SVC1\*.log -Pattern "200" | Select-String -Pattern "\.asp"
```

### 四、流量取证命令

> 适用场景：已有抓包文件 capture.pcap，需从中提取攻击证据。

#### 4.1 HTTP 流量分析

```bash
# 读取 pcap 文件并以 ASCII 方式显示（最常用）
tcpdump -r capture.pcap -A

# 读取 pcap 文件并显示 HTTP 流量
tshark -r capture.pcap -Y "http"

# 提取 HTTP 请求 URL
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# 提取 HTTP POST 数据（webshell 上传排查）
tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e http.file_data

# 导出 pcap 中所有 HTTP 传输的文件（如 webshell 上传文件）
tshark -r capture.pcap --export-objects http,/tmp/http_objects/
```

#### 4.2 工控协议分析（电力场景）

```bash
# 提取 Modbus 流量（电力 SCADA 常用协议）
tshark -r capture.pcap -Y "modbus"

# 提取 Modbus 写线圈指令（攻击者写线圈攻击）
tshark -r capture.pcap -Y "modbus.func_code == 5 || modbus.func_code == 6 || modbus.func_code == 15 || modbus.func_code == 16"

# 提取 S7comm 流量（西门子 PLC 协议）
tshark -r capture.pcap -Y "s7comm"

# 提取 IEC 60870-5-104 流量（电力远动协议）
tshark -r capture.pcap -Y "iec60870_104"

# 提取 DNP3 流量（电力分布式网络协议）
tshark -r capture.pcap -Y "dnp3"
```

#### 4.3 SSH 暴力破解分析

```bash
# 统计 pcap 中同一源 IP 对 22 端口的连接数（暴力破解特征）
tshark -r capture.pcap -Y "tcp.dstport == 22" -T fields -e ip.src | sort | uniq -c | sort -rn | head -20

# 提取 SSH 协议流量
tshark -r capture.pcap -Y "ssh" -T fields -e frame.time -e ip.src -e ip.dst -e ssh.message_code
```

### 五、IOC 收集命令模板

#### 5.1 Linux IOC 收集

```bash
# 计算 /var/www/html 下所有 PHP 文件的 MD5，输出到 ioc.txt
md5sum /var/www/html/*.php > /tmp/ioc.txt

# 计算 /var/www/html 下所有 PHP 文件的 SHA256（更安全）
sha256sum /var/www/html/*.php > /tmp/ioc_sha256.txt

# 递归计算所有 PHP 文件 MD5
find /var/www/html -name "*.php" -exec md5sum {} \; > /tmp/ioc_recursive.txt

# 收集最近 3 天修改的所有文件清单（全盘）
find / -type f -mtime -3 -ls > /tmp/recent_files.txt

# 收集所有 crontab（用户级 + 系统级）
for user in $(cut -f1 -d: /etc/passwd); do echo "=== $user ==="; crontab -u $user -l 2>/dev/null; done > /tmp/all_crontabs.txt

# 收集 /etc/passwd 与 /etc/shadow（口令哈希排查）
cp /etc/passwd /tmp/passwd.bak
cp /etc/shadow /tmp/shadow.bak

# 收集所有监听端口与对应进程
ss -antp | grep LISTEN > /tmp/listening_ports.txt
```

#### 5.2 Windows IOC 收集

```powershell
# 计算指定目录下所有文件的 SHA256
Get-FileHash C:\inetpub\wwwroot\*.asp -Algorithm SHA256 | Format-Table -AutoSize > C:\temp\ioc_sha256.txt

# 递归计算 IIS 根目录所有文件哈希
Get-ChildItem C:\inetpub\wwwroot -Recurse -File | Get-FileHash -Algorithm SHA256 | Format-Table -AutoSize > C:\temp\ioc_recursive.txt

# 收集最近 3 天修改的所有文件
Get-ChildItem C:\ -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-3) } | Select-Object FullName, LastWriteTime, Length > C:\temp\recent_files.txt

# 收集所有计划任务
schtasks /query /fo LIST /v > C:\temp\all_scheduled_tasks.txt

# 导出注册表 Run 项（自启动排查）
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" > C:\temp\autorun_hklm.txt
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" > C:\temp\autorun_hkcu.txt
```

### 六、证据固化命令

> 核心原则：所有证据文件在采集后立即计算哈希，提交前再次计算哈希，两者一致方可作为可信证据。

#### 6.1 Linux 证据固化

```bash
# 1. 采集阶段：计算证据文件 SHA256 并保存
sha256sum /tmp/evidence.pcap > /tmp/evidence.sha256

# 2. 提交阶段：重新计算并与原哈希对比
sha256sum -c /tmp/evidence.sha256
# 输出 /tmp/evidence.pcap: OK 即表示文件未被篡改

# 同时计算 MD5（双重保险）
md5sum /tmp/evidence.pcap > /tmp/evidence.md5
md5sum -c /tmp/evidence.md5

# 批量计算多个证据文件哈希
sha256sum /tmp/evidence_1.pcap /tmp/evidence_2.pcap /tmp/log.tar.gz > /tmp/all_evidence.sha256
sha256sum -c /tmp/all_evidence.sha256
```

#### 6.2 Windows 证据固化

```powershell
# 1. 采集阶段：计算证据文件 SHA256
Get-FileHash C:\temp\evidence.pcap -Algorithm SHA256 | Out-File C:\temp\evidence.sha256

# 2. 提交阶段：重新计算并手动对比
$hash_new = (Get-FileHash C:\temp\evidence.pcap -Algorithm SHA256).Hash
$hash_old = (Get-Content C:\temp\evidence.sha256).Split(' ')[0]
if ($hash_new -eq $hash_old) { Write-Host "OK: 证据文件未被篡改" } else { Write-Host "WARNING: 哈希不一致" }

# 同时计算 MD5
Get-FileHash C:\temp\evidence.pcap -Algorithm MD5 | Out-File C:\temp\evidence.md5
```

### 七、截图规范

#### 7.1 必须截图的内容

| 序号 | 截图内容 | 用途 |
|------|----------|------|
| 1 | webshell 文件原始内容（cat / vim 显示） | 证明 webshell 存在 |
| 2 | webshell 文件 stat 时间戳 | 建立时间线 |
| 3 | 攻击日志原文（secure / auth.log / access.log） | 证明攻击行为 |
| 4 | 网络连接异常截图（ss -antp 输出） | 证明 C2 连接 |
| 5 | 加固前配置截图（如 PermitRootLogin yes） | 对比基准 |
| 6 | 加固后配置截图（如 PermitRootLogin no） | 证明加固完成 |
| 7 | 业务可用性验证截图（curl 200 OK） | 证明未误操作 |
| 8 | 哈希对比结果截图（sha256sum -c 输出 OK） | 证明证据完整 |

#### 7.2 文件命名规则

```
格式：evidence-YYYYMMDD-HHMM-描述.png
示例：
  evidence-20240811-0225-webshell-content.png
  evidence-20240811-0225-webshell-stat.png
  evidence-20240811-0230-ssh-brute-log.png
  evidence-20240811-0235-hardening-before.png
  evidence-20240811-0240-hardening-after.png
  evidence-20240811-0245-business-verify.png
  evidence-20240811-0250-hash-verify-ok.png
```

#### 7.3 存放路径

```
统一存放目录：/evidence/screenshots/
子目录建议：
  /evidence/screenshots/         截图
  /evidence/pcap/                抓包文件
  /evidence/ioc/                 IOC 列表
  /evidence/logs/                原始日志备份
  /evidence/hashes/              哈希文件
```

#### 7.4 截图工具

```bash
# Linux - flameshot（图形化截图工具，适合有 GUI 的工控机）
# 安装（Ubuntu 20.04）
sudo apt install -y flameshot
# 启动截图
flameshot gui
# 截图后自动保存到 /evidence/screenshots/，或手动另存

# Linux - 无 GUI 服务器（无头环境）
# 使用 scrot（需 X11 转发）或直接用命令行重定向输出到文本文件
# 推荐方式：将命令输出保存为文本，再用脚本转换为图片
ss -antp | grep ESTABLISHED > /evidence/logs/established_connections.txt

# Windows Server 2016
# 方式 1：自带截图工具（Win + Shift + S）
# 方式 2：截图工具（Snipping Tool，开始菜单搜索 "截图工具"）
# 方式 3：PowerShell 自动截屏
Add-Type -AssemblyName System.Windows.Forms
$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
$bitmap.Save("C:\evidence\screenshots\evidence-$(Get-Date -Format yyyyMMdd-HHmm)-auto.png")
```

### 八、Wireshark 导出特定 TCP 流 GUI 步骤

> 适用环境：有图形化桌面的工控机 / Windows 工作站（GUI 路径）；无头服务器请使用 7.4 节 tshark 命令行。

#### 8.1 GUI 路径：导出 HTTP 对象（File -> Export Objects -> HTTP）

```
步骤 1：打开 Wireshark，菜单栏 File -> Open，选择 capture.pcap
步骤 2：菜单栏 File -> Export Objects -> HTTP...
步骤 3：在弹出的 HTTP Object List 窗口中：
        - 可看到所有 HTTP 传输的文件（含文件名、Content-Type、大小）
        - 点击列标题可排序（按大小排序有助于发现 webshell 上传文件）
        - 选中目标文件，点击 Save As，保存到 /evidence/pcap/http_objects/
步骤 4：保存完成后，对导出文件计算 SHA256：
        sha256sum /evidence/pcap/http_objects/shell.php > /evidence/hashes/shell.sha256
```

#### 8.2 GUI 路径：Follow TCP Stream 并保存为 .txt

```
步骤 1：在 Wireshark 主窗口，选中一条可疑的 HTTP 数据包
步骤 2：右键 -> Follow -> TCP Stream
        （或菜单栏 Analyze -> Follow -> TCP Stream）
步骤 3：在弹出的 Follow TCP Stream 窗口中：
        - 红色文本为客户端请求（攻击者发送）
        - 蓝色文本为服务端响应（被攻击机返回）
        - 可在底部下拉框切换显示方向（单向 / 双向）
步骤 4：点击右下角 Save As... 按钮
步骤 5：保存到 /evidence/pcap/tcp_stream_<流编号>.txt
步骤 6：保存后计算哈希固化：
        sha256sum /evidence/pcap/tcp_stream_5.txt > /evidence/hashes/tcp_stream_5.sha256
```

#### 8.3 CLI 路径（无头服务器）：使用 tshark 导出

```bash
# 导出 HTTP 对象（等价 GUI 步骤 8.1）
tshark -r capture.pcap --export-objects http,/evidence/pcap/http_objects/

# 导出指定 TCP 流内容（等价 GUI 步骤 8.2，流编号 5）
tshark -r capture.pcap -qz "follow,tcp,ascii,5" > /evidence/pcap/tcp_stream_5.txt

# 列出所有 TCP 流编号
tshark -r capture.pcap -T fields -e tcp.stream | sort -n | uniq
```

### 九、Process Explorer 保存进程树 GUI 步骤

> 适用环境：Windows Server 2016 图形化环境；Linux 无头环境请使用 ps auxwwf 重定向到文本文件。

#### 9.1 GUI 路径：Process Explorer 保存进程树

```
步骤 1：下载 Process Explorer
        官方地址：https://docs.microsoft.com/sysinternals/downloads/process-explorer
        解压后右键 procexp64.exe -> 以管理员身份运行

步骤 2：定位可疑进程
        - 顶部菜单 View -> Show Process Tree（确保勾选，显示进程树）
        - 顶部菜单 Find -> Find Handle or DLL，输入可疑文件名（如 shell.exe）
        - 或按 Ctrl+F 搜索可疑字符串（如攻击者 IP、webshell 名称）

步骤 3：保存进程树
        - 顶部菜单 File -> Save as Process Tree...
        - 选择保存路径：C:\evidence\screenshots\process_tree_20240811.txt
        - 保存格式为文本文件，包含所有进程的 PID、PPID、路径、命令行

步骤 4：（可选）保存单个进程属性
        - 右键可疑进程 -> Properties
        - 在弹出的 Properties 窗口中切换到 Threads / TCP/IP Tabs 查看详细信息
        - 点击 Save 按钮保存该进程详细信息

步骤 5：截图固化（额外证据）
        - 选中可疑进程，按 Ctrl+S 或 File -> Save Snapshot 保存快照
        - 使用截图工具保存可视化进程树到
          C:\evidence\screenshots\evidence-20240811-0300-process-tree.png

步骤 6：哈希固化
        Get-FileHash C:\evidence\screenshots\process_tree_20240811.txt -Algorithm SHA256 | Out-File C:\evidence\hashes\process_tree.sha256
```

#### 9.2 CLI 路径（无头 Windows Server 2016）：使用 PowerShell 替代

```powershell
# 导出所有进程及父进程关系（等价 Process Explorer 进程树）
Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine | Format-Table -AutoSize > C:\evidence\screenshots\process_tree_ps.txt

# 查找指定名称的进程及其子进程
Get-CimInstance Win32_Process | Where-Object { $_.Name -like "*shell*" } | Select-Object ProcessId, ParentProcessId, Name, CommandLine

# 递归查找某 PID 的所有子进程
function Get-ChildProcess($parentId) {
    Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $parentId } | ForEach-Object {
        $_
        Get-ChildProcess $_.ProcessId
    }
}
Get-ChildProcess <可疑PID> | Format-Table ProcessId, ParentProcessId, Name, CommandLine
```

#### 9.3 CLI 路径（无头 Linux）：使用 ps 替代

```bash
# 导出进程树（等价 Process Explorer 进程树）
ps auxwwf > /evidence/screenshots/process_tree.txt

# 查看指定 PID 的进程树
pstree -p <PID>

# 哈希固化
sha256sum /evidence/screenshots/process_tree.txt > /evidence/hashes/process_tree.sha256
```

### 十、GUI 与无头双路径对照速查表

| 任务 | GUI 路径 | CLI 路径（无头服务器） |
|------|----------|------------------------|
| 查看 SSH 暴力破解 | （无可视化工具） | grep "Failed password" /var/log/secure |
| 查找 webshell 文件 | 文件管理器浏览 /var/www/html | find /var/www -name "*.php" -mtime -3 |
| 查看网络连接 | （无可视化工具） | ss -antp \| grep ESTABLISHED |
| 分析抓包文件 | Wireshark 图形化 | tshark -r capture.pcap -Y "http" |
| 截图取证 | flameshot gui / Win+Shift+S | 命令输出重定向到文本文件 |
| 导出 HTTP 对象 | Wireshark File -> Export Objects -> HTTP | tshark --export-objects http,/path/ |
| 查看 TCP 流 | Wireshark Follow -> TCP Stream | tshark -qz "follow,tcp,ascii,5" |
| 进程树排查 | Process Explorer File -> Save as Process Tree | ps auxwwf / Get-CimInstance Win32_Process |
| 计算文件哈希 | （无可视化工具） | sha256sum file / Get-FileHash file |
| 计划任务排查 | taskschd.msc（Windows GUI） | crontab -l / schtasks /query |

### 十一、新手检查清单（提交 Writeup 前自检）

```
[ ] 1. 时间线是否完整（从初始访问到处置完成，每个关键动作有时间戳）
[ ] 2. 每条时间戳是否有对应日志或截图证据
[ ] 3. webshell 文件是否已截图内容 + stat 时间戳
[ ] 4. 攻击源 IP 是否在日志中找到并记录
[ ] 5. 处置动作是否每条都有命令记录
[ ] 6. 加固前后是否有对比截图或配置 diff
[ ] 7. 业务可用性是否已验证并截图（curl 200 OK）
[ ] 8. 所有证据文件是否已计算 SHA256 并固化
[ ] 9. 截图命名是否遵循 evidence-YYYYMMDD-HHMM-描述.png 规则
[ ] 10. 截图是否统一存放在 /evidence/screenshots/ 目录
[ ] 11. 结论是否说明"已彻底消除入口，防止同方式再次失分"
[ ] 12. IOC 列表是否包含 webshell MD5/SHA256
[ ] 13. 是否区分了 GUI 路径与无头 CLI 路径的操作记录
[ ] 14. 是否覆盖了 CentOS 7 / Ubuntu 20.04 / Windows Server 2016 三种系统
[ ] 15. 报告是否能在比赛结束前通过平台按时提交
```

