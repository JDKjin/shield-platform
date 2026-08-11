# 通用加固清单（操作系统 + Web）

## 账户与口令
- 修改默认/弱口令：SSH、数据库、Web 后台、工控管理口
- 禁用 root 远程 SSH：PermitRootLogin no；改 SSH 端口、仅密钥登录
- 锁定可疑账户：检查 /etc/passwd、/etc/shadow 异常 uid=0 账户；删除未知账户
- Windows：重命名 Administrator、禁用 Guest、强密码策略

## 服务与端口最小化
- 关闭非必要端口与服务（尤其是 23/telnet、21/ftp 匿名、137-139/445 非必要）
- 用 iptables / firewalld / Windows 防火墙做白名单，仅放行业务端口
- 封禁可疑外连：iptables 限制出站到未知 IP

## 文件与目录
- Web 目录禁止执行：上传目录设 php_flag engine off 或移除执行权限
- 关键目录只读挂载或降权：chmod、chattr +i 关键配置文件
- 定期文件完整性校验：记录重要文件哈希，发现新增/篡改及时处置

## 应用加固
- Web 中间件：IIS/Nginx/Apache 关闭目录遍历、限制上传类型、隐藏版本号
- 数据库：禁止远程 root、关闭危险函数、禁用 local_infile
- PHP：disable_functions 加入 exec/system/passthru/proc_open/popen/eval（按需）
- 删除测试页面、phpinfo、默认后台

## 日志与监测
- 开启并集中保存：auth.log、secure、auditd、Windows Event Log/Sysmon、Web 访问日志
- 部署 IDS/流量捕获（Suricata、Zeek、tcpdump）
- 监控反弹 shell、可疑进程、异常外连

## 加固后必须验证
- 业务可用性优先：加固不能导致服务中断（可能触发额外扣分）
- 加固动作留痕：截图、日志、配置 diff，用于人工评分材料

## 补强篇：完整加固命令速查（GUI / 无头服务器双路径）

> 本篇区分两种操作路径：
> - GUI（图形化）：适用于带桌面的服务器（如 Windows Server 带 Desktop Experience、Ubuntu Desktop、CentOS 带 GNOME）
> - CLI（无头服务器）：适用于仅 SSH 接入的纯命令行环境
> 命令示例覆盖 CentOS 7 / Ubuntu 20.04 / Windows Server 2016。

---

### 1. Linux SSH 加固完整流程

#### CLI 路径（无头服务器通用，CentOS 7 / Ubuntu 20.04）

备份原配置：

```bash
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F)
```

修改关键参数（推荐使用 sed 直接落地，新手可逐条复制）：

```bash
# 禁用 root 远程登录
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# 禁用密码登录，仅密钥（务必先确认密钥可用再重启）
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

# 禁用空密码
sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config

# 修改默认端口（示例 52022，按需调整；同步放行防火墙）
sed -i 's/^#\?Port.*/Port 52022/' /etc/ssh/sshd_config

# 限制允许登录用户
echo 'AllowUsers deploy ops' >> /etc/ssh/sshd_config

# 禁用不安全算法
echo 'Protocol 2' >> /etc/ssh/sshd_config
echo 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com' >> /etc/ssh/sshd_config
```

重启并验证：

```bash
# CentOS 7
systemctl restart sshd
systemctl status sshd --no-pager

# Ubuntu 20.04（服务名为 ssh）
systemctl restart ssh
systemctl status ssh --no-pager

# 验证监听端口
ss -tlnp | grep ssh

# 验证配置语法（不会重启服务，安全检查）
sshd -t
```

#### GUI 路径（带桌面环境）

- 打开 "终端"（CentOS: Applications -> Utilities -> Terminal；Ubuntu: Ctrl+Alt+T）
- 使用 `sudo gedit /etc/ssh/sshd_config` 或 `sudo nano /etc/ssh/sshd_config` 编辑
- 保存后仍需在终端执行 `sudo systemctl restart sshd`（CentOS）/ `sudo systemctl restart ssh`（Ubuntu）

---

### 2. Linux 防火墙命令对照（firewalld vs ufw）

#### firewalld（CentOS 7 默认）

```bash
# 查看状态与默认区域
systemctl status firewalld --no-pager
firewall-cmd --get-default-zone

# 启用并开机自启
systemctl enable --now firewalld

# 放行业务端口（永久生效，需 reload）
firewall-cmd --permanent --add-port=52022/tcp    # SSH 新端口
firewall-cmd --permanent --add-port=80/tcp       # HTTP
firewall-cmd --permanent --add-port=443/tcp      # HTTPS

# 放行服务（推荐写法）
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --permanent --add-service=ssh

# 重新加载使规则生效
firewall-cmd --reload

# 查看当前生效规则
firewall-cmd --list-all

# 删除规则（示例删除 80 端口）
firewall-cmd --permanent --remove-port=80/tcp
firewall-cmd --reload

# 限制来源 IP（仅允许 192.168.1.0/24 访问 22）
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="22" protocol="tcp" accept'
firewall-cmd --reload
```

#### ufw（Ubuntu 20.04 默认）

```bash
# 启用并开机自启（首次启用会提示确认）
ufw enable
systemctl enable ufw

# 放行端口
ufw allow 52022/tcp      # SSH 新端口
ufw allow 80/tcp         # HTTP
ufw allow 443/tcp        # HTTPS

# 限制来源 IP（仅允许 192.168.1.0/24 访问 22）
ufw allow from 192.168.1.0/24 to any port 22 proto tcp

# 拒绝某端口
ufw deny 23/tcp          # 禁用 telnet

# 查看规则（带编号）
ufw status numbered

# 删除规则（先用 numbered 找到编号，再删除）
ufw delete 2
# 或按规则删除
ufw delete allow 80/tcp

# 重载配置
ufw reload

# 关闭（不建议，仅排错时使用）
ufw disable
```

#### GUI 路径

- CentOS 7（GNOME）：Applications -> Sundry -> Firewall（需安装 `firewall-config`）
- Ubuntu 20.04：安装 `gufw` 后运行 `sudo gufw`，图形界面切换开关即可

---

### 3. Linux 账户锁定命令

#### 锁定单个账户（CLI 通用）

```bash
# passwd 方式（推荐，标记为 !! 不可登录）
passwd -l suspicious_user

# usermod 方式（效果等同）
usermod -L suspicious_user

# 解锁
passwd -u suspicious_user
usermod -U suspicious_user

# 查看锁定状态（字段以 ! 或 !! 开头表示已锁）
passwd -S suspicious_user
grep suspicious_user /etc/shadow
```

#### pam_tally2（CentOS 7 / Ubuntu 较老版本）

编辑 `/etc/pam.d/system-auth`（CentOS）或 `/etc/pam.d/common-auth`（Ubuntu），追加：

```text
auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900 even_deny_root root_unlock_time=600
account required pam_tally2.so
```

查看与重置：

```bash
pam_tally2 --user=deploy
pam_tally2 --user=deploy --reset
```

#### faillock（CentOS 7 / Ubuntu 20.04 推荐）

编辑 `/etc/security/faillock.conf`：

```text
deny = 5
fail_interval = 900
unlock_time = 600
even_deny_root
root_unlock_time = 900
```

或修改 `/etc/pam.d/system-auth` 与 `/etc/pam.d/password-auth`：

```text
auth required pam_faillock.so preauth silent deny=5 unlock_time=600
auth required pam_faillock.so authfail deny=5 unlock_time=600
account required pam_faillock.so
```

查看与重置：

```bash
faillock --user deploy
faillock --user deploy --reset
```

---

### 4. Linux 文件完整性校验

#### rpm 包校验（CentOS 7）

```bash
# 校验所有已安装 RPM 包（输出 S=大小变化 5=MD5变化 T=时间变化 等）
rpm -Va > /var/log/rpm_va_$(date +%F).log

# 校验单个包
rpm -V openssh-server

# 查看某文件属于哪个包
rpm -qf /etc/ssh/sshd_config
```

#### debsums（Ubuntu 20.04）

```bash
# 安装
apt install -y debsums

# 校验所有包
debsums -s > /var/log/debsums_$(date +%F).log

# 校验单个包
debsums -s openssh-server
```

#### AIDE 完整流程（推荐，跨发行版）

安装：

```bash
# CentOS 7
yum install -y aide

# Ubuntu 20.04
apt install -y aide
```

初始化数据库（首次部署后立即执行）：

```bash
# CentOS 7
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# Ubuntu 20.04（路径略有差异）
aideinit
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

日常校验：

```bash
aide --check
# Ubuntu 也可用
aide --check --config /etc/aide/aide.conf
```

校验后更新数据库（确认变更合法后）：

```bash
aide --update
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
```

建议加入 cron：

```bash
echo '0 3 * * * root /usr/sbin/aide --check | mail -s "AIDE Report $(hostname)" security@example.com' > /etc/cron.d/aide
```

---

### 5. Linux auditd 配置示例

安装并启用：

```bash
# CentOS 7
yum install -y audit
systemctl enable --now auditd

# Ubuntu 20.04
apt install -y auditd
systemctl enable --now auditd
```

编辑 `/etc/audit/rules.d/audit.rules`，追加以下规则片段：

```text
# 删除已有规则
-D
# 缓冲区
-b 8192

# 监控 passwd / shadow 读写
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity

# 监控 SSH 配置变更
-w /etc/ssh/sshd_config -p wa -k ssh_config

# 监控 sudoers
-w /etc/sudoers -p wa -k sudoers

# 监控登录相关二进制
-w /bin/login -p x -k logins
-w /bin/su -p x -k privileged

# 监控 crontab
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron

# 监控模块加载
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# 系统调用监控（64 位）
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rmdir -k delete
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod

# 锁定规则（可选，0=不锁 1=锁规则 2=锁规则+事件 详见 auditctl(8)）
# -e 2
```

加载规则并重启服务：

```bash
# 合并 rules.d 下的规则到 /etc/audit/audit.rules
augenrules --load

# 验证已加载规则
auditctl -l

# 重启服务（注意：auditd 不响应 systemctl restart，需用 service）
service auditd restart

# 查询日志
ausearch -k identity
ausearch -k ssh_config --start today
aureport --summary
```

GUI 路径：审计日志可在 CentOS GNOME 的 "Log"（gnome-logs）查看；无 GUI 时统一用 `ausearch` / `aureport`。

---

### 6. Windows Server 2016 加固命令（PowerShell / CMD）

#### 6.1 账户管理

```powershell
# 查看本地用户
net user

# 创建新管理员账户
net user SecAdmin "P@ssw0rd!2026" /add
net localgroup Administrators SecAdmin /add

# 重命名默认 Administrator（建议）
Rename-LocalUser -Name "Administrator" -NewName "Admin_Disabled"

# 禁用 Guest
net user Guest /active:no

# 设置密码永不过期 + 不能更改（针对服务账户）
Set-LocalUser -Name "ServiceUser" -PasswordNeverExpires $true

# 禁用账户
Disable-LocalUser -Name "Admin_Disabled"

# 修改账户密码
net user SecAdmin "NewP@ssw0rd!2026"
```

#### 6.2 密码策略（net accounts）

```powershell
# 查看当前策略
net accounts

# 密码最小长度 14 位
net accounts /minpwlen:14

# 密码最长有效期 90 天
net accounts /maxpwage:90

# 密码最短有效期 1 天
net accounts /minpwage:1

# 密码唯一性记录 5 次
net accounts /uniquepw:5

# 账户锁定阈值 5 次
net accounts /lockoutthreshold:5

# 锁定持续时间 30 分钟
net accounts /lockoutduration:30

# 锁定观察窗口 30 分钟
net accounts /lockoutwindow:30
```

#### 6.3 secedit 导入安全模板

编写 `secpol.inf`（示例保存到 `C:\Hardening\secpol.inf`）：

```ini
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Profile Description]
Description=Hardening Baseline for Windows Server 2016
[System Access]
MinimumPasswordLength = 14
PasswordComplexity = 1
MinimumPasswordAge = 1
MaximumPasswordAge = 90
PasswordHistorySize = 5
LockoutBadCount = 5
LockoutDuration = 30
ResetLockoutCount = 30
EnableGuestAccount = 0
[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditObjectAccess = 3
[Registry Values]
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableIdleShutdown=4,0
```

导入并应用：

```powershell
# 应用配置
secedit /configure /cfg C:\Hardening\secpol.inf /db C:\Hardening\secpol.sdb /quiet

# 导出当前策略供复核
secedit /export /cfg C:\Hardening\current_secpol.inf /quiet

# 刷新组策略
gpupdate /force
```

#### 6.4 注册表加固（Set-ItemProperty）

```powershell
# 禁用 SMBv1（防 WannaCry 类攻击）
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord
Stop-Service -Name LanmanServer -Force
Start-Service -Name LanmanServer

# 禁用 RDP NLA 弱化（强制 NLA）
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Type DWord

# 隐藏上次登录用户名
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1 -Type DWord

# 禁用自动播放
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord

# 启用 PowerShell 脚本日志
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
```

---

### 7. Windows 防火墙命令

#### 7.1 netsh advfirewall（CMD 路径，兼容性最好）

```powershell
# 启用所有网络配置文件的防火墙
netsh advfirewall set allprofiles state on

# 查看状态
netsh advfirewall show allprofiles state

# 放行 RDP（3389）仅限 192.168.1.0/24
netsh advfirewall firewall add rule name="Allow-RDP-LAN" dir=in action=allow protocol=TCP localport=3389 remoteip=192.168.1.0/24

# 放行 HTTP / HTTPS
netsh advfirewall firewall add rule name="Allow-HTTP" dir=in action=allow protocol=TCP localport=80
netsh advfirewall firewall add rule name="Allow-HTTPS" dir=in action=allow protocol=TCP localport=443

# 拒绝某端口（如封禁 445 外部访问）
netsh advfirewall firewall add rule name="Block-SMB-Out" dir=in action=block protocol=TCP localport=445

# 删除规则（按名称）
netsh advfirewall firewall delete rule name="Allow-HTTP"

# 查看所有规则
netsh advfirewall firewall show rule name=all
```

#### 7.2 PowerShell New-NetFirewallRule（推荐）

```powershell
# 启用防火墙
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# 放行 RDP 限源
New-NetFirewallRule -DisplayName "Allow-RDP-LAN" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 -RemoteAddress 192.168.1.0/24

# 放行 Web 端口
New-NetFirewallRule -DisplayName "Allow-HTTP" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80
New-NetFirewallRule -DisplayName "Allow-HTTPS" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 443

# 封禁 SMB 入站
New-NetFirewallRule -DisplayName "Block-SMB-In" -Direction Inbound -Action Block -Protocol TCP -LocalPort 445

# 按名称删除
Remove-NetFirewallRule -DisplayName "Allow-HTTP"

# 查看规则
Get-NetFirewallRule -DisplayName "Allow-*" | Format-Table DisplayName,Enabled,Direction,Action
```

---

### 8. Windows 本地安全策略 GUI 路径

#### 8.1 打开 secpol.msc（本地安全策略）

GUI 步骤：
1. 按 `Win + R` 打开"运行"
2. 输入 `secpol.msc` 回车
3. 左侧树展开节点：
   - 账户策略 -> 密码策略：设置密码长度、复杂度、最短/最长有效期
   - 账户策略 -> 账户锁定策略：设置锁定阈值、时长
   - 本地策略 -> 审核策略：开启登录、特权使用、对象访问审核
   - 本地策略 -> 用户权限分配：限制"从网络访问此计算机"、"允许本地登录"
   - 本地策略 -> 安全选项：禁用 Guest、不显示最后用户名等

#### 8.2 打开 gpedit.msc（组策略）

GUI 步骤：
1. 按 `Win + R`
2. 输入 `gpedit.msc` 回车
3. 路径示例：
   - 计算机配置 -> 管理模板 -> Windows 组件 -> 远程桌面服务 -> 远程桌面会话主机 -> 安全：要求使用 NLA 进行远程身份验证
   - 计算机配置 -> Windows 设置 -> 安全设置 -> 高级审核策略配置：细化审核类别

#### 8.3 无头服务器（CLI）等价操作

```powershell
# Server Core 无 GUI，必须用 secedit /auditpol
auditpol /set /category:"Logon" /success:enable /failure:enable
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /get /category:*

# 通过 secedit 应用前述 secpol.inf
secedit /configure /cfg C:\Hardening\secpol.inf /db C:\Hardening\secpol.sdb /quiet
```

---

### 9. Nginx 完整安全配置段

将以下段加入 `/etc/nginx/nginx.conf` 的 `http {}` 块，或站点配置 `server {}` 块：

```nginx
# 隐藏版本号
server_tokens off;

# 关闭目录遍历
autoindex off;

# 安全头（HTTP 块全局生效）
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

# 限制请求体大小（防大文件上传攻击）
client_max_body_size 10m;

# 限制请求方法
if ($request_method !~ ^(GET|POST|HEAD)$ ) {
    return 405;
}

# 禁止访问隐藏文件（.git、.env 等）
location ~ /\. {
    deny all;
    access_log off;
    log_not_found off;
}

# 禁止访问备份/敏感文件
location ~* \.(bak|swp|sql|log|env|ini|sh)$ {
    deny all;
    access_log off;
    log_not_found off;
}

# 上传目录禁用 PHP 执行
location ~* /uploads/.*\.php$ {
    deny all;
}

# 隐藏 Nginx 版本号头（再次确认已生效）
server_tokens off;

# SSL 加固（HTTPS 站点）
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;
```

应用并验证：

```bash
nginx -t
systemctl reload nginx
```

---

### 10. Apache 完整安全配置段

编辑 `/etc/httpd/conf/httpd.conf`（CentOS）或 `/etc/apache2/apache2.conf`（Ubuntu），主配置或站点 VirtualHost 中加入：

```apache
# 隐藏版本号（ProductOnly）
ServerTokens Prod
ServerSignature Off
TraceEnable Off

# 关闭目录遍历（关键）
<Directory /var/www/html>
    Options -Indexes
    AllowOverride None
    Require all granted
</Directory>

# 全局禁用 FollowSymLinks（防软链接越权），如需用则改 SymLinksIfOwnerMatch
<Directory />
    Options -Indexes -ExecCGI -Includes
    AllowOverride None
    Require all denied
</Directory>

# 安全头（启用 mod_headers）
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "no-referrer-when-downgrade"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set Content-Security-Policy "default-src 'self'; object-src 'none'"
</IfModule>

# 禁止访问敏感文件
<FilesMatch "(^\.|\.bak$|\.swp$|\.sql$|\.log$|\.env$|\.ini$|\.sh$)">
    Require all denied
</FilesMatch>

# 隐藏目录
<DirectoryMatch "/\.">
    Require all denied
</DirectoryMatch>

# 限制请求体
LimitRequestBody 10485760

# 禁用不必要的 HTTP 方法
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>

# SSL 加固（https 站点的 VirtualHost）
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'
SSLHonorCipherOrder on
SSLSessionTickets off
```

应用并验证：

```bash
# CentOS 7
httpd -t
systemctl reload httpd

# Ubuntu 20.04
apache2ctl configtest
systemctl reload apache2
```

---

### 11. MySQL 加固 SQL 命令

登录 MySQL：

```bash
mysql -uroot -p
```

执行以下 SQL（MySQL 5.7 / 8.0 通用）：

```sql
-- 删除匿名账户
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');
FLUSH PRIVILEGES;

-- 删除 test 库及其权限
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';
FLUSH PRIVILEGES;

-- 禁用 LOAD DATA LOCAL INFILE（防任意文件读取）
SET GLOBAL local_infile=0;
SHOW VARIABLES LIKE 'local_infile';

-- 强制强密码插件（MySQL 8.0）
INSTALL COMPONENT 'file://component_validate_password';
SET GLOBAL validate_password.policy=STRONG;
SET GLOBAL validate_password.length=14;
SET GLOBAL validate_password.mixed_case_count=1;
SET GLOBAL validate_password.number_count=1;
SET GLOBAL validate_password.special_char_count=1;

-- MySQL 5.7 等价
INSTALL PLUGIN validate_password SONAME 'validate_password.so';
SET GLOBAL validate_password_policy=STRONG;
SET GLOBAL validate_password_length=14;

-- 修改 root 密码（强密码）
ALTER USER 'root'@'localhost' IDENTIFIED BY 'RootP@ssw0rd!2026';

-- 创建业务专用账户并限权
CREATE USER 'webapp'@'10.0.0.%' IDENTIFIED BY 'WebAppP@ssw0rd!2026';
GRANT SELECT, INSERT, UPDATE, DELETE ON webdb.* TO 'webapp'@'10.0.0.%';
FLUSH PRIVILEGES;

-- 查看权限
SHOW GRANTS FOR 'webapp'@'10.0.0.%';

-- 移除危险全局权限
REVOKE FILE ON *.* FROM 'webapp'@'10.0.0.%';
REVOKE PROCESS ON *.* FROM 'webapp'@'10.0.0.%';
REVOKE SUPER ON *.* FROM 'webapp'@'10.0.0.%';
FLUSH PRIVILEGES;

-- 开启审计日志（如已配置插件）
INSTALL PLUGIN audit_log SONAME 'audit_log.so';
SET GLOBAL audit_log_policy=ALL;
```

配置文件加固（`/etc/my.cnf` 或 `/etc/mysql/mysql.conf.d/mysqld.cnf`）：

```ini
[mysqld]
local_infile=0
skip_symbolic_links=1
bind-address=127.0.0.1
max_connections=100
max_user_connections=50
```

重载：

```bash
systemctl restart mysqld     # CentOS
systemctl restart mysql      # Ubuntu
```

---

### 12. PHP 完整安全配置

编辑 `/etc/php.ini`（CentOS）或 `/etc/php/7.x/fpm/php.ini`（Ubuntu），修改以下项：

```ini
; 禁用危险函数（一行示例，新手可直接复制）
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,eval,assert,pcntl_exec,putenv,dl,highlight_file,ini_restore,link,symlink,tmpfile,unpack

; 防止 PHP 脚本越权访问文件系统（按站点目录限定，多站点用冒号分隔）
open_basedir = /var/www/html/:/tmp/

; 禁止远程文件包含
allow_url_include = Off

; 禁止远程文件读取（推荐）
allow_url_fopen = Off

; 隐藏 PHP 版本
expose_php = Off

; 限制上传
file_uploads = On
upload_max_filesize = 2M
post_max_size = 8M
max_file_uploads = 5

; 限制执行时间与内存
max_execution_time = 30
max_input_time = 60
memory_limit = 128M

; 关闭危险特性
magic_quotes_gpc = Off      ; PHP 5.3 及以下
register_globals = Off       ; PHP 5.3 及以下
session.use_strict_mode = 1
session.use_only_cookies = 1
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = Strict

; 错误信息不外泄（生产环境）
display_errors = Off
display_startup_errors = Off
log_errors = On
error_log = /var/log/php/error.log

; 禁用危险函数后的二次确认
disable_classes = RecursiveDirectoryIterator,RecursiveIteratorIterator
```

应用（FPM 模式）：

```bash
# CentOS 7
systemctl restart php-fpm

# Ubuntu 20.04
systemctl restart php7.4-fpm
systemctl reload apache2
```

验证生效：

```bash
php -i | grep -E 'disable_functions|open_basedir|allow_url_include|expose_php'
```

GUI 路径：可在 Web 目录创建 `phpinfo.php` 临时查看（验证后立即删除）：

```bash
echo '<?php phpinfo(); ?>' > /var/www/html/phpinfo.php
# 验证后务必删除
rm -f /var/www/html/phpinfo.php
```

---

### 13. 加固动作清单（建议执行顺序）

1. 备份原配置（sshd_config、nginx.conf、php.ini、my.cnf）
2. 创建新管理员账户并测试登录，禁用默认账户
3. 加固 SSH（端口、密钥、禁 root）
4. 启用防火墙，仅放行业务端口
5. 配置账户锁定策略（pam_faillock）
6. 加固 Web 中间件（Nginx/Apache 安全头 + 隐藏版本）
7. 加固 PHP（disable_functions + open_basedir）
8. 加固数据库（删匿名、删 test、强密码、限权）
9. 部署 AIDE 与 auditd，初始化基线
10. 集中收集日志，配置告警
11. 加固后逐项验证业务可用性，记录变更 diff
