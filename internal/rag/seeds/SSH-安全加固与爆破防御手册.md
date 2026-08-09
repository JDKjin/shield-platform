# SSH 安全加固与爆破防御手册

> SSH 是 AWD/防御赛被爆破与种后门的头号入口。目标：禁 root 口令登录、限失败次数、防爆破、封来源 IP，同时保证自己还能通过 SSH 管理。

## 一、sshd_config 关键加固项

```bash
vi /etc/ssh/sshd_config
```

| 配置 | 建议值 | 说明 |
|------|--------|------|
| `PermitRootLogin` | `no` | 禁 root 直接登录，避免 root 被爆破；需要时先登普通用户再 su |
| `PasswordAuthentication` | `no` | 禁口令登录，仅密钥（比赛保留口令需配合限速时留 `yes`） |
| `PubkeyAuthentication` | `yes` | 开启密钥登录 |
| `MaxAuthTries` | `3` | 单连接最大认证失败次数 |
| `LoginGraceTime` | `30` | 登录超时秒数 |
| `AllowUsers` / `AllowGroups` | 白名单 | 仅允许指定用户/组登录 |
| `Protocol` | `2` | 仅 SSHv2 |
| `ClientAliveInterval` | `300` | 心跳间隔，断开僵尸连接 |

```bash
# 校验并生效
sshd -t && systemctl restart sshd
```

## 二、生成并部署自己的密钥

```bash
# 本机生成密钥对（无口令短语便于自动化）
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''
# 推送到靶机（保留自己的登录通道）
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@靶机IP
# 确认后清理 authorized_keys 里其他公钥
grep -v "$(cat ~/.ssh/id_ed25519.pub)" ~/.ssh/authorized_keys > /tmp/ak && mv /tmp/ak ~/.ssh/authorized_keys
```

> 加固前务必先把密钥装好再禁口令登录，否则锁死自己。

## 三、爆破检测与处置

```bash
# Linux 查爆破来源（按失败次数排序）
grep 'Failed password' /var/log/secure | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head
# Ubuntu
grep -E 'Failed|Invalid' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head

# 成功登录审计（对照是否被进来过）
grep 'Accepted' /var/log/secure
# 最近登录记录
last -20

# 封爆破源 IP
iptables -I INPUT -s <爆破IP> -j DROP
# 或按端口限速（限每秒连接数，不影响正常连接）
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
```

## 四、fail2ban 自动封禁

```bash
# CentOS / Ubuntu
yum install -y fail2ban   # 或 apt-get install -y fail2ban
cat > /etc/fail2ban/jail.local <<'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/secure
maxretry = 5
findtime = 300
bantime = 600
EOF
# Ubuntu 靶机 logpath 改为 /var/log/auth.log
systemctl enable --now fail2ban

# 手动封禁/解封
fail2ban-client set sshd banip <IP>
fail2ban-client set sshd unbanip <IP>
# 查看当前封禁
fail2ban-client status sshd
```

## 五、Windows OpenSSH / RDP 爆破防御

```powershell
# 查 RDP 爆破来源（4625 登录失败事件）
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} | ForEach-Object { $_.Properties[18].Value } | Group-Object | Sort-Object Count -Descending | Select -First 10
# 封来源 IP
New-NetFirewallRule -DisplayName "BlockRDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress <IP> -Action Block
# 开启账户锁定策略（防 RDP/SSH 爆破）
net accounts /lockoutthreshold:5 /lockoutduration:15
# 限制远程桌面用户
```

## 六、收尾自查

1. 自己能否正常 SSH 登录（密钥通道先验证）。
2. `grep 'Failed' /var/log/secure | tail` 确认爆破已被限速/封禁。
3. 移除靶机上可疑的 `authorized_keys` 与新建账号，防止攻击者反向利用 SSH 通道。
4. 比赛内网仍可能被横向爆破，配合面板 `ban_ip` 与 `ss -tlnp` 巡检异常登录。
