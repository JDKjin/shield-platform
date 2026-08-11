# Linux 异常登录监测与应急响应手册

> 培训内容深化整理：/etc/passwd 与 /etc/shadow、特权账户排查、爆破检测、异常进程分析。
> 适用场景：综合防御竞赛靶机 Linux 系统被入侵后的应急响应。

## 一、账号文件结构

### 1.1 /etc/passwd

存储用户基本信息（所有用户可读）：

```
root:x:0:0:root:/root:/bin/bash
 │  │ │ │   │     │       │
 │  │ │ │   │     │       └─ 默认 Shell
 │  │ │ │   │     └─ 家目录
 │  │ │ │   └─ GECOS（描述）
 │  │ │ └─ GID（组 ID）
 │  │ └─ UID（0=特权）
 │  └─ 密码占位（x 表示在 shadow）
 └─ 用户名
```

### 1.2 /etc/shadow

存储加密密码与策略（仅 root 可读）：

```
root:$6$o5i2prfM$CB6k2zeLaB70BHDaom7AwZ7C...:20155:0:99999:7:::
 │   │                                   │      │  │    │  │ └─ 过期警告
 │   │                                   │      │  │    │  └─ 最大天数间隔
 │   │                                   │      │  │    └─ 最小天数间隔
 │   │                                   │      │  └─ 最后修改日期（距 1970）
 │   │                                   │      └─ 加密密码（$6$=SHA-512, $1$=MD5, $5$=SHA-256）
 │   │                                   └─ 最后修改日期
 │   └─ 加密密码（! 或 * 表示禁用）
 └─ 用户名
```

**算法标识**：
- `$1$` → MD5（弱）
- `$5$` → SHA-256（中）
- `$6$` → SHA-512（强，推荐）
- `!` 或 `*` → 账号锁定

## 二、特权账户排查

### 2.1 查找 UID=0 的超级用户

```bash
# 标准做法：只有 root 应该是 UID=0
awk -F: '$3==0{print $1}' /etc/passwd

# 查找 GID=0 的用户（root 组）
awk -F: '$4==0{print $1}' /etc/passwd
```

**异常**：除 root 外出现其他 UID=0 用户 → 后门账号。

### 2.2 查找可远程登录的特权账号

```bash
# 可以远程登录的账号（Shell 为 bash/sh/zsh 且 UID>=1000 或 UID==0）
awk -F: '($7 ~ /bash|sh|zsh/) && ($3 == 0 || $3 >= 1000) {print $1}' /etc/passwd

# 查看哪些用户为 root 权限
cat /etc/passwd | grep x:0

# 查看除不可登录以外的用户
cat /etc/passwd | grep -v nologin
```

### 2.3 查找新增账号

```bash
# 查看密码文件最后修改时间（用于判断是否被改）
stat /etc/passwd
stat /etc/shadow

# 对比备份
diff /etc/passwd /etc/passwd.bak 2>/dev/null
```

### 2.4 sudo 权限审查

```bash
# 查找 sudo 全权限账号
more /etc/sudoers | grep -v "^#\|^$" | grep "ALL=(ALL"

# 检查 sudoers.d 目录
ls /etc/sudoers.d/
cat /etc/sudoers.d/*
```

**高危**：`NOPASSWD: ALL` 出现在非 root 账号上。

### 2.5 锁定/删除可疑账号

```bash
# 锁定（保留账号，禁止登录）
usermod -L <username>

# 删除（彻底清除）
userdel -r <username>

# 修改 Shell 为不可登录
usermod -s /sbin/nologin <username>
```

## 三、异常登录检测

### 3.1 当前登录用户

```bash
who      # 当前登录用户（tty=本地, pts=远程）
w        # 详细信息（含正在执行的命令）
uptime   # 登录时长、负载
```

### 3.2 登录历史

```bash
# 最近登录记录
last | head -20

# 失败登录
lastb | head -20
```

### 3.3 判断是否被爆破

```bash
# 检查 auth.log 中的 Failed password
cat /var/log/auth.log | grep "Failed password for root"

# 统计失败登录的用户名及次数
cat /var/log/auth.log | grep "Failed password" | \
  perl -e 'while($_=<>){ /for(.*?)from/; print "$1\n";}' | \
  sort | uniq -c | sort -nr

# 统计爆破者 IP 及次数
cat /var/log/auth.log | grep "Failed password for" | grep "root" | \
  grep -Po '(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])(\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)){3}' | \
  sort | uniq -c | sort -nr

# 查找成功登录的恶意用户
cat /var/log/auth.log | grep "Accept"
```

**判断标准**：
- 短时间内同一 IP 出现大量 `Failed password` → 爆破
- 爆破后出现 `Accepted password` → 爆破成功

### 3.4 防御措施

```bash
# 1. 限制 SSH 来源（/etc/hosts.allow, /etc/hosts.deny）
echo "sshd: 10.0.0.0/8" >> /etc/hosts.allow
echo "sshd: ALL" >> /etc/hosts.deny

# 2. 使用 fail2ban（自动封禁爆破 IP）
apt install fail2ban -y
systemctl enable fail2ban

# 3. 修改 SSH 端口
sed -i 's/^#Port 22/Port 22222/' /etc/ssh/sshd_config
systemctl restart sshd

# 4. 禁用密码登录（仅密钥）
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
```

## 四、异常端口/进程/服务

### 4.1 异常端口

```bash
netstat -atnlp
# 或
ss -atnlp
```

**关注**：
- 监听在 0.0.0.0 的高危端口（4444、5555、6666、31337）
- Established 连接中的外部 IP（可能是 C2 回连）
- 异常的 ICMP/UDP 流量

### 4.2 异常进程

```bash
# 查看进程对应的可执行文件
ls -l /proc/PID/exe

# 查看进程详细信息
cat /proc/PID/exe | more    # 二进制内容
ps auxf                     # 进程树
```

**关注**：
- 进程名伪装（如 `[kworker]`、`[kthreadd]` 伪装内核线程）
- 已删除的执行文件（`ls -l /proc/PID/exe` 显示 `(deleted)`）
- CPU/内存占用异常

### 4.3 strace 分析恶意进程

```bash
# 跟踪程序的系统调用与子进程
strace -f -o trace.log ./elf

# 跟踪已运行进程
strace -f -p <PID> -o trace.log
```

**关注系统调用**：
- `connect(` → 网络回连
- `open(` + `/etc/passwd` → 读取账号文件
- `execve(` → 执行新程序
- `ptrace(` → 进程注入

### 4.4 异常服务

```bash
# 查看开机启动项
systemctl list-unit-files | grep enabled

# 查看正在运行的服务
systemctl list-units --type=service --state=running

# 检查 rc.local
cat /etc/rc.local 2>/dev/null
ls /etc/rc*.d/
```

## 五、持久化排查

### 5.1 计划任务

```bash
crontab -l -u root
crontab -l -u <user>

# 系统级
cat /etc/crontab
ls /etc/cron.d/
ls /etc/cron.{hourly,daily,weekly,monthly}/
```

**高危特征**：
- 含 `curl|wget|bash -i|/dev/tcp|nc `
- 执行位于 /tmp、/dev/shm、/var/tmp 的脚本
- 频率异常高（每分钟执行）

### 5.2 启动项

```bash
# systemd 服务
ls /etc/systemd/system/multi-user.target.wants/

# init.d
ls /etc/init.d/

# rc.local
cat /etc/rc.local
```

### 5.3 LD_PRELOAD 后门

```bash
cat /etc/ld.so.preload    # 应为空
cat /etc/ld.so.conf       # 检查异常路径
env | grep LD_PRELOAD
```

### 5.4 SSH 公钥后门

```bash
for h in /root /home/*; do
  [ -f "$h/.ssh/authorized_keys" ] && \
    echo "== $h/.ssh/authorized_keys ==" && \
    cat "$h/.ssh/authorized_keys"
done
```

### 5.5 Shell 环境污染

```bash
# 检查 /etc/profile, /etc/bash.bashrc, /etc/profile.d/*
for f in /etc/profile /etc/bash.bashrc /etc/profile.d/*; do
  [ -f "$f" ] || continue
  if grep -qE 'curl|wget|/dev/tcp|base64 -d|nc |python -c|LD_PRELOAD' "$f"; then
    echo "[SUSPECT] $f"
  fi
done
```

## 六、应急响应决策流程

```
告警触发（爆破/异常进程/异常登录）
  ↓
Step 1: 隔离（防火墙封禁源 IP）
  ↓
Step 2: 取证（保留现场）
  ├─ netstat -atnlp > /tmp/netstat.log
  ├─ ps auxf > /tmp/ps.log
  ├─ last > /tmp/last.log
  ├─ lastb > /tmp/lastb.log
  ├─ cat /var/log/auth.log > /tmp/auth.log
  └─ cp /etc/passwd /etc/shadow /tmp/
  ↓
Step 3: 止损
  ├─ usermod -L <可疑账号>
  ├─ kill -9 <恶意 PID>
  ├─ rm -f <恶意文件>
  ├─ 清理 crontab / rc.local / LD_PRELOAD
  └─ 移除 authorized_keys 中的未知公钥
  ↓
Step 4: 根因分析
  ├─ 爆破入口？→ 改密码、限制 SSH
  ├─ Web 漏洞？→ 修复应用、审计日志
  └─ 内鬼？→ 审计 sudo 历史
  ↓
Step 5: 加固（执行一键加固）
  ├─ ssh_harden
  ├─ user_lock
  ├─ pam_lockout
  └─ cron_clean
```

## 七、相关加固项

| 加固项 ID | 作用 |
|---|---|
| `ssh_harden` | SSH 加固（禁 Root、禁密码、改端口） |
| `user_lock` | 锁定空密码与 UID=0 非 root |
| `pam_lockout` | PAM 失败锁定（5 次锁 300s） |
| `passwd_policy` | 密码策略强化 |
| `sudo_restrict` | sudo 权限收紧 |
| `cron_clean` | 后门清理（计划任务/启动项/LD_PRELOAD） |
| `pubkey_check` | SSH 公钥审查 |
| `audit_log` | 审计日志启用 |

## 八、常用速查命令

```bash
# 一键导出系统快照
netstat -atnlp > /tmp/snap_netstat.txt
ps auxf > /tmp/snap_ps.txt
ss -antp > /tmp/snap_ss.txt
last > /tmp/snap_last.txt
lastb > /tmp/snap_lastb.txt
cat /etc/passwd > /tmp/snap_passwd.txt
cat /etc/shadow > /tmp/snap_shadow.txt 2>/dev/null
cat /etc/sudoers > /tmp/snap_sudoers.txt 2>/dev/null
crontab -l > /tmp/snap_crontab_root.txt 2>/dev/null
ls /etc/cron.d/ > /tmp/snap_cron_d.txt
systemctl list-unit-files --state=enabled > /tmp/snap_services.txt

# 一键排查恶意进程
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  exe=$(readlink /proc/$pid/exe 2>/dev/null)
  [ -n "$exe" ] && echo "$pid: $exe"
done | grep -iE 'deleted|/tmp|/dev/shm|/var/tmp'

# 检查 SUID 文件
find / -perm -4000 -type f 2>/dev/null

# 检查最近修改的文件（24h 内）
find / -mtime -1 -type f 2>/dev/null | grep -vE '/proc|/sys|/run'
```

## 九、参考

- 培训 PDF：应急响应.pdf（异常登录监测与响应章节）
- Linux 应急响应手册（同行种子文档）：linux-incident-response.md
- fail2ban：https://github.com/fail2ban/fail2ban
