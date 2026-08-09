# Linux 持久化后门排查与应急手册

> 攻击者拿到权限后必然会做持久化。排查思路：按「计划任务 → 启动项 → 服务 → SSH 公钥 → 账号 → 内核/库劫持 → 隐藏痕迹」七条线全查。先取证（只读记录）再清理，清理后保留证据文件。

## 一、计划任务

```bash
# 当前用户与 root 的 crontab
crontab -l
# 全系统计划任务
cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -v '^#'
ls -la /var/spool/cron/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null
# systemd 定时器（新型持久化常走这里）
systemctl list-timers --all
# 排查特征：curl/wget 下载执行、/tmp 下脚本、base64 -d、反向 shell 关键字
grep -rE 'wget|curl|/dev/tcp|base64|chmod \+x' /etc/cron* /var/spool/cron/ 2>/dev/null
```

## 二、开机启动项

```bash
# 传统 rc.local / init.d
cat /etc/rc.local /etc/rc.d/rc.local 2>/dev/null
ls -la /etc/init.d/ | grep -vE 'functions|README'
# bash 启动文件（登录即执行，隐蔽后门高发地）
grep -nE 'wget|curl|/dev/tcp|base64|nohup' /etc/profile /etc/profile.d/*.sh /etc/bashrc ~/.bashrc ~/.bash_profile 2>/dev/null
# systemd 服务（重点看新加的、名字伪装系统的）
systemctl list-unit-files | grep -iE 'service' | grep -vE '^proc|^sys|^dev'
grep -lE 'ExecStart=.*(wget|curl|nohup|/tmp|/dev/tcp|bash -i)' /etc/systemd/system/*.service /usr/lib/systemd/system/*.service 2>/dev/null
```

## 三、SSH 后门（最常被种入）

```bash
# 注入公钥（检查每个用户的 authorized_keys）
find /home /root -name authorized_keys -exec sh -c 'echo "== {} =="; cat {}' \;
# 非 root 用户目录下出现 .ssh（新建用户后门）
find / -path '*/\.ssh/*' -newer /etc/passwd -type f 2>/dev/null
# SSH 配置被改（禁用口令、开放 root、改端口、诱饵账号）
grep -Ev '^\s*(#|$)' /etc/ssh/sshd_config
# 伪装的 sshd（高仿端口/进程名）：ss -tlnp 对照系统服务列表逐个核
ss -tlnp | grep -E 'sshd|:22|:2222|:22222'
```

## 四、账号后门

```bash
# 新增用户 / UID 0 的隐藏 root / 以 $ 结尾的隐藏用户
awk -F: '$3==0{print}' /etc/passwd
grep -E '\$|^[a-z]+$' /etc/passwd
ls -la /etc/passwd /etc/shadow /etc/sudoers
# 空口令账号（可直接登录）
awk -F: '($2==""){print $1}' /etc/shadow
# sudoers 被加白名单（免密执行）
grep -vE '^\s*(#|$)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null
# 最近创建的用户与家目录
ls -ld /home/* | grep -vE ' /home/(root|原有用户)$'
```

## 五、库劫持与内核态

```bash
# LD_PRELOAD 劫持
cat /etc/ld.so.preload 2>/dev/null
env | grep -i LD_PRELOAD
# 可疑 .so / 内核模块
find /lib /usr/lib /lib64 -name '*.so' -mtime -30 -ls 2>/dev/null | head
lsmod | grep -vE '^Module|^$'
```

## 六、隐藏与伪装痕迹

```bash
# 隐藏目录/文件（..空格、特殊字符、点开头随机名）
ls -la /tmp /var/tmp /dev/shm /root /home/* 2>/dev/null | grep -E '^d.*\.\.|\.\.\.'
# 进程名伪装（bash 假名、随机串）：核对 ps 与 /proc 一致性
ps -ef | grep -vE '^\s+UID' | awk '{print $8}' | grep -E '\[|\{|\]' 
ls -l /proc/*/exe 2>/dev/null | grep -E 'deleted|/tmp|/dev/shm' | head
# 网络后门（非业务端口监听）
ss -tlnp | awk 'NR>1{print $4}' | grep -vE ':(80|443|22|3306|6379|8080|8443|9000)$'
```

## 七、应急处置顺序

1. **只读取证**：`mkdir -p /root/evidence && cp -a <后门文件> /root/evidence/`，`stat` 记时间戳，`grep` 日志找来源。
2. **清计划任务**：`crontab -r` 或删指定行；删 `/etc/cron.d/` 可疑文件与 systemd timer。
3. **删启动项**：注释/删除 rc.local、profile 注入、恶意 systemd unit。
4. **清 SSH 公钥**：删 `authorized_keys` 中非本人公钥；恢复 sshd_config 并 `systemctl restart sshd`。
5. **锁账号**：`passwd -l <后门用户>`；删 UID 0 同名用户；重置被改口令。
6. **断外连**：`iptables -I OUTPUT -d <回连IP> -j DROP`，封后门回连端口。
7. **重启验证**：重启受影响服务（php-fpm/apache/sshd）后再次全量排查，确认后门未复现再收尾。
