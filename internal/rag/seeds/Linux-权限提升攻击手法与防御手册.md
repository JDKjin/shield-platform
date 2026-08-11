# Linux 权限提升攻击手法与防御手册

> 攻击者拿到低权限后会尝试提权到 root。本手册梳理 Linux 高频提权手法与其对应检测/防御点，用于「提前封堵提权路径」，把攻击者卡在低权限。

## 一、SUID 提权

```bash
# 检测：找 SUID 文件（重点危险程序）
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null
# 危险 SUID 程序（可被利用）：find、vim、bash、less、more、nano、cp、python、perl、env、awk
# 防御
chmod -s /usr/bin/vim /usr/bin/find 2>/dev/null
# 系统关键 SUID 需保留（passwd、su、sudo、mount）
```

## 二、sudo 提权（配置错误）

```bash
# 检测：本用户可免密执行的命令
sudo -l
# 危险 NOPASSWD 项：sudo NOPASSWD: ALL / 允许 find|vi|bash 等任意命令
grep -vE '^\s*(#|$)' /etc/sudoers /etc/sudoers.d/*
# 防御
# 删除危险 NOPASSWD 条目，只保留最小必要的免密命令
visudo
```

## 三、内核漏洞提权

```bash
# 检测：内核版本与已知 EXP
uname -a
cat /proc/version
# 常见提权 CVE：CVE-2021-3493（overlayfs）、CVE-2022-0847（Dirty Pipe）、CVE-2023-2640
# 防御
# 升级内核 / 禁用用户命名空间
sysctl -w kernel.unprivileged_userns_clone=0
echo 'kernel.unprivileged_userns_clone=0' >> /etc/sysctl.conf
```

## 四、可写文件/服务弱权限

```bash
# 检测：PATH 中的可写目录可劫持
echo $PATH; ls -ld $(echo $PATH | tr ':' ' ')
# 检测：全局可写的配置文件/脚本（可被注入）
find /etc /usr/local -type f -perm -002 -exec ls -la {} \; 2>/dev/null
# 检测：弱权限的服务二进制
find / -type f -perm -002 -exec ls -la {} \; 2>/dev/null | head
# 防御
chmod o-w /etc /usr/local/bin
```

## 五、计划任务/定时任务提权

```bash
# 检测：root 运行的 crontab 指向可写脚本
crontab -l; cat /etc/cron.d/* /etc/crontab
# 攻击者会替换 root 定时任务里可写的脚本
# 防御
chown root:root /var/spool/cron/ && chmod 700 /var/spool/cron/
```

## 六、其他常见手法

| 手法 | 检测 | 防御 |
|------|------|------|
| Docker 组权限（挂载逃逸） | `id` 看是否在 docker 组 | 移除用户 docker 组 |
| Capabilities | `getcap -r / 2>/dev/null` | 移除多余 cap |
| NFS 配置错误 | `cat /etc/exports`（no_root_squash） | 加 root_squash |
| 数据库提权（MySQL UDF） | `SELECT * FROM mysql.func` | 禁 UDF、最小权限 |
| 环境变量劫持 | PATH 可写、LD_PRELOAD 可写 | 收紧目录权限、禁 LD_PRELOAD |

## 七、提权防御总原则

1. **最小权限**：服务进程一律非 root 运行，文件属主明确。
2. **收紧 SUID/sudo/capability**：非必要不留提权接口。
3. **目录写权限收敛**：/tmp、可执行目录禁止写入可执行文件。
4. **监控提权行为**：`journalctl -u sshd`、`lastb`、审计 root 登录与 sudo 使用，异常即告警。
5. **比赛实操**：开局一键加固已覆盖高危 SUID/可写目录/sudo 配置项，加固后再自查一遍 `find / -perm -4000`。
