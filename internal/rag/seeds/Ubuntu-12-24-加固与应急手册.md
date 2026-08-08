# Ubuntu 12.04 ~ 24.04 加固与应急手册

> 覆盖 Ubuntu 12.04/12.10、14.04、16.04、18.04、20.04、22.04、24.04（LTS 及中间版本）。
> init 差异是重点：Ubuntu 12~14 用 **upstart/sysvinit**（无 systemctl），15.04 起用 systemd。
> 包管理器统一 apt，网络管理 12~15 用 ifupdown/NetworkManager，16+ 用 netplan/systemd-networkd。

## 版本差异速查
- init：Ubuntu 12.04~14.04 用 upstart（`service`/`initctl`），**没有 systemctl**；15.04+ 用 systemd
- os-release：12.04 无 /etc/os-release（用 `lsb_release -a`）；14.04 起有
- 包管理：统一 `apt-get`（12~14）与 `apt`（16+），均可兼容
- 防火墙：统一 ufw（12~24 全支持）
- 网络查看：12~14 用 `ifconfig`/`route`（net-tools）；16+ 用 `ip`/`ss`
- ssh 服务名：12~14 与 16+ 均为 `ssh`（`service ssh restart`）；systemd 版 `systemctl restart ssh`

## 服务管理（upstart 12~14 兼容写法）
- 无 systemctl 时全部用 `service 服务名 status|restart|start|stop`（12~24 通用）
- 12~14 查自启：`ls /etc/init/`（upstart 任务）；15+：`systemctl list-unit-files | grep enabled`
- 12~14 查 rc 脚本：`ls /etc/rc*.d/`；15+：`systemctl list-unit-files`

## 防火墙（ufw，12~24 通用）
- 查看：`ufw status verbose`；启用：`ufw --force enable`；默认拒绝入站：`ufw default deny incoming`
- 放行：`ufw allow 22/tcp`、`ufw allow 80/tcp`、`ufw allow from IP`；封禁：`ufw deny from IP`、`ufw deny 4444/tcp`
- 删除规则：`ufw delete deny 4444/tcp`；封禁记录查看：`grep UFW /var/log/ufw.log | tail`
- 回退 iptables（ufw 失效时）：`iptables -I INPUT -s IP -j DROP`、`iptables -I INPUT -p tcp --dport 4444 -j DROP`

## 包管理与补丁
- 更新：`apt-get update && apt-get upgrade -y`；只升安全：`apt-get update && apt-get upgrade --only-upgrade 包名`
- 查最近安装：`grep " install " /var/log/dpkg.log | tail -20`；卸载可疑包：`apt-get remove --purge 包名`
- 文件归属：`dpkg -S /路径/文件`；校验篡改：`debsums 包名`（需 `apt-get install debsums`）
- 12.04 老源：EOL 需切换 `http://old-releases.ubuntu.com/`，否则 `apt-get update` 404

## 用户与权限（12~24 通用）
- UID=0：`awk -F: '$3==0{print $1}' /etc/passwd`；空口令：`awk -F: '$2==""{print $1}' /etc/shadow`
- 锁定用户：`usermod -L 用户名`；sudo 组：`grep sudo /etc/group`（16+）/ `grep admin /etc/group`（12~14）
- sudoers：`grep -E "NOPASSWD|ALL=\(ALL\)" /etc/sudoers /etc/sudoers.d/*`
- 12.04 passwd 格式：直接查看 `cat /etc/passwd` 中 shell 为 /bin/bash 且 uid>=1000 的账号

## SSH 加固（服务名 ssh）
- 编辑 /etc/ssh/sshd_config：`PermitRootLogin no`、`MaxAuthTries 3`、`PasswordAuthentication no`、`UseDNS no`
- 校验重启：`sshd -t && systemctl restart ssh`（15+）或 `service ssh restart`（12~14 通用）
- 登录审计：12~14 日志在 /var/log/auth.log（统一）：`grep -iE "Failed password|Accepted" /var/log/auth.log | tail`
- 当前登录：`who`、`last`、`lastb`

## 持久化后门排查
- cron：`crontab -l`；`cat /etc/crontab`；`ls /etc/cron.d/`
- upstart（12~14）后门：`ls /etc/init/`、`cat /etc/init/*.conf | grep -E "exec|start on"`；`cat /etc/rc.local`
- systemd（16+）后门：`grep -rn "ExecStart" /etc/systemd/system/ | grep -E "/tmp|/dev/shm|curl|wget"`
- LD_PRELOAD：`cat /etc/ld.so.preload`；profile 注入：`grep -rnE "curl|wget|/dev/tcp|base64|nc " /etc/profile /etc/profile.d/ /etc/bash.bashrc`

## 内核加固（sysctl，12~24 通用）
- 立即：`sysctl -w net.ipv4.tcp_syncookies=1 net.ipv4.conf.all.rp_filter=1 net.ipv4.ip_forward=0`
- 永久：追加 /etc/sysctl.conf 后 `sysctl -p`

## AppArmor（Ubuntu 默认）
- 查看状态：`aa-status`；强制配置：`aa-enforce /etc/apparmor.d/*`（16+）/ `aa-enforce /etc/apparmor.d/*`（12~14 用 `apparmor_parser -a`）
- 排查：`grep DENIED /var/log/audit/audit.log /var/log/syslog | grep apparmor`

## 网络排查差异
- 12~14：`ifconfig -a`、`route -n`、`netstat -tlnp`、`lsof -i`；16+：`ip addr`、`ip route`、`ss -tlnp`
- 无 netstat 时（20.04+ 默认无 net-tools）：`apt-get install -y net-tools` 或直接用 `ss`
- 网卡配置文件：12~14 在 /etc/network/interfaces；18+ 在 /etc/netplan/*.yaml

## Ubuntu 特有应急差异
- 12.04/14.04 无 `ss` 命令时用 `netstat -tlnp`（net-tools 默认已装）
- 24.04 起 `iptables` 走 nftables 后端（iptables-nft），命令语法不变
- 统一日志：`/var/log/auth.log`、`/var/log/syslog`、`/var/log/ufw.log`
- 加固后验证：ufw active、无 UID=0 非 root、ssh 配置生效、`service ssh status` 正常
