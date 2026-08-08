# Linux 加固清单（CentOS 7 + Ubuntu 20.04）

> 覆盖 AWD 靶机群 Linux 系统：CentOS7_Linux、CentOS7_Mysql、Ubuntu_20.04。命令均以 root 执行，先备份再改动，加固后验证业务可用。

## CentOS7 firewalld 防火墙加固（封禁/放行端口与 IP）
- 查看状态与活动 zone：`systemctl status firewalld`、`firewall-cmd --get-active-zones`
- 封禁 IP：`firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=IP/32 reject"`；封禁端口：`firewall-cmd --permanent --add-rich-rule='rule port port="4444" protocol=tcp reject'`
- 放行业务端口：`firewall-cmd --permanent --add-port=80/tcp`
- 生效并查看：`firewall-cmd --reload && firewall-cmd --list-all`

## CentOS7 iptables 规则落库
- 查看规则：`iptables -L -n --line-numbers`；封禁 IP：`iptables -I INPUT -s IP -j DROP`；封禁端口：`iptables -I INPUT -p tcp --dport 4444 -j DROP`
- 放行端口：`iptables -I INPUT -p tcp --dport 80 -j ACCEPT`
- 落库（重启生效）：`service iptables save`（CentOS7 需先 `yum install iptables-services`）或 `iptables-save > /etc/sysconfig/iptables`

## CentOS7 systemctl 服务管理
- 查看运行中服务：`systemctl list-units --type=service --state=running`；启动失败项：`systemctl --failed`
- 停止并禁用后门服务：`systemctl stop 服务名 && systemctl disable 服务名`
- 查看服务可执行路径：`systemctl cat 服务名`

## CentOS7 yum 补丁升级
- 刷新源并升级：`yum clean all && yum update -y`
- 只升安全补丁：`yum update --security -y`（需 yum-plugin-security）
- 查最近安装记录：`rpm -qa --last | head -20`

## CentOS7 SELinux 状态检查
- 查看状态：`getenforce`（Enforcing=强制 / Permissive=宽容 / Disabled=关闭）；临时切换：`setenforce 1`（强制）、`setenforce 0`（宽容）
- 永久配置：编辑 /etc/selinux/config 设 `SELINUX=enforcing`
- 查违规日志：`grep SELinux /var/log/audit/audit.log | tail`

## CentOS7 PAM 密码策略加固
- 安装质量库：`yum install pam_pwquality -y`，并在 /etc/pam.d/system-auth 的 password 段加入：`password requisite pam_pwquality.so retry=3 minlen=8 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1`
- 密码过期策略：`chage -M 90 -m 1 用户名`（90 天改密）；查看：`chage -l 用户名`

## CentOS7 sshd_config 加固
- 编辑 /etc/ssh/sshd_config：`PermitRootLogin no`、`MaxAuthTries 3`、`UseDNS no`、`PasswordAuthentication no`（仅密钥）；追加白名单：`AllowUsers user1 user2`
- 生成密钥：`ssh-keygen -t ed25519`，公钥写入目标机 ~/.ssh/authorized_keys
- 校验并重启：`sshd -t && systemctl restart sshd`

## CentOS7 shadow 空口令检查
- 检查空口令：`awk -F: '$2=="" {print "空口令:", $1}' /etc/shadow`
- 检查 /etc/passwd 空口令：`awk -F: '$2=="" {print $1}' /etc/passwd`
- 锁定空口令账户：`passwd -l 用户名`

## CentOS7 登录日志排查
- secure 日志：`grep -iE "Failed password|Accepted password" /var/log/secure`
- 失败登录记录：`lastb | head -20`；当前登录：`who`、`last`

## Ubuntu ufw 防火墙加固
- 启用：`ufw enable && ufw status verbose`
- 默认收紧：`ufw default deny incoming && ufw default allow outgoing`
- 放行：`ufw allow 22/tcp && ufw allow 80/tcp`；封禁：`ufw deny from IP`；删除：`ufw delete deny from IP`

## Ubuntu apt 补丁升级
- 更新源并升级：`apt update && apt upgrade -y`
- 查看可更新列表：`apt list --upgradable`

## Ubuntu AppArmor 加固
- 查看状态：`aa-status`（或 apparmor_status）
- 强制模式：`aa-enforce 程序路径`；宽容模式：`aa-complain 程序路径`
- 拒绝日志：`grep -i "apparmor.*DENIED" /var/log/syslog | tail`

## Ubuntu PAM 密码策略加固
- 安装：`apt install libpam-pwquality -y`
- /etc/pam.d/common-password 确认含：`password requisite pam_pwquality.so retry=3 minlen=8 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1`
- 强制改密：`chage -M 90 -W 7 用户名`

## Ubuntu sshd 与 auth.log 日志
- sshd_config 同 CentOS7 配置，校验重启：`sshd -t && systemctl restart ssh`
- 查看登录：`grep -iE "Failed|Accepted" /var/log/auth.log`
- 实时监控：`tail -f /var/log/auth.log`

## Ubuntu 无人值守升级
- 启用：`apt install unattended-upgrades -y && dpkg-reconfigure --priority=low unattended-upgrades`
- 配置 /etc/apt/apt.conf.d/50unattended-upgrades 中 Allowed-Origins 含 security 源
- 查看状态：`systemctl status unattended-upgrades`

## 通用 异常账户排查（uid=0）
- 找 uid=0 非 root：`awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd`
- 列出可登录用户：`awk -F: '$7!="/sbin/nologin" && $7!="/bin/false" {print $1}' /etc/passwd`
- 查看所有用户最近登录：`lastlog`

## 通用 SSH 公钥后门排查
- 查看全部授权公钥：`find /home /root -name authorized_keys -type f 2>/dev/null -exec cat {} \;`
- 找近期新增公钥：`find / -name authorized_keys -mtime -7 2>/dev/null`
- 可疑公钥先备份再删除：`rm -f ~/.ssh/authorized_keys`

## 通用 crontab 清理
- 遍历查看所有用户定时任务：`for u in $(cut -d: -f1 /etc/passwd); do echo "==$u"; crontab -l -u $u 2>/dev/null; done`
- 查系统任务：`cat /etc/crontab; ls -la /etc/cron.d /etc/cron.daily`
- 删除可疑任务：`crontab -r -u 用户名`

## 通用 rc.local / systemd 启动项排查
- 检查 rc.local：`cat /etc/rc.local`
- 看启用服务（过滤异常项）：`systemctl list-unit-files --state=enabled`
- 找近期新增 unit：`find /etc/systemd/system /lib/systemd/system -name "*.service" -mtime -7 2>/dev/null`

## 通用 hosts 文件篡改检查
- 查看映射：`cat /etc/hosts`（警惕外网域名指向内网 IP 的篡改）
- 查看修改时间：`stat /etc/hosts`
- 先备份再修复：`cp /etc/hosts /etc/hosts.bak`

## 通用 可疑外连排查（ss -antp）
- 查看所有连接与进程：`ss -antp`；只看已建立外连：`ss -antp | grep ESTAB`
- 查反弹 shell 常用端口：`ss -antp | grep -E ":(4444|5555|6666|8888)"`
- 定位外连进程：`lsof -i TCP -n -P | grep ESTABLISHED`

## 通用 /tmp 可执行文件排查
- 找 /tmp 近期新增文件：`find /tmp -type f -mtime -3 -exec file {} \; | grep -iE "executable|script"`；看大文件：`du -ah /tmp | sort -rh | head`
- 可疑文件备份后删除，并查对应进程：`ss -antp | grep PID`
