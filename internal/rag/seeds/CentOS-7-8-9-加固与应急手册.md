# CentOS 7 / 8 / 9 加固与应急手册

> 覆盖 CentOS 7（7.x）、CentOS 8（8.0~8.5，EOL 2022）、CentOS Stream 9 / Rocky9 / Alma9。
> CentOS7 用 yum + firewalld + systemd；CentOS8 用 dnf（yum 软链）+ firewalld + systemd；CentOS9 用 dnf5 + firewalld + systemd。
> 命令均已做版本差异兼容，先备份再改动。

## 版本差异速查
- 包管理器：CentOS7 `yum`；CentOS8 `dnf`（`yum` 软链到 dnf）；CentOS9 `dnf`/`dnf5`
- 防火墙：CentOS7/8/9 均默认 firewalld（`firewall-cmd`），底层 nftables（CentOS8+）/iptables（CentOS7）
- init：三者均为 systemd
- 网络工具：CentOS7 可能无 `ss`（需 `iproute`）；三版本均可用 `netstat`（需 net-tools 包）
- Python：CentOS7 默认 py2、CentOS8 有 py3.6、CentOS9 无默认 python（需 python3）

## 防火墙（firewalld 通用）
- 查看状态：`firewall-cmd --state`；活动区域：`firewall-cmd --get-active-zones`
- 封禁 IP：`firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=IP reject"` 后 `firewall-cmd --reload`
- 封禁端口：`firewall-cmd --permanent --add-rich-rule='rule port port="4444" protocol=tcp reject'`
- 放行：`firewall-cmd --permanent --add-port=80/tcp`、`firewall-cmd --permanent --add-service=http`
- 默认拒绝入站：`firewall-cmd --set-default-zone=drop`（放行前勿开，避免断网）
- 查看全部：`firewall-cmd --list-all`；临时测试：`firewall-cmd --add-port=8080/tcp`（不 permanent，重启失效）
- 服务启停：`systemctl enable --now firewalld`

## 包管理与补丁
- CentOS7 更新：`yum clean all && yum update -y`；安全补丁：`yum update --security -y`
- CentOS8/9 更新：`dnf clean all && dnf update -y`；安全补丁：`dnf update --security -y`
- 查最近安装：`rpm -qa --last | head -20`
- 查询软件归属包：`rpm -qf /usr/bin/xx`；文件校验（被篡改检测）：`rpm -V 包名`

## systemd 服务排查（三版本通用）
- 运行中服务：`systemctl list-units --type=service --state=running`
- 失败项：`systemctl --failed`；停止并禁用后门服务：`systemctl stop 服务名 && systemctl disable 服务名`
- 查看服务可执行路径：`systemctl cat 服务名`；查可疑 unit 目录：`/etc/systemd/system/`、`/usr/lib/systemd/system/`
- 排查 ExecStart 指向 /tmp、/dev/shm 的单元：`grep -rn "ExecStart" /etc/systemd/system/ | grep -E "/tmp|/dev/shm|curl|wget|base64"`

## 用户与权限
- UID=0 用户：`awk -F: '$3==0{print $1}' /etc/passwd`（应只有 root）
- 空口令：`awk -F: '$2==""{print $1}' /etc/shadow`
- 锁定用户：`usermod -L 用户名`；查看用户属组：`id 用户名`
- sudoers 检查：`grep -E "NOPASSWD|ALL=\(ALL\)" /etc/sudoers /etc/sudoers.d/*`
- 最近新增用户：`ls -lt /etc/passwd`；`awk -F: '$3>=1000{print $1" uid="$3}' /etc/passwd`

## SSH 加固
- 编辑 /etc/ssh/sshd_config：`PermitRootLogin no`、`MaxAuthTries 3`、`PasswordAuthentication no`（仅密钥）、`UseDNS no`
- 生成密钥：`ssh-keygen -t ed25519`；写入目标机 ~/.ssh/authorized_keys
- 校验并重启：`sshd -t && systemctl restart sshd`
- 登录审计：`grep -iE "Failed password|Accepted" /var/log/secure | tail`；`lastb | head`；`who`、`last`

## 持久化后门排查（三版本通用）
- cron：`crontab -l`；`cat /etc/crontab`；`ls /etc/cron.d/ && cat /etc/cron.d/*`
- 自启：`cat /etc/rc.d/rc.local`；`systemctl list-unit-files | grep enabled`
- LD_PRELOAD：`cat /etc/ld.so.preload`；环境变量：`grep -rn "LD_PRELOAD" /etc/profile /etc/profile.d/ /root/.bashrc`
- 排查 profile.d 恶意脚本：`grep -rnE "curl|wget|/dev/tcp|base64|nc " /etc/profile.d/`
- 最近被改动的系统文件：`find /bin /usr/bin /sbin -mtime -1 -type f 2>/dev/null`

## 内核加固（sysctl）
- 立即生效：`sysctl -w net.ipv4.tcp_syncookies=1 net.ipv4.conf.all.rp_filter=1 net.ipv4.ip_forward=0`
- 永久：追加 /etc/sysctl.conf 后 `sysctl -p`：
  `net.ipv4.tcp_syncookies=1`、`net.ipv4.conf.all.rp_filter=1`、`net.ipv4.conf.all.accept_redirects=0`、`net.ipv4.ip_forward=0`

## SELinux
- 查看：`getenforce`；临时强制：`setenforce 1`；永久：`/etc/selinux/config` 设 `SELINUX=enforcing`
- 排查违规：`grep SELinux /var/log/audit/audit.log | tail`

## CentOS 特有应急差异
- CentOS7 无 `ss` 时用 netstat：`yum install -y net-tools` 后 `netstat -tlnp`
- CentOS8/9 排查 dnf 历史：`dnf history`；卸载可疑包：`dnf remove 包名`
- CentOS9 无 `python` 裸命令，脚本需用 `python3`
- 三版本通用取证：`ps -ef`、`ss -tnp`、`lsof -i`（需 lsof 包）、`last -20`

## 加固后验证
- 复扫：无 UID=0 非 root、无空口令、firewalld active、sshd 配置生效、无新增监听端口
- 业务验证：Web 服务端口可达、SSH 可登录、数据库连接正常
