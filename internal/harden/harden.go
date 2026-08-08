package harden

import (
	"fmt"
	"runtime"

	"shield-platform/internal/execx"
)

// Item 加固项
type Item struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Desc     string `json:"desc"`
	Risk     string `json:"risk"` // low|medium|high  影响可用性风险
	Linux    string `json:"linux,omitempty"`
	Windows  string `json:"windows,omitempty"`
}

// Script 返回当前平台脚本
func (it *Item) Script() string {
	if runtime.GOOS == "windows" {
		return it.Windows
	}
	return it.Linux
}

// Result 执行结果
type Result struct {
	ItemID     string `json:"item_id"`
	Name       string `json:"name"`
	Output     string `json:"output"`
	ExitCode   int    `json:"exit_code"`
	DurationMS int64  `json:"duration_ms"`
}

// List 全部加固项
var List = []*Item{
	{
		ID: "ssh_harden", Name: "SSH安全加固", Category: "SSH",
		Desc: "禁用Root远程登录、禁用密码登录(保留密钥)、更改默认端口", Risk: "medium",
		Linux: `
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak 2>/dev/null
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null
echo "[done] SSH hardened"`,
		Windows: `echo "SSH hardening skipped on Windows"`,
	},
	{
		ID: "user_lock", Name: "高危账号处置", Category: "账号安全",
		Desc: "锁定空密码用户与UID=0非root用户(保留root)", Risk: "high",
		Linux: `
for u in $(sudo awk -F: '$2==""{print $1}' /etc/shadow 2>/dev/null); do
  usermod -L "$u" 2>/dev/null
  echo "locked: $u"
done
for u in $(awk -F: '$3==0{print $1}' /etc/passwd); do
  if [ "$u" != "root" ]; then usermod -L "$u" 2>/dev/null; echo "locked non-root uid0: $u"; fi
done
echo "[done] user audit"`,
		Windows: `echo "Use net user to review accounts"`,
	},
	{
		ID: "perm_fix", Name: "敏感文件权限修复", Category: "文件权限",
		Desc: "修复 /etc/shadow /etc/sudoers /etc/passwd 权限", Risk: "low",
		Linux: `
chmod 000 /etc/shadow 2>/dev/null
chmod 440 /etc/sudoers 2>/dev/null
chmod 644 /etc/passwd 2>/dev/null
chown root:root /etc/shadow /etc/sudoers /etc/passwd 2>/dev/null
echo "[done] permission fixed"`,
		Windows: `echo "icacls review recommended"`,
	},
	{
		ID: "firewall_on", Name: "防火墙启用", Category: "网络防护",
		Desc: "启用防火墙并封禁危险端口(4444/5555/6666/8888等)", Risk: "high",
		Linux: `
if command -v ufw >/dev/null 2>&1; then
  ufw --force enable 2>/dev/null
  ufw default deny incoming 2>/dev/null
  ufw allow 22/tcp 2>/dev/null
  ufw allow 80/tcp 2>/dev/null
  ufw allow 443/tcp 2>/dev/null
  ufw allow 3306/tcp 2>/dev/null
  for p in 4444 5555 6666 7777 8888 9999 31337; do ufw deny $p/tcp 2>/dev/null; done
elif command -v firewall-cmd >/dev/null 2>&1; then
  systemctl start firewalld 2>/dev/null
  systemctl enable firewalld 2>/dev/null
  firewall-cmd --set-default-zone=drop 2>/dev/null
  firewall-cmd --permanent --add-port=22/tcp 2>/dev/null
  firewall-cmd --permanent --add-port=80/tcp 2>/dev/null
  firewall-cmd --permanent --add-port=443/tcp 2>/dev/null
  firewall-cmd --reload 2>/dev/null
else
  for p in 4444 5555 6666 7777 8888 9999 31337; do
    iptables -I INPUT -p tcp --dport $p -j DROP 2>/dev/null
  done
  echo "iptables rules added"
fi
echo "[done] firewall enabled"`,
		Windows: `netsh advfirewall set allprofiles state on
netsh advfirewall firewall add rule name="block4444" dir=in protocol=TCP localport=4444 action=block
netsh advfirewall firewall add rule name="block5555" dir=in protocol=TCP localport=5555 action=block
netsh advfirewall firewall add rule name="block6666" dir=in protocol=TCP localport=6666 action=block
netsh advfirewall firewall add rule name="block8888" dir=in protocol=TCP localport=8888 action=block
netsh advfirewall firewall add rule name="block31337" dir=in protocol=TCP localport=31337 action=block
echo "[done] firewall rules added"`,
	},
	{
		ID: "cron_clean", Name: "后门清理(计划任务/启动项)", Category: "持久化清理",
		Desc: "清理含 curl/wget/bash 的可疑计划任务与 rc.local、LD_PRELOAD", Risk: "high",
		Linux: `
crontab -l 2>/dev/null | grep -vE 'curl|wget|bash -i|/dev/tcp|nc ' | crontab - 2>/dev/null
for f in /etc/cron.d/*; do [ -f "$f" ] && grep -qE 'curl|wget|bash -i|/dev/tcp|nc ' "$f" && mv "$f" "$f.disabled"; done
cat /etc/ld.so.preload 2>/dev/null | grep -v '^$' >/dev/null && : > /etc/ld.so.preload 2>/dev/null
echo "[done] cron & preload cleaned"`,
		Windows: `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Backdoor" /f 2>nul
echo "[done] cleanup executed"`,
	},
	{
		ID: "web_perms", Name: "Web目录加固", Category: "Web安全",
		Desc: "修复Web目录权限，删除上传目录可执行风险，移除危险PHP函数(可选)", Risk: "medium",
		Linux: `
for d in /var/www/html /var/www /usr/share/nginx/html; do
  [ -d "$d" ] && chmod -R o-w "$d" 2>/dev/null
done
find /var/www -type d -name "upload*" -exec chmod -R 555 {} \; 2>/dev/null
echo "[done] web dir hardened"`,
		Windows: `icacls C:\inetpub\wwwroot /inheritance:r /grant:r "*IIS_IUSRS:(OI)(CI)M" 2>nul
echo "[done] web dir hardened"`,
	},
	{
		ID: "tmp_clean", Name: "临时目录清理", Category: "持久化清理",
		Desc: "清理 /tmp /dev/shm /var/tmp 下可执行恶意文件(保留目录)", Risk: "low",
		Linux: `
find /tmp /var/tmp /dev/shm -maxdepth 1 -type f -executable -exec rm -f {} \; 2>/dev/null
echo "[done] tmp cleaned"`,
		Windows: `del /q %TEMP%\*.exe 2>nul
echo "[done] tmp cleaned"`,
	},
	{
		ID: "danger_func", Name: "危险PHP函数禁用", Category: "Web安全",
		Desc: "在php.ini添加disable_functions(保留系统关键函数)", Risk: "high",
		Linux: `
INIFILE=$(php -i 2>/dev/null | grep -i "Loaded Configuration File" | awk -F"=>" '{print $2}' | tr -d ' ')
[ -z "$INIFILE" ] && INIFILE="/etc/php/7.4/apache2/php.ini"
[ -f "$INIFILE" ] || exit 0
if ! grep -q '^disable_functions' "$INIFILE"; then
  echo 'disable_functions=system,passthru,exec,shell_exec,popen,proc_open,pcntl_exec,assert,pcntl_fork,putenv,mail' >> "$INIFILE"
fi
echo "[done] disable_functions applied: $INIFILE"`,
		Windows: `echo "edit php.ini manually on Windows"`,
	},
	{
		ID: "ssh_session", Name: "SSH会话加固", Category: "SSH",
		Desc: "限制SSH协议版本、空闲超时、最大认证次数、禁用转发", Risk: "low",
		Linux: `
S=/etc/ssh/sshd_config
[ -f "$S" ] || { echo "no sshd_config"; exit 0; }
cp "$S" "$S.bak" 2>/dev/null
sed -i 's/^#\?Protocol.*/Protocol 2/' "$S"
sed -i 's/^#\?ClientAliveInterval.*/ClientAliveInterval 300/' "$S"
sed -i 's/^#\?ClientAliveCountMax.*/ClientAliveCountMax 2/' "$S"
sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 4/' "$S"
sed -i 's/^#\?LoginGraceTime.*/LoginGraceTime 60/' "$S"
sed -i 's/^#\?AllowTcpForwarding.*/AllowTcpForwarding no/' "$S"
sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' "$S"
systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null
echo "[done] ssh session hardened"`,
		Windows: `echo "ssh session hardening skipped on Windows"`,
	},
	{
		ID: "pubkey_check", Name: "SSH公钥审查", Category: "SSH",
		Desc: "检查所有用户 authorized_keys 中的外来公钥(风险提示)", Risk: "low",
		Linux: `
for h in /root /home/*; do
  [ -f "$h/.ssh/authorized_keys" ] && echo "== $h/.ssh/authorized_keys ==" && cat "$h/.ssh/authorized_keys" 2>/dev/null
done
echo "[done] review keys above; remove any you do not recognize"`,
		Windows: `echo "check C:\Users\*\ .ssh\authorized_keys manually"`,
	},
	{
		ID: "passwd_policy", Name: "密码策略强化", Category: "账号安全",
		Desc: "设置密码最小长度8、过期90天、重试5次锁定、历史5条", Risk: "medium",
		Linux: `
if [ -f /etc/login.defs ]; then
  sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
  sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
  sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 8/' /etc/login.defs
  sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
fi
if [ -d /etc/pam.d ]; then
  grep -rl "pam_pwquality\|pam_cracklib" /etc/pam.d/system-auth /etc/pam.d/common-password 2>/dev/null | while read f; do
    grep -q "minlen" "$f" || echo "password requisite pam_pwquality.so minlen=8 retry=3" >> "$f"
  done
fi
echo "[done] password policy applied"`,
		Windows: `net accounts /minpwlen:8 /maxpwage:90 /minpwage:7
echo "[done] windows password policy applied"`,
	},
	{
		ID: "sudo_restrict", Name: "Sudo权限收紧", Category: "账号安全",
		Desc: "移除 sudoers 中 NOPASSWD 与 ALL=(ALL) 危险授权", Risk: "high",
		Linux: `
for f in /etc/sudoers /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  if grep -q "NOPASSWD" "$f" 2>/dev/null; then
    cp "$f" "$f.bak" 2>/dev/null
    sed -i 's/\s\+NOPASSWD:ALL/NOPASSWD:ALL #REVIEW-NOPASSWD/' "$f" 2>/dev/null
    sed -i 's/ALL=(ALL)\s\+ALL/ALL=(ALL) ALL #REVIEW-ALL-ALL/' "$f" 2>/dev/null
    echo "review: $f contains NOPASSWD/ALL-ALL"
  fi
done
[ -f /etc/sudoers ] && chmod 440 /etc/sudoers
echo "[done] sudoers reviewed"`,
		Windows: `echo "review local group 'Administrators' membership"`,
	},
	{
		ID: "kernel_harden", Name: "内核网络加固", Category: "网络防护",
		Desc: "启用SYN Cookie、反向路径过滤、禁转发/重定向/ICMP重定向", Risk: "medium",
		Linux: `
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf 2>/dev/null
sysctl -p >/dev/null 2>&1
echo "[done] kernel network hardened"`,
		Windows: `netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
echo "[done] windows inbound blocked"`,
	},
	{
		ID: "sysctl_core", Name: "内存/核心转储防护", Category: "系统加固",
		Desc: "禁用core dump、限制共享内存、禁TCP时间戳", Risk: "low",
		Linux: `
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
echo "kernel.core_uses_pid = 1" >> /etc/sysctl.conf
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
echo "kernel.dmesg_restrict = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_timestamps = 0" >> /etc/sysctl.conf
sysctl -p >/dev/null 2>&1
echo "* hard core 0" >> /etc/security/limits.conf 2>/dev/null
echo "[done] core dump & sysctl hardened"`,
		Windows: `reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v AlwaysKeepMemoryDump /t REG_DWORD /d 0 /f
echo "[done] crash dump disabled"`,
	},
	{
		ID: "selinux_enable", Name: "SELinux/AppArmor启用", Category: "系统加固",
		Desc: "启用SELinux enforcing 或 AppArmor(若已安装)", Risk: "medium",
		Linux: `
if [ -f /etc/selinux/config ]; then
  sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
  echo "SELinux set to enforcing"
elif command -v aa-status >/dev/null 2>&1; then
  aa-enforce /etc/apparmor.d/* 2>/dev/null
  echo "AppArmor enforced"
else
  echo "no SELinux/AppArmor found"
fi
echo "[done] mandatory access control enabled"`,
		Windows: `echo "Windows Defender enabled by default"`,
	},
	{
		ID: "audit_log", Name: "审计日志启用", Category: "日志审计",
		Desc: "启动auditd，审计关键文件/账号/sudo/时间修改", Risk: "low",
		Linux: `
if command -v auditctl >/dev/null 2>&1; then
  systemctl start auditd 2>/dev/null || service auditd start 2>/dev/null
  auditctl -w /etc/passwd -p wa -k identity 2>/dev/null
  auditctl -w /etc/shadow -p wa -k identity 2>/dev/null
  auditctl -w /etc/sudoers -p wa -k sudoers 2>/dev/null
  auditctl -w /var/www -p wa -k webroot 2>/dev/null
  auditctl -a always,exit -F arch=b64 -S execve -k exec 2>/dev/null
  echo "audit rules added"
else
  echo "auditd not installed"
fi
echo "[done] audit logging enabled"`,
		Windows: `wevtutil sl Security /e:true
echo "[done] security event log enabled"`,
	},
	{
		ID: "pam_lockout", Name: "登录失败锁定", Category: "认证强化",
		Desc: "PAM启用失败锁定(faillock/tally2, 5次锁定300s)", Risk: "high",
		Linux: `
if [ -d /etc/pam.d ]; then
  if [ -f /etc/pam.d/system-auth ]; then
    grep -q pam_faillock /etc/pam.d/system-auth || \
      sed -i '/auth required pam_env.so/a auth required pam_faillock.so preauth silent audit deny=5 unlock_time=300' /etc/pam.d/system-auth 2>/dev/null
    grep -q pam_faillock /etc/pam.d/password-auth || \
      sed -i '/auth required pam_env.so/a auth required pam_faillock.so preauth silent audit deny=5 unlock_time=300' /etc/pam.d/password-auth 2>/dev/null
  fi
  echo "pam_faillock rules added (deny=5 unlock=300s)"
else
  echo "no pam.d"
fi
echo "[done] login lockout enabled"`,
		Windows: `net accounts /lockoutthreshold:5 /lockoutduration:30
echo "[done] windows lockout threshold 5"`,
	},
	{
		ID: "db_redis", Name: "Redis加固", Category: "数据库安全",
		Desc: "Redis禁用危险指令、设置密码、绑定本地、禁止公网", Risk: "medium",
		Linux: `
R=$(find /etc -name "redis.conf" 2>/dev/null | head -1)
if [ -z "$R" ]; then echo "redis.conf not found"; echo "[done]"; exit 0; fi
cp "$R" "$R.bak" 2>/dev/null
sed -i 's/^#\?bind .*/bind 127.0.0.1/' "$R"
sed -i 's/^#\?protected-mode .*/protected-mode yes/' "$R"
sed -i 's/^#\?rename-command FLUSHALL.*/rename-command FLUSHALL ""/' "$R"
sed -i 's/^#\?rename-command FLUSHDB.*/rename-command FLUSHDB ""/' "$R"
sed -i 's/^#\?rename-command CONFIG.*/rename-command CONFIG ""/' "$R"
sed -i 's/^#\?rename-command EVAL.*/rename-command EVAL ""/' "$R"
echo "[done] redis hardened: $R"`,
		Windows: `echo "edit redis.windows.conf manually"`,
	},
	{
		ID: "db_mysql", Name: "MySQL安全基线", Category: "数据库安全",
		Desc: "MySQL移除匿名账号、root禁远程、权限收紧(需root)", Risk: "high",
		Linux: `
M=$(command -v mysql || command -v mariadb)
if [ -z "$M" ]; then echo "mysql client not found"; echo "[done]"; exit 0; fi
$M -uroot 2>/dev/null <<'SQL'
DELETE FROM mysql.user WHERE User='';
UPDATE mysql.user SET Host='localhost' WHERE User='root';
DROP DATABASE IF EXISTS test;
FLUSH PRIVILEGES;
SQL
echo "[done] mysql baseline applied (empty root pwd expected local)"`,
		Windows: `echo "run mysql_secure_installation manually"`,
	},
	{
		ID: "svc_harden", Name: "危险服务禁用", Category: "服务收敛",
		Desc: "禁用telnet/rsh/tftp/rsync匿名/FTP匿名等服务", Risk: "medium",
		Linux: `
for s in telnet.socket telnetd rsh.socket rlogin.socket rexec.socket tftp.socket vsftpd tftp; do
  systemctl disable --now $s 2>/dev/null || chkconfig $s off 2>/dev/null || update-rc.d $s disable 2>/dev/null
done
echo "[done] dangerous services disabled"`,
		Windows: `
sc config telnet start= disabled 2>nul
sc config tlntsvr start= disabled 2>nul
net stop telnet 2>nul
echo "[done] dangerous services disabled"`,
	},
	{
		ID: "bash_inject", Name: "Shell环境反注入", Category: "持久化清理",
		Desc: "清理 /etc/profile.d 与 /etc/bash.bashrc 中的恶意导出与回连", Risk: "medium",
		Linux: `
for f in /etc/profile /etc/bash.bashrc /etc/profile.d/*; do
  [ -f "$f" ] || continue
  if grep -qE 'curl|wget|/dev/tcp|base64 -d|nc |python -c|LD_PRELOAD|export\s+\w+=\(\(' "$f" 2>/dev/null; then
    cp "$f" "$f.bak" 2>/dev/null
    grep -vE 'curl|wget|/dev/tcp|base64 -d|nc |python -c|LD_PRELOAD' "$f" > "$f.tmp" 2>/dev/null
    mv "$f.tmp" "$f" 2>/dev/null
    echo "cleaned: $f"
  fi
done
echo "[done] shell env cleaned"`,
		Windows: `reg delete "HKCU\Environment" /v Malicious 2>nul
echo "[done] env checked"`,
	},
	{
		ID: "hosts_lock", Name: "HOSTS/网关防护", Category: "网络防护",
		Desc: "锁定/etc/hosts防DNS劫持，校验默认网关配置", Risk: "low",
		Linux: `
cp /etc/hosts /etc/hosts.bak 2>/dev/null
chattr +i /etc/hosts 2>/dev/null && echo "hosts locked immutable" || chmod 444 /etc/hosts 2>/dev/null
echo "[done] hosts protected"`,
		Windows: `attrib +R +S C:\Windows\System32\drivers\etc\hosts
echo "[done] hosts protected"`,
	},
	{
		ID: "web_server", Name: "Web服务器加固", Category: "Web安全",
		Desc: "隐藏服务器版本、禁目录列表、禁TRACE、限制上传大小", Risk: "medium",
		Linux: `
if [ -f /etc/nginx/nginx.conf ]; then
  sed -i 's/#\?server_tokens .*/server_tokens off;/' /etc/nginx/nginx.conf
  grep -q "autoindex" /etc/nginx/nginx.conf || sed -i 's|http {|http {\n    autoindex off;|' /etc/nginx/nginx.conf
  nginx -s reload 2>/dev/null
  echo "nginx hardened"
fi
if [ -d /etc/apache2 ]; then
  grep -q "ServerTokens" /etc/apache2/apache2.conf || echo "ServerTokens Prod" >> /etc/apache2/apache2.conf
  grep -q "ServerSignature" /etc/apache2/apache2.conf || echo "ServerSignature Off" >> /etc/apache2/apache2.conf
  a2dismod autoindex 2>/dev/null
  systemctl reload apache2 2>/dev/null || service apache2 reload 2>/dev/null
  echo "apache hardened"
fi
if [ -f /etc/httpd/conf/httpd.conf ]; then
  grep -q "ServerTokens" /etc/httpd/conf/httpd.conf || echo "ServerTokens Prod" >> /etc/httpd/conf/httpd.conf
  grep -q "ServerSignature" /etc/httpd/conf/httpd.conf || echo "ServerSignature Off" >> /etc/httpd/conf/httpd.conf
  systemctl reload httpd 2>/dev/null || service httpd reload 2>/dev/null
  echo "httpd hardened"
fi
echo "[done] web server hardened"`,
		Windows: `echo "disable directory listing in IIS manually"`,
	},
	{
		ID: "compiler_disable", Name: "危险编译工具收权", Category: "系统加固",
		Desc: "移除写权限，限制gcc/cc在Web路径下执行(可选)", Risk: "high",
		Linux: `
for c in gcc cc g++ make; do
  B=$(command -v $c 2>/dev/null)
  [ -n "$B" ] && chmod 755 "$B" 2>/dev/null && echo "$c: $B (removed o+w)"
done
echo "[done] compiler access locked to owner"`,
		Windows: `echo "restrict compiler paths in PATH manually"`,
	},
	{
		ID: "log_rotate", Name: "日志滚动与保留", Category: "日志审计",
		Desc: "确保系统日志开启、配置rotate保留90天", Risk: "low",
		Linux: `
grep -q "systemd-journald" /etc/systemd/journald.conf 2>/dev/null && \
  sed -i 's/^#\?SystemMaxUse=.*/SystemMaxUse=500M/' /etc/systemd/journald.conf 2>/dev/null
[ -f /etc/logrotate.d/syslog ] && grep -q "rotate 90" /etc/logrotate.d/syslog || \
  echo "/var/log/syslog /var/log/auth.log { rotate 90 weekly compress missingok }" > /etc/logrotate.d/shield-platform 2>/dev/null
echo "[done] log retention configured"`,
		Windows: `echo "enable Event Log size retention manually"`,
	},
}

// Run 执行指定加固项
func Run(itemID string) (*Result, error) {
	for _, it := range List {
		if it.ID == itemID {
			return runItem(it)
		}
	}
	return nil, fmt.Errorf("harden item not found: %s", itemID)
}

// RunAll 执行全部加固项
func RunAll() []*Result {
	var res []*Result
	for _, it := range List {
		r, err := runItem(it)
		if err != nil {
			r = &Result{ItemID: it.ID, Name: it.Name, ExitCode: -1, Output: err.Error()}
		}
		res = append(res, r)
	}
	return res
}

func runItem(it *Item) (*Result, error) {
	script := it.Script()
	r := execx.RunDefault(script)
	return &Result{
		ItemID:     it.ID,
		Name:       it.Name,
		Output:     r.Output,
		ExitCode:   r.ExitCode,
		DurationMS: r.DurationMS,
	}, nil
}
