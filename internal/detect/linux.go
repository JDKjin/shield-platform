//go:build !windows

package detect

import (
	"os"
	"regexp"
	"strconv"
	"strings"

	"shield-platform/internal/execx"
	"shield-platform/internal/platform"
)

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func f(category, title, detail, severity, raw string) *Finding {
	return &Finding{Category: category, Title: title, Detail: detail, Severity: severity, Raw: raw}
}

func checkSysInfo() []*Finding {
	uname := execx.RunShort("uname -a; cat /etc/os-release 2>/dev/null | head -5; lsb_release -a 2>/dev/null | head -4; uptime")
	return []*Finding{f("系统信息", "系统基础信息", strings.TrimSpace(execx.Sanitize(uname.Output)), "info", "")}
}

func checkProcess() []*Finding {
	out := execx.RunShort("ps -eo pid,user,%cpu,%mem,args --sort=-%cpu | head -40")
	var res []*Finding
	for _, line := range strings.Split(out.Output, "\n") {
		low := strings.ToLower(line)
		if strings.Contains(low, "(deleted)") ||
			strings.Contains(low, "bash -i") ||
			strings.Contains(low, "/dev/tcp") ||
			strings.Contains(low, "/dev/udp") ||
			strings.Contains(line, "/tmp/") ||
			strings.Contains(line, "/dev/shm/") ||
			strings.Contains(line, "/var/tmp/") {
			res = append(res, f("进程异常", "可疑进程", strings.TrimSpace(line), "critical", ""))
		}
	}
	if len(res) == 0 {
		res = append(res, f("进程异常", "进程检查通过", "未发现可疑进程特征", "info", ""))
	}
	return res
}

func checkListeners() []*Finding {
	out := execx.RunShort("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || netstat -tln 2>/dev/null")
	var res []*Finding
	for _, line := range strings.Split(out.Output, "\n") {
		if !strings.Contains(line, "LISTEN") {
			continue
		}
		// 提取端口
		port := extractPort(line)
		if port > 0 && (port > 30000 || port == 4444 || port == 5555 || port == 6666 || port == 8888 || port == 1234 || port == 31337 || port == 7777 || port == 9999) {
			res = append(res, f("监听端口", "可疑监听端口", strings.TrimSpace(line), "high", ""))
		}
	}
	if len(res) == 0 {
		res = append(res, f("监听端口", "监听检查通过", "未发现异常监听端口", "info", ""))
	}
	return res
}

var portRe = regexp.MustCompile(`[:\s](\d{2,5})\s`)

func extractPort(line string) int {
	m := portRe.FindStringSubmatch(line)
	if m == nil {
		return 0
	}
	p, _ := strconv.Atoi(m[1])
	return p
}

func checkNetwork() []*Finding {
	out := execx.RunShort("ss -tnp state established 2>/dev/null || netstat -tnp 2>/dev/null")
	var res []*Finding
	for _, line := range strings.Split(out.Output, "\n") {
		low := strings.ToLower(line)
		for _, port := range []string{"4444", "5555", "6666", "7777", "8888", "9999", "31337"} {
			if strings.Contains(low, ":"+port) {
				res = append(res, f("网络后门", "可疑外连/回连连接", strings.TrimSpace(line), "critical", ""))
				break
			}
		}
	}
	if len(res) == 0 {
		res = append(res, f("网络后门", "网络连接检查通过", "未发现可疑外连端口", "info", ""))
	}
	return res
}

func checkUsers() []*Finding {
	var res []*Finding
	// UID 0 用户
	out := execx.RunShort(`awk -F: '$3==0{print $1" (uid=0)"}' /etc/passwd`)
	rootUsers := nonEmptyLines(out.Output)
	for _, u := range rootUsers {
		if u != "root" {
			res = append(res, f("账号安全", "非root的UID=0用户", u, "critical", ""))
		}
	}
	// 空密码
	shadow := execx.RunShort(`sudo cat /etc/shadow 2>/dev/null | awk -F: '$2==""{print $1}'`)
	for _, u := range nonEmptyLines(shadow.Output) {
		res = append(res, f("账号安全", "空密码用户", u, "critical", ""))
	}
	// 有shell无home
	noHome := execx.RunShort(`awk -F: '$NF ~ /(bash|sh|zsh)$/ && $6!="/root"{print $1" "$6}' /etc/passwd`)
	for _, u := range nonEmptyLines(noHome.Output) {
		res = append(res, f("账号安全", "有Shell用户(需人工确认)", u, "low", ""))
	}
	// 最近新增用户
	newUsers := execx.RunShort(`awk -F: '$3>=1000 && $3<60000{print $1" uid="$3}' /etc/passwd`)
	if len(nonEmptyLines(newUsers.Output)) > 0 {
		res = append(res, f("账号安全", "UID>=1000的普通用户", strings.Join(nonEmptyLines(newUsers.Output), "; "), "info", ""))
	}
	if len(res) == 0 {
		res = append(res, f("账号安全", "账号检查通过", "未发现高危账号问题", "info", ""))
	}
	return res
}

func checkLogins() []*Finding {
	var res []*Finding
	bf := execx.RunShort(`grep -i "failed password" /var/log/auth.log /var/log/secure 2>/dev/null | tail -5`)
	for _, l := range nonEmptyLines(bf.Output) {
		res = append(res, f("登录审计", "SSH爆破尝试", strings.TrimSpace(l), "high", ""))
	}
	who := execx.RunShort("who -a 2>/dev/null || w")
	for _, l := range nonEmptyLines(who.Output) {
		res = append(res, f("登录审计", "当前登录用户", strings.TrimSpace(l), "info", ""))
	}
	last := execx.RunShort("last -10 2>/dev/null | grep -v 'wtmp begins'")
	for _, l := range nonEmptyLines(last.Output) {
		res = append(res, f("登录审计", "最近登录记录", strings.TrimSpace(l), "info", ""))
	}
	if len(res) == 0 {
		res = append(res, f("登录审计", "登录检查通过", "未发现异常登录", "info", ""))
	}
	return res
}

func checkPersistence() []*Finding {
	var res []*Finding
	cron := execx.RunShort(`(crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null; ls /etc/cron.d 2>/dev/null | while read f; do cat /etc/cron.d/$f 2>/dev/null; done) | grep -vE '^#|^$' | grep -E 'curl|wget|nc |bash -|python|perl|/dev/tcp|/dev/udp|/tmp/'`)
	for _, l := range nonEmptyLines(cron.Output) {
		res = append(res, f("持久化后门", "可疑计划任务", strings.TrimSpace(l), "critical", ""))
	}
	bashrc := execx.RunShort(`grep -rnE 'curl|wget|nc |socat|bash -i|/dev/tcp|/dev/udp|base64' /root/.bashrc /root/.bash_profile /root/.profile /home/*/.bashrc /home/*/.profile 2>/dev/null`)
	for _, l := range nonEmptyLines(bashrc.Output) {
		res = append(res, f("持久化后门", "Shell配置篡改", strings.TrimSpace(l), "critical", ""))
	}
	systemd := execx.RunShort(`grep -rnE 'ExecStart.*(curl|wget|nc|bash|python|perl|/tmp/|/dev/shm/)' /etc/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null`)
	for _, l := range nonEmptyLines(systemd.Output) {
		res = append(res, f("持久化后门", "systemd后门单元", strings.TrimSpace(l), "high", ""))
	}
	rclocal := execx.RunShort(`cat /etc/rc.local /etc/rc.d/rc.local 2>/dev/null | grep -vE '^#|^$|exit 0'`)
	for _, l := range nonEmptyLines(rclocal.Output) {
		res = append(res, f("持久化后门", "rc.local启动项", strings.TrimSpace(l), "high", ""))
	}
	ld := execx.RunShort(`cat /etc/ld.so.preload 2>/dev/null`)
	for _, l := range nonEmptyLines(ld.Output) {
		res = append(res, f("持久化后门", "LD_PRELOAD劫持", strings.TrimSpace(l), "critical", ""))
	}
	if len(res) == 0 {
		res = append(res, f("持久化后门", "持久化检查通过", "未发现可疑持久化机制", "info", ""))
	}
	return res
}

func checkWebshell() []*Finding {
	dirs := []string{"/var/www", "/usr/share/nginx/html", "/opt/lampp/htdocs", "/srv/www", "/var/www/html"}
	for _, d := range dirs {
		if _, err := os.Stat(d); err != nil {
			continue
		}
		out := execx.RunShort(`find ` + d + ` -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.asp" -o -name "*.aspx" -o -name "*.cgi" \) -exec grep -lE 'eval\s*\(|base64_decode|system\s*\(|passthru|shell_exec|assert\s*\(|\$_POST\[|gzinflate|str_rot13|create_function|preg_replace.*\/e' {} \; 2>/dev/null`)
		lines := nonEmptyLines(out.Output)
		if len(lines) > 0 {
			var res []*Finding
			for _, l := range lines {
				res = append(res, f("WebShell", "疑似WebShell", l, "critical", ""))
			}
			return res
		}
	}
	return []*Finding{f("WebShell", "WebShell检查通过", "Web目录未发现常见WebShell特征", "info", "")}
}

func checkSUID() []*Finding {
	out := execx.RunShort("find / -perm -4000 -type f 2>/dev/null | head -50")
	lines := nonEmptyLines(out.Output)
	if len(lines) > 0 {
		return []*Finding{f("SUID权限", "SUID文件清单", strings.Join(lines, "\n"), "low", strings.Join(lines, "; "))}
	}
	return []*Finding{f("SUID权限", "SUID检查通过", "未发现SUID文件", "info", "")}
}

func checkSSH() []*Finding {
	out := execx.RunShort("cat /etc/ssh/sshd_config 2>/dev/null | grep -vE '^#|^$'")
	cfg := strings.ToLower(out.Output)
	var res []*Finding
	if strings.Contains(cfg, "permitrootlogin yes") {
		res = append(res, f("SSH配置", "允许Root远程登录", "PermitRootLogin yes，存在风险", "medium", ""))
	}
	if strings.Contains(cfg, "passwordauthentication yes") || !strings.Contains(cfg, "passwordauthentication no") {
		res = append(res, f("SSH配置", "允许密码登录", "PasswordAuthentication 未禁用，易被爆破", "medium", ""))
	}
	if len(res) == 0 {
		res = append(res, f("SSH配置", "SSH检查通过", "SSH配置未发现明显风险", "info", ""))
	}
	return res
}

func checkFirewall() []*Finding {
	// 按发行版分支：CentOS 用 firewalld/iptables，Ubuntu 用 ufw，老系统用 service 检测
	out := execx.RunShort(platform.FirewallStatusCmd())
	o := strings.ToLower(out.Output)
	active := strings.Contains(o, "active") || strings.Contains(o, "running") || strings.Contains(o, "grep -c active") && strings.Contains(o, "1")
	if strings.Contains(o, "inactive") {
		active = false
	}
	if active {
		return []*Finding{f("防火墙", "防火墙状态", "防火墙已启用", "info", "")}
	}
	return []*Finding{f("防火墙", "防火墙状态", "防火墙未启用，建议立即加固", "high", "")}
}

func checkFilePerm() []*Finding {
	out := execx.RunShort(`ls -l /etc/shadow /etc/sudoers /etc/passwd 2>/dev/null`)
	var res []*Finding
	for _, l := range nonEmptyLines(out.Output) {
		if strings.Contains(l, "shadow") && !strings.HasPrefix(l, "-r--------") && !strings.HasPrefix(l, "-rw-------") {
			res = append(res, f("敏感文件权限", "/etc/shadow权限异常", l, "critical", ""))
		}
		if strings.Contains(l, "sudoers") && !strings.HasPrefix(l, "-r--r-----") {
			res = append(res, f("敏感文件权限", "/etc/sudoers权限异常", l, "high", ""))
		}
	}
	if len(res) == 0 {
		res = append(res, f("敏感文件权限", "敏感文件权限检查通过", "shadow/sudoers 权限正常", "info", ""))
	}
	return res
}

func checkPasswordPolicy() []*Finding {
	out := execx.RunShort(`grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE' /etc/login.defs 2>/dev/null`)
	if len(nonEmptyLines(out.Output)) == 0 {
		return []*Finding{f("密码策略", "未配置密码策略", "未在 /etc/login.defs 配置密码过期策略", "medium", "")}
	}
	return []*Finding{f("密码策略", "密码策略", strings.TrimSpace(out.Output), "info", "")}
}

func checkTmpFiles() []*Finding {
	out := execx.RunShort(`find /tmp /var/tmp /dev/shm -maxdepth 2 -type f -mmin -60 2>/dev/null | head -30`)
	lines := nonEmptyLines(out.Output)
	if len(lines) > 0 {
		return []*Finding{f("异常临时文件", "近期异常临时文件", strings.Join(lines, "\n"), "medium", strings.Join(lines, "; "))}
	}
	return []*Finding{f("异常临时文件", "临时文件检查通过", "近一小时无异常临时文件", "info", "")}
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func checkWinStartup() []*Finding {
	return []*Finding{f("启动项", "启动项", "非 Windows 平台跳过", "info", "")}
}

func checkWinTasks() []*Finding {
	return []*Finding{f("计划任务", "计划任务", "非 Windows 平台跳过", "info", "")}
}

func checkWinServices() []*Finding {
	return []*Finding{f("可疑服务", "可疑服务", "非 Windows 平台跳过", "info", "")}
}

func checkWinAdmins() []*Finding {
	return []*Finding{f("管理员组", "管理员组", "非 Windows 平台跳过", "info", "")}
}
