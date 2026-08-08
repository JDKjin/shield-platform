package platform

import (
	"fmt"
	"runtime"
)

// Cmd 生成跨平台 shell 命令，自动适配 Windows cmd 与 Linux sh 语法
// linux 用 sh -c，windows 用 cmd /C；差异通过 prefix 与 redirect 控制
type Cmd struct {
	Base     string // 命令主体（不含重定向）
	Linux    string // Linux 发行版差异命令（非空则优先使用）
	Redirect string // 错误重定向，linux: "2>/dev/null"，windows: "2>nul"
}

func (c Cmd) String() string {
	if runtime.GOOS == "windows" {
		return c.Base + " " + c.Redirect
	}
	if c.Linux != "" {
		return c.Linux
	}
	if c.Redirect == "" {
		return c.Base
	}
	return c.Base + " " + c.Redirect
}

// RedirectFor 返回当前平台错误重定向写法
func RedirectFor() string {
	if runtime.GOOS == "windows" {
		return "2>nul"
	}
	return "2>/dev/null"
}

// ListeningCmd 监听端口命令（Linux 优先 ss，回退 netstat；Windows 用 netstat -ano）
func ListeningCmd() string {
	if runtime.GOOS == "windows" {
		return "netstat -ano"
	}
	return "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"
}

// EstablishedCmd 已建立连接命令
func EstablishedCmd() string {
	if runtime.GOOS == "windows" {
		return "netstat -ano"
	}
	return "ss -tnH state established 2>/dev/null || netstat -tan 2>/dev/null"
}

// ProcessCmd 进程列表命令
func ProcessCmd() string {
	if runtime.GOOS == "windows" {
		return "tasklist /fo csv"
	}
	return "ps -eo pid,args 2>/dev/null"
}

// KillProcCmd 终止进程命令（Windows 用 taskkill）
func KillProcCmd(pid string) string {
	if runtime.GOOS == "windows" {
		return "taskkill /F /PID " + pid
	}
	return "kill -9 " + pid
}

// RestartServiceCmd 重启服务（兼容 systemd / upstart / sysv）
func RestartServiceCmd(name string) string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("sc stop %s & sc start %s", name, name)
	}
	return fmt.Sprintf("systemctl restart %s 2>/dev/null || service %s restart 2>/dev/null || /etc/init.d/%s restart 2>/dev/null", name, name, name)
}

// DisableServiceCmd 禁用服务开机自启
func DisableServiceCmd(name string) string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("sc config %s start= disabled", name)
	}
	return fmt.Sprintf("systemctl disable --now %s 2>/dev/null || chkconfig %s off 2>/dev/null || update-rc.d %s disable 2>/dev/null", name, name, name)
}

// FirewallStatusCmd 防火墙状态检测命令（按发行版分支）
func FirewallStatusCmd() string {
	if runtime.GOOS == "windows" {
		return "netsh advfirewall show allprofiles state | findstr ON"
	}
	d := Current()
	if d.Distro == "ubuntu" {
		return "ufw status 2>/dev/null | grep -q 'Status: active' && echo active || echo inactive"
	}
	if d.Distro == "centos" {
		return "systemctl is-active firewalld 2>/dev/null || firewall-cmd --state 2>/dev/null"
	}
	return "systemctl is-active firewalld ufw iptables 2>/dev/null | grep -c active"
}

// PortBlockCmd 封禁端口命令（按发行版/防火墙分支）
func PortBlockCmd(port int) string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("netsh advfirewall firewall add rule name=\"shield_block_%d\" dir=in protocol=TCP localport=%d action=block", port, port)
	}
	d := Current()
	if d.Distro == "ubuntu" {
		return fmt.Sprintf("ufw deny %d/tcp", port)
	}
	if d.Distro == "centos" {
		return fmt.Sprintf("firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=0.0.0.0/0 port protocol=tcp port=%d drop' && firewall-cmd --reload", port)
	}
	return fmt.Sprintf("iptables -I INPUT -p tcp --dport %d -j DROP", port)
}

// IPBlockCmd 封禁 IP 命令
func IPBlockCmd(ip string) string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("netsh advfirewall firewall add rule name=\"shield_ban_%s\" dir=in action=block remoteip=%s", ip, ip)
	}
	d := Current()
	if d.Distro == "ubuntu" {
		return fmt.Sprintf("ufw deny from %s", ip)
	}
	return fmt.Sprintf("iptables -I INPUT -s %s -j DROP", ip)
}
