package defense

import (
	"regexp"
	"runtime"
	"strings"

	"shield-platform/internal/execx"
)

// BlockIP 防火墙封禁一个 IP，成功返回 true（先做合法性校验防注入）
func BlockIP(ip string) bool {
	ip = strings.TrimSpace(ip)
	if !validIP(ip) {
		return false
	}
	switch runtime.GOOS {
	case "windows":
		return winBlock(ip)
	default:
		return linuxBlock(ip)
	}
}

// UnblockIP 解封 IP
func UnblockIP(ip string) bool {
	ip = strings.TrimSpace(ip)
	if !validIP(ip) {
		return false
	}
	switch runtime.GOOS {
	case "windows":
		name := "shield_ban_" + strings.ReplaceAll(strings.ReplaceAll(ip, ".", "_"), ":", "_")
		r := execx.RunShort(`netsh advfirewall firewall delete rule name=` + name)
		return r.ExitCode == 0
	default:
		r := execx.RunShort("iptables -D INPUT -s " + ip + " -j DROP")
		if r.ExitCode == 0 {
			return true
		}
		rule := `rule source address="` + ip + `" reject`
		r2 := execx.RunShort(`firewall-cmd --permanent --remove-rich-rule=` + rule)
		if r2.ExitCode == 0 {
			execx.RunShort("firewall-cmd --reload")
			return true
		}
		return false
	}
}

func linuxBlock(ip string) bool {
	r := execx.RunShort("iptables -I INPUT -s " + ip + " -j DROP")
	if r.ExitCode == 0 {
		return true
	}
	rule := `rule source address="` + ip + `" reject`
	r2 := execx.RunShort(`firewall-cmd --permanent --add-rich-rule=` + rule)
	if r2.ExitCode == 0 {
		execx.RunShort("firewall-cmd --reload")
		return true
	}
	return false
}

func winBlock(ip string) bool {
	name := "shield_ban_" + strings.ReplaceAll(strings.ReplaceAll(ip, ".", "_"), ":", "_")
	r := execx.RunShort(`netsh advfirewall firewall add rule name=` + name +
		` dir=in action=block remoteip=` + ip)
	return r.ExitCode == 0
}

// validIP 校验 IPv4/IPv6 合法性，防止防火墙命令注入
func validIP(ip string) bool {
	if ip == "" {
		return false
	}
	if m, _ := regexp.MatchString(`^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$`, ip); m {
		for _, g := range regexp.MustCompile(`\d+`).FindAllString(ip, -1) {
			if len(g) > 1 && g[0] == '0' {
				continue
			}
			n := 0
			for _, c := range g {
				n = n*10 + int(c-'0')
			}
			if n > 255 {
				return false
			}
		}
		return true
	}
	if strings.Contains(ip, ":") {
		if m, _ := regexp.MatchString(`^[0-9a-fA-F:.]+$`, ip); m {
			return true
		}
	}
	return false
}
