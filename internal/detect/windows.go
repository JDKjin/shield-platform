//go:build windows

package detect

import (
	"os"
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
	out := execx.RunShort("ver & systeminfo | findstr /C:\"OS Name\" /C:\"System Type\"")
	ver := platform.Current().Version
	detail := strings.TrimSpace(execx.Sanitize(out.Output))
	if ver != "" {
		detail = "Windows " + ver + "\n" + detail
	}
	return []*Finding{f("系统信息", "系统基础信息", detail, "info", "")}
}

func checkProcess() []*Finding {
	out := execx.RunShort("powershell -NoProfile -Command \"Get-Process | Where-Object {$_.Path -like 'C:\\\\Users\\\\*\\\\AppData\\\\*' -or $_.Path -like '*\\\\Temp\\\\*' -or $_.Path -eq $null} | Select-Object Name,Id,Path | Format-List\"")
	var res []*Finding
	for _, l := range nonEmptyLines(out.Output) {
		if strings.Contains(strings.ToLower(l), "name") || strings.Contains(strings.ToLower(l), "path") {
			res = append(res, f("进程异常", "可疑进程", strings.TrimSpace(l), "high", ""))
		}
	}
	if len(res) == 0 {
		res = append(res, f("进程异常", "进程检查通过", "未发现可疑进程特征", "info", ""))
	}
	return res
}

func checkListeners() []*Finding {
	out := execx.RunShort("netstat -ano | findstr LISTENING")
	var res []*Finding
	for _, line := range strings.Split(out.Output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addr := fields[1]
		idx := strings.LastIndex(addr, ":")
		if idx < 0 {
			continue
		}
		port, err := strconv.Atoi(addr[idx+1:])
		if err != nil {
			continue
		}
		if port > 30000 || port == 4444 || port == 5555 || port == 6666 || port == 7777 || port == 8888 || port == 9999 || port == 31337 {
			res = append(res, f("监听端口", "可疑监听端口", strings.TrimSpace(line), "high", ""))
		}
	}
	if len(res) == 0 {
		res = append(res, f("监听端口", "监听检查通过", "未发现异常监听端口", "info", ""))
	}
	return res
}

func checkNetwork() []*Finding {
	out := execx.RunShort("netstat -ano | findstr ESTABLISHED")
	var res []*Finding
	for _, line := range strings.Split(out.Output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		remote := fields[2]
		idx := strings.LastIndex(remote, ":")
		if idx < 0 {
			continue
		}
		port := remote[idx+1:]
		switch port {
		case "4444", "5555", "6666", "7777", "8888", "9999", "31337":
			res = append(res, f("网络后门", "可疑外连连接", strings.TrimSpace(line), "critical", ""))
		}
	}
	if len(res) == 0 {
		res = append(res, f("网络后门", "网络连接检查通过", "未发现可疑外连端口", "info", ""))
	}
	return res
}

func checkUsers() []*Finding {
	out := execx.RunShort("net user")
	var res []*Finding
	users := nonEmptyLines(out.Output)
	if len(users) > 0 {
		res = append(res, f("账号安全", "系统用户列表", strings.Join(users, "; "), "info", strings.Join(users, "; ")))
	}
	return res
}

func checkLogins() []*Finding {
	out := execx.RunShort("powershell -NoProfile -Command \"Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 5 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Message | Format-List\"")
	lines := nonEmptyLines(out.Output)
	if len(lines) > 0 {
		return []*Finding{f("登录审计", "最近登录失败记录", strings.Join(lines, "\n"), "high", strings.Join(lines, "; "))}
	}
	// 回退：net 会话 与 事件日志（老系统或权限不足时）
	out2 := execx.RunShort("net session 2>nul | findstr /i \"computer user\"")
	if len(nonEmptyLines(out2.Output)) > 0 {
		return []*Finding{f("登录审计", "当前会话", strings.Join(nonEmptyLines(out2.Output), "\n"), "info", "")}
	}
	return []*Finding{f("登录审计", "登录检查通过", "未发现明显登录失败记录", "info", "")}
}

func checkPersistence() []*Finding {
	out := execx.RunShort(`reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" & reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" 2>nul & reg query "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" 2>nul`)
	var res []*Finding
	for _, l := range nonEmptyLines(out.Output) {
		if strings.Contains(l, "REG_SZ") {
			res = append(res, f("持久化后门", "注册表Run启动项", strings.TrimSpace(l), "high", ""))
		}
	}
	if len(res) == 0 {
		res = append(res, f("持久化后门", "启动项检查通过", "注册表Run未发现可疑项", "info", ""))
	}
	return res
}

func checkWebshell() []*Finding {
	out := execx.RunShort(`powershell -NoProfile -Command "Get-ChildItem C:\inetpub\wwwroot -Recurse -Include *.asp,*.aspx,*.php,*.jsp -ErrorAction SilentlyContinue | Select-String -Pattern 'eval|execute|base64|cmd' -List | Select-Object Path | Format-Table -HideTableHeaders"`)
	lines := nonEmptyLines(out.Output)
	if len(lines) > 0 {
		var res []*Finding
		for _, l := range lines {
			res = append(res, f("WebShell", "疑似WebShell", l, "critical", ""))
		}
		return res
	}
	return []*Finding{f("WebShell", "WebShell检查通过", "Web目录未发现常见WebShell特征", "info", "")}
}

func checkSUID() []*Finding {
	out := execx.RunShort("where icacls 2>nul & icacls C:\\Windows\\System32\\cmd.exe 2>nul | findstr /i \"Everyone\"")
	if len(nonEmptyLines(out.Output)) > 0 {
		return []*Finding{f("SUID权限", "权限委派检查", "存在 Everyone 权限异常项", "medium", "")}
	}
	return []*Finding{f("SUID权限", "权限检查通过", "未发现权限异常", "info", "")}
}

func checkSSH() []*Finding {
	out := execx.RunShort(`powershell -NoProfile -Command "Get-Service sshd -ErrorAction SilentlyContinue | Select-Object Name,Status | Format-List"`)
	if len(nonEmptyLines(out.Output)) > 0 {
		return []*Finding{f("SSH配置", "SSH服务状态", strings.TrimSpace(out.Output), "info", "")}
	}
	return []*Finding{f("SSH配置", "SSH服务", "未安装/未启用 SSH 服务", "info", "")}
}

func checkFirewall() []*Finding {
	out := execx.RunShort("netsh advfirewall show allprofiles state | findstr ON")
	if len(nonEmptyLines(out.Output)) > 0 {
		return []*Finding{f("防火墙", "防火墙状态", "Windows 防火墙已启用", "info", "")}
	}
	return []*Finding{f("防火墙", "防火墙状态", "Windows 防火墙未启用", "high", "")}
}

func checkFilePerm() []*Finding {
	return []*Finding{f("敏感文件权限", "敏感文件权限", "Windows 平台此项简化，结合 ACL 审计", "info", "")}
}

func checkPasswordPolicy() []*Finding {
	out := execx.RunShort("net accounts")
	if len(nonEmptyLines(out.Output)) > 0 {
		return []*Finding{f("密码策略", "账号策略", strings.TrimSpace(out.Output), "info", "")}
	}
	return []*Finding{f("密码策略", "密码策略", "未获取到账号策略", "info", "")}
}

func checkTmpFiles() []*Finding {
	out := execx.RunShort(`powershell -NoProfile -Command "Get-ChildItem $env:TEMP -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 20 Name,LastWriteTime | Format-Table -HideTableHeaders"`)
	lines := nonEmptyLines(out.Output)
	if len(lines) > 0 {
		return []*Finding{f("异常临时文件", "近期临时文件", strings.Join(lines, "\n"), "low", strings.Join(lines, "; "))}
	}
	return []*Finding{f("异常临时文件", "临时文件检查通过", "无近期临时文件", "info", "")}
}

// 以下为 Windows 专属检测

func checkWinStartup() []*Finding {
	// Win11 已移除 wmic，改用 PowerShell Get-CimInstance（Win7 兼容 Get-WmiObject）
	out := execx.RunShort(`powershell -NoProfile -Command "Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Select-Object Caption,Command | Format-List"`)
	if strings.TrimSpace(out.Output) == "" {
		out = execx.RunShort(`powershell -NoProfile -Command "Get-WmiObject Win32_StartupCommand -ErrorAction SilentlyContinue | Select-Object Caption,Command | Format-List"`)
	}
	lines := nonEmptyLines(out.Output)
	if len(lines) > 0 {
		var res []*Finding
		for _, l := range lines {
			res = append(res, f("启动项", "自启动程序", strings.TrimSpace(l), "info", ""))
		}
		return res
	}
	return []*Finding{f("启动项", "启动项检查通过", "未发现自启动程序", "info", "")}
}

func checkWinTasks() []*Finding {
	out := execx.RunShort("schtasks /query /fo LIST | findstr /i \"TaskName\\|Task To Run\"")
	lines := nonEmptyLines(out.Output)
	if len(lines) > 0 {
		var res []*Finding
		for _, l := range lines {
			res = append(res, f("计划任务", "计划任务项", strings.TrimSpace(l), "info", ""))
		}
		return res
	}
	return []*Finding{f("计划任务", "计划任务检查通过", "未发现计划任务", "info", "")}
}

func checkWinServices() []*Finding {
	// Win7 PS2.0 兼容：优先 Get-CimInstance（Win8+），回退 Get-WmiObject（Win7）
	out := execx.RunShort(`powershell -NoProfile -Command "Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {$_.PathName -like '*Temp*' -or $_.PathName -like '*AppData*'} | Select-Object Name,State,PathName | Format-List"`)
	if strings.TrimSpace(out.Output) == "" {
		out = execx.RunShort(`powershell -NoProfile -Command "Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | Where-Object {$_.PathName -like '*Temp*' -or $_.PathName -like '*AppData*'} | Select-Object Name,State,PathName | Format-List"`)
	}
	lines := nonEmptyLines(out.Output)
	if len(lines) > 0 {
		return []*Finding{f("可疑服务", "可疑服务", strings.Join(lines, "\n"), "high", strings.Join(lines, "; "))}
	}
	return []*Finding{f("可疑服务", "服务检查通过", "未发现可疑服务", "info", "")}
}

func checkWinAdmins() []*Finding {
	out := execx.RunShort("net localgroup administrators")
	lines := nonEmptyLines(out.Output)
	if len(lines) > 0 {
		return []*Finding{f("管理员组", "管理员组成员", strings.Join(lines, "\n"), "info", strings.Join(lines, "; "))}
	}
	return []*Finding{f("管理员组", "管理员组检查", "未获取到管理员组成员", "info", "")}
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
