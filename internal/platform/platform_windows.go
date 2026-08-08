//go:build windows

package platform

import (
	"regexp"
	"strings"
	"sync"

	"shield-platform/internal/execx"
)

var (
	once   sync.Once
	cached Info
)

// detect Windows 版本识别
func detect() Info {
	once.Do(func() {
		cached = Info{OS: "windows", Distro: "windows", Version: "", Init: "unknown"}
		cached.Version = windowsVersion()
	})
	return cached
}

// windowsVersion 返回如 "7"/"8.1"/"10"/"11"（优先注册表，回退 ver 命令）
func windowsVersion() string {
	if v := regProduct(); v != "" {
		return v
	}
	return verFallback()
}

// regProduct 通过注册表读取精确产品名（Win7~Win11 均支持 reg query）
func regProduct() string {
	r := execx.RunShort(`reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName`)
	for _, line := range strings.Split(r.Output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "ProductName") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			// 例如 Windows 10 Pro / Windows 11 家庭中文版
			name := strings.Join(fields[2:], " ")
			low := strings.ToLower(name)
			switch {
			case strings.Contains(low, "windows 11"):
				return "11"
			case strings.Contains(low, "windows 10"):
				return "10"
			case strings.Contains(low, "windows 8.1"):
				return "8.1"
			case strings.Contains(low, "windows 8"):
				return "8"
			case strings.Contains(low, "windows 7"):
				return "7"
			}
			return name
		}
	}
	return ""
}

// verFallback 回退 ver 命令（中文系统输出 [版本 X]）
func verFallback() string {
	r := execx.RunShort("cmd /c ver")
	out := strings.ToLower(r.Output)
	re := regexp.MustCompile(`(\d+\.\d+)[\.\s]`)
	if m := re.FindStringSubmatch(out); len(m) == 2 {
		switch m[1] {
		case "6.1":
			return "7"
		case "6.2":
			return "8"
		case "6.3":
			return "8.1"
		case "10.0":
			return "10"
		}
	}
	return strings.TrimSpace(r.Output)
}
