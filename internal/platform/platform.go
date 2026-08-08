// Package platform 提供跨发行版/跨平台的系统识别与命令适配
package platform

import "runtime"

// Info 运行环境识别结果
type Info struct {
	OS      string // "linux" | "windows"
	Distro  string // "centos" | "ubuntu" | "debian" | "redhat" | "unknown"
	Version string // 主版本号，如 "7" / "20.04" / "11"
	Init    string // "systemd" | "upstart" | "sysv" | "unknown"
}

// Current 返回当前平台识别结果（带缓存）
func Current() Info {
	return detect()
}

// IsLinux 是否 Linux
func IsLinux() bool { return runtime.GOOS == "linux" }

// IsWindows 是否 Windows
func IsWindows() bool { return runtime.GOOS == "windows" }

// IsSystemd 是否 systemd init
func IsSystemd() bool { return Current().Init == "systemd" }

// IsRHELFamily 是否 RHEL 系（CentOS/RedHat）
func IsRHELFamily() bool {
	d := Current().Distro
	return d == "centos" || d == "redhat"
}

// IsDebianFamily 是否 Debian 系（Ubuntu/Debian）
func IsDebianFamily() bool {
	d := Current().Distro
	return d == "ubuntu" || d == "debian"
}
