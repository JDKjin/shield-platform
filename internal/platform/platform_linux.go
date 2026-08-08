//go:build !windows

package platform

import (
	"os"
	"os/exec"
	"strings"
	"sync"
)

var (
	once   sync.Once
	cached Info
)

// detect Linux 发行版与 init 系统识别
func detect() Info {
	once.Do(func() {
		cached = Info{OS: "linux", Distro: "unknown", Version: "", Init: "unknown"}
		cached.Distro, cached.Version = readRelease()
		cached.Init = detectInit()
	})
	return cached
}

// readRelease 读取 /etc/os-release 与发行版回退文件
func readRelease() (distro, version string) {
	// 优先 /etc/os-release（CentOS7+/Ubuntu14.04+ 均存在）
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		content := string(b)
		id := field(content, "ID=")
		idLike := field(content, "ID_LIKE=")
		versionID := field(content, "VERSION_ID=")
		switch id {
		case "centos", "rhel":
			return "centos", normVersion(versionID)
		case "ubuntu":
			return "ubuntu", versionID
		case "debian":
			return "debian", versionID
		}
		if strings.Contains(idLike, "rhel") || strings.Contains(idLike, "fedora") {
			return "centos", normVersion(versionID)
		}
		if strings.Contains(idLike, "debian") {
			return "debian", versionID
		}
		return id, versionID
	}
	// 回退：老 CentOS / Ubuntu 12
	if b, err := os.ReadFile("/etc/redhat-release"); err == nil {
		content := string(b)
		if strings.Contains(content, "CentOS") {
			return "centos", regexpDigits(content)
		}
		return "redhat", regexpDigits(content)
	}
	if b, err := os.ReadFile("/etc/lsb-release"); err == nil {
		content := string(b)
		if strings.Contains(content, "Ubuntu") {
			return "ubuntu", field(content, "DISTRIB_RELEASE=")
		}
	}
	if b, err := os.ReadFile("/etc/debian_version"); err == nil {
		return "debian", strings.TrimSpace(string(b))
	}
	return "unknown", ""
}

func field(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key) {
			v := strings.Trim(strings.TrimPrefix(line, key), `"'`)
			return v
		}
	}
	return ""
}

func normVersion(v string) string {
	if v == "" {
		return v
	}
	// "7.9" -> "7"（取主版本）
	if i := strings.IndexByte(v, '.'); i > 0 {
		return v[:i]
	}
	return v
}

func regexpDigits(s string) string {
	var b strings.Builder
	started := false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
			started = true
		} else if started {
			break
		}
	}
	return b.String()
}

// detectInit 判断 init 系统：systemd / upstart / sysv
func detectInit() string {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return "systemd"
	}
	// 容器/精简环境可能无 /run/systemd/system，但 systemctl 存在即为 systemd
	if _, err := exec.LookPath("systemctl"); err == nil {
		return "systemd"
	}
	if _, err := os.Stat("/sbin/upstart"); err == nil {
		return "upstart"
	}
	if _, err := os.Stat("/sbin/init"); err == nil {
		return "sysv"
	}
	return "unknown"
}
