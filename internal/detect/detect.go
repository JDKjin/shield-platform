package detect

import (
	"runtime"
	"sort"
	"time"
)

// Finding 单条检测发现
type Finding struct {
	Category string `json:"category"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"` // critical|high|medium|low|info
	Raw      string `json:"raw,omitempty"`
}

// Report 一次检测报告
type Report struct {
	OS        string     `json:"os"`
	Host      string     `json:"host"`
	Timestamp int64      `json:"timestamp"`
	DurationMS int64     `json:"duration_ms"`
	Findings  []*Finding `json:"findings"`
}

// Check 检测项
type Check struct {
	ID   string
	Name string
	Run  func() []*Finding
}

var (
	checksMu    = make(chan struct{}, 1) // 防止并发修改
	allChecks   []*Check
)

func init() {
	allChecks = buildChecks()
}

func buildChecks() []*Check {
	list := []*Check{
		{ID: "sysinfo", Name: "系统信息", Run: checkSysInfo},
		{ID: "process", Name: "进程异常", Run: checkProcess},
		{ID: "listeners", Name: "监听端口", Run: checkListeners},
		{ID: "network", Name: "网络后门", Run: checkNetwork},
		{ID: "users", Name: "账号安全", Run: checkUsers},
		{ID: "logins", Name: "登录审计", Run: checkLogins},
		{ID: "persistence", Name: "持久化后门", Run: checkPersistence},
		{ID: "webshell", Name: "WebShell", Run: checkWebshell},
		{ID: "suid", Name: "SUID权限", Run: checkSUID},
		{ID: "ssh", Name: "SSH配置", Run: checkSSH},
		{ID: "firewall", Name: "防火墙", Run: checkFirewall},
		{ID: "fileperm", Name: "敏感文件权限", Run: checkFilePerm},
		{ID: "passwd_policy", Name: "密码策略", Run: checkPasswordPolicy},
		{ID: "tmp", Name: "异常临时文件", Run: checkTmpFiles},
	}
	if runtime.GOOS == "windows" {
		list = append(list,
			&Check{ID: "win_startup", Name: "启动项", Run: checkWinStartup},
			&Check{ID: "win_tasks", Name: "计划任务", Run: checkWinTasks},
			&Check{ID: "win_services", Name: "可疑服务", Run: checkWinServices},
			&Check{ID: "win_admins", Name: "管理员组", Run: checkWinAdmins},
		)
	}
	return list
}

// Checks 获取全部检测项定义
func Checks() []*Check {
	return allChecks
}

// RunAll 执行全部检测
func RunAll() *Report {
	start := time.Now()
	rep := &Report{
		OS:        runtime.GOOS,
		Host:      hostname(),
		Timestamp: time.Now().Unix(),
	}
	for _, c := range allChecks {
		rep.Findings = append(rep.Findings, c.Run()...)
	}
	rep.DurationMS = time.Since(start).Milliseconds()
	// 按严重程度排序
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		return sevRank(rep.Findings[i].Severity) < sevRank(rep.Findings[j].Severity)
	})
	return rep
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}
