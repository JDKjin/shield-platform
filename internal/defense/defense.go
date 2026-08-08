package defense

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"shield-platform/internal/execx"
)

// Finding 防御监控发现
type Finding struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Detail   string `json:"detail,omitempty"`
	Time     int64  `json:"time"`
}

// Config 防御守护配置
type Config struct {
	WatchPaths       []string `json:"watch_paths"`
	QuarantineDir    string   `json:"quarantine_dir"`
	BackupDir        string   `json:"backup_dir"`
	MonitorInterval  int      `json:"monitor_interval"`  // 秒
	BackdoorSigs     []string `json:"backdoor_sigs"`     // 后门特征正则
	ConnWhitelist    []string `json:"conn_whitelist"`    // 出站连接白名单
	BruteThreshold   int      `json:"brute_threshold"`   // SSH 爆破阈值 次/5min
	WebExt           []string `json:"web_ext"`           // 新增可疑扩展名
}

// DefaultConfig 默认防御配置
func DefaultConfig() *Config {
	return &Config{
		WatchPaths:      []string{"/var/www/html"},
		QuarantineDir:   "logs/quarantine",
		BackupDir:       "logs/web_backup",
		MonitorInterval: 5,
		BackdoorSigs: []string{
			`(?i)(eval\s*\(\s*\$|assert\s*\(\s*\$|system\s*\(\s*\$|passthru\s*\(\s*\$|shell_exec\s*\(\s*)`,
			`(?i)(base64_decode\s*\(\s*['"]|gzinflate\s*\(\s*base64_decode|str_rot13\s*\(\s*['"]|pack\s*\(\s*['"]H\*)`,
			`(?i)(/dev/tcp/|bash\s+-i|nc\s+-[e]|ncat\s+-[e]|mknod\s+/tmp|chmod\s+4755)`,
			`(?i)(@\s*eval|@\s*assert|call_user_func\s*\(\s*['"]|preg_replace\s*\(\s*['"]/.*?/e)`,
			`(?i)(create_function\s*\(|array_map\s*\(\s*['"]|assert\s*\(\s*['"]\w+\s*=\s*\$)`,
			`(?i)(file_put_contents\s*\(\s*['"]\S*?\.(php|phtml|php5))`,
		},
		ConnWhitelist:  []string{},
		BruteThreshold: 10,
		WebExt:         []string{".php", ".php3", ".php4", ".php5", ".phtml", ".pht", ".jsp", ".jspx", ".war", ".asp", ".aspx", ".py", ".pl", ".sh", ".cgi"},
	}
}

// Monitor 防御守护实例
type Monitor struct {
	cfg    *Config
	mu     sync.Mutex
	log    func(f *Finding)
	// 文件快照
	snapshot map[string]string
	// 基线
	portBaseline   []int
	connReported   map[string]bool
	accountBase    string
	bruteReported  map[string]bool
	weakpassDone   map[string]bool
	backdoorRE     []*regexp.Regexp
}

// NewMonitor 创建监控实例
func NewMonitor(cfg *Config) *Monitor {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	m := &Monitor{
		cfg:           cfg,
		snapshot:      make(map[string]string),
		connReported:  make(map[string]bool),
		bruteReported: make(map[string]bool),
		weakpassDone:  make(map[string]bool),
	}
	m.compileSigs()
	return m
}

// SetLogger 注入发现回调
func (m *Monitor) SetLogger(fn func(f *Finding)) {
	m.log = fn
}

func (m *Monitor) emit(category, severity, message string) {
	if m.log == nil {
		return
	}
	m.log(&Finding{Category: category, Severity: severity, Message: message, Time: time.Now().Unix()})
}

func (m *Monitor) compileSigs() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.backdoorRE = m.backdoorRE[:0]
	for _, s := range m.cfg.BackdoorSigs {
		if re, err := regexp.Compile(s); err == nil {
			m.backdoorRE = append(m.backdoorRE, re)
		}
	}
}

// RescanBackdoor 重新编译特征并立即扫描文件监控（供加固复用）
func (m *Monitor) RescanBackdoor() {
	m.compileSigs()
	m.buildSnapshot()
	m.MonitorFiles()
}

// BuildSnapshot 建立文件哈希快照
func (m *Monitor) buildSnapshot() {
	m.mu.Lock()
	m.snapshot = make(map[string]string)
	m.mu.Unlock()
	for _, base := range m.cfg.WatchPaths {
		filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			m.snapshot[path] = sha256File(path)
			return nil
		})
	}
}

// EnsureSnapshot 快照为空时建立（防御没跑过的场景）
func (m *Monitor) EnsureSnapshot() {
	m.mu.Lock()
	empty := len(m.snapshot) == 0
	m.mu.Unlock()
	if empty {
		m.buildSnapshot()
	}
}

func sha256File(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 64*1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// scanBackdoor 检查文件前 200KB 是否命中后门特征，返回命中的 pattern
func (m *Monitor) scanBackdoor(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 200*1024)
	n, _ := f.Read(buf)
	text := strings.ToLower(string(buf[:n]))
	m.mu.Lock()
	res := m.backdoorRE
	m.mu.Unlock()
	for _, re := range res {
		if re.MatchString(text) {
			return re.String()
		}
	}
	return ""
}

// quarantine 隔离文件（移动而非删除，可恢复）
func (m *Monitor) quarantine(path, reason string) {
	qdir := m.cfg.QuarantineDir
	if qdir == "" {
		qdir = "logs/quarantine"
	}
	_ = os.MkdirAll(qdir, 0o755)
	ts := time.Now().Format("20060102-150405")
	dest := filepath.Join(qdir, ts+"_"+filepath.Base(path)+".quarantine")
	if err := os.Rename(path, dest); err != nil {
		m.emit("quarantine_failed", "error", "隔离失败 "+path+": "+err.Error())
		return
	}
	m.emit("backdoor_quarantined", "critical", "隔离后门文件 "+path+" 原因:"+reason+" -> "+dest)
}

// MonitorFiles 文件监控：新增/篡改检测 + 后门隔离
func (m *Monitor) MonitorFiles() {
	for _, base := range m.cfg.WatchPaths {
		filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			cur := sha256File(path)
			if cur == "" {
				return nil
			}
			m.mu.Lock()
			prev, exists := m.snapshot[path]
			m.mu.Unlock()
			ext := strings.ToLower(filepath.Ext(path))
			isWeb := containsStr(m.cfg.WebExt, ext)
			if !exists {
				sig := m.scanBackdoor(path)
				reason := "新增可疑文件"
				if sig != "" {
					reason += " 命中:" + sig
				}
				if sig != "" || isWeb {
					m.quarantine(path, reason)
				}
				m.mu.Lock()
				m.snapshot[path] = cur
				m.mu.Unlock()
			} else if prev != cur {
				sig := m.scanBackdoor(path)
				if sig != "" {
					m.quarantine(path, "文件被篡改 命中后门特征:"+sig)
				}
				m.mu.Lock()
				m.snapshot[path] = cur
				m.mu.Unlock()
			}
			return nil
		})
	}
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// SuspiciousProc 可疑进程特征
var SuspiciousProc = []string{
	"nc -", "ncat", "netcat", "metasploit", "meterpreter", "cobaltstrike",
	"mimikatz", "xmrig", "minerd", "bash -i", "/dev/tcp/",
	"python -c", "perl -e", "powershell -enc", "powershell -e ",
}

// MonitorProcs 进程监控
func (m *Monitor) MonitorProcs() {
	var out string
	if runtime.GOOS == "windows" {
		r := execx.RunShort("tasklist /fo csv 2>nul")
		out = r.Output
	} else {
		r := execx.RunShort("ps -eo pid,args 2>/dev/null")
		out = r.Output
	}
	low := strings.ToLower(out)
	for _, sig := range SuspiciousProc {
		s := strings.ToLower(sig)
		if i := strings.Index(low, s); i >= 0 {
			line := lineAt(out, i)
			m.emit("suspicious_proc", "warning", "可疑进程: "+strings.TrimSpace(line))
		}
	}
}

func lineAt(s string, idx int) string {
	start := strings.LastIndex(s[:idx], "\n") + 1
	end := strings.Index(s[idx:], "\n")
	if end < 0 {
		end = len(s) - idx
	}
	return s[start : idx+end]
}

// MonitorPorts 监听端口基线对比
func (m *Monitor) MonitorPorts() {
	ports := m.listeningPorts()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.portBaseline == nil {
		m.portBaseline = ports
		return
	}
	var news []int
	for _, p := range ports {
		if !containsInt(m.portBaseline, p) {
			news = append(news, p)
		}
	}
	if len(news) > 0 {
		var ss []string
		for _, p := range news {
			ss = append(ss, strconv.Itoa(p))
		}
		m.mu.Unlock()
		m.emit("new_port", "warning", "新增监听端口: "+strings.Join(ss, ","))
		m.mu.Lock()
	}
	m.portBaseline = ports
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// listeningPorts 监听端口（Linux 优先 ss 回退 netstat；Windows 用 netstat -ano）
func (m *Monitor) listeningPorts() []int {
	var r *execx.Result
	if runtime.GOOS == "windows" {
		r = execx.RunShort("netstat -ano | findstr LISTENING")
	} else {
		r = execx.RunShort("ss -tln 2>/dev/null || netstat -tln 2>/dev/null")
	}
	re := regexp.MustCompile(`:(\d+)\s`)
	var ports []int
	seen := map[int]bool{}
	for _, line := range strings.Split(r.Output, "\n") {
		m := re.FindStringSubmatch(line)
		if len(m) == 2 {
			if n, err := strconv.Atoi(m[1]); err == nil && n > 0 && !seen[n] {
				seen[n] = true
				ports = append(ports, n)
			}
		}
	}
	sort.Ints(ports)
	return ports
}

// MonitorConns 出站连接监控（非白名单、非本地网段、去重告警）
func (m *Monitor) MonitorConns() {
	var r *execx.Result
	if runtime.GOOS == "windows" {
		r = execx.RunShort("netstat -ano | findstr ESTABLISHED")
	} else {
		// 优先 ss(-H 无表头)，回退 netstat
		r = execx.RunShort("ss -tnH state established 2>/dev/null")
		if strings.TrimSpace(r.Output) == "" {
			r = execx.RunShort("netstat -tan 2>/dev/null")
		}
	}
	wl := m.cfg.ConnWhitelist
	for _, line := range strings.Split(r.Output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "State") || strings.HasPrefix(line, "Netid") ||
			strings.HasPrefix(line, "Proto") || strings.Contains(line, "Address:Port") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		var remote string
		if strings.EqualFold(parts[0], "tcp") {
			// netstat: tcp ... local foreign State，remote 为倒数第二列
			remote = parts[len(parts)-2]
		} else {
			// ss: Recv-Q Send-Q Local Peer，remote 为最后一列
			remote = parts[len(parts)-1]
		}
		rip := remoteHost(remote)
		if rip == "" || isLocalIP(rip) {
			continue
		}
		if matchesWhitelist(rip, remote, wl) {
			continue
		}
		m.mu.Lock()
		if m.connReported[rip] {
			m.mu.Unlock()
			continue
		}
		m.connReported[rip] = true
		m.mu.Unlock()
		m.emit("outbound_conn", "warning", "检测到出站连接 "+remote)
	}
}

func remoteHost(addr string) string {
	addr = strings.TrimSpace(addr)
	if strings.HasPrefix(addr, "[") {
		// IPv6 带端口: [addr]:port
		if i := strings.Index(addr, "]"); i >= 0 {
			return strings.TrimPrefix(addr[:i+1], "[")
		}
	}
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}

func matchesWhitelist(rip, remote string, wl []string) bool {
	for _, w := range wl {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		if w == rip || w == remote {
			return true
		}
		if strings.Count(w, ":") == 1 {
			host := w[:strings.LastIndex(w, ":")]
			if host == rip {
				return true
			}
		}
	}
	return false
}

func isLocalIP(ip string) bool {
	ip = strings.ToLower(ip)
	for _, p := range []string{"127.", "10.", "192.168.", "::1", "fe80", "fc", "fd", "::ffff:127."} {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	if matched, _ := regexp.MatchString(`^172\.(1[6-9]|2\d|3[01])\.`, ip); matched {
		return true
	}
	return false
}

// accountBlob /etc/passwd + /etc/shadow 合并哈希
func accountBlob() string {
	h := sha256.New()
	for _, p := range []string{"/etc/passwd", "/etc/shadow"} {
		if b, err := os.ReadFile(p); err == nil {
			h.Write([]byte("\n"))
			h.Write(b)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// MonitorAccounts 账户文件监控（仅 Linux）
func (m *Monitor) MonitorAccounts() {
	if runtime.GOOS != "linux" {
		return
	}
	cur := accountBlob()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.accountBase == "" {
		m.accountBase = cur
		return
	}
	if cur != m.accountBase {
		m.mu.Unlock()
		m.emit("account_change", "critical", "账户文件 /etc/passwd 或 /etc/shadow 发生变化")
		m.mu.Lock()
		m.accountBase = cur
	}
}

// MonitorSSHBrute SSH 暴力破解监控
func (m *Monitor) MonitorSSHBrute() {
	if runtime.GOOS != "linux" {
		return
	}
	logf := ""
	for _, c := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if _, err := os.Stat(c); err == nil {
			logf = c
			break
		}
	}
	if logf == "" {
		return
	}
	cutoff := time.Now().Unix() - 300
	failed := map[string]int{}
	tail := readTail(logf, 4*1024*1024)
	for _, line := range strings.Split(tail, "\n") {
		if !strings.Contains(line, "Failed password") {
			continue
		}
		ts := parseLogTS(line)
		if ts == 0 || ts < cutoff {
			continue
		}
		m := regexp.MustCompile(`from\s+([0-9a-fA-F:.]+)`).FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		failed[m[1]]++
	}
	threshold := m.cfg.BruteThreshold
	if threshold <= 0 {
		threshold = 10
	}
	for ip, cnt := range failed {
		if cnt < threshold {
			continue
		}
		m.mu.Lock()
		if m.bruteReported[ip] {
			m.mu.Unlock()
			continue
		}
		m.bruteReported[ip] = true
		m.mu.Unlock()
		banned := BlockIP(ip)
		msg := "SSH 暴力破解 " + strconv.Itoa(cnt) + "次/5min from " + ip
		if banned {
			msg += " 已封禁"
		} else {
			msg += " 封禁失败"
		}
		m.emit("ssh_brute", "critical", msg)
	}
}

func readTail(path string, maxBytes int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, _ := f.Stat()
	if st == nil {
		return ""
	}
	size := st.Size()
	start := size - maxBytes
	if start < 0 {
		start = 0
	}
	buf := make([]byte, size-start)
	_, _ = f.ReadAt(buf, start)
	return string(buf)
}

var months = map[string]int{"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

func parseLogTS(line string) int64 {
	m := regexp.MustCompile(`^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})`).FindStringSubmatch(line)
	if len(m) < 6 {
		return 0
	}
	mon, ok := months[m[1]]
	if !ok {
		return 0
	}
	day := atoi(m[2])
	hh, mm, ss := atoi(m[3]), atoi(m[4]), atoi(m[5])
	now := time.Now()
	t := time.Date(now.Year(), time.Month(mon), day, hh, mm, ss, 0, now.Location())
	if t.After(time.Now().Add(24 * time.Hour)) {
		t = time.Date(now.Year()-1, time.Month(mon), day, hh, mm, ss, 0, now.Location())
	}
	return t.Unix()
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// WeakPassScan 弱口令检测（Linux 空密码账户，仅告警）
func (m *Monitor) WeakPassScan() {
	if runtime.GOOS != "linux" {
		return
	}
	b, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		user, pwd := parts[0], parts[1]
		if pwd != "" && pwd != "!" {
			continue
		}
		m.mu.Lock()
		if m.weakpassDone[user] {
			m.mu.Unlock()
			continue
		}
		m.weakpassDone[user] = true
		m.mu.Unlock()
		m.emit("weakpass", "warning", "账户 "+user+" 无密码/锁定型空口令")
	}
}

// RunAll 一次性执行全部监控检查，返回每项结果
func (m *Monitor) RunAll() map[string]string {
	m.EnsureSnapshot()
	checks := map[string]string{}
	run := func(name string, fn func()) {
		defer func() {
			if r := recover(); r != nil {
				checks[name] = "panic"
			}
		}()
		fn()
		checks[name] = "ok"
	}
	run("file_monitor", m.MonitorFiles)
	run("proc_monitor", m.MonitorProcs)
	run("weakpass", m.WeakPassScan)
	run("port_monitor", m.MonitorPorts)
	run("conn_monitor", m.MonitorConns)
	run("account_monitor", m.MonitorAccounts)
	run("ssh_brute_monitor", m.MonitorSSHBrute)
	return checks
}

// Config 返回当前配置
func (m *Monitor) Config() *Config {
	return m.cfg
}

// ScanWeb 即时全盘扫描 Web 后门，返回统计（不自动处置）
func (m *Monitor) ScanWeb() map[string]interface{} {
	m.compileSigs()
	m.EnsureSnapshot()
	result := map[string]interface{}{
		"scanned": 0, "new_files": []string{}, "backdoor_hits": []map[string]string{}, "changed": []string{},
	}
	newFiles := []string{}
	changed := []string{}
	hits := []map[string]string{}
	scanned := 0
	for _, base := range m.cfg.WatchPaths {
		filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			scanned++
			cur := sha256File(path)
			if cur == "" {
				return nil
			}
			m.mu.Lock()
			prev, exists := m.snapshot[path]
			m.mu.Unlock()
			if !exists {
				newFiles = append(newFiles, path)
				if sig := m.scanBackdoor(path); sig != "" {
					hits = append(hits, map[string]string{"file": path, "sig": sig})
				}
				m.mu.Lock()
				m.snapshot[path] = cur
				m.mu.Unlock()
			} else if prev != cur {
				changed = append(changed, path)
				if sig := m.scanBackdoor(path); sig != "" {
					hits = append(hits, map[string]string{"file": path, "sig": sig})
				}
				m.mu.Lock()
				m.snapshot[path] = cur
				m.mu.Unlock()
			}
			return nil
		})
	}
	result["scanned"] = scanned
	result["new_files"] = newFiles
	result["changed"] = changed
	result["backdoor_hits"] = hits
	return result
}

// ListPorts 列出监听端口
func (m *Monitor) ListPorts() []map[string]interface{} {
	var r *execx.Result
	if runtime.GOOS == "windows" {
		r = execx.RunShort("netstat -ano | findstr LISTENING")
	} else {
		r = execx.RunShort("ss -tlnpH 2>/dev/null || netstat -tlnp 2>/dev/null")
	}
	var out []map[string]interface{}
	for _, line := range strings.Split(r.Output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "State") || strings.HasPrefix(line, "Netid") ||
			strings.HasPrefix(line, "Proto") || strings.Contains(line, "Address:Port") {
			continue
		}
		parts := strings.Fields(line)
		idx := 0
		if isPortState(parts[0]) {
			idx = 1 // 跳过 State 列
		}
		if len(parts) < idx+4 {
			continue
		}
		// Windows netstat: TCP  local  foreign  LISTENING  pid
		// Linux netstat:  tcp  0      0        local     foreign  LISTENING
		addrIdx := 1
		if runtime.GOOS == "windows" {
			addrIdx = 1
		} else if strings.EqualFold(parts[0], "tcp") && idx == 0 {
			addrIdx = len(parts) - 2
		} else if !strings.EqualFold(parts[0], "tcp") {
			addrIdx = 2
		}
		if addrIdx >= len(parts) {
			continue
		}
		addr := parts[addrIdx]
		port := lastColon(addr)
		if port == "" {
			continue
		}
		proc := ""
		if runtime.GOOS == "windows" {
			proc = "PID " + parts[len(parts)-1]
		} else if len(parts) > addrIdx+1 {
			proc = strings.Join(parts[addrIdx+1:], " ")
		}
		out = append(out, map[string]interface{}{"addr": addr, "port": port, "process": proc})
	}
	return out
}

// ListConns 列出出站连接
func (m *Monitor) ListConns() []map[string]interface{} {
	var r *execx.Result
	if runtime.GOOS == "windows" {
		r = execx.RunShort("netstat -ano | findstr ESTABLISHED")
	} else {
		r = execx.RunShort("ss -tnH state established 2>/dev/null || netstat -tan 2>/dev/null")
	}
	var out []map[string]interface{}
	for _, line := range strings.Split(r.Output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "State") || strings.HasPrefix(line, "Netid") ||
			strings.HasPrefix(line, "Proto") || strings.Contains(line, "Address:Port") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		var local, remote string
		if strings.EqualFold(parts[0], "tcp") {
			// netstat: tcp ... local foreign State
			if runtime.GOOS == "windows" {
				local = parts[1]
				remote = parts[2]
			} else {
				local = parts[len(parts)-3]
				remote = parts[len(parts)-2]
			}
		} else {
			// ss: Recv-Q Send-Q Local Peer
			local = parts[len(parts)-2]
			remote = parts[len(parts)-1]
		}
		out = append(out, map[string]interface{}{"local": local, "remote": remote})
	}
	return out
}

func isPortState(s string) bool {
	switch s {
	case "LISTEN", "ESTAB", "SYN-SENT", "SYN-RECV", "FIN-WAIT-1", "FIN-WAIT-2",
		"TIME-WAIT", "CLOSE-WAIT", "LAST-ACK", "UNCONN", "CLOSING", "CLOSED":
		return true
	}
	return false
}

func lastColon(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[i+1:]
	}
	return ""
}

// Loop 常驻监控循环
func (m *Monitor) Loop(stop <-chan struct{}) {
	m.EnsureSnapshot()
	// 预热基线
	m.MonitorPorts()
	if runtime.GOOS == "linux" {
		m.MonitorAccounts()
	}
	interval := time.Duration(m.cfg.MonitorInterval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			m.MonitorFiles()
			m.MonitorProcs()
			m.WeakPassScan()
			m.MonitorPorts()
			m.MonitorConns()
			if runtime.GOOS == "linux" {
				m.MonitorAccounts()
				m.MonitorSSHBrute()
			}
		}
	}
}
