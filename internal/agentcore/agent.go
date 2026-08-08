package agentcore

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"shield-platform/internal/config"
	"shield-platform/internal/defense"
	"shield-platform/internal/detect"
	"shield-platform/internal/execx"
	"shield-platform/internal/harden"
	"shield-platform/internal/util"
	"shield-platform/internal/waf"
	"shield-platform/internal/ws"
)

// Agent 靶机端 Agent
type Agent struct {
	cfg     *config.AgentConfig
	log     *util.Logger
	conn    *websocket.Conn
	ctx     context.Context
	cancel  context.CancelFunc
	rules   []*waf.Rule
	wafDeployed bool
	defense *defense.Monitor
	defenseStop chan struct{}
	revproxy *waf.ReverseWAF
}

func NewAgent(cfg *config.AgentConfig, logger *util.Logger) *Agent {
	ctx, cancel := context.WithCancel(context.Background())
	return &Agent{
		cfg:    cfg,
		log:    logger,
		ctx:    ctx,
		cancel: cancel,
		defenseStop: make(chan struct{}),
	}
}

// Run 启动并维持回连
func (a *Agent) Run() error {
	url := a.cfg.Server
	a.log.Infof("agent connecting to panel: %s", url)
	for {
		if a.ctx.Err() != nil {
			return nil
		}
		err := a.connectLoop(url)
		if err != nil {
			a.log.Warnf("connection ended: %v, retry in 3s", err)
		}
		select {
		case <-a.ctx.Done():
			return nil
		case <-time.After(3 * time.Second):
		}
	}
}

func (a *Agent) Stop() {
	a.cancel()
	if a.conn != nil {
		_ = a.conn.Close(websocket.StatusNormalClosure, "agent shutdown")
	}
}

func (a *Agent) connectLoop(url string) error {
	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPHeader: httpHeader(a.cfg.Secret),
	})
	if err != nil {
		return err
	}
	a.conn = conn
	a.log.Infof("connected to panel")

	// 注册
	a.send(&ws.Message{
		Type: "hello",
		Data: mustJSON(helloData(a.cfg)),
	})

	// 后台心跳与监控
	go a.monitorLoop(conn)
	// 持续防御守护（AutoDefense 或已在运行）
	a.startDefenseIfNeeded()

	// 主读取循环
	for {
		var m ws.Message
		if err := wsjson.Read(a.ctx, conn, &m); err != nil {
			return err
		}
		a.handleMessage(&m)
	}
}

type helloPayload struct {
	Name     string `json:"name"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
	Host     string `json:"host"`
	WebRoot  string `json:"web_root"`
	Uptime   int64  `json:"uptime"`
}

func helloData(cfg *config.AgentConfig) helloPayload {
	return helloPayload{
		Name:    cfg.Name,
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		Version: "1.0.0",
		Host:    util.Hostname(),
		WebRoot: cfg.WebRoot,
		Uptime:  time.Now().Unix(),
	}
}

// monitorLoop 周期上报心跳+简要监控
func (a *Agent) monitorLoop(conn *websocket.Conn) {
	interval := time.Duration(a.cfg.Interval) * time.Second
	if interval <= 0 {
		interval = 3 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-t.C:
			if conn == nil {
				continue
			}
			a.send(&ws.Message{Type: "heartbeat", Data: mustJSON(a.briefMonitor())})
		}
	}
}

// briefMonitor 轻量监控数据
func (a *Agent) briefMonitor() map[string]interface{} {
	osName := runtime.GOOS
	var load, mem, disk string
	if osName == "linux" {
		l := execx.RunShort(`uptime | awk -F'load average:' '{print $2}'`)
		load = strings.TrimSpace(l.Output)
		m := execx.RunShort(`free -m | awk '/Mem:/{printf "%d/%dMB", $3,$2}'`)
		mem = strings.TrimSpace(m.Output)
		d := execx.RunShort(`df -h / | awk 'NR==2{print $3"/"$2" "$5}'`)
		disk = strings.TrimSpace(d.Output)
	} else {
		// Win7/10 用 wmic；Win11 已移除 wmic，回退 PowerShell
		l := execx.RunShort("wmic cpu get loadpercentage /value 2>nul | findstr Load")
		if strings.TrimSpace(l.Output) == "" {
			l = execx.RunShort(`powershell -NoProfile -Command "(Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue).LoadPercentage"`)
			if strings.TrimSpace(l.Output) == "" {
				l = execx.RunShort(`powershell -NoProfile -Command "(Get-WmiObject Win32_Processor -ErrorAction SilentlyContinue).LoadPercentage"`)
			}
		}
		load = strings.TrimSpace(l.Output)
	}
	var conns *execx.Result
	if osName == "windows" {
		conns = execx.RunShort("netstat -ano | find /c \"ESTABLISHED\"")
	} else {
		conns = execx.RunShort("ss -tn state established 2>/dev/null | wc -l")
	}
	return map[string]interface{}{
		"cpu":      load,
		"mem":      mem,
		"disk":     disk,
		"estab":    strings.TrimSpace(conns.Output),
		"web_root": a.cfg.WebRoot,
		"waf":      a.wafDeployed,
		"ts":       time.Now().Unix(),
	}
}

// handleMessage 处理面板下发指令
func (a *Agent) handleMessage(m *ws.Message) {
	switch m.Type {
	case "exec":
		a.handleExec(m)
	case "scan":
		a.handleScan(m)
	case "harden":
		a.handleHarden(m)
	case "deploy_waf":
		a.handleDeployWAF(m)
	case "disable_waf":
		a.handleDisableWAF(m)
	case "get_waf_rules":
		a.send(&ws.Message{Type: "waf_rules", Data: mustJSON(a.rules)})
	case "ping":
		a.send(&ws.Message{Type: "pong", Data: mustJSON(map[string]interface{}{"ts": time.Now().Unix()})})
	case "kill":
		a.handleKill(m)
	case "scan_web":
		a.handleScanWeb(m)
	case "sync_rules":
		a.handleSyncRules(m)
	case "backup_web":
		a.handleBackupWeb(m)
	case "rollback_web":
		a.handleRollbackWeb(m)
	case "ban_ip":
		a.handleBanIP(m)
	case "unban_ip":
		a.handleUnbanIP(m)
	case "list_ports":
		a.handleListPorts(m)
	case "list_conns":
		a.handleListConns(m)
	case "defense_now":
		a.handleDefenseNow(m)
	case "refresh":
		a.handleRefresh(m)
	case "start_defense":
		a.handleStartDefense(m)
	case "stop_defense":
		a.handleStopDefense(m)
	case "deploy_revproxy":
		a.handleDeployRevproxy(m)
	case "disable_revproxy":
		a.handleDisableRevproxy(m)
	default:
		a.log.Debugf("unknown msg type: %s", m.Type)
	}
}

func (a *Agent) handleExec(m *ws.Message) {
	var req struct {
		Command string `json:"command"`
		Timeout int    `json:"timeout"`
	}
	_ = json.Unmarshal(m.Data, &req)
	a.log.Infof("exec: %s", req.Command)
	r := execx.Run(a.ctx, req.Command, time.Duration(req.Timeout)*time.Second)
	a.send(&ws.Message{
		Type: "cmd_result",
		ID:   m.ID,
		Data: mustJSON(map[string]interface{}{
			"command":     req.Command,
			"output":      r.Output,
			"exit_code":   r.ExitCode,
			"duration_ms": r.DurationMS,
		}),
	})
}

func (a *Agent) handleScan(m *ws.Message) {
	a.log.Infof("run full scan")
	rep := detect.RunAll()
	a.send(&ws.Message{Type: "scan_result", ID: m.ID, Data: mustJSON(rep)})
}

func (a *Agent) handleHarden(m *ws.Message) {
	var req struct {
		Items []string `json:"items"` // 为空则全部
	}
	_ = json.Unmarshal(m.Data, &req)
	var results []*harden.Result
	if len(req.Items) == 0 {
		results = harden.RunAll()
	} else {
		for _, id := range req.Items {
			r, err := harden.Run(id)
			if err != nil {
				results = append(results, &harden.Result{ItemID: id, ExitCode: -1, Output: err.Error()})
				continue
			}
			results = append(results, r)
		}
	}
	a.send(&ws.Message{Type: "harden_result", ID: m.ID, Data: mustJSON(results)})
}

func (a *Agent) handleDeployWAF(m *ws.Message) {
	var req waf.DeployRequest
	_ = json.Unmarshal(m.Data, &req)
	if req.WebRoot == "" {
		req.WebRoot = a.cfg.WebRoot
	}
	rules := req.Rules
	if len(rules) == 0 {
		rules = a.rules
	}
	if len(rules) == 0 {
		rules = waf.DefaultRules()
	}
	a.rules = rules
	res, err := waf.Deploy(rules, &req)
	payload := map[string]interface{}{
		"request": req,
		"result":  res,
		"error":   errString(err),
	}
	if err == nil {
		a.wafDeployed = true
	}
	a.send(&ws.Message{Type: "deploy_waf_result", ID: m.ID, Data: mustJSON(payload)})
}

func (a *Agent) handleDisableWAF(m *ws.Message) {
	var req waf.DeployRequest
	_ = json.Unmarshal(m.Data, &req)
	if req.WebRoot == "" {
		req.WebRoot = a.cfg.WebRoot
	}
	res, err := waf.Disable(&req)
	a.wafDeployed = false
	a.send(&ws.Message{Type: "disable_waf_result", ID: m.ID, Data: mustJSON(map[string]interface{}{"result": res, "error": errString(err)})})
}

func (a *Agent) send(m *ws.Message) {
	if m.ID == "" {
		m.ID = a.cfg.ID
	}
	if m.TS == 0 {
		m.TS = time.Now().Unix()
	}
	if a.conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()
	if err := wsjson.Write(ctx, a.conn, m); err != nil {
		a.log.Warnf("send failed: %v", err)
	}
}

func mustJSON(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func httpHeader(secret string) http.Header {
	h := http.Header{}
	h.Set("User-Agent", "shield-platform-agent/1.0")
	if secret != "" {
		h.Set("X-Agent-Secret", secret)
	}
	return h
}
