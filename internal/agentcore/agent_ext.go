package agentcore

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	"shield-platform/internal/config"
	"shield-platform/internal/defense"
	"shield-platform/internal/execx"
	"shield-platform/internal/platform"
	"shield-platform/internal/waf"
	"shield-platform/internal/ws"
)

// ============ 持续防御守护 ============

// newDefenseMonitor 根据 Agent 配置创建防御监控实例
func (a *Agent) newDefenseMonitor() *defense.Monitor {
	cfg := defense.DefaultConfig()
	if a.cfg.Defense != nil {
		d := a.cfg.Defense
		if len(d.WatchPaths) > 0 {
			cfg.WatchPaths = d.WatchPaths
		}
		if d.QuarantineDir != "" {
			cfg.QuarantineDir = d.QuarantineDir
		}
		if d.BackupDir != "" {
			cfg.BackupDir = d.BackupDir
		}
		if d.MonitorInterval > 0 {
			cfg.MonitorInterval = d.MonitorInterval
		}
		if len(d.BackdoorSigs) > 0 {
			cfg.BackdoorSigs = d.BackdoorSigs
		}
		if len(d.ConnWhitelist) > 0 {
			cfg.ConnWhitelist = d.ConnWhitelist
		}
		if d.BruteThreshold > 0 {
			cfg.BruteThreshold = d.BruteThreshold
		}
		if len(d.WebExt) > 0 {
			cfg.WebExt = d.WebExt
		}
	} else if a.cfg.WebRoot != "" {
		cfg.WatchPaths = []string{a.cfg.WebRoot}
	}
	m := defense.NewMonitor(cfg)
	m.SetLogger(a.emitFinding)
	return m
}

func (a *Agent) startDefenseIfNeeded() {
	if !a.cfg.AutoDefense {
		return
	}
	a.startDefense()
}

// startDefense 启动持续防御守护
func (a *Agent) startDefense() {
	if a.defense != nil {
		return
	}
	a.defense = a.newDefenseMonitor()
	a.defenseStop = make(chan struct{})
	go a.defense.Loop(a.defenseStop)
	a.log.Infof("defense monitor started")
	a.send(&ws.Message{Type: "defense_status", Data: mustJSON(map[string]interface{}{
		"running": true, "watch_paths": a.defense.Config().WatchPaths,
	})})
}

// stopDefense 停止持续防御守护
func (a *Agent) stopDefense() {
	if a.defense == nil {
		return
	}
	close(a.defenseStop)
	a.defense = nil
	a.log.Infof("defense monitor stopped")
	a.send(&ws.Message{Type: "defense_status", Data: mustJSON(map[string]interface{}{"running": false})})
}

// emitFinding 防御发现回调 -> 上报面板
func (a *Agent) emitFinding(f *defense.Finding) {
	a.send(&ws.Message{Type: "defense_finding", Data: mustJSON(f)})
}

// ============ 新指令 ============

// killReq 终止可疑进程
func (a *Agent) handleKill(m *ws.Message) {
	sigs := []string{"/dev/tcp/", "bash -i", "ncat", "meterpreter", "xmrig", "minerd"}
	var killed []string
	var r *execx.Result
	if runtime.GOOS == "windows" {
		r = execx.Run(a.ctx, "tasklist /fo csv /nh", 15*time.Second)
	} else {
		r = execx.Run(a.ctx, "ps -eo pid,args 2>/dev/null", 15*time.Second)
	}
	for _, ln := range strings.Split(r.Output, "\n")[1:] {
		low := strings.ToLower(ln)
		for _, s := range sigs {
			if !strings.Contains(low, s) {
				continue
			}
			f := strings.Fields(ln)
			if len(f) == 0 {
				continue
			}
			pid := f[0]
			execx.Run(a.ctx, platform.KillProcCmd(pid), 5*time.Second)
			killed = append(killed, pid)
			break
		}
	}
	msg := fmt.Sprintf("终止可疑进程 %v", killed)
	if len(killed) == 0 {
		msg = "未发现可疑进程"
	}
	a.send(&ws.Message{Type: "kill_result", ID: m.ID, Data: mustJSON(map[string]interface{}{
		"killed": killed, "message": msg,
	})})
}

// handleScanWeb 即时全盘扫描 Web 后门（不自动处置）
func (a *Agent) handleScanWeb(m *ws.Message) {
	mon := a.defense
	if mon == nil {
		mon = a.newDefenseMonitor()
		mon.EnsureSnapshot()
	}
	result := mon.ScanWeb()
	a.send(&ws.Message{Type: "scan_web_result", ID: m.ID, Data: mustJSON(result)})
}

// handleSyncRules 同步规则开关与 block_mode 配置
func (a *Agent) handleSyncRules(m *ws.Message) {
	var req struct {
		Rules     []*waf.Rule `json:"rules,omitempty"`
		BlockMode *bool       `json:"block_mode,omitempty"`
	}
	_ = json.Unmarshal(m.Data, &req)
	if len(req.Rules) > 0 {
		a.rules = req.Rules
	}
	a.send(&ws.Message{Type: "sync_rules_result", ID: m.ID, Data: mustJSON(map[string]interface{}{
		"ok": true, "rules_count": len(a.rules), "block_mode": req.BlockMode,
	})})
}

// handleBackupWeb 备份 Web 目录
func (a *Agent) handleBackupWeb(m *ws.Message) {
	mon := a.defense
	if mon == nil {
		mon = a.newDefenseMonitor()
	}
	res := mon.BackupWeb()
	a.send(&ws.Message{Type: "backup_web_result", ID: m.ID, Data: mustJSON(res)})
}

// handleRollbackWeb 回滚 Web 目录
func (a *Agent) handleRollbackWeb(m *ws.Message) {
	var req struct {
		Backup string `json:"backup"`
	}
	_ = json.Unmarshal(m.Data, &req)
	mon := a.defense
	if mon == nil {
		mon = a.newDefenseMonitor()
	}
	res := mon.RollbackWeb(req.Backup)
	a.send(&ws.Message{Type: "rollback_web_result", ID: m.ID, Data: mustJSON(res)})
}

// handleBanIP 封禁 IP（真实防火墙 + 动态封禁）
func (a *Agent) handleBanIP(m *ws.Message) {
	var req struct {
		IP        string `json:"ip"`
		TTLSeconds int   `json:"ttl_seconds"`
		Firewall  bool   `json:"firewall"`
	}
	_ = json.Unmarshal(m.Data, &req)
	if a.revproxy != nil {
		a.revproxy.Ban().Ban(req.IP, req.TTLSeconds, "manual")
	}
	fwOK := false
	if req.Firewall {
		fwOK = defense.BlockIP(req.IP)
	}
	a.send(&ws.Message{Type: "ban_ip_result", ID: m.ID, Data: mustJSON(map[string]interface{}{
		"ip": req.IP, "firewall": fwOK, "ok": true,
	})})
}

// handleUnbanIP 解封 IP
func (a *Agent) handleUnbanIP(m *ws.Message) {
	var req struct {
		IP       string `json:"ip"`
		Firewall bool   `json:"firewall"`
	}
	_ = json.Unmarshal(m.Data, &req)
	if a.revproxy != nil {
		a.revproxy.Ban().Unban(req.IP)
	}
	fwOK := false
	if req.Firewall {
		fwOK = defense.UnblockIP(req.IP)
	}
	a.send(&ws.Message{Type: "unban_ip_result", ID: m.ID, Data: mustJSON(map[string]interface{}{
		"ip": req.IP, "firewall": fwOK, "ok": true,
	})})
}

// handleListPorts 列出监听端口
func (a *Agent) handleListPorts(m *ws.Message) {
	mon := a.defense
	if mon == nil {
		mon = a.newDefenseMonitor()
	}
	ports := mon.ListPorts()
	a.send(&ws.Message{Type: "list_ports_result", ID: m.ID, Data: mustJSON(ports)})
}

// handleListConns 列出出站连接
func (a *Agent) handleListConns(m *ws.Message) {
	mon := a.defense
	if mon == nil {
		mon = a.newDefenseMonitor()
	}
	conns := mon.ListConns()
	a.send(&ws.Message{Type: "list_conns_result", ID: m.ID, Data: mustJSON(conns)})
}

// handleDefenseNow 一次性执行全部监控检查
func (a *Agent) handleDefenseNow(m *ws.Message) {
	mon := a.defense
	if mon == nil {
		mon = a.newDefenseMonitor()
	}
	checks := mon.RunAll()
	a.send(&ws.Message{Type: "defense_now_result", ID: m.ID, Data: mustJSON(map[string]interface{}{
		"checks": checks, "ts": time.Now().Unix(),
	})})
}

// handleRefresh 返回运行状态快照
func (a *Agent) handleRefresh(m *ws.Message) {
	rep := map[string]interface{}{
		"ts":          time.Now().Unix(),
		"uptime":      time.Now().Unix(),
		"web_root":    a.cfg.WebRoot,
		"waf":         a.wafDeployed,
		"defense":     a.defense != nil,
		"revproxy":    a.revproxy != nil,
		"rules_count": len(a.rules),
	}
	if a.revproxy != nil {
		rep["revproxy_snapshot"] = a.revproxy.Ban().Snapshot()
		rep["revproxy_hits"] = a.revproxy.Hits(20)
	}
	a.send(&ws.Message{Type: "refresh_result", ID: m.ID, Data: mustJSON(rep)})
}

// handleStartDefense 手动启动防御
func (a *Agent) handleStartDefense(m *ws.Message) {
	a.startDefense()
	a.send(&ws.Message{Type: "start_defense_result", ID: m.ID, Data: mustJSON(map[string]interface{}{"ok": true})})
}

// handleStopDefense 手动停止防御
func (a *Agent) handleStopDefense(m *ws.Message) {
	a.stopDefense()
	a.send(&ws.Message{Type: "stop_defense_result", ID: m.ID, Data: mustJSON(map[string]interface{}{"ok": true})})
}

// handleDeployRevproxy 部署反向代理 WAF（双模式：作为 .user.ini 软 WAF 的补充）
func (a *Agent) handleDeployRevproxy(m *ws.Message) {
	var req struct {
		ListenAddr     string `json:"listen_addr"`
		UpstreamScheme string `json:"upstream_scheme"`
		UpstreamHost   string `json:"upstream_host"`
		UpstreamPort   int    `json:"upstream_port"`
		BlockMode      bool   `json:"block_mode"`
		FlagProtect    bool   `json:"flag_protect"`
		Enabled        bool   `json:"enabled"`
		Threshold      int    `json:"threshold"`
		TTLSeconds     int    `json:"ttl_seconds"`
		RateLimit      int    `json:"rate_limit"`
		RateWindow     int    `json:"rate_window"`
		Whitelist      []string `json:"whitelist"`
	}
	_ = json.Unmarshal(m.Data, &req)
	if a.revproxy != nil {
		a.revproxy.Stop()
		a.revproxy = nil
	}
	if !req.Enabled {
		a.send(&ws.Message{Type: "deploy_revproxy_result", ID: m.ID, Data: mustJSON(map[string]interface{}{"ok": true, "running": false})})
		return
	}
	if req.ListenAddr == "" {
		req.ListenAddr = ":8080"
	}
	if req.UpstreamHost == "" {
		req.UpstreamHost = "127.0.0.1"
	}
	if req.UpstreamPort == 0 {
		req.UpstreamPort = 80
	}
	cfg := waf.RVConfig{
		ListenAddr:     req.ListenAddr,
		UpstreamScheme: req.UpstreamScheme,
		UpstreamHost:   req.UpstreamHost,
		UpstreamPort:   req.UpstreamPort,
		BlockMode:      req.BlockMode,
		FlagProtect:    req.FlagProtect,
	}
	if cfg.UpstreamScheme == "" {
		cfg.UpstreamScheme = "http"
	}
	rv, err := waf.NewReverseWAF(cfg)
	if err != nil {
		a.send(&ws.Message{Type: "deploy_revproxy_result", ID: m.ID, Data: mustJSON(map[string]interface{}{"ok": false, "error": err.Error()})})
		return
	}
	rv.SetOnHit(func(h *waf.RVHit, replaced bool) {
		sev := h.Severity
		if sev == "" {
			sev = "warning"
		}
		msg := fmt.Sprintf("WAF拦截 %s %s -> %s (规则: %s)", h.Method, h.Path, h.Name, h.RuleID)
		if h.Side == "response" {
			if replaced {
				msg = fmt.Sprintf("响应Flag保护: 泄露内容已替换为假flag (规则: %s)", h.RuleID)
			} else {
				msg = fmt.Sprintf("响应Flag检测命中 (规则: %s)", h.RuleID)
			}
		}
		a.emitFinding(&defense.Finding{
			Category: "revproxy_waf",
			Severity: sev,
			Message:  msg,
			Detail:   fmt.Sprintf("%s @ %s pattern=%s", h.Name, h.IP, h.Pattern),
			Time:     time.Now().Unix(),
		})
	})
	a.revproxy = rv
	if req.Threshold > 0 || req.TTLSeconds > 0 || req.RateLimit > 0 {
		rv.SetBanConfig(waf.IPBanConfig{
			Enabled:    true,
			Threshold:  req.Threshold,
			TTLSeconds: req.TTLSeconds,
			RateLimit:  req.RateLimit,
			RateWindow: req.RateWindow,
			Whitelist:  req.Whitelist,
		})
	}
	go rv.Start()
	a.send(&ws.Message{Type: "deploy_revproxy_result", ID: m.ID, Data: mustJSON(map[string]interface{}{
		"ok": true, "running": true, "listen": req.ListenAddr,
		"upstream": fmt.Sprintf("%s://%s:%d", cfg.UpstreamScheme, req.UpstreamHost, req.UpstreamPort),
	})})
}

// handleDisableRevproxy 停用反向代理 WAF
func (a *Agent) handleDisableRevproxy(m *ws.Message) {
	if a.revproxy != nil {
		_ = a.revproxy.Stop()
		a.revproxy = nil
	}
	a.send(&ws.Message{Type: "disable_revproxy_result", ID: m.ID, Data: mustJSON(map[string]interface{}{"ok": true})})
}

var _ = config.AgentConfig{}
