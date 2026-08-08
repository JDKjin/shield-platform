package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"shield-platform/internal/config"
	"shield-platform/internal/detect"
	"shield-platform/internal/harden"
	"shield-platform/internal/rag"
	"shield-platform/internal/store"
	"shield-platform/internal/util"
	"shield-platform/internal/waf"
	"shield-platform/internal/ws"
)

// Server 面板 API 服务
type Server struct {
	cfg    *config.PanelConfig
	store  *store.Store
	hub    *ws.Hub
	rag    *rag.Engine
	log    *util.Logger
	mux    *http.ServeMux
	panelClients map[string]*websocket.Conn
}

func NewServer(cfg *config.PanelConfig, st *store.Store, hub *ws.Hub, logger *util.Logger) *Server {
	s := &Server{
		cfg:          cfg,
		store:        st,
		hub:          hub,
		rag:          rag.NewEngine(st),
		log:          logger,
		mux:          http.NewServeMux(),
		panelClients: make(map[string]*websocket.Conn),
	}
	if err := s.rag.SeedIfEmpty(); err != nil {
		logger.Warnf("seed kb: %v", err)
	}
	s.seedWAFRules()
	s.hub.SetMessageHandler(s.handleAgentMessage)
	s.routes()
	return s
}

func (s *Server) routes() {
	// REST
	s.mux.HandleFunc("/api/login", s.handleLogin)
	s.mux.HandleFunc("/api/status", s.auth(s.handleStatus))
	s.mux.HandleFunc("/api/targets", s.auth(s.handleTargets))
	s.mux.HandleFunc("/api/targets/", s.auth(s.handleTargetDetail))
	s.mux.HandleFunc("/api/alerts", s.auth(s.handleAlerts))
	s.mux.HandleFunc("/api/alerts/", s.auth(s.handleAlertDetail))
	s.mux.HandleFunc("/api/rules", s.auth(s.handleRules))
	s.mux.HandleFunc("/api/rules/seed", s.auth(s.handleRulesSeed))
	s.mux.HandleFunc("/api/rules/", s.auth(s.handleRuleDetail))
	s.mux.HandleFunc("/api/events", s.auth(s.handleEvents))
	s.mux.HandleFunc("/api/harden/items", s.auth(s.handleHardenItems))
	s.mux.HandleFunc("/api/detect/checks", s.auth(s.handleDetectChecks))
	s.mux.HandleFunc("/api/kb", s.auth(s.handleKB))
	s.mux.HandleFunc("/api/kb/", s.auth(s.handleKBDetail))
	s.mux.HandleFunc("/api/kb/search", s.auth(s.handleKBSearch))
	s.mux.HandleFunc("/api/kb/ask", s.auth(s.handleKBAsk))
	s.mux.HandleFunc("/api/broadcast", s.auth(s.handleBroadcast))
	s.mux.HandleFunc("/api/audit", s.auth(s.handleAudit))
	// WebSocket
	s.mux.HandleFunc("/ws/agent", s.handleAgentWS)
	s.mux.HandleFunc("/ws/panel", s.authWS(s.handlePanelWS))
	// 静态资源
	s.mux.HandleFunc("/", s.handleStatic)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// ============ 认证 ============

func (s *Server) validToken(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") && strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")) == s.cfg.Token {
		return true
	}
	q := r.URL.Query().Get("token")
	if q != "" && q == s.cfg.Token {
		return true
	}
	if c, err := r.Cookie("shield_token"); err == nil && c.Value == s.cfg.Token {
		return true
	}
	return false
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.validToken(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (s *Server) authWS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.validToken(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Token != s.cfg.Token {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "wrong token"})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "shield_token", Value: s.cfg.Token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// ============ Agent 消息处理 ============

func (s *Server) handleAgentMessage(m *ws.Message) {
	switch m.Type {
	case "hello":
		s.onAgentHello(m)
	case "heartbeat":
		s.onAgentHeartbeat(m)
	case "scan_result":
		s.onScanResult(m)
	case "cmd_result":
		s.onCmdResult(m)
	case "harden_result":
		s.onHardenResult(m)
	case "deploy_waf_result":
		s.onEvent("deploy_waf", m)
	case "disable_waf_result":
		s.onEvent("disable_waf", m)
	case "waf_rules":
		s.onEvent("waf_rules", m)
	case "defense_finding":
		s.onDefenseFinding(m)
	case "defense_status", "start_defense_result", "stop_defense_result":
		s.onEvent(m.Type, m)
	case "kill_result", "scan_web_result", "backup_web_result", "rollback_web_result":
		s.onEvent(m.Type, m)
	case "ban_ip_result", "unban_ip_result", "list_ports_result", "list_conns_result":
		s.onEvent(m.Type, m)
	case "defense_now_result", "refresh_result", "sync_rules_result":
		s.onEvent(m.Type, m)
	case "deploy_revproxy_result", "disable_revproxy_result":
		s.onEvent(m.Type, m)
	}
}

// onDefenseFinding 防御发现 -> 存告警并广播
func (s *Server) onDefenseFinding(m *ws.Message) {
	var f struct {
		Category string `json:"category"`
		Severity string `json:"severity"`
		Message  string `json:"message"`
		Detail   string `json:"detail"`
		Time     int64  `json:"time"`
	}
	_ = json.Unmarshal(m.Data, &f)
	sev := f.Severity
	if sev != "critical" && sev != "high" && sev != "medium" && sev != "low" && sev != "warning" && sev != "error" {
		sev = "medium"
	}
	if sev == "warning" {
		sev = "medium"
	}
	if sev == "error" {
		sev = "high"
	}
	a := &store.Alert{
		TargetID: m.ID,
		Severity: sev,
		Category: f.Category,
		Title:    f.Category,
		Message:  truncate(f.Message, 2000),
		Data:     mapStr(f.Detail),
	}
	if err := s.store.AddAlert(a); err != nil {
		s.log.Errorf("add defense alert: %v", err)
	}
	s.hub.BroadcastPanel(ws.NewMsg("alerts_updated", nil))
	s.onEvent("defense_finding", m)
}

type helloData struct {
	Name    string `json:"name"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Version string `json:"version"`
	Host    string `json:"host"`
	WebRoot string `json:"web_root"`
	Uptime  int64  `json:"uptime"`
}

func (s *Server) onAgentHello(m *ws.Message) {
	var h helloData
	_ = json.Unmarshal(m.Data, &h)
	if h.Name == "" {
		h.Name = m.ID
	}
	t := &store.Target{
		ID:        m.ID,
		Name:      h.Name,
		Host:      h.Host,
		OS:        h.OS,
		Arch:      h.Arch,
		Version:   h.Version,
		Status:    "online",
		WebRoot:   h.WebRoot,
		Interval:  3,
		LastSeen:  time.Now().Unix(),
		CreatedAt: time.Now().Unix(),
	}
	if err := s.store.UpsertTarget(t); err != nil {
		s.log.Errorf("upsert target: %v", err)
	}
	s.broadcast(t)
	s.log.Infof("target registered: %s (%s)", t.Name, t.ID)
}

func (s *Server) onAgentHeartbeat(m *ws.Message) {
	_ = s.store.TouchTarget(m.ID)
	var data map[string]interface{}
	_ = json.Unmarshal(m.Data, &data)
	data["target_id"] = m.ID
	data["online"] = true
	s.broadcast(&mapPayload{"heartbeat", data})
}

func (s *Server) onScanResult(m *ws.Message) {
	var rep *detect.Report
	if err := json.Unmarshal(m.Data, &rep); err != nil {
		s.log.Errorf("parse scan_result: %v", err)
		return
	}
	if rep == nil {
		return
	}
	s.broadcast(&mapPayload{"scan_result", rep})
	for _, f := range rep.Findings {
		if f.Severity == "info" {
			continue
		}
		a := &store.Alert{
			TargetID: m.ID,
			Severity: f.Severity,
			Category: f.Category,
			Title:    f.Title,
			Message:  truncate(f.Detail, 2000),
			Data:     mapStr(f.Raw),
		}
		if err := s.store.AddAlert(a); err != nil {
			s.log.Errorf("add alert: %v", err)
		}
	}
	// 广播告警
	s.hub.BroadcastPanel(ws.NewMsg("alerts_updated", nil))
}

func (s *Server) onCmdResult(m *ws.Message) {
	var res map[string]interface{}
	_ = json.Unmarshal(m.Data, &res)
	cmd, _ := res["command"].(string)
	out, _ := res["output"].(string)
	code, _ := res["exit_code"].(float64)
	dur, _ := res["duration_ms"].(float64)
	cl := &store.CommandLog{
		TargetID:   m.ID,
		Command:    truncate(cmd, 2000),
		Output:     truncate(out, 8000),
		ExitCode:   int(code),
		DurationMS: int64(dur),
	}
	_ = s.store.AddCommandLog(cl)
	s.broadcast(&mapPayload{"cmd_result", res})
}

func (s *Server) onHardenResult(m *ws.Message) {
	s.onEvent("harden_result", m)
}

func (s *Server) onEvent(typ string, m *ws.Message) {
	_ = s.store.AddEvent(m.ID, typ, m.Data)
	s.broadcast(m)
}

// ============ 广播 ============

type mapPayload struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

func (s *Server) broadcast(v interface{}) {
	s.hub.BroadcastPanel(ws.NewMsg("push", v))
}

// ============ Handlers ============

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	targets, _ := s.store.ListTargets()
	alerts, _ := s.store.CountAlertsUnhandled()
	online := 0
	for _, t := range targets {
		if time.Now().Unix()-t.LastSeen < 30 {
			online++
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"version":       "1.0.0",
			"targets_total": len(targets),
			"targets_online": online,
			"alerts_unhandled": alerts,
			"server_time":    time.Now().Unix(),
			"llm_enabled":    rag.LoadLLMConfig() != nil,
		},
	})
}

func (s *Server) handleTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.store.ListTargets()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	now := time.Now().Unix()
	for _, t := range targets {
		if t.Status == "online" && now-t.LastSeen > 30 {
			t.Status = "offline"
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": targets})
}

func (s *Server) handleTargetDetail(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/targets/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	if id == "" {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 2 {
		s.handleTargetAction(w, r, id)
		return
	}
	switch r.Method {
	case http.MethodGet:
		t, err := s.store.GetTarget(id)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "target not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": t})
	case http.MethodDelete:
		_ = s.store.DeleteTarget(id)
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	default:
		s.handleTargetAction(w, r, id)
	}
}

// handleTargetAction 转发指令到 Agent
func (s *Server) handleTargetAction(w http.ResponseWriter, r *http.Request, id string) {
	path := strings.TrimPrefix(r.URL.Path, "/api/targets/"+id)
	if !strings.HasPrefix(path, "/") {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 {
		http.NotFound(w, r)
		return
	}
	action := parts[0]
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	var payload interface{}
	switch action {
	case "exec":
		var req struct {
			Command string `json:"command"`
			Timeout int    `json:"timeout"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Command == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "command required"})
			return
		}
		payload = req
	case "scan":
		payload = map[string]interface{}{}
	case "harden":
		var req struct {
			Items []string `json:"items"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		payload = req
	case "deploy_waf":
		var req waf.DeployRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.WAFFileName == "" {
			req.WAFFileName = "waf.php"
		}
		if req.BlockAction == "" {
			req.BlockAction = "403"
		}
		payload = req
	case "disable_waf":
		var req waf.DeployRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		payload = req
	case "get_waf_rules":
		payload = map[string]interface{}{}
	case "kill":
		payload = map[string]interface{}{}
	case "scan_web":
		payload = map[string]interface{}{}
	case "sync_rules":
		var req struct {
			Rules     []*waf.Rule `json:"rules"`
			BlockMode *bool       `json:"block_mode"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		rules, _ := s.store.ListWAFRules()
		if len(req.Rules) == 0 {
			req.Rules = wafFromStore(rules)
		}
		payload = req
	case "backup_web":
		payload = map[string]interface{}{}
	case "rollback_web":
		var req struct {
			Backup string `json:"backup"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		payload = req
	case "ban_ip":
		var req struct {
			IP         string `json:"ip"`
			TTLSeconds int    `json:"ttl_seconds"`
			Firewall   bool   `json:"firewall"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.IP == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "ip required"})
			return
		}
		payload = req
	case "unban_ip":
		var req struct {
			IP       string `json:"ip"`
			Firewall bool   `json:"firewall"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.IP == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "ip required"})
			return
		}
		payload = req
	case "list_ports":
		payload = map[string]interface{}{}
	case "list_conns":
		payload = map[string]interface{}{}
	case "defense_now":
		payload = map[string]interface{}{}
	case "refresh":
		payload = map[string]interface{}{}
	case "start_defense":
		payload = map[string]interface{}{}
	case "stop_defense":
		payload = map[string]interface{}{}
	case "deploy_revproxy":
		var req struct {
			ListenAddr     string   `json:"listen_addr"`
			UpstreamScheme string   `json:"upstream_scheme"`
			UpstreamHost   string   `json:"upstream_host"`
			UpstreamPort   int      `json:"upstream_port"`
			BlockMode      bool     `json:"block_mode"`
			FlagProtect    bool     `json:"flag_protect"`
			Enabled        bool     `json:"enabled"`
			Threshold      int      `json:"threshold"`
			TTLSeconds     int      `json:"ttl_seconds"`
			RateLimit      int      `json:"rate_limit"`
			RateWindow     int      `json:"rate_window"`
			Whitelist      []string `json:"whitelist"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		payload = req
	case "disable_revproxy":
		payload = map[string]interface{}{}
	default:
		http.NotFound(w, r)
		return
	}

	// 获取当前 WAF 规则（部署时下发）
	if action == "deploy_waf" {
		rules, _ := s.store.ListWAFRules()
		req, _ := payload.(waf.DeployRequest)
		req.Rules = wafFromStore(rules)
		payload = req
	}

	msg := ws.NewMsg(action, payload)
	if err := s.hub.SendToAgent(ctx, id, msg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "msg_id": msg.ID})
}

// seedWAFRules 按规则 ID 增量补种默认规则（已有则跳过，支持老库升级补充新规则）
func (s *Server) seedWAFRules() {
	existing := map[string]bool{}
	rules, err := s.store.ListWAFRules()
	if err == nil {
		for _, r := range rules {
			existing[r.ID] = true
		}
	}
	added := 0
	for _, r := range waf.DefaultRules() {
		if existing[r.ID] {
			continue
		}
		sr := &store.WAFRule{
			ID:       r.ID,
			Name:     r.Name,
			Category: r.Category,
			Pattern:  r.Pattern,
			Action:   r.Action,
			Enabled:  bool2int(r.Enabled),
			Level:    r.Level,
		}
		if err := s.store.UpsertWAFRule(sr); err != nil {
			s.log.Warnf("seed waf rule %s: %v", r.ID, err)
		} else {
			added++
		}
	}
	if added > 0 {
		s.log.Infof("seeded %d new default WAF rules (total %d)", added, len(waf.DefaultRules()))
	}
}

func wafFromStore(rules []*store.WAFRule) []*waf.Rule {
	if len(rules) == 0 {
		return waf.DefaultRules()
	}
	var out []*waf.Rule
	for _, r := range rules {
		if r.Pattern == "" {
			continue
		}
		out = append(out, &waf.Rule{
			ID:       r.ID,
			Name:     r.Name,
			Category: r.Category,
			Pattern:  r.Pattern,
			Action:   r.Action,
			Enabled:  r.Enabled == 1,
			Level:    r.Level,
		})
	}
	if len(out) == 0 {
		return waf.DefaultRules()
	}
	return out
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	alerts, err := s.store.ListAlerts(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": alerts})
}

func (s *Server) handleAlertDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/alerts/")
	if id == "" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	_ = s.store.MarkAlertHandled(id)
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {	switch r.Method {
	case http.MethodGet:
		rules, _ := s.store.ListWAFRules()
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": rules})
	case http.MethodPost:
		var req waf.Rule
		_ = json.NewDecoder(r.Body).Decode(&req)
		if err := waf.Compile(req.Pattern); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid pattern: " + err.Error()})
			return
		}
		if req.Action == "" {
			req.Action = "block"
		}
		sr := &store.WAFRule{ID: req.ID, Name: req.Name, Category: req.Category, Pattern: req.Pattern, Action: req.Action, Enabled: bool2int(req.Enabled), Level: req.Level}
		if err := s.store.UpsertWAFRule(sr); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": sr})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRulesSeed 手动触发默认规则增量补种
func (s *Server) handleRulesSeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	before, _ := s.store.ListWAFRules()
	s.seedWAFRules()
	after, _ := s.store.ListWAFRules()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"added":   len(after) - len(before),
		"total":   len(after),
	})
}

func (s *Server) handleRuleDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/rules/")
	if id == "" || r.Method != http.MethodDelete {
		http.NotFound(w, r)
		return
	}
	_ = s.store.DeleteWAFRule(id)
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	events, err := s.store.ListEvents(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": events})
}

// handleBroadcast 向所有在线 Agent 广播指令（人机协同：操作留痕在事件流）
func (s *Server) handleBroadcast(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Type    string          `json:"type"`
		Data    json.RawMessage `json:"data"`
		Message string          `json:"message"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Type == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "type required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	online := s.hub.OnlineAgents()
	sent := 0
	for _, id := range online {
		msg := ws.NewMsg(req.Type, json.RawMessage(req.Data))
		if err := s.hub.SendToAgent(ctx, id, msg); err == nil {
			sent++
		}
	}
	// 操作审计：广播动作记录到事件流（target_id=broadcast）
	_ = s.store.AddEvent("broadcast", "broadcast", map[string]interface{}{
		"type": req.Type, "message": req.Message, "targets": online, "sent": sent, "time": time.Now().Unix(),
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "online": online, "sent": sent})
}

// handleAudit 操作审计（事件流聚合展示：谁/何时/做了什么）
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	events, err := s.store.ListEvents(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	cmds, _ := s.store.ListCommandLogs("", 50)
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": map[string]interface{}{
		"events": events, "commands": cmds,
	}})
}

func (s *Server) handleHardenItems(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": harden.List})
}

func (s *Server) handleDetectChecks(w http.ResponseWriter, r *http.Request) {
	checks := detect.Checks()
	var out []map[string]string
	for _, c := range checks {
		out = append(out, map[string]string{"id": c.ID, "name": c.Name})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": out})
}

// ============ RAG Handlers ============

func (s *Server) handleKB(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		docs, err := s.rag.List()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": docs})
	case http.MethodPost:
		var req struct {
			Title   string `json:"title"`
			Content string `json:"content"`
			Source  string `json:"source"`
			Tags    string `json:"tags"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if strings.TrimSpace(req.Content) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "content required"})
			return
		}
		if req.Title == "" {
			req.Title = "导入知识 " + time.Now().Format("2006-01-02 15:04")
		}
		if req.Source == "" {
			req.Source = "manual"
		}
		added, err := s.rag.ImportText(req.Title, req.Content, req.Source, req.Tags)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "added": added})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleKBDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/kb/")
	if id == "" || r.Method != http.MethodDelete {
		http.NotFound(w, r)
		return
	}
	_ = s.rag.Delete(id)
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func (s *Server) handleKBSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	top := 5
	if v := r.URL.Query().Get("top"); v != "" {
		fmt.Sscanf(v, "%d", &top)
	}
	if q == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": []interface{}{}})
		return
	}
	res, err := s.rag.Search(q, top)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": res})
}

func (s *Server) handleKBAsk(w http.ResponseWriter, r *http.Request) {
	var req rag.AnswerRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if strings.TrimSpace(req.Question) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "question required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	ans, err := s.rag.Answer(ctx, req.Question, 5)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": ans})
}

// ============ WebSocket ============

func (s *Server) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	secret := r.Header.Get("X-Agent-Secret")
	if secret != "" && secret != s.cfg.AgentSecret {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "closed")

	// 读取第一个 hello 消息确定 target id
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	var hello ws.Message
	if err := wsjson.Read(ctx, conn, &hello); err != nil || hello.Type != "hello" {
		return
	}
	targetID := hello.ID
	if targetID == "" {
		targetID = util.GenID()
	}
	hello.ID = targetID

	ac := &ws.AgentConn{TargetID: targetID, Conn: conn, LastSeen: time.Now().Unix()}
	var hinfo helloData
	_ = json.Unmarshal(hello.Data, &hinfo)
	ac.Name = hinfo.Name
	ac.OS = hinfo.OS
	ac.Arch = hinfo.Arch
	if ac.Name == "" {
		ac.Name = targetID
	}
	s.hub.RegisterAgent(ac)
	defer s.hub.UnregisterAgent(targetID)

	// 处理 hello
	s.handleAgentMessage(&hello)
	// 继续处理后续消息
	go func() {
		for {
			var m ws.Message
			if err := wsjson.Read(r.Context(), conn, &m); err != nil {
				return
			}
			m.ID = targetID
			s.handleAgentMessage(&m)
		}
	}()
	// 等待断开
	<-r.Context().Done()
}

func (s *Server) handlePanelWS(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "closed")
	clientID := util.GenID()
	s.panelClients[clientID] = conn
	defer delete(s.panelClients, clientID)
	s.hub.HandlePanelConn(conn, clientID, func() {})
}

// ============ 静态资源 ============

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		r.URL.Path = "/index.html"
	}
	serveEmbedded(w, r)
}

// ============ 工具函数 ============

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func mapStr(s string) string {
	if s == "" {
		return "{}"
	}
	return s
}

func bool2int(b bool) int {
	if b {
		return 1
	}
	return 0
}
