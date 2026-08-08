package waf

import (
	"crypto/rand"
	"encoding/hex"
	"html"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// RVConfig 反向代理 WAF 配置
type RVConfig struct {
	ListenAddr     string `json:"listen_addr"`     // WAF 监听地址，如 :8080
	UpstreamScheme string `json:"upstream_scheme"` // http|https
	UpstreamHost   string `json:"upstream_host"`   // 上游业务 IP/host
	UpstreamPort   int    `json:"upstream_port"`   // 上游业务端口
	BlockMode      bool   `json:"block_mode"`      // true=拦截 false=仅告警
	BlockTitle     string `json:"block_title"`
	FlagProtect    bool   `json:"flag_protect"`    // 响应侧 flag 泄露保护
}

// RVHit 一次请求/响应命中记录
type RVHit struct {
	RuleID   string `json:"rule_id"`
	Name     string `json:"name"`
	Action   string `json:"action"` // block|alert
	Pattern  string `json:"pattern"`
	Severity string `json:"severity"`
	Side     string `json:"side"` // request|response
	IP       string `json:"ip,omitempty"`
	Method   string `json:"method,omitempty"`
	Path     string `json:"path,omitempty"`
	Time     int64  `json:"time"`
}

// rvRule 编译后的反向代理规则
type rvRule struct {
	ID       string
	Name     string
	Action   string
	Severity string
	Side     string // request|response
	Patterns []*regexp.Regexp
}

// ReverseWAF 反向代理 WAF 服务
type ReverseWAF struct {
	cfg    RVConfig
	ban    *IPBan
	rules  []rvRule
	mu     sync.RWMutex
	srv    *http.Server
	router *url.URL
	hits   []RVHit
	hitMu  sync.Mutex
	// onHit 命中回调（上报事件/告警，由 Agent 注入）
	onHit func(h *RVHit, replaced bool)
}

// NewReverseWAF 创建反向代理 WAF
func NewReverseWAF(cfg RVConfig) (*ReverseWAF, error) {
	if cfg.UpstreamPort <= 0 {
		cfg.UpstreamPort = 80
	}
	if cfg.UpstreamScheme == "" {
		cfg.UpstreamScheme = "http"
	}
	if cfg.UpstreamHost == "" {
		cfg.UpstreamHost = "127.0.0.1"
	}
	if cfg.BlockTitle == "" {
		cfg.BlockTitle = "请求已被 WAF 拦截"
	}
	target := &url.URL{Scheme: cfg.UpstreamScheme, Host: ipPort(cfg.UpstreamHost, cfg.UpstreamPort)}
	rv := &ReverseWAF{
		cfg:    cfg,
		ban:    NewIPBan(),
		router: target,
	}
	rv.rules = append(rv.rules, compileRVBasic()...)
	rv.rules = append(rv.rules, compileRVICS()...)
	return rv, nil
}

func ipPort(host string, port int) string {
	if port == 80 || port == 443 {
		return host
	}
	return host + ":" + itoa(port)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// SetBanConfig 设置动态封禁配置
func (r *ReverseWAF) SetBanConfig(cfg IPBanConfig) {
	r.ban.Configure(cfg)
}

// Ban 获取封禁管理器
func (r *ReverseWAF) Ban() *IPBan {
	return r.ban
}

// SetOnHit 注入命中回调
func (r *ReverseWAF) SetOnHit(fn func(h *RVHit, replaced bool)) {
	r.onHit = fn
}

// Start 启动 WAF 服务
func (r *ReverseWAF) Start() error {
	handler := http.HandlerFunc(r.serve)
	r.srv = &http.Server{
		Addr:              r.cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	err := r.srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Stop 停止服务
func (r *ReverseWAF) Stop() error {
	if r.srv == nil {
		return nil
	}
	return r.srv.Close()
}

// Hits 最近命中记录
func (r *ReverseWAF) Hits(limit int) []RVHit {
	r.hitMu.Lock()
	defer r.hitMu.Unlock()
	if limit <= 0 || limit > len(r.hits) {
		limit = len(r.hits)
	}
	out := make([]RVHit, limit)
	copy(out, r.hits[len(r.hits)-limit:])
	return out
}

func (r *ReverseWAF) recordHit(h *RVHit, replaced bool) {
	r.hitMu.Lock()
	r.hits = append(r.hits, *h)
	if len(r.hits) > 2000 {
		r.hits = r.hits[len(r.hits)-1000:]
	}
	r.hitMu.Unlock()
	if r.onHit != nil {
		r.onHit(h, replaced)
	}
}

// serve 反向代理主入口
func (r *ReverseWAF) serve(w http.ResponseWriter, req *http.Request) {
	clientIP := clientIP(req)
	if r.ban.IsBanned(clientIP) {
		writeBlock(w, r.cfg.BlockTitle, "IP 已被封禁")
		return
	}
	if r.ban.CheckRate(clientIP) {
		writeBlock(w, r.cfg.BlockTitle, "请求频率超限")
		return
	}

	body, _ := io.ReadAll(req.Body)
	req.Body.Close()

	// 请求侧检测
	if hit := r.checkRequest(req, string(body), clientIP); hit != nil {
		if hit.Action == "block" && r.cfg.BlockMode {
			r.recordHit(hit, false)
			writeBlock(w, r.cfg.BlockTitle, hit.Name)
			return
		}
		r.recordHit(hit, false)
	}

	// 复制请求头并清理 hop-by-hop
	hdr := make(http.Header, len(req.Header))
	for k, vv := range req.Header {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vv {
			hdr.Add(k, v)
		}
	}

	// 构造上游请求
	upstream := &http.Request{
		Method: req.Method,
		URL: &url.URL{
			Scheme: r.router.Scheme,
			Host:   r.router.Host,
			Path:   req.URL.Path,
			RawQuery: req.URL.RawQuery,
		},
		Header: hdr,
		Body:   io.NopCloser(strings.NewReader(string(body))),
	}
	upstream.ContentLength = int64(len(body))

	resp, err := http.DefaultTransport.RoundTrip(upstream)
	if err != nil {
		writeBlockStatus(w, http.StatusBadGateway, "502 Bad Gateway", "上游连接失败: "+err.Error())
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// 响应侧检测（flag 保护）
	replaced := false
	if r.cfg.FlagProtect {
		hit := r.checkResponse(respBody, clientIP)
		if hit != nil {
			fake := fakeFlag()
			re := regexp.MustCompile(hit.Pattern)
			if re.Match(respBody) {
				respBody = re.ReplaceAll(respBody, []byte(fake))
				replaced = true
			}
			r.recordHit(hit, replaced)
		}
	}

	// 写回客户端
	outHdr := w.Header()
	for k, vv := range resp.Header {
		if isHopByHop(k) {
			continue
		}
		if strings.EqualFold(k, "Server") {
			continue
		}
		// 响应体被改写后长度可能变化，移除 Content-Length 交由 Go 自动计算
		if replaced && strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vv {
			outHdr.Add(k, v)
		}
	}
	outHdr.Set("X-Energy-WAF", "protected")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

func clientIP(req *http.Request) string {
	xff := req.Header.Get("X-Forwarded-For")
	if xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host := req.RemoteAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		return host[:i]
	}
	return host
}

var hopByHop = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-authenticate": true,
	"proxy-authorization": true, "te": true, "trailers": true,
	"transfer-encoding": true, "upgrade": true, "proxy-connection": true,
}

func isHopByHop(k string) bool {
	return hopByHop[strings.ToLower(k)]
}

func writeBlock(w http.ResponseWriter, title, reason string) {
	writeBlockStatus(w, http.StatusForbidden, title, reason)
}

func writeBlockStatus(w http.ResponseWriter, status int, title, reason string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	body := "<html><head><meta charset='utf-8'><title>" + htmlEscape(title) +
		"</title></head><body style='font-family:sans-serif;text-align:center;margin-top:15%'>" +
		"<h1>" + htmlEscape(title) + "</h1><p>请求已被通用防御 WAF 拦截。</p>" +
		"<p style='color:#888;font-size:13px'>命中规则：" + htmlEscape(reason) + "</p></body></html>"
	_, _ = io.WriteString(w, body)
}

func htmlEscape(s string) string {
	return html.EscapeString(s)
}

// decodeLayers 多层解码，对抗编码绕过（URL/HTML实体/二次编码）
func decodeLayers(s string) []string {
	if s == "" {
		return nil
	}
	seen := map[string]bool{s: true}
	stack := []string{s}
	pop := func() string {
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		return v
	}
	push := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			stack = append(stack, v)
		}
	}
	for len(stack) > 0 {
		v := pop()
		push(urlDecode(v))
		push(urlDecodePlus(v))
		push(html.UnescapeString(v))
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	return out
}

func urlDecode(s string) string {
	if v, err := url.PathUnescape(s); err == nil {
		return v
	}
	return s
}

func urlDecodePlus(s string) string {
	v, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return v
}

// checkRequest 请求侧检测
func (r *ReverseWAF) checkRequest(req *http.Request, body, ip string) *RVHit {
	r.mu.RLock()
	rules := r.rules
	r.mu.RUnlock()

	path := req.URL.Path
	query := req.URL.RawQuery
	blob := path + "?" + query + " " + body
	variants := decodeLayers(blob)
	hdr := req.Header.Get("User-Agent") + " " + req.Header.Get("Referer") + " " + req.Header.Get("X-Forwarded-For")
	hdrVariants := decodeLayers(hdr)

	for _, rule := range rules {
		if rule.Side != "request" {
			continue
		}
		for _, pat := range rule.Patterns {
			for _, v := range variants {
				if pat.MatchString(v) {
					return &RVHit{RuleID: rule.ID, Name: rule.Name, Action: rule.Action,
						Pattern: pat.String(), Severity: rule.Severity, Side: "request",
						IP: ip, Method: req.Method, Path: path, Time: time.Now().Unix()}
				}
			}
			for _, v := range hdrVariants {
				if pat.MatchString(v) {
					return &RVHit{RuleID: rule.ID, Name: rule.Name, Action: rule.Action,
						Pattern: pat.String(), Severity: rule.Severity, Side: "request",
						IP: ip, Method: req.Method, Path: path, Time: time.Now().Unix()}
				}
			}
		}
	}
	return nil
}

// checkResponse 响应侧检测（flag 泄露）
func (r *ReverseWAF) checkResponse(body []byte, ip string) *RVHit {
	if len(body) == 0 {
		return nil
	}
	r.mu.RLock()
	rules := r.rules
	r.mu.RUnlock()

	text := string(body)
	variants := decodeLayers(text)
	for _, rule := range rules {
		if rule.ID != "flag_protect" {
			continue
		}
		for _, pat := range rule.Patterns {
			for _, v := range variants {
				if pat.MatchString(v) {
					return &RVHit{RuleID: rule.ID, Name: rule.Name, Action: rule.Action,
						Pattern: pat.String(), Severity: rule.Severity, Side: "response",
						IP: ip, Time: time.Now().Unix()}
				}
			}
		}
	}
	return nil
}

// fakeFlag 生成假 flag 迷惑攻击者
func fakeFlag() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "flag{" + hex.EncodeToString(b) + "}"
}

// DisableReverseProxy 便捷关闭（供 Agent 调用）
func (r *ReverseWAF) Close() error {
	return r.Stop()
}

// 避免 unused 引用 httputil（保留以便未来升级路由）
var _ = httputil.NewSingleHostReverseProxy
