package waf

import (
	"sync"
	"time"
)

// IPBanConfig 动态 IP 封禁配置
type IPBanConfig struct {
	Enabled     bool     `json:"enabled"`
	Threshold   int      `json:"threshold"`    // 攻击触发封禁阈值（命中次数）
	TTLSeconds  int      `json:"ttl_seconds"`  // 封禁时长
	RateLimit   int      `json:"rate_limit"`   // 单窗口最大请求数
	RateWindow  int      `json:"rate_window"`  // 窗口秒数
	Whitelist   []string `json:"whitelist,omitempty"`
}

// IPBanStats 封禁统计
type IPBanStats struct {
	TotalBanned   int            `json:"total_banned"`
	BanByAttack   int            `json:"ban_by_attack"`
	BanByRate     int            `json:"ban_by_rate"`
	ManualBan     int            `json:"manual_ban"`
}

// BanEntry 封禁快照条目
type BanEntry struct {
	IP        string `json:"ip"`
	ExpireIn  int64  `json:"expire_in"`
	Reason    string `json:"reason"`
}

// IPBan 动态 IP 封禁 + CC 频率限制（线程安全，纯内存）
type IPBan struct {
	mu        sync.RWMutex
	enabled   bool
	bans      map[string]int64
	banReason map[string]string
	attackCnt map[string]int
	rate      map[string][]int64
	whitelist map[string]bool

	threshold  int
	ttl        time.Duration
	rateLimit  int
	rateWindow time.Duration

	totalBanned int
	stats       IPBanStats
}

// NewIPBan 默认配置实例
func NewIPBan() *IPBan {
	return &IPBan{
		enabled:   true,
		bans:      make(map[string]int64),
		banReason: make(map[string]string),
		attackCnt: make(map[string]int),
		rate:      make(map[string][]int64),
		whitelist: make(map[string]bool),
		threshold: 5,
		ttl:       300 * time.Second,
		rateLimit: 100,
		rateWindow: 10 * time.Second,
	}
}

// Configure 应用配置
func (b *IPBan) Configure(cfg IPBanConfig) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.enabled = cfg.Enabled
	if cfg.Threshold > 0 {
		b.threshold = cfg.Threshold
	}
	if cfg.TTLSeconds >= 30 {
		b.ttl = time.Duration(cfg.TTLSeconds) * time.Second
	}
	if cfg.RateLimit > 0 {
		b.rateLimit = cfg.RateLimit
	}
	if cfg.RateWindow > 0 {
		b.rateWindow = time.Duration(cfg.RateWindow) * time.Second
	}
	b.whitelist = make(map[string]bool, len(cfg.Whitelist))
	for _, ip := range cfg.Whitelist {
		b.whitelist[ip] = true
	}
}

// IsBanned 判断 IP 是否被封禁
func (b *IPBan) IsBanned(ip string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if !b.enabled {
		return false
	}
	if b.whitelist[ip] {
		return false
	}
	exp, ok := b.bans[ip]
	if !ok {
		return false
	}
	now := time.Now().Unix()
	if exp > now {
		return true
	}
	b.mu.RUnlock()
	b.mu.Lock()
	delete(b.bans, ip)
	delete(b.banReason, ip)
	b.mu.Unlock()
	b.mu.RLock()
	return false
}

// CheckRate 滑动窗口计数，超限自动封禁并返回 true
func (b *IPBan) CheckRate(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.enabled || b.whitelist[ip] {
		return false
	}
	now := time.Now().Unix()
	q := b.rate[ip]
	window := int64(b.rateWindow.Seconds())
	keep := q[:0]
	for _, t := range q {
		if now-t <= window {
			keep = append(keep, t)
		}
	}
	keep = append(keep, now)
	b.rate[ip] = keep
	if len(keep) > b.rateLimit {
		b.banLocked(ip, "rate")
		return true
	}
	return false
}

// OnAttack 命中拦截规则时计数，超阈值自动封禁
func (b *IPBan) OnAttack(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.enabled || b.whitelist[ip] {
		return false
	}
	b.attackCnt[ip]++
	if b.attackCnt[ip] >= b.threshold {
		b.banLocked(ip, "attack")
		return true
	}
	return false
}

func (b *IPBan) banLocked(ip, reason string) {
	b.bans[ip] = time.Now().Unix() + int64(b.ttl.Seconds())
	b.banReason[ip] = reason
	b.totalBanned++
	switch reason {
	case "attack":
		b.stats.BanByAttack++
	case "rate":
		b.stats.BanByRate++
	default:
		b.stats.ManualBan++
	}
}

// Ban 手动封禁
func (b *IPBan) Ban(ip string, ttlSeconds int, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ttlSeconds <= 0 {
		ttlSeconds = int(b.ttl.Seconds())
	}
	b.bans[ip] = time.Now().Unix() + int64(ttlSeconds)
	b.banReason[ip] = reason
	b.stats.ManualBan++
}

// Unban 解封
func (b *IPBan) Unban(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.bans, ip)
	delete(b.banReason, ip)
	delete(b.attackCnt, ip)
	delete(b.rate, ip)
}

// AddWhitelist 加入白名单（同时解封）
func (b *IPBan) AddWhitelist(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.whitelist[ip] = true
	delete(b.bans, ip)
	delete(b.banReason, ip)
}

// RemoveWhitelist 移除白名单
func (b *IPBan) RemoveWhitelist(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.whitelist, ip)
}

// Snapshot 快照：当前封禁、统计、白名单
func (b *IPBan) Snapshot() map[string]interface{} {
	b.mu.RLock()
	defer b.mu.RUnlock()
	now := time.Now().Unix()
	bans := make([]BanEntry, 0)
	for ip, exp := range b.bans {
		if exp > now {
			bans = append(bans, BanEntry{IP: ip, ExpireIn: exp - now, Reason: b.banReason[ip]})
		}
	}
	wl := make([]string, 0, len(b.whitelist))
	for ip := range b.whitelist {
		wl = append(wl, ip)
	}
	attackCnt := make(map[string]int)
	for ip, n := range b.attackCnt {
		if n > 0 {
			attackCnt[ip] = n
		}
	}
	return map[string]interface{}{
		"enabled":      b.enabled,
		"bans":         bans,
		"whitelist":    wl,
		"total_banned": b.totalBanned,
		"stats":        b.stats,
		"attack_count": attackCnt,
	}
}
