package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store 数据存储
type Store struct {
	db   *sql.DB
	mu   sync.Mutex
	path string
}

// Open 打开数据库
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, path: path}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) init() error {
	schema := `
CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    host TEXT,
    os TEXT,
    arch TEXT,
    version TEXT,
    status TEXT DEFAULT 'offline',
    ip TEXT,
    web_root TEXT,
    interval INTEGER DEFAULT 3,
    last_seen INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT 0,
    extra TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    target_id TEXT,
    severity TEXT,
    category TEXT,
    title TEXT,
    message TEXT,
    data TEXT DEFAULT '{}',
    time INTEGER DEFAULT 0,
    handled INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS waf_rules (
    id TEXT PRIMARY KEY,
    name TEXT,
    category TEXT,
    pattern TEXT,
    action TEXT DEFAULT 'block',
    enabled INTEGER DEFAULT 1,
    level INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS event_logs (
    id TEXT PRIMARY KEY,
    target_id TEXT,
    type TEXT,
    payload TEXT,
    time INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS command_logs (
    id TEXT PRIMARY KEY,
    target_id TEXT,
    command TEXT,
    output TEXT,
    exit_code INTEGER,
    duration_ms INTEGER,
    time INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS kb_docs (
    id TEXT PRIMARY KEY,
    title TEXT,
    content TEXT,
    source TEXT,
    tags TEXT DEFAULT '',
    hash TEXT,
    created_at INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_target ON alerts(target_id, time);
CREATE INDEX IF NOT EXISTS idx_events_target ON event_logs(target_id, time);
CREATE INDEX IF NOT EXISTS idx_cmdlog_target ON command_logs(target_id, time);
`
	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}
	return s.applyMigrations()
}

// applyMigrations 兼容老库：为已存在的表补充新增列
func (s *Store) applyMigrations() error {
	if !s.hasColumn("waf_rules", "level") {
		if _, err := s.db.Exec(`ALTER TABLE waf_rules ADD COLUMN level INTEGER DEFAULT 0`); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) hasColumn(table, col string) bool {
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false
		}
		if name == col {
			return true
		}
	}
	return false
}

// ============ Settings ============

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// ============ Targets ============

type Target struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Host      string `json:"host"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Version   string `json:"version"`
	Status    string `json:"status"`
	IP        string `json:"ip"`
	WebRoot   string `json:"web_root"`
	Interval  int    `json:"interval"`
	LastSeen  int64  `json:"last_seen"`
	CreatedAt int64  `json:"created_at"`
	Extra     string `json:"extra"`
}

func (s *Store) UpsertTarget(t *Target) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO targets(id,name,host,os,arch,version,status,ip,web_root,interval,last_seen,created_at,extra)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,host=excluded.host,os=excluded.os,
		arch=excluded.arch,version=excluded.version,status=excluded.status,ip=excluded.ip,
		web_root=excluded.web_root,interval=excluded.interval,last_seen=excluded.last_seen,extra=excluded.extra`,
		t.ID, t.Name, t.Host, t.OS, t.Arch, t.Version, t.Status, t.IP, t.WebRoot, t.Interval, t.LastSeen, t.CreatedAt, t.Extra)
	return err
}

func (s *Store) GetTarget(id string) (*Target, error) {
	row := s.db.QueryRow(`SELECT id,name,host,os,arch,version,status,ip,web_root,interval,last_seen,created_at,extra FROM targets WHERE id=?`, id)
	return scanTarget(row)
}

func (s *Store) ListTargets() ([]*Target, error) {
	rows, err := s.db.Query(`SELECT id,name,host,os,arch,version,status,ip,web_root,interval,last_seen,created_at,extra FROM targets ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

func (s *Store) SetTargetStatus(id, status string) error {
	_, err := s.db.Exec(`UPDATE targets SET status=?, last_seen=? WHERE id=?`, status, time.Now().Unix(), id)
	return err
}

func (s *Store) TouchTarget(id string) error {
	_, err := s.db.Exec(`UPDATE targets SET last_seen=? WHERE id=?`, time.Now().Unix(), id)
	return err
}

func (s *Store) DeleteTarget(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM targets WHERE id=?`, id)
	return err
}

type rowScanner interface{ Scan(dest ...interface{}) error }

func scanTarget(r rowScanner) (*Target, error) {
	var t Target
	err := r.Scan(&t.ID, &t.Name, &t.Host, &t.OS, &t.Arch, &t.Version, &t.Status, &t.IP, &t.WebRoot, &t.Interval, &t.LastSeen, &t.CreatedAt, &t.Extra)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ============ Alerts ============

type Alert struct {
	ID        string `json:"id"`
	TargetID  string `json:"target_id"`
	Severity  string `json:"severity"`
	Category  string `json:"category"`
	Title     string `json:"title"`
	Message   string `json:"message"`
	Data      string `json:"data"`
	Time      int64  `json:"time"`
	Handled   int    `json:"handled"`
}

func (s *Store) AddAlert(a *Alert) error {
	if a.ID == "" {
		a.ID = fmt.Sprintf("%d%s", time.Now().UnixNano(), a.TargetID)
	}
	if a.Time == 0 {
		a.Time = time.Now().Unix()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO alerts(id,target_id,severity,category,title,message,data,time,handled)
		VALUES(?,?,?,?,?,?,?,?,?)`, a.ID, a.TargetID, a.Severity, a.Category, a.Title, a.Message, a.Data, a.Time, a.Handled)
	return err
}

func (s *Store) ListAlerts(limit int) ([]*Alert, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT id,target_id,severity,category,title,message,data,time,handled FROM alerts ORDER BY time DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.TargetID, &a.Severity, &a.Category, &a.Title, &a.Message, &a.Data, &a.Time, &a.Handled); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, nil
}

func (s *Store) CountAlertsUnhandled() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE handled=0`).Scan(&n)
	return n, err
}

func (s *Store) MarkAlertHandled(id string) error {
	_, err := s.db.Exec(`UPDATE alerts SET handled=1 WHERE id=?`, id)
	return err
}

// ============ WAF Rules ============

type WAFRule struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Category  string `json:"category"`
	Pattern   string `json:"pattern"`
	Action    string `json:"action"`
	Enabled   int    `json:"enabled"`
	Level     int    `json:"level"`
	CreatedAt int64  `json:"created_at"`
}

func (s *Store) UpsertWAFRule(r *WAFRule) error {
	if r.ID == "" {
		r.ID = fmt.Sprintf("r_%d", time.Now().UnixNano())
	}
	if r.CreatedAt == 0 {
		r.CreatedAt = time.Now().Unix()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO waf_rules(id,name,category,pattern,action,enabled,level,created_at)
		VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,category=excluded.category,
		pattern=excluded.pattern,action=excluded.action,enabled=excluded.enabled,level=excluded.level`,
		r.ID, r.Name, r.Category, r.Pattern, r.Action, r.Enabled, r.Level, r.CreatedAt)
	return err
}

func (s *Store) ListWAFRules() ([]*WAFRule, error) {
	rows, err := s.db.Query(`SELECT id,name,category,pattern,action,enabled,level,created_at FROM waf_rules ORDER BY category, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WAFRule
	for rows.Next() {
		var r WAFRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Category, &r.Pattern, &r.Action, &r.Enabled, &r.Level, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	return out, nil
}

func (s *Store) DeleteWAFRule(id string) error {
	_, err := s.db.Exec(`DELETE FROM waf_rules WHERE id=?`, id)
	return err
}

// ============ Event Logs ============

func (s *Store) AddEvent(targetID, typ string, payload interface{}) error {
	b, _ := json.Marshal(payload)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO event_logs(id,target_id,type,payload,time) VALUES(?,?,?,?,?)`,
		fmt.Sprintf("%d%s", time.Now().UnixNano(), targetID), targetID, typ, string(b), time.Now().Unix())
	return err
}

func (s *Store) ListEvents(limit int) ([]map[string]interface{}, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id,target_id,type,payload,time FROM event_logs ORDER BY time DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var id, targetID, typ, payload string
		var t int64
		if err := rows.Scan(&id, &targetID, &typ, &payload, &t); err != nil {
			return nil, err
		}
		out = append(out, map[string]interface{}{"id": id, "target_id": targetID, "type": typ, "payload": json.RawMessage(payload), "time": t})
	}
	return out, nil
}

// ============ Command Logs ============

type CommandLog struct {
	ID         string `json:"id"`
	TargetID   string `json:"target_id"`
	Command    string `json:"command"`
	Output     string `json:"output"`
	ExitCode   int    `json:"exit_code"`
	DurationMS int64  `json:"duration_ms"`
	Time       int64  `json:"time"`
}

func (s *Store) AddCommandLog(l *CommandLog) error {
	if l.ID == "" {
		l.ID = fmt.Sprintf("c_%d", time.Now().UnixNano())
	}
	if l.Time == 0 {
		l.Time = time.Now().Unix()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO command_logs(id,target_id,command,output,exit_code,duration_ms,time) VALUES(?,?,?,?,?,?,?)`,
		l.ID, l.TargetID, l.Command, l.Output, l.ExitCode, l.DurationMS, l.Time)
	return err
}

func (s *Store) ListCommandLogs(targetID string, limit int) ([]*CommandLog, error) {
	if limit <= 0 {
		limit = 100
	}
	var rows *sql.Rows
	var err error
	if targetID == "" {
		rows, err = s.db.Query(`SELECT id,target_id,command,output,exit_code,duration_ms,time FROM command_logs ORDER BY time DESC LIMIT ?`, limit)
	} else {
		rows, err = s.db.Query(`SELECT id,target_id,command,output,exit_code,duration_ms,time FROM command_logs WHERE target_id=? ORDER BY time DESC LIMIT ?`, targetID, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CommandLog
	for rows.Next() {
		var l CommandLog
		if err := rows.Scan(&l.ID, &l.TargetID, &l.Command, &l.Output, &l.ExitCode, &l.DurationMS, &l.Time); err != nil {
			return nil, err
		}
		out = append(out, &l)
	}
	return out, nil
}

// ============ Knowledge Base (RAG) ============

type KBDoc struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	Source    string `json:"source"`
	Tags      string `json:"tags"`
	Hash      string `json:"hash"`
	CreatedAt int64  `json:"created_at"`
}

func (s *Store) UpsertKBDoc(d *KBDoc) error {
	if d.ID == "" {
		d.ID = fmt.Sprintf("kb_%d", time.Now().UnixNano())
	}
	if d.CreatedAt == 0 {
		d.CreatedAt = time.Now().Unix()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO kb_docs(id,title,content,source,tags,hash,created_at)
		VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET title=excluded.title,content=excluded.content,
		source=excluded.source,tags=excluded.tags,hash=excluded.hash`,
		d.ID, d.Title, d.Content, d.Source, d.Tags, d.Hash, d.CreatedAt)
	return err
}

func (s *Store) GetKBDocByHash(hash string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM kb_docs WHERE hash=?`, hash).Scan(&n)
	return n > 0, err
}

func (s *Store) UpdateKBTags(hash, tags string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE kb_docs SET tags=? WHERE hash=?`, tags, hash)
	return err
}

func (s *Store) ListKBDocs() ([]*KBDoc, error) {
	rows, err := s.db.Query(`SELECT id,title,content,source,tags,hash,created_at FROM kb_docs ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*KBDoc
	for rows.Next() {
		var d KBDoc
		if err := rows.Scan(&d.ID, &d.Title, &d.Content, &d.Source, &d.Tags, &d.Hash, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &d)
	}
	return out, nil
}

func (s *Store) DeleteKBDoc(id string) error {
	_, err := s.db.Exec(`DELETE FROM kb_docs WHERE id=?`, id)
	return err
}
