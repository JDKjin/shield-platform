package config

import (
	"encoding/json"
	"os"
	"path/filepath"

	"shield-platform/internal/util"
)

// PanelConfig 主控面板配置
type PanelConfig struct {
	Listen       string `json:"listen"`        // 面板监听地址，默认 :8080
	Token        string `json:"token"`         // 面板访问令牌
	AgentSecret  string `json:"agent_secret"`  // Agent 回连鉴权密钥
	DataDir      string `json:"data_dir"`      // 数据目录
	Debug        bool   `json:"debug"`         // 调试日志
	RAGDataDir   string `json:"rag_data_dir"`  // RAG 知识库目录
}

// DefaultPanel 默认面板配置
func DefaultPanel() *PanelConfig {
	return &PanelConfig{
		Listen:      ":8080",
		Token:       "admin",
		AgentSecret: util.GenID() + util.GenID(),
		DataDir:     util.DataDir(),
		Debug:       false,
	}
}

// LoadPanel 从文件加载面板配置，不存在则生成默认
func LoadPanel(path string) (*PanelConfig, error) {
	if path == "" {
		path = filepath.Join(util.DataDir(), "panel.json")
	}
	cfg := DefaultPanel()
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, cfg); err != nil {
			return nil, err
		}
	} else {
		if err := util.EnsureDir(filepath.Dir(path)); err != nil {
			return nil, err
		}
		b, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// SavePanel 保存面板配置
func SavePanel(path string, cfg *PanelConfig) error {
	if path == "" {
		path = filepath.Join(util.DataDir(), "panel.json")
	}
	if err := util.EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// AgentConfig 靶机 Agent 配置
type AgentConfig struct {
	ID          string `json:"id"`           // 靶机唯一 ID，首次运行生成并持久化
	Server      string `json:"server"`       // 面板地址 ws://host:port/ws/agent
	Name        string `json:"name"`         // 靶机显示名
	Secret      string `json:"secret"`       // 回连密钥（与面板一致）
	Interval    int    `json:"interval"`     // 心跳/监控间隔秒
	DataDir     string `json:"data_dir"`     // 本地数据目录
	WebRoot     string `json:"web_root"`     // Web 根目录（WAF 部署用）
	PhpCmd      string `json:"php_cmd"`      // PHP 可执行路径
	AutoHarden  bool   `json:"auto_harden"`  // 回连后是否自动执行一键加固
	AutoDeployWAF bool `json:"auto_deploy_waf"` // 回连后是否自动部署软WAF
	AutoDefense bool   `json:"auto_defense"` // 回连后是否启动持续防御守护
	Defense     *DefenseConfig `json:"defense,omitempty"` // 防御守护配置
	Debug       bool   `json:"debug"`
}

// DefenseConfig 防御守护配置（与 defense.Config 对齐）
type DefenseConfig struct {
	WatchPaths      []string `json:"watch_paths"`
	QuarantineDir   string   `json:"quarantine_dir"`
	BackupDir       string   `json:"backup_dir"`
	MonitorInterval int      `json:"monitor_interval"`
	BackdoorSigs    []string `json:"backdoor_sigs"`
	ConnWhitelist   []string `json:"conn_whitelist"`
	BruteThreshold  int      `json:"brute_threshold"`
	WebExt          []string `json:"web_ext"`
}

// DefaultAgent 默认 Agent 配置
func DefaultAgent() *AgentConfig {
	return &AgentConfig{
		ID:            util.GenID(),
		Server:        "ws://127.0.0.1:8080/ws/agent",
		Name:          util.Hostname(),
		Secret:        "",
		Interval:      3,
		DataDir:       util.DataDir(),
		WebRoot:       "/var/www/html",
		PhpCmd:        "",
		AutoHarden:    false,
		AutoDeployWAF: false,
		AutoDefense:   false,
		Defense:       nil,
		Debug:         false,
	}
}

// LoadAgent 加载 Agent 配置
func LoadAgent(path string) (*AgentConfig, error) {
	if path == "" {
		path = filepath.Join(util.DataDir(), "agent.json")
	}
	cfg := DefaultAgent()
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, cfg); err != nil {
			return nil, err
		}
	} else {
		if err := util.EnsureDir(filepath.Dir(path)); err != nil {
			return nil, err
		}
		b, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// SaveAgent 保存 Agent 配置
func SaveAgent(path string, cfg *AgentConfig) error {
	if path == "" {
		path = filepath.Join(util.DataDir(), "agent.json")
	}
	if err := util.EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
