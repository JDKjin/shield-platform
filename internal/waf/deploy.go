package waf

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"shield-platform/internal/execx"
)

// DeployRequest 部署请求
type DeployRequest struct {
	WebRoot      string `json:"web_root"`
	WAFFileName  string `json:"waf_filename"`
	AntiImmortal bool   `json:"anti_immortal"`
	BlockAction  string `json:"block_action"`
	Rules        []*Rule `json:"rules,omitempty"`
}

// DeployResult 部署结果
type DeployResult struct {
	WAFPath    string   `json:"waf_path"`
	UserIni    string   `json:"user_ini"`
	Immutable  string   `json:"immutable,omitempty"`
	Created    []string `json:"created"`
	Errors     []string `json:"errors"`
}

// Deploy 在本地靶机执行软WAF部署
// 流程: 写 waf.php -> 写 .user.ini(auto_prepend_file) -> chattr +i 防不死马
func Deploy(rules []*Rule, req *DeployRequest) (*DeployResult, error) {
	res := &DeployResult{}
	if req.WebRoot == "" {
		req.WebRoot = "/var/www/html"
	}
	if req.WAFFileName == "" {
		req.WAFFileName = "waf.php"
	}
	if req.BlockAction == "" {
		req.BlockAction = "403"
	}
	if !strings.HasSuffix(req.WAFFileName, ".php") {
		req.WAFFileName += ".php"
	}

	if err := os.MkdirAll(req.WebRoot, 0o755); err != nil {
		return nil, fmt.Errorf("web_root not accessible: %w", err)
	}

	code := GenPHP(rules, req.AntiImmortal, req.BlockAction)
	wafPath := filepath.Join(req.WebRoot, req.WAFFileName)
	if err := os.WriteFile(wafPath, []byte(code), 0o644); err != nil {
		return nil, fmt.Errorf("write waf failed: %w", err)
	}
	res.WAFPath = wafPath
	res.Created = append(res.Created, wafPath)

	iniPath := filepath.Join(req.WebRoot, ".user.ini")
	ini := UserIni(req.WAFFileName)
	if err := os.WriteFile(iniPath, []byte(ini), 0o644); err != nil {
		res.Errors = append(res.Errors, err.Error())
	} else {
		res.UserIni = iniPath
		res.Created = append(res.Created, iniPath)
	}

	// 部署完成提示（.user.ini 对 PHP-FPM/FastCGI 生效，无需重启）
	if res.Errors == nil {
		res.Errors = []string{}
	}

	// chattr +i 加固（仅 linux 且非容器特殊文件系统时生效）
	if isLinux() {
		r := execx.RunDefault(fmt.Sprintf(`chattr +i %s %s 2>&1 || chattr +i %s 2>&1; lsattr %s 2>&1`, wafPath, iniPath, wafPath, wafPath))
		res.Immutable = strings.TrimSpace(r.Output)
	}
	return res, nil
}

// Disable 禁用软WAF（删除 .user.ini 与 waf.php 的不可变位并移除）
func Disable(req *DeployRequest) (*DeployResult, error) {
	res := &DeployResult{}
	if req.WebRoot == "" {
		req.WebRoot = "/var/www/html"
	}
	if req.WAFFileName == "" {
		req.WAFFileName = "waf.php"
	}
	if !strings.HasSuffix(req.WAFFileName, ".php") {
		req.WAFFileName += ".php"
	}
	if isLinux() {
		execx.RunDefault(fmt.Sprintf("chattr -i %s %s 2>/dev/null; chattr -i %s 2>/dev/null", filepath.Join(req.WebRoot, req.WAFFileName), filepath.Join(req.WebRoot, ".user.ini"), filepath.Join(req.WebRoot, req.WAFFileName)))
	}
	_ = os.Remove(filepath.Join(req.WebRoot, req.WAFFileName))
	_ = os.Remove(filepath.Join(req.WebRoot, ".user.ini"))
	res.Created = []string{"removed waf.php and .user.ini"}
	return res, nil
}

func isLinux() bool {
	return runtime.GOOS == "linux"
}

// ExportJSON 规则序列化为 JSON 字节
func ExportJSON(rules []*Rule) ([]byte, error) {
	return json.MarshalIndent(rules, "", "  ")
}

// ImportJSON 从 JSON 导入规则
func ImportJSON(b []byte) ([]*Rule, error) {
	var rules []*Rule
	if err := json.Unmarshal(b, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}
