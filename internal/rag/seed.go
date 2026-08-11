package rag

import (
	"embed"
	"io/fs"
	"path"
	"strings"
)

//go:embed seeds/*.md
var seedFS embed.FS

// SeedIfEmpty 导入预置文档（按内容 hash 去重，可增量补充新种子）
func (e *Engine) SeedIfEmpty() error {
	entries, err := fs.ReadDir(seedFS, "seeds")
	if err != nil {
		return err
	}
	added := 0
	for _, en := range entries {
		if en.IsDir() {
			continue
		}
		name := en.Name()
		// 注意：embed.FS 始终使用正斜杠分隔符，必须用 path.Join 而非 filepath.Join
		// 否则在 Windows 上 filepath.Join 会产生反斜杠导致 "file does not exist"
		b, err := seedFS.ReadFile(path.Join("seeds", name))
		if err != nil {
			return err
		}
		title := strings.TrimSuffix(name, path.Ext(name))
		tags := seedTags(title)
		ok, err := e.ImportText(title, string(b), "预置知识库", tags)
		if err != nil {
			return err
		}
		if ok {
			added++
		}
	}
	return nil
}

// seedTags 根据种子文档标题推断分类标签
func seedTags(title string) string {
	t := title
	base := "内置"
	var cats []string
	has := func(kws ...string) bool {
		for _, k := range kws {
			if strings.Contains(t, k) {
				return true
			}
		}
		return false
	}
	if has("Linux", "加固", "hardening", "incident") {
		cats = append(cats, "加固")
	}
	if has("Windows", "Win10", "Server") {
		cats = append(cats, "Windows")
	}
	if has("Web", "webshell", "后门") {
		cats = append(cats, "Web安全")
	}
	if has("工控", "能源", "发电", "电网", "油气", "电力") {
		cats = append(cats, "工控安全")
	}
	if has("应急", "incident", "突发") {
		cats = append(cats, "应急响应")
	}
	if has("取证", "溯源", "Writeup", "IOC") {
		cats = append(cats, "取证溯源")
	}
	if has("渗透", "攻击", "红队", "工具", "免杀", "对抗", "隐蔽") {
		cats = append(cats, "攻击对抗")
	}
	if has("容器", "Docker") {
		cats = append(cats, "容器安全")
	}
	if has("中间件", "CVE", "漏洞", "数据库", "MySQL", "Redis", "Nginx", "Tomcat") {
		cats = append(cats, "漏洞库")
	}
	if has("Java", "Spring", "Shiro", "JAR", "JVM", "Tomcat", "内存马", "反序列化", "Actuator", "Arthas", "Fastjson", "Log4j", "heapdump") {
		cats = append(cats, "Java安全")
	}
	if has("MFA", "多因素", "认证", "权限控制", "PoLP", "爆破", "登录") {
		cats = append(cats, "认证强化")
	}
	if has("赛事", "综合防御", "规则", "计分", "FAQ", "画像", "策略") {
		cats = append(cats, "赛事知识")
	}
	if has("CTF", "Crypto", "MISC", "Writeup", "隐写", "密码学", "工控流量") {
		cats = append(cats, "CTF")
	}
	cats = append(cats, "应急", "防护")
	seen := map[string]bool{}
	out := []string{base}
	for _, c := range cats {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return strings.Join(out, ",")
}
