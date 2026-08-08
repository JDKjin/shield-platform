// 主控面板入口
package main

import (
	"flag"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"shield-platform/internal/api"
	"shield-platform/internal/config"
	"shield-platform/internal/store"
	"shield-platform/internal/util"
	"shield-platform/internal/ws"
)

func main() {
	var cfgPath, listen, token string
	var debug bool
	flag.StringVar(&cfgPath, "c", "", "面板配置文件路径")
	flag.StringVar(&listen, "l", "", "监听地址，如 :8080")
	flag.StringVar(&token, "token", "", "面板访问令牌")
	flag.BoolVar(&debug, "debug", false, "调试日志")
	flag.Parse()

	cfg, err := config.LoadPanel(cfgPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	if listen != "" {
		cfg.Listen = listen
	}
	if token != "" {
		cfg.Token = token
	}
	if debug {
		cfg.Debug = true
	}

	if err := config.SavePanel(cfgPath, cfg); err != nil {
		log.Fatalf("保存面板配置失败: %v", err)
	}

	logger := util.NewLogger(cfg.Debug)
	if err := util.EnsureDir(cfg.DataDir); err != nil {
		log.Fatalf("创建数据目录失败: %v", err)
	}

	dbPath := filepath.Join(cfg.DataDir, "panel.db")
	st, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}
	defer st.Close()

	hub := ws.NewHub(logger)
	srv := api.NewServer(cfg, st, hub, logger)

	// 打印连接信息
	addr := cfg.Listen
	if addr == "" {
		addr = ":8080"
	}
	logger.Infof("综合防御平台 面板已启动: http://127.0.0.1%s", addr)
	logger.Infof("访问令牌: %s", cfg.Token)
	logger.Infof("Agent 回连地址: ws://<面板IP>%s/ws/agent", addr)
	logger.Infof("Agent 回连密钥: %s", cfg.AgentSecret)

	s := &http.Server{
		Addr:         addr,
		Handler:      srv,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0,
	}
	if err := s.ListenAndServe(); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}
