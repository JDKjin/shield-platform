// 靶机 Agent 入口
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"shield-platform/internal/agentcore"
	"shield-platform/internal/config"
	"shield-platform/internal/util"
)

func main() {
	var cfgPath, server, name, secret string
	var debug bool
	flag.StringVar(&cfgPath, "c", "", "Agent 配置文件路径")
	flag.StringVar(&server, "s", "", "面板地址，如 ws://192.168.1.10:8080/ws/agent")
	flag.StringVar(&name, "n", "", "靶机显示名")
	flag.StringVar(&secret, "k", "", "回连密钥")
	flag.BoolVar(&debug, "debug", false, "调试日志")
	flag.Parse()

	cfg, err := config.LoadAgent(cfgPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	if cfg.ID == "" {
		cfg.ID = util.GenID()
	}
	if server != "" {
		cfg.Server = server
	}
	if name != "" {
		cfg.Name = name
	}
	if secret != "" {
		cfg.Secret = secret
	}
	if debug {
		cfg.Debug = true
	}
	if err := config.SaveAgent(cfgPath, cfg); err != nil {
		log.Fatalf("保存配置失败: %v", err)
	}

	logger := util.NewLogger(cfg.Debug)
	if err := util.EnsureDir(cfg.DataDir); err != nil {
		log.Fatalf("创建数据目录失败: %v", err)
	}

	logger.Infof("Agent 启动: %s -> %s", cfg.Name, cfg.Server)

	ag := agentcore.NewAgent(cfg, logger)
	go func() {
		if err := ag.Run(); err != nil {
			log.Fatalf("Agent 运行失败: %v", err)
		}
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	logger.Infof("Agent 退出")
	ag.Stop()
}
