package rag

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// LLMConfig LLM 配置（用户自行提供，采用项目级环境变量，不读取平台内部 Key）
type LLMConfig struct {
	BaseURL string
	APIKey  string
	Model   string
}

// LoadLLMConfig 从环境变量加载 LLM 配置（面向用户项目命名）
// 支持: USER_LLM_BASE_URL / USER_LLM_API_KEY / USER_LLM_MODEL
// 未配置时返回 nil，表示仅使用本地检索
func LoadLLMConfig() *LLMConfig {
	base := os.Getenv("USER_LLM_BASE_URL")
	key := os.Getenv("USER_LLM_API_KEY")
	model := os.Getenv("USER_LLM_MODEL")
	if base == "" || key == "" {
		return nil
	}
	if model == "" {
		model = "deepseek-chat"
	}
	if !strings.HasSuffix(base, "/v1") && !strings.HasSuffix(base, "/v1/") {
		base = strings.TrimRight(base, "/") + "/v1"
	}
	return &LLMConfig{BaseURL: strings.TrimRight(base, "/"), APIKey: key, Model: model}
}

// AnswerRequest 问答请求
type AnswerRequest struct {
	Question    string   `json:"question"`
	ContextDocs []*SearchResult `json:"context_docs,omitempty"`
}

// Answer 基于检索上下文调用 LLM 生成回答
// 无 LLM 配置时降级为直接返回检索到的知识片段
func (e *Engine) Answer(ctx context.Context, q string, topK int) (string, error) {
	if strings.TrimSpace(q) == "" {
		return "", fmt.Errorf("question is empty")
	}
	docs, err := e.Search(q, topK)
	if err != nil {
		return "", err
	}
	cfg := LoadLLMConfig()
	if cfg == nil {
		// 本地降级：拼装检索片段
		if len(docs) == 0 {
			return "知识库中未检索到相关内容。请先导入应急响应/漏洞知识文档，或配置 USER_LLM_API_KEY 启用 LLM 增强回答。", nil
		}
		var sb strings.Builder
		sb.WriteString("以下为知识库本地检索结果（未配置 LLM，仅返回原文）：\n\n")
		for i, d := range docs {
			sb.WriteString(fmt.Sprintf("[%d] %s (%s)\n%s\n\n", i+1, d.Title, d.Source, d.Content))
		}
		return sb.String(), nil
	}
	return e.callLLM(ctx, cfg, q, docs)
}

func (e *Engine) callLLM(ctx context.Context, cfg *LLMConfig, q string, docs []*SearchResult) (string, error) {
	var context strings.Builder
	for i, d := range docs {
		context.WriteString(fmt.Sprintf("### 知识片段 %d（来源：%s）\n%s\n\n", i+1, d.Source, d.Content))
	}
	user := fmt.Sprintf("请基于以下知识库内容回答应急响应/加固问题。若知识库信息不足，请明确说明。\n\n问题：%s\n\n知识库内容：\n%s", q, context.String())

	payload := map[string]interface{}{
		"model": cfg.Model,
		"messages": []map[string]string{
			{"role": "system", "content": "你是能源行业网络安全应急响应专家，回答需简洁、可操作、包含具体命令。"},
			{"role": "user", "content": user},
		},
		"stream": false,
	}
	body, _ := json.Marshal(payload)
	url := cfg.BaseURL + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("LLM API status %d: %s", resp.StatusCode, string(data))
	}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", err
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("LLM returned no choices")
	}
	return parsed.Choices[0].Message.Content, nil
}
