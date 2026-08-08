package rag

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"shield-platform/internal/store"
)

// Engine RAG 检索引擎
type Engine struct {
	store *store.Store
}

func NewEngine(s *store.Store) *Engine {
	return &Engine{store: s}
}

// Chunk 分块后的文档片段
type Chunk struct {
	DocID   string
	Title   string
	Content string
	Source  string
	Tokens  []string
}

// ImportText 导入文本知识（按内容 hash 去重；已存在但标签变更时更新标签）
func (e *Engine) ImportText(title, content, source, tags string) (bool, error) {
	h := sha256.Sum256([]byte(title + content))
	hash := hex.EncodeToString(h[:])
	exists, err := e.store.GetKBDocByHash(hash)
	if err != nil {
		return false, err
	}
	if exists {
		if err := e.store.UpdateKBTags(hash, tags); err != nil {
			return false, err
		}
		return false, nil // 已存在
	}
	doc := &store.KBDoc{
		ID:      hash,
		Title:   title,
		Content: content,
		Source:  source,
		Tags:    tags,
		Hash:    hash,
	}
	if err := e.store.UpsertKBDoc(doc); err != nil {
		return false, err
	}
	return true, nil
}

// ImportFile 导入文件（按行读取 txt/md）
func (e *Engine) ImportFile(path, source string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	title := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	var content strings.Builder
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "# ") && strings.TrimSpace(strings.TrimPrefix(line, "# ")) != "" {
			title = strings.TrimSpace(strings.TrimPrefix(line, "# "))
		}
		content.WriteString(line)
		content.WriteString("\n")
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	added, err := e.ImportText(title, content.String(), source, "file")
	if err != nil {
		return 0, err
	}
	if added {
		return 1, nil
	}
	return 0, nil
}

// Delete 删除知识
func (e *Engine) Delete(id string) error {
	return e.store.DeleteKBDoc(id)
}

// List 列出知识
func (e *Engine) List() ([]*store.KBDoc, error) {
	return e.store.ListKBDocs()
}

// SearchResult 检索结果
type SearchResult struct {
	DocID    string   `json:"doc_id"`
	Title    string   `json:"title"`
	Source   string   `json:"source"`
	Tags     string   `json:"tags"`
	Content  string   `json:"content"`
	Score    float64  `json:"score"`
	Matched  []string `json:"matched"`
}

// Search BM25 + 关键词混合检索
func (e *Engine) Search(query string, topK int) ([]*SearchResult, error) {
	docs, err := e.store.ListKBDocs()
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return nil, nil
	}
	if topK <= 0 {
		topK = 5
	}
	qTokens := tokenize(query)
	if len(qTokens) == 0 {
		return nil, nil
	}

	// 构建倒排
	df := make(map[string]int)
	corpus := make([]*Chunk, 0, len(docs))
	for _, d := range docs {
		chunk := &Chunk{DocID: d.ID, Title: d.Title, Content: d.Content, Source: d.Source, Tokens: tokenize(d.Title + " " + d.Content)}
		corpus = append(corpus, chunk)
		seen := make(map[string]bool)
		for _, t := range chunk.Tokens {
			if !seen[t] {
				seen[t] = true
				df[t]++
			}
		}
	}
	n := float64(len(corpus))
	k1, b := 1.5, 0.75

	type scored struct {
		chunk *Chunk
		score float64
	}
	var results []scored
	for _, c := range corpus {
		// BM25
		termFreq := make(map[string]int)
		for _, t := range c.Tokens {
			termFreq[t]++
		}
		avgdl := avgDocLen(corpus)
		var s float64
		for _, q := range qTokens {
			tf := float64(termFreq[q])
			if tf == 0 {
				continue
			}
			idf := math.Log(1 + (n-float64(df[q])+0.5)/(float64(df[q])+0.5))
			dl := float64(len(c.Tokens))
			s += idf * (tf * (k1 + 1)) / (tf + k1*(1-b+b*dl/avgdl))
		}
		// 标题命中加权
		titleBoost := 0.0
		for _, q := range qTokens {
			if strings.Contains(c.Title, q) {
				titleBoost += 2.0
			}
		}
		s += titleBoost
		if s > 0 {
			results = append(results, scored{c, s})
		}
	}

	sort.Slice(results, func(i, j int) bool { return results[i].score > results[j].score })
	if len(results) > topK {
		results = results[:topK]
	}

	var out []*SearchResult
	for _, r := range results {
		out = append(out, &SearchResult{
			DocID:   r.chunk.DocID,
			Title:   r.chunk.Title,
			Source:  r.chunk.Source,
			Tags:    "",
			Content: snippet(r.chunk.Content, query, 500),
			Score:   r.score,
			Matched: qTokens,
		})
	}
	return out, nil
}

func avgDocLen(corpus []*Chunk) float64 {
	var total int
	for _, c := range corpus {
		total += len(c.Tokens)
	}
	if len(corpus) == 0 {
		return 1
	}
	return float64(total) / float64(len(corpus))
}

// ============ 分词 ============

var (
	cjkRe   = regexp.MustCompile(`[\p{Han}]`)
	wordRe  = regexp.MustCompile(`[a-zA-Z0-9_]+`)
	stopMap = map[string]bool{
		"的": true, "了": true, "是": true, "在": true, "我": true, "有": true,
		"和": true, "就": true, "不": true, "人": true, "都": true, "一": true,
		"一个": true, "上": true, "也": true, "很": true, "到": true, "说": true,
		"要": true, "去": true, "你": true, "会": true, "着": true, "没有": true,
		"the": true, "a": true, "an": true, "of": true, "to": true, "and": true,
		"is": true, "in": true, "on": true, "for": true, "with": true,
	}
)

// tokenize 中文按字符双字组 + 英文单词
func tokenize(s string) []string {
	s = strings.ToLower(s)
	var toks []string
	words := wordRe.FindAllString(s, -1)
	for _, w := range words {
		if !cjkRe.MatchString(w) {
			if len(w) >= 2 && !stopMap[w] {
				toks = append(toks, w)
			}
		}
	}
	// 中文字符双字组
	runes := []rune(s)
	for i := 0; i < len(runes)-1; i++ {
		if isCJK(runes[i]) && isCJK(runes[i+1]) {
			bigram := string(runes[i]) + string(runes[i+1])
			if !stopMap[bigram] {
				toks = append(toks, bigram)
			}
		}
	}
	return toks
}

func isCJK(r rune) bool {
	return r >= 0x4E00 && r <= 0x9FFF
}

// snippet 截取命中片段
func snippet(content, query string, maxLen int) string {
	q := strings.ToLower(query)
	idx := strings.Index(strings.ToLower(content), q)
	content = strings.Join(strings.Fields(content), " ")
	runes := []rune(content)
	if idx < 0 || len(runes) <= maxLen {
		if len(runes) > maxLen {
			return string(runes[:maxLen])
		}
		return content
	}
	start := idx - 100
	if start < 0 {
		start = 0
	}
	end := start + maxLen
	if end > len(runes) {
		end = len(runes)
	}
	return "..." + string(runes[start:end]) + "..."
}
