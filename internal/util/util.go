package util

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Logger 简单日志封装
type Logger struct {
	debug bool
}

func NewLogger(debug bool) *Logger {
	return &Logger{debug: debug}
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	if l.debug {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func (l *Logger) Infof(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}

func (l *Logger) Warnf(format string, args ...interface{}) {
	log.Printf("[WARN] "+format, args...)
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

// GenID 生成随机 ID
func GenID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// NowUnix 当前 Unix 秒
func NowUnix() int64 {
	return time.Now().Unix()
}

// Hostname 获取主机名
func Hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

// OSName 判断当前运行系统
func OSName() string {
	return runtime.GOOS
}

// DataDir 获取数据目录（可被环境变量覆盖）
func DataDir() string {
	if d := os.Getenv("SHIELD_DATA_DIR"); d != "" {
		return d
	}
	base, err := os.UserHomeDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, ".shield-platform")
}

// EnsureDir 确保目录存在
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0o755)
}

// AppError 简单应用错误
type AppError struct{ Msg string }

func (e *AppError) Error() string { return e.Msg }

// FmtSize 人类可读大小
func FmtSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
