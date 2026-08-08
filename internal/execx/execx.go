package execx

import (
	"bytes"
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Result 命令执行结果
type Result struct {
	Output     string
	ExitCode   int
	DurationMS int64
	TimedOut   bool
}

// Shell 根据平台返回 shell 调用方式
func Shell() []string {
	if runtime.GOOS == "windows" {
		return []string{"cmd", "/C"}
	}
	return []string{"/bin/sh", "-c"}
}

// Run 执行命令并返回结果
func Run(ctx context.Context, command string, timeout time.Duration) *Result {
	start := time.Now()
	sh := Shell()
	args := append(sh[1:], command)
	cmd := exec.CommandContext(ctx, sh[0], args...)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")

	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()

	res := &Result{
		Output:     buf.String(),
		DurationMS: time.Since(start).Milliseconds(),
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		} else if cctx.Err() == context.DeadlineExceeded {
			res.TimedOut = true
		} else {
			res.ExitCode = -1
		}
	}
	// 截断超大输出
	if len(res.Output) > 2<<20 {
		res.Output = res.Output[:2<<20]
	}
	return res
}

// RunDefault 默认 60s 超时执行
func RunDefault(command string) *Result {
	return Run(context.Background(), command, 60*time.Second)
}

// RunShort 短超时（用于监控，5s）
func RunShort(command string) *Result {
	return Run(context.Background(), command, 5*time.Second)
}

// Sanitize 清理输出（控制字符等）
func Sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 32 && r != '\n' && r != '\t' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
