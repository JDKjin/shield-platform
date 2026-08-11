#!/usr/bin/env bash
# 综合防御平台 交叉编译脚本
# 产物输出到 dist/ 目录
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"
VERSION="${1:-1.0.0}"
mkdir -p "$DIST"
cd "$ROOT"

# 编译面板（Linux amd64/386/arm64）
echo "==> 构建 panel (linux/amd64)"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w" \
  -o "$DIST/shield-panel-linux-amd64" "$ROOT/cmd/panel"
echo "==> 构建 panel (linux/386)"
CGO_ENABLED=0 GOOS=linux GOARCH=386 \
  go build -trimpath -ldflags "-s -w" \
  -o "$DIST/shield-panel-linux-386" "$ROOT/cmd/panel"
echo "==> 构建 panel (linux/arm64)"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags "-s -w" \
  -o "$DIST/shield-panel-linux-arm64" "$ROOT/cmd/panel"

# 编译面板（Windows amd64/386/arm64）
echo "==> 构建 panel (windows/amd64)"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w" \
  -o "$DIST/shield-panel-windows-amd64.exe" "$ROOT/cmd/panel"
echo "==> 构建 panel (windows/386)"
CGO_ENABLED=0 GOOS=windows GOARCH=386 \
  go build -trimpath -ldflags "-s -w" \
  -o "$DIST/shield-panel-windows-386.exe" "$ROOT/cmd/panel"
echo "==> 构建 panel (windows/arm64)"
CGO_ENABLED=0 GOOS=windows GOARCH=arm64 \
  go build -trimpath -ldflags "-s -w" \
  -o "$DIST/shield-panel-windows-arm64.exe" "$ROOT/cmd/panel"

# 编译 Agent（Linux amd64/386/arm64）
echo "==> 构建 agent (linux/amd64)"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w" \
  -o "$DIST/shield-agent-linux-amd64" "$ROOT/cmd/agent"
echo "==> 构建 agent (linux/386)"
CGO_ENABLED=0 GOOS=linux GOARCH=386 \
  go build -trimpath -ldflags "-s -w" \
  -o "$DIST/shield-agent-linux-386" "$ROOT/cmd/agent"
echo "==> 构建 agent (linux/arm64)"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags "-s -w" \
  -o "$DIST/shield-agent-linux-arm64" "$ROOT/cmd/agent"

# 编译 Agent（Windows amd64/386/arm64）
echo "==> 构建 agent (windows/amd64)"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w" \
  -o "$DIST/shield-agent-windows-amd64.exe" "$ROOT/cmd/agent"
echo "==> 构建 agent (windows/386)"
CGO_ENABLED=0 GOOS=windows GOARCH=386 \
  go build -trimpath -ldflags "-s -w" \
  -o "$DIST/shield-agent-windows-386.exe" "$ROOT/cmd/agent"
echo "==> 构建 agent (windows/arm64)"
CGO_ENABLED=0 GOOS=windows GOARCH=arm64 \
  go build -trimpath -ldflags "-s -w" \
  -o "$DIST/shield-agent-windows-arm64.exe" "$ROOT/cmd/agent"

ls -lh "$DIST"
