// Package embedfs 嵌入前端静态资源
package embedfs

import "embed"

//go:embed web
var FS embed.FS
