package api

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"shield-platform"
)

func serveEmbedded(w http.ResponseWriter, r *http.Request) {
	clean := path.Clean(strings.TrimPrefix(r.URL.Path, "/"))
	if clean == "." || clean == "/" {
		clean = "index.html"
	}
	b, err := fs.ReadFile(embedfs.FS, "web/"+clean)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ct := contentType(clean)
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(b)
}

func contentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(name, ".js"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(name, ".png"):
		return "image/png"
	case strings.HasSuffix(name, ".json"):
		return "application/json; charset=utf-8"
	default:
		return "text/plain; charset=utf-8"
	}
}
