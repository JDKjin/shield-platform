package defense

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// BackupResult 备份结果
type BackupResult struct {
	OK   bool   `json:"ok"`
	Path string `json:"path"`
	Size int64  `json:"size"`
	Msg  string `json:"msg"`
}

// RestoreResult 回滚结果
type RestoreResult struct {
	OK       bool     `json:"ok"`
	Msg      string   `json:"msg"`
	Backup   string   `json:"backup,omitempty"`
	Restored []string `json:"restored"`
}

// BackupWeb 把 WatchPaths 下存在的目录打包到 BackupDir（tar.gz，内置实现）
func (m *Monitor) BackupWeb() BackupResult {
	dirs := m.existingPaths()
	if len(dirs) == 0 {
		return BackupResult{OK: false, Msg: "无可备份目录"}
	}
	bd := m.cfg.BackupDir
	if bd == "" {
		bd = "logs/web_backup"
	}
	if err := os.MkdirAll(bd, 0o755); err != nil {
		return BackupResult{OK: false, Msg: "创建备份目录失败: " + err.Error()}
	}
	ts := time.Now().Format("20060102-150405")
	dest := filepath.Join(bd, "web_backup_"+ts+".tar.gz")
	f, err := os.Create(dest)
	if err != nil {
		return BackupResult{OK: false, Msg: "创建备份文件失败: " + err.Error()}
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	written := int64(0)
	for _, dir := range dirs {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			name := strings.TrimPrefix(path, string(filepath.Separator))
			link := ""
			if info.Mode()&os.ModeSymlink != 0 {
				if target, e := os.Readlink(path); e == nil {
					link = target
				}
			}
			hdr, err := tar.FileInfoHeader(info, link)
			if err != nil {
				return nil
			}
			hdr.Name = name
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			if info.IsDir() || link != "" {
				return nil
			}
			src, err := os.Open(path)
			if err != nil {
				return nil
			}
			n, cerr := io.Copy(tw, src)
			src.Close()
			written += n
			if cerr != nil {
				return cerr
			}
			return nil
		})
		if err != nil {
			tw.Close()
			gw.Close()
			f.Close()
			_ = os.Remove(dest)
			return BackupResult{OK: false, Msg: "备份失败: " + err.Error()}
		}
	}
	if err := tw.Close(); err != nil {
		gw.Close()
		f.Close()
		_ = os.Remove(dest)
		return BackupResult{OK: false, Msg: "备份失败: " + err.Error()}
	}
	gw.Close()
	f.Close()
	st, err := os.Stat(dest)
	size := int64(0)
	if err == nil {
		size = st.Size()
	}
	_ = written
	if size <= 0 {
		_ = os.Remove(dest)
		return BackupResult{OK: false, Msg: "备份为空文件"}
	}
	msg := fmt.Sprintf("备份成功 -> %s (%d bytes)", dest, size)
	m.emit("backup_web", "info", msg)
	return BackupResult{OK: true, Path: dest, Size: size, Msg: msg}
}

// existingPaths 返回存在且是目录的 WatchPaths
func (m *Monitor) existingPaths() []string {
	var out []string
	for _, p := range m.cfg.WatchPaths {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

// ListBackups 列出可用备份文件
func (m *Monitor) ListBackups() []string {
	bd := m.cfg.BackupDir
	if bd == "" {
		bd = "logs/web_backup"
	}
	var out []string
	if ents, err := os.ReadDir(bd); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			if strings.HasSuffix(e.Name(), ".tar.gz") || strings.HasSuffix(e.Name(), ".zip") {
				out = append(out, filepath.Join(bd, e.Name()))
			}
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out
}

// RollbackWeb 恢复备份到原目录（先备份当前再覆盖）
func (m *Monitor) RollbackWeb(backupName string) RestoreResult {
	bd := m.cfg.BackupDir
	if bd == "" {
		bd = "logs/web_backup"
	}
	target := m.resolveBackup(backupName)
	if target == "" {
		return RestoreResult{OK: false, Msg: "未找到备份文件: " + backupName}
	}

	// 1) 回滚前先备份当前目录（安全网）
	cur := m.BackupWeb()
	if !cur.OK {
		return RestoreResult{OK: false, Msg: "回滚前备份当前目录失败: " + cur.Msg}
	}

	// 2) 解压到临时目录
	tmp := filepath.Join(bd, "_rollback_tmp")
	_ = os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return RestoreResult{OK: false, Msg: "创建临时目录失败: " + err.Error()}
	}
	if strings.HasSuffix(target, ".zip") {
		if err := unzipTo(target, tmp); err != nil {
			_ = os.RemoveAll(tmp)
			return RestoreResult{OK: false, Msg: "解压备份失败: " + err.Error()}
		}
	} else {
		if err := untarTo(target, tmp); err != nil {
			_ = os.RemoveAll(tmp)
			return RestoreResult{OK: false, Msg: "解压备份失败: " + err.Error()}
		}
	}

	// 3) 覆盖恢复原目录
	restored := []string{}
	for _, base := range m.cfg.WatchPaths {
		pb := base
		st, err := os.Stat(pb)
		if err != nil || !st.IsDir() {
			continue
		}
		src := findRestoreDir(tmp, filepath.Base(pb), pb)
		if src == "" {
			continue
		}
		// 清空原目录
		if ents, err := os.ReadDir(pb); err == nil {
			for _, e := range ents {
				_ = os.RemoveAll(filepath.Join(pb, e.Name()))
			}
		}
		// 复制恢复
		if err := copyTree(src, pb); err != nil {
			m.emit("rollback_web", "error", "恢复 "+pb+" 部分失败: "+err.Error())
		}
		restored = append(restored, pb)
	}
	_ = os.RemoveAll(tmp)
	msg := "回滚完成，恢复目录: " + strings.Join(restored, ", ")
	m.emit("rollback_web", "info", msg)
	return RestoreResult{OK: true, Msg: msg, Backup: target, Restored: restored}
}

func (m *Monitor) resolveBackup(name string) string {
	bd := m.cfg.BackupDir
	if bd == "" {
		bd = "logs/web_backup"
	}
	if name != "" {
		// 绝对路径或备份目录内文件
		cand := name
		if !filepath.IsAbs(cand) {
			cand = filepath.Join(bd, filepath.Base(name))
		}
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand
		}
		// 允许只传时间戳部分
		if ents, err := os.ReadDir(bd); err == nil {
			for _, e := range ents {
				if strings.Contains(e.Name(), name) {
					return filepath.Join(bd, e.Name())
				}
			}
		}
		return ""
	}
	// 最新备份
	list := m.ListBackups()
	if len(list) > 0 {
		return list[0]
	}
	return ""
}

// findRestoreDir 在解压临时目录定位与原目录对应的恢复源目录（按名字后缀匹配最多者）
func findRestoreDir(tmp, name, target string) string {
	var candidates []string
	_ = filepath.Walk(tmp, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return nil
		}
		if filepath.Base(path) == name {
			candidates = append(candidates, path)
		}
		return nil
	})
	if len(candidates) == 0 {
		return ""
	}
	tp := strings.Split(filepath.ToSlash(target), "/")
	best, bestLen := "", -1
	for _, c := range candidates {
		cp := strings.Split(filepath.ToSlash(c), "/")
		n := 0
		for i := 0; i < len(cp) && i < len(tp); i++ {
			if cp[len(cp)-1-i] == tp[len(tp)-1-i] {
				n++
			} else {
				break
			}
		}
		if n > bestLen {
			best, bestLen = c, n
		}
	}
	return best
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return nil
		}
		dest := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(dest, info.Mode())
		}
		if info.Mode()&os.ModeSymlink != 0 {
			link, e := os.Readlink(path)
			if e != nil {
				return nil
			}
			_ = os.Remove(dest)
			return os.Symlink(link, dest)
		}
		in, e := os.Open(path)
		if e != nil {
			return nil
		}
		defer in.Close()
		out, e := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
		if e != nil {
			return nil
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
}

func unzipTo(zipPath, dst string) error {
	r, err := openZip(zipPath)
	if err != nil {
		return err
	}
	return extractZip(r, dst)
}

// untarTo 原生解压 tar.gz（Windows 无系统 tar，跨平台依赖内置实现）
func untarTo(tarPath, dst string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// 防路径穿越
		target := filepath.Join(dst, hdr.Name)
		if !strings.HasPrefix(target, filepath.Clean(dst)+string(filepath.Separator)) {
			return fmt.Errorf("illegal tar path: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeSymlink:
			_ = os.Remove(target)
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		}
	}
	return nil
}

func openZip(zipPath string) (*zip.Reader, error) {
	f, err := os.Open(zipPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return zip.NewReader(f, st.Size())
}

func extractZip(r *zip.Reader, dst string) error {
	for _, zf := range r.File {
		path := filepath.Join(dst, zf.Name)
		if !strings.HasPrefix(path, filepath.Clean(dst)+string(filepath.Separator)) {
			return fmt.Errorf("illegal zip path: %s", zf.Name)
		}
		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(path, zf.Mode()); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, zf.Mode())
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		rc.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
