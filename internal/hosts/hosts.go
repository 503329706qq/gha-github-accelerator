// Package hosts 负责 hosts 文件的块级改写。
//
// 这个包最要紧的性质是"只动自己那一块"：真实机器的 hosts 里往往还有别的程序写的
// 块（几十行，指向 127.0.0.1 或某台内网机器），任何一次重写都必须让它们逐字节不变；
// 文件开头的 UTF-8 BOM 和全文 CRLF 也必须原样保留（Windows 记事本与部分程序对此敏感）。
package hosts

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// BeginMarker / EndMarker 是我们这一块的边界行，纯 ASCII 便于人工识别。
	BeginMarker = "# >>> gha-github-accelerator >>>"
	EndMarker   = "# <<< gha-github-accelerator <<<"

	bom = "\xef\xbb\xbf"
)

// Render 生成块本体（含首尾标记），行尾统一 CRLF。
func Render(domains []string) []byte {
	var b bytes.Buffer
	b.WriteString(BeginMarker + "\r\n")
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		b.WriteString("127.0.0.1 " + d + "\r\n")
	}
	b.WriteString(EndMarker + "\r\n")
	return b.Bytes()
}

// splitLines 把内容切成“带行尾”的行：末尾的 \r 留在行内，行之间用 \n 分隔，
// 因此用 strings.Join(lines, "\n") 可以逐字节还原。
func splitLines(s string) []string { return strings.Split(s, "\n") }

// cutBlock 删除第一个完整块（含标记行）。找不到标记时原样返回。
// 只有起始标记而没有结束标记时，从起始标记删到文件末尾——宁可整块丢弃，
// 也不要把半个块留在文件里。
func cutBlock(s string) (string, bool) {
	lines := splitLines(s)
	out := make([]string, 0, len(lines))
	found := false
	inBlock := false
	for _, ln := range lines {
		trimmed := strings.TrimSuffix(ln, "\r")
		switch {
		case !inBlock && trimmed == BeginMarker:
			inBlock = true
			found = true
			continue
		case inBlock && trimmed == EndMarker:
			inBlock = false
			continue
		case inBlock:
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n"), found
}

// Remove 返回删除我方块之后的内容。BOM 与非我方行保持原样。
func Remove(orig []byte) []byte {
	hasBOM := bytes.HasPrefix(orig, []byte(bom))
	body := string(orig)
	if hasBOM {
		body = body[len(bom):]
	}
	body, _ = cutBlock(body)
	if hasBOM {
		return append([]byte(bom), body...)
	}
	return []byte(body)
}

// Upsert 先删旧块再追加新块。返回值可直接落盘。
// 若现有内容不以换行结尾，先补一个 CRLF，保证块从新行开始。
func Upsert(orig, block []byte) []byte {
	base := Remove(orig)
	if len(base) > 0 && !bytes.HasSuffix(base, []byte("\n")) {
		base = append(base, []byte("\r\n")...)
	}
	return append(base, block...)
}

// Status 报告文件里是否还有我方块，以及块内条目数。
func Status(path string) (present bool, lines int, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, 0, err
	}
	body := string(raw)
	if bytes.HasPrefix(raw, []byte(bom)) {
		body = body[len(bom):]
	}
	inBlock := false
	for _, ln := range splitLines(body) {
		trimmed := strings.TrimSuffix(ln, "\r")
		switch {
		case !inBlock && trimmed == BeginMarker:
			inBlock, present = true, true
		case inBlock && trimmed == EndMarker:
			inBlock = false
		case inBlock && strings.TrimSpace(trimmed) != "":
			lines++
		}
	}
	return present, lines, nil
}

// Apply 把新块写入 path（幂等）。内容无变化时返回 changed=false 且不产生备份。
// 写入策略：同目录临时文件 + Rename 原子替换，替换前把原文件复制一份带时间戳的备份。
func Apply(path string, domains []string) (changed bool, err error) {
	return ApplyTo(path, domains, "")
}

// ApplyTo 与 Apply 相同，但把备份写到 backupDir（为空则退回 hosts 同目录）。
// 备份是给用户排查用的，不该堆在 System32\drivers\etc 里。
func ApplyTo(path string, domains []string, backupDir string) (changed bool, err error) {
	orig, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	next := Upsert(orig, Render(domains))
	if bytes.Equal(next, orig) {
		return false, nil
	}
	if err := backup(path, backupDir, orig); err != nil {
		return false, err
	}
	if err := writeAtomic(path, next); err != nil {
		return false, err
	}
	return true, nil
}

// Restore 删除我方块；本来就没有时返回 changed=false。
func Restore(path string) (changed bool, err error) {
	return RestoreTo(path, "")
}

// RestoreTo 与 Restore 相同，备份同样写到 backupDir。
func RestoreTo(path, backupDir string) (changed bool, err error) {
	orig, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	next := Remove(orig)
	if bytes.Equal(next, orig) {
		return false, nil
	}
	if err := backup(path, backupDir, orig); err != nil {
		return false, err
	}
	if err := writeAtomic(path, next); err != nil {
		return false, err
	}
	return true, nil
}

// writeAtomic 在同目录写临时文件再 Rename，避免半截文件。
// hosts 往往被系统或其他程序短暂独占，失败时重试几次。
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".gha-hosts-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// CreateTemp 建的是 0600，hosts 习惯是 0644。
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	var lastErr error
	for i := 0; i < 5; i++ {
		if err := os.Rename(tmpName, path); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(time.Duration(50*(i+1)) * time.Millisecond)
	}
	return fmt.Errorf("rename %s: %w", path, lastErr)
}

// backup 留一份带时间戳的副本，只保留最近 5 份。
// dir 为空时写在 hosts 同目录（保持老行为，主要给测试和手工调用用）。
func backup(path, dir string, data []byte) error {
	if dir == "" {
		dir = filepath.Dir(path)
	} else if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	name := filepath.Join(dir, "hosts.backup-"+time.Now().Format("20060102-150405.000000"))
	if err := os.WriteFile(name, data, 0o644); err != nil {
		return err
	}
	pruneBackups(dir, 5)
	return nil
}

func pruneBackups(dir string, keep int) {
	matches, err := filepath.Glob(filepath.Join(dir, "hosts.backup-*"))
	if err != nil || len(matches) <= keep {
		return
	}
	sort.Strings(matches) // 时间戳定长，字典序即时间序
	for _, m := range matches[:len(matches)-keep] {
		os.Remove(m)
	}
}
