// Package log 提供单行请求日志，并在写入前对敏感参数打码。
//
// 不记录的东西：Authorization、Cookie、请求体、响应体。
// 会打码的 query 参数：token/access_token/password/passwd/key/secret/signature/ticket。
package log

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Level 控制详细程度。默认 Info 只记录每条请求一行。
type Level int

const (
	LevelInfo Level = iota
	LevelDebug
)

// ParseLevel 把配置里的字符串映射为等级，未知值回落 Info。
func ParseLevel(s string) Level {
	if strings.EqualFold(strings.TrimSpace(s), "debug") {
		return LevelDebug
	}
	return LevelInfo
}

// sensitiveKeys 是会被替换为 *** 的 query/表单键（小写比较）。
var sensitiveKeys = map[string]struct{}{
	"token":         {},
	"access_token":  {},
	"password":      {},
	"passwd":        {},
	"key":           {},
	"secret":        {},
	"signature":     {},
	"ticket":        {},
	"client_secret": {},
}

// RedactQuery 按 “&” 分组、按首个 “=” 切分键值，对敏感键把值替换成 ***。
// 不使用 url.ParseQuery：它会重排键值并丢掉空值，日志会变得难以对照。
func RedactQuery(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	for i, p := range parts {
		if p == "" {
			continue
		}
		key := p
		if idx := strings.IndexByte(p, '='); idx >= 0 {
			key = p[:idx]
		}
		if _, bad := sensitiveKeys[strings.ToLower(key)]; bad {
			parts[i] = key + "=***"
		}
	}
	return strings.Join(parts, "&")
}

// Logger 是并发安全的行日志写入器。
type Logger struct {
	mu  sync.Mutex
	w   io.Writer
	lvl Level
}

// New 构造一个 Logger。w 为 nil 时丢弃所有输出（测试方便）。
func New(w io.Writer, lvl Level) *Logger {
	return &Logger{w: w, lvl: lvl}
}

// Level 返回当前等级。
func (l *Logger) Level() Level { return l.lvl }

func (l *Logger) write(prefix, format string, args ...any) {
	if l == nil || l.w == nil {
		return
	}
	line := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s %s %s\n", time.Now().Format("2006-01-02T15:04:05.000"), prefix, line)
}

// Debug 只在 debug 等级输出。
func (l *Logger) Debug(format string, args ...any) {
	if l == nil || l.lvl < LevelDebug {
		return
	}
	l.write("DEBUG", format, args...)
}

// Info 总是输出。
func (l *Logger) Info(format string, args ...any) { l.write("INFO", format, args...) }

// Error 总是输出。
func (l *Logger) Error(format string, args ...any) { l.write("ERROR", format, args...) }

// Request 输出一条请求摘要：host method path?query status bytes ms ip。
// query 会被打码；path 里的 query 也会被切掉后重新拼接，避免重复。
func (l *Logger) Request(host, method, path, rawQuery string, status int, n int64, d time.Duration, ip string) {
	if l == nil || l.w == nil {
		return
	}
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	target := path
	if q := RedactQuery(rawQuery); q != "" {
		target = path + "?" + q
	}
	l.write("INFO", "%s %s %s %d %dB %dms %s",
		host, method, target, status, n, d.Milliseconds(), ip)
}
