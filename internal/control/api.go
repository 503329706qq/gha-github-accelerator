// Package control 提供 gha 的本地控制接口（默认监听 127.0.0.1:12080）。
//
// 只有三条路径对外：
//   - GET  /status  需要 X-Gha-Token，返回运行状态 JSON（CLI 的 gha status 用它）
//   - POST /quit    需要 X-Gha-Token，优雅退出
//   - POST /reload  需要 X-Gha-Token，重新读取配置并刷新 hosts
//   - GET  /ca.crl  免鉴权：TLS 客户端做吊销检查时会来取，必须匿名可取
//
// 之所以绑 127.0.0.1 而不是 0.0.0.0：控制面不该被局域网里的其他机器碰到；
// CRL 也不需要出网——它的消费者（Schannel/CryptoAPI）就跑在本机。
package control

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
)

// Options 描述控制接口需要的外部依赖，全部由调用方注入，便于测试。
type Options struct {
	// Token 是 X-Gha-Token 的期望值。为空时一律拒绝（宁可不可用，也不要裸奔）。
	Token string
	// CRL 返回 DER 编码的证书吊销列表。
	CRL func() ([]byte, error)
	// Status 返回任意可 JSON 序列化的状态快照。
	Status func() any
	// OnQuit 在收到 POST /quit 时同步调用；实现方应当快速返回并在后台收尾。
	OnQuit func()
	// OnReload 在收到 POST /reload 时调用，返回错误则回 500。
	OnReload func() error
}

// Handler 是控制接口的 http.Handler 实现。
type Handler struct {
	opts Options
	mux  *http.ServeMux
}

// New 构造控制接口。Options 里缺省的回调会被替换成安全的空实现。
func New(o Options) *Handler {
	if o.CRL == nil {
		o.CRL = func() ([]byte, error) { return nil, fmt.Errorf("no CRL configured") }
	}
	if o.Status == nil {
		o.Status = func() any { return map[string]any{} }
	}
	if o.OnQuit == nil {
		o.OnQuit = func() {}
	}
	if o.OnReload == nil {
		o.OnReload = func() error { return nil }
	}

	h := &Handler{opts: o, mux: http.NewServeMux()}
	// Go 1.22+ 的方法路由：GET 之外的动词自动 405，省掉手写判断。
	h.mux.HandleFunc("GET /status", h.guarded(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(h.opts.Status()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	h.mux.HandleFunc("POST /quit", h.guarded(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintln(w, "bye")
		h.opts.OnQuit()
	}))
	h.mux.HandleFunc("POST /reload", h.guarded(func(w http.ResponseWriter, r *http.Request) {
		if err := h.opts.OnReload(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, "reloaded")
	}))
	h.mux.HandleFunc("GET /ca.crl", func(w http.ResponseWriter, r *http.Request) {
		der, err := h.opts.CRL()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Header().Set("Content-Length", fmt.Sprint(len(der)))
		w.Write(der)
	})
	return h
}

// ServeHTTP 让 Handler 直接当 http.Handler 用。
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

// guarded 用常量时间比较校验 token，避免把鉴权做成可计时侧信道。
func (h *Handler) guarded(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Gha-Token")
		if h.opts.Token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(h.opts.Token)) != 1 {
			w.Header().Set("WWW-Authenticate", `GhaToken realm="gha"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
