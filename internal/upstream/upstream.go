// Package upstream 在"代理层"与"拨号层"之间传递每次尝试真正使用的上游 IP。
//
// 背景：GitHub 的前端 IP 会出现"TCP 通、TLS 握手成功、之后零字节"的黑洞形态。
// 拨号层的探测（ProbeTLS）只能覆盖热门域名，长尾域名（avatars 等）的候选 IP
// 没有实测数据；而一条被黑洞的连接上的请求会以"响应头超时"失败。为了让
// 重试层能把**这一次真正拨号的 IP**记成失败（而不是盲目惩罚整个域名），
// 拨号器在选出赢家后把 IP 写进挂在请求 ctx 上的 Recorder；重试层每次尝试
// 建一个新 Recorder，失败时取出来交给 onFail 回调惩罚。
//
// 前提：上游走 HTTP/1.1（h2 连接多路复用会让 DialContext 的 ctx 与单个请求
// 失去对应关系，这正是我们要避免的，见 proxy.Transport 的 ForceAttemptHTTP2=false）。
package upstream

import (
	"context"
	"net/netip"
	"sync"
)

// NewRecorder 建一个空 Recorder。
func NewRecorder() *Recorder { return &Recorder{} }

// Recorder 记录"某次尝试实际拨到的 IP"。每个重试尝试独享一个实例。
type Recorder struct {
	mu sync.Mutex
	ip netip.Addr
	ok bool
}

// Set 由拨号层在选出赢家后调用。
func (r *Recorder) Set(ip netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ip = ip
	r.ok = true
}

// Get 返回记录的 IP；没有拨号发生（例如命中空闲连接、或非拨号错误）时返回 false。
func (r *Recorder) Get() (netip.Addr, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ip, r.ok
}

type ctxKey struct{}

// With 把 rec 挂到 ctx 上。
func With(ctx context.Context, rec *Recorder) context.Context {
	return context.WithValue(ctx, ctxKey{}, rec)
}

// From 取出 ctx 上的 Recorder；没有则返回 nil。
func From(ctx context.Context) *Recorder {
	rec, _ := ctx.Value(ctxKey{}).(*Recorder)
	return rec
}
