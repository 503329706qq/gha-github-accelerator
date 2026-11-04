// Package resolver 用 DoH 解析域名，彻底绕开系统 DNS（也就绕开了 DNS 污染）。
//
// 三条路径，按顺序尝试：
//  1. 阿里 DNS 的 JSON 接口（GET ?name=&type=）；
//  2. 腾讯的 RFC 8484 wire 接口（POST application/dns-message）；
//  3. 裸 UDP DNS 到 223.5.5.5:53。
//
// 最后一条是应急路径：它直接向 DNS 服务器发包，不经过系统解析器，因此
// 不会读到我们自己写进 hosts 的行（那会解析回 127.0.0.1，形成自环）。
package resolver

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Options 配置解析器。
type Options struct {
	JSON     []string      // 例如 https://223.5.5.5/resolve
	Wire     []string      // 例如 https://doh.pub/dns-query
	Fallback string        // 例如 223.5.5.5:53
	IPv6     bool          // 是否也查 AAAA
	TTLMin   time.Duration // 缓存下限，默认 60s
	TTLMax   time.Duration // 缓存上限，默认 600s
	Timeout  time.Duration // 单次查询超时，默认 3s
	Client   *http.Client  // 可注入（测试）

	// Seeds 是内置的种子 IP，按域名索引。DoH 拿到的地址未必可用：污染与时断时通
	// 是常态（实测 github.com 的 A 记录 20.205.243.166 会有整段时间被黑洞，而
	// 同一时刻 20.207.73.82 仍然可连）。种子只作为"额外候选"合并进结果，由拨号
	// 层竞速决定用哪个，不覆盖 DoH 的答案。
	Seeds map[string][]netip.Addr
}

type cacheEntry struct {
	addrs  []netip.Addr
	expire time.Time
}

// Resolver 是并发安全的 DoH 客户端。
type Resolver struct {
	o     Options
	cli   *http.Client
	mu    sync.Mutex
	cache map[string]cacheEntry
}

// New 构造解析器，并把零值选项补成默认值。
func New(o Options) *Resolver {
	if o.TTLMin <= 0 {
		o.TTLMin = time.Minute
	}
	if o.TTLMax <= 0 {
		o.TTLMax = 10 * time.Minute
	}
	if o.TTLMax < o.TTLMin {
		o.TTLMax = o.TTLMin
	}
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Second
	}
	cli := o.Client
	if cli == nil {
		cli = &http.Client{Timeout: o.Timeout}
	}
	return &Resolver{o: o, cli: cli, cache: make(map[string]cacheEntry)}
}

// Lookup 解析域名。结果会缓存到 TTL（夹在 TTLMin/TTLMax 之间）。
// 解析到回环/未指定地址时返回错误——那几乎总是 hosts 自环或上游被串改。
func (r *Resolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, fmt.Errorf("resolver: empty host")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}

	r.mu.Lock()
	if e, ok := r.cache[host]; ok && time.Now().Before(e.expire) {
		addrs := append([]netip.Addr(nil), e.addrs...)
		r.mu.Unlock()
		return addrs, nil
	}
	r.mu.Unlock()

	types := []uint16{typeA}
	if r.o.IPv6 {
		types = append(types, typeAAAA)
	}

	var lastErr error
	var addrs []netip.Addr
	ttl := uint32(0)

	// 1) JSON DoH
	for _, base := range r.o.JSON {
		got, gotTTL, err := r.viaJSON(ctx, base, host, types)
		if err == nil && len(got) > 0 {
			addrs, ttl, lastErr = got, gotTTL, nil
			break
		}
		if err != nil {
			lastErr = err
		}
	}
	// 2) wire DoH
	if len(addrs) == 0 {
		for _, ep := range r.o.Wire {
			got, gotTTL, err := r.viaWire(ctx, ep, host, types)
			if err == nil && len(got) > 0 {
				addrs, ttl, lastErr = got, gotTTL, nil
				break
			}
			if err != nil {
				lastErr = err
			}
		}
	}
	// 3) 裸 DNS（不经过系统解析器，避免读到自己的 hosts）
	if len(addrs) == 0 && r.o.Fallback != "" {
		got, gotTTL, err := r.viaBareDNS(ctx, r.o.Fallback, host, types)
		if err == nil && len(got) > 0 {
			addrs, ttl, lastErr = got, gotTTL, nil
		} else if err != nil {
			lastErr = err
		}
	}
	// 种子 IP 排在 DoH 结果前面再交给拨号层竞速。
	//
	// 顺序很重要：拨号层初始评分相同，是按候选顺序错峰起跑的，谁先连上谁赢。
	// 实测 DoH 有时会返回"TCP 能握手、TLS 永远不回"的黑洞地址（2026-11-03
	// 140.82.113.4 就是这个症状，一次请求挂 20s 才 502），而种子表里是长期
	// 验证过能用的地址段，所以让种子先跑；种子里也有境外 IP 兜底，不担心失效。
	addrs = mergeAddrs(r.o.Seeds[host], addrs)
	if len(addrs) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("resolver: no answer for %s", host)
		}
		return nil, lastErr
	}

	for _, a := range addrs {
		if a.IsLoopback() || a.IsUnspecified() {
			return nil, fmt.Errorf("resolver: refusing loopback address %s for %s (hosts self-loop?)", a, host)
		}
	}

	d := time.Duration(ttl) * time.Second
	if d < r.o.TTLMin {
		d = r.o.TTLMin
	}
	if d > r.o.TTLMax {
		d = r.o.TTLMax
	}
	r.mu.Lock()
	r.cache[host] = cacheEntry{addrs: addrs, expire: time.Now().Add(d)}
	r.mu.Unlock()
	return addrs, nil
}

// mergeAddrs 追加不重复的地址，保留原有顺序（DoH 结果在前，种子在后）。
func mergeAddrs(dst, extra []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(dst)+len(extra))
	out := make([]netip.Addr, 0, len(dst)+len(extra))
	for _, list := range [][]netip.Addr{dst, extra} {
		for _, a := range list {
			if _, dup := seen[a]; dup {
				continue
			}
			seen[a] = struct{}{}
			out = append(out, a)
		}
	}
	return out
}

// Prefetch 预热一批域名；失败只忽略（启动阶段不能因此阻塞）。
func (r *Resolver) Prefetch(ctx context.Context, hosts []string) {
	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_, _ = r.Lookup(c, h)
		}(h)
	}
	wg.Wait()
}

// viaJSON 走阿里 DNS 的 JSON 接口。
func (r *Resolver) viaJSON(ctx context.Context, base, host string, types []uint16) ([]netip.Addr, uint32, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, 0, err
	}
	var addrs []netip.Addr
	var minTTL uint32 = 1<<32 - 1
	got := false

	for _, qt := range types {
		q := u.Query()
		q.Set("name", host)
		q.Set("type", fmt.Sprintf("%d", qt))
		call := *u
		call.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, call.String(), nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Accept", "application/dns-json")

		resp, err := r.cli.Do(req)
		if err != nil {
			return nil, 0, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			return nil, 0, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, 0, fmt.Errorf("doh json %s: status %d", base, resp.StatusCode)
		}

		var payload struct {
			Status int `json:"Status"`
			Answer []struct {
				Name string `json:"name"`
				TTL  uint32 `json:"TTL"`
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, 0, err
		}
		if payload.Status != 0 {
			return nil, 0, fmt.Errorf("doh json %s: status %d", base, payload.Status)
		}
		for _, a := range payload.Answer {
			if a.Type != typeA && a.Type != typeAAAA {
				continue // CNAME 等跳过
			}
			ip, err := netip.ParseAddr(a.Data)
			if err != nil {
				continue
			}
			if ip.Is6() && !r.o.IPv6 {
				continue
			}
			addrs = append(addrs, ip)
			if a.TTL < minTTL {
				minTTL = a.TTL
			}
			got = true
		}
	}
	if !got {
		return nil, 0, fmt.Errorf("doh json %s: empty answer", base)
	}
	if minTTL == 1<<32-1 {
		minTTL = 0
	}
	return addrs, minTTL, nil
}

// viaWire 走 RFC 8484（application/dns-message）。
func (r *Resolver) viaWire(ctx context.Context, endpoint, host string, types []uint16) ([]netip.Addr, uint32, error) {
	var addrs []netip.Addr
	var minTTL uint32 = 1<<32 - 1
	got := false

	for _, qt := range types {
		id := uint16(rand.Uint32())
		pkt := buildQuery(id, host, qt)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(pkt))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")

		resp, err := r.cli.Do(req)
		if err != nil {
			return nil, 0, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		if err != nil {
			return nil, 0, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, 0, fmt.Errorf("doh wire %s: status %d", endpoint, resp.StatusCode)
		}
		gotAddrs, ttl, err := parseResponse(body, id)
		if err != nil {
			return nil, 0, err
		}
		for _, ip := range gotAddrs {
			if ip.Is6() && !r.o.IPv6 {
				continue
			}
			addrs = append(addrs, ip)
			got = true
		}
		if ttl < minTTL {
			minTTL = ttl
		}
	}
	if !got {
		return nil, 0, fmt.Errorf("doh wire %s: empty answer", endpoint)
	}
	if minTTL == 1<<32-1 {
		minTTL = 0
	}
	return addrs, minTTL, nil
}

// viaBareDNS 直接向 DNS 服务器发 UDP 查询。绝不调用 net.Resolver。
func (r *Resolver) viaBareDNS(ctx context.Context, server, host string, types []uint16) ([]netip.Addr, uint32, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	} else {
		conn.SetDeadline(time.Now().Add(r.o.Timeout))
	}

	var addrs []netip.Addr
	var minTTL uint32 = 1<<32 - 1
	got := false
	buf := make([]byte, 1500)

	for _, qt := range types {
		id := uint16(rand.Uint32())
		if _, err := conn.Write(buildQuery(id, host, qt)); err != nil {
			return nil, 0, err
		}
		n, err := conn.Read(buf)
		if err != nil {
			return nil, 0, err
		}
		gotAddrs, ttl, err := parseResponse(buf[:n], id)
		if err != nil {
			return nil, 0, err
		}
		for _, ip := range gotAddrs {
			if ip.Is6() && !r.o.IPv6 {
				continue
			}
			addrs = append(addrs, ip)
			got = true
		}
		if ttl < minTTL {
			minTTL = ttl
		}
	}
	if !got {
		return nil, 0, fmt.Errorf("bare dns %s: empty answer", server)
	}
	if minTTL == 1<<32-1 {
		minTTL = 0
	}
	return addrs, minTTL, nil
}

var _ = binary.BigEndian // 保留 encoding/binary 引用（rawdns.go 使用）
