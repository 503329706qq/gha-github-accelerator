// Package sni 从 TLS ClientHello 里取出 SNI，并判断域名是否属于 GitHub 白名单。
//
// 这里必须自己解析：Go 的 crypto/tls 只在完成握手后才给出 ServerName，而我们
// 要在“握手之前”就决定是终结 TLS 还是原样透传。
package sni

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Suffixes 是白名单的父域后缀（带前导点）。只写一个父域就能覆盖
// avatars0-3、objects、media、camo、private-user-images 等几十个子域。
var Suffixes = []string{
	".github.com",
	".githubusercontent.com",
	".githubassets.com",
	".githubapp.com",
}

// exactNames 是「本身就要接管、但不是别人子域」的裸域名。
var exactNames = []string{
	"github.com",
	"githubusercontent.com",
	"githubassets.com",
	"githubapp.com",
	"github.dev",
	"github.io",
	"www.github.io",
}

// InAllowlist 判断域名是否在 GitHub 白名单内（后缀匹配 + 精确匹配，大小写无关）。
func InAllowlist(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" || !strings.Contains(name, ".") {
		return false
	}
	for _, s := range Suffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	for _, e := range exactNames {
		if name == e {
			return true
		}
	}
	return false
}

const (
	recordTypeHandshake  = 22
	handshakeClientHello = 1
	extServerName        = 0
)

var errNotTLS = errors.New("sni: not a TLS handshake record")

// ErrNotTLS 表示这段字节不是 TLS 握手记录（例如明文 HTTP），调用方据此决定放弃。
var ErrNotTLS = errNotTLS

// ParseClientHello 解析 b 开头的 ClientHello。
//
// 返回值：
//   - serverName 为空且 need==0：报文完整但客户端没发 SNI；
//   - need > 0：字节还不够，需要再读 need 字节（b 已被原样消耗，调用方要保留）；
//   - err != nil：这不是 TLS 握手记录（例如明文 HTTP）。
func ParseClientHello(b []byte) (serverName string, need int, err error) {
	if len(b) < 5 {
		return "", 5 - len(b), nil
	}
	if b[0] != recordTypeHandshake {
		return "", 0, errNotTLS
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen == 0 || recLen > 1<<14 {
		return "", 0, errNotTLS
	}
	total := 5 + recLen
	if len(b) < total {
		return "", total - len(b), nil
	}
	hs := b[5:total]
	if len(hs) < 4 {
		return "", 0, errors.New("sni: truncated handshake header")
	}
	if hs[0] != handshakeClientHello {
		return "", 0, fmt.Errorf("sni: handshake type %d is not ClientHello", hs[0])
	}
	bodyLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+bodyLen {
		return "", 0, errors.New("sni: truncated ClientHello body")
	}
	name, err := parseHelloBody(hs[4 : 4+bodyLen])
	if err != nil {
		return "", 0, err
	}
	return name, 0, nil
}

// parseHelloBody 走一遍 ClientHello 的固定字段，再遍历扩展找 server_name。
func parseHelloBody(b []byte) (string, error) {
	p := 0
	// legacy_version(2) + random(32)
	if len(b) < 34 {
		return "", errors.New("sni: short hello body")
	}
	p = 34
	// session_id
	if p >= len(b) {
		return "", errors.New("sni: no session_id")
	}
	p += 1 + int(b[p])
	// cipher_suites
	if p+2 > len(b) {
		return "", errors.New("sni: no cipher_suites")
	}
	p += 2 + int(binary.BigEndian.Uint16(b[p:p+2]))
	// compression_methods
	if p >= len(b) {
		return "", errors.New("sni: no compression_methods")
	}
	p += 1 + int(b[p])
	// extensions 可以整体缺失
	if p == len(b) {
		return "", nil
	}
	if p+2 > len(b) {
		return "", errors.New("sni: truncated extensions length")
	}
	extEnd := p + 2 + int(binary.BigEndian.Uint16(b[p:p+2]))
	if extEnd > len(b) {
		extEnd = len(b) // 宽容处理：有些客户端填的长度比实际长
	}
	p += 2
	for p+4 <= extEnd {
		typ := binary.BigEndian.Uint16(b[p : p+2])
		ln := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
		p += 4
		if p+ln > extEnd {
			break
		}
		data := b[p : p+ln]
		p += ln
		if typ == extServerName {
			return parseServerNameExt(data)
		}
	}
	return "", nil
}

// parseServerNameExt 解析 server_name 扩展：list_len(2) + [type(1) len(2) host]。
func parseServerNameExt(d []byte) (string, error) {
	if len(d) < 2 {
		return "", nil
	}
	listLen := int(binary.BigEndian.Uint16(d[:2]))
	end := 2 + listLen
	if end > len(d) {
		end = len(d)
	}
	p := 2
	for p+3 <= end {
		typ := d[p]
		ln := int(binary.BigEndian.Uint16(d[p+1 : p+3]))
		p += 3
		if p+ln > end {
			break
		}
		if typ == 0 { // host_name
			return strings.ToLower(string(d[p : p+ln])), nil
		}
		p += ln
	}
	return "", nil
}
