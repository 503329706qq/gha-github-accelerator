package resolver

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// DNS 常量（只用到 IPv4/IPv6 的 A/AAAA）。
const (
	typeA    = 1
	typeAAAA = 28
	classIN  = 1
)

// buildQuery 构造一个标准查询报文：ID + RD=1 + QDCOUNT=1 + qname + qtype + qclass。
func buildQuery(id uint16, name string, qtype uint16) []byte {
	b := make([]byte, 12, 12+len(name)+6)
	binary.BigEndian.PutUint16(b[0:2], id)
	b[2] = 0x01 // RD
	binary.BigEndian.PutUint16(b[4:6], 1)

	// 去掉末尾的点，逐段压成长度前缀标签
	name = strings.TrimSuffix(name, ".")
	if name != "" {
		for _, label := range strings.Split(name, ".") {
			b = append(b, byte(len(label)))
			b = append(b, label...)
		}
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, classIN)
	return b
}

// BuildQueryForTest 只给测试用，暴露报文构造。
func BuildQueryForTest(id uint16, name string, qtype uint16) []byte {
	return buildQuery(id, name, qtype)
}

// skipName 跳过（可能是压缩指针的）域名，返回新的偏移。
func skipName(msg []byte, p int) (int, error) {
	for {
		if p >= len(msg) {
			return 0, errors.New("dns: name out of range")
		}
		l := msg[p]
		switch {
		case l == 0:
			return p + 1, nil
		case l&0xC0 == 0xC0:
			if p+2 > len(msg) {
				return 0, errors.New("dns: truncated pointer")
			}
			return p + 2, nil
		default:
			p += 1 + int(l)
		}
	}
}

// parseResponse 取出 A/AAAA 记录，返回地址与最小 TTL（秒）。
func parseResponse(msg []byte, wantID uint16) ([]netip.Addr, uint32, error) {
	if len(msg) < 12 {
		return nil, 0, errors.New("dns: response too short")
	}
	if id := binary.BigEndian.Uint16(msg[0:2]); id != wantID {
		return nil, 0, fmt.Errorf("dns: id mismatch %04x != %04x", id, wantID)
	}
	if msg[2]&0x80 == 0 {
		return nil, 0, errors.New("dns: not a response")
	}
	if rcode := msg[3] & 0x0F; rcode != 0 {
		return nil, 0, fmt.Errorf("dns: rcode %d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))

	p := 12
	for i := 0; i < qd; i++ {
		var err error
		if p, err = skipName(msg, p); err != nil {
			return nil, 0, err
		}
		p += 4
	}

	var addrs []netip.Addr
	var minTTL uint32 = 1<<32 - 1
	for i := 0; i < an; i++ {
		var err error
		if p, err = skipName(msg, p); err != nil {
			return nil, 0, err
		}
		if p+10 > len(msg) {
			return nil, 0, errors.New("dns: truncated answer")
		}
		typ := binary.BigEndian.Uint16(msg[p : p+2])
		ttl := binary.BigEndian.Uint32(msg[p+4 : p+8])
		rdlen := int(binary.BigEndian.Uint16(msg[p+8 : p+10]))
		p += 10
		if p+rdlen > len(msg) {
			return nil, 0, errors.New("dns: rdata out of range")
		}
		rdata := msg[p : p+rdlen]
		p += rdlen

		switch {
		case typ == typeA && rdlen == 4:
			addrs = append(addrs, netip.AddrFrom4([4]byte(rdata)))
		case typ == typeAAAA && rdlen == 16:
			addrs = append(addrs, netip.AddrFrom16([16]byte(rdata)))
		}
		if ttl < minTTL {
			minTTL = ttl
		}
	}
	if minTTL == 1<<32-1 {
		minTTL = 0
	}
	return addrs, minTTL, nil
}
