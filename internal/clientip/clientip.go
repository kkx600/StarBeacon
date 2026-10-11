// Package clientip 在明确的代理信任边界内解析审计与限流使用的客户端地址。
package clientip

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Policy 的零值只使用实际 TCP 对端；代理名单只能由部署配置提供。
type Policy struct{ trusted []netip.Prefix }

func Parse(raw string) (Policy, error) {
	var policy Policy
	if raw == "" {
		return policy, nil
	}
	parts := strings.Split(raw, ",")
	if len(raw) > 2048 || len(parts) > 32 {
		return policy, fmt.Errorf("可信代理配置最多 32 个 CIDR、2048 字节")
	}
	seen := map[netip.Prefix]bool{}
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil || prefix.Bits() == 0 || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
			return Policy{}, fmt.Errorf("可信代理必须为明确的 IPv4／IPv6 网段，不能使用全网范围或带主机位的 CIDR")
		}
		if !seen[prefix] {
			policy.trusted = append(policy.trusted, prefix)
			seen[prefix] = true
		}
	}
	return policy, nil
}

func (p Policy) Resolve(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || peer.Zone() != "" {
		return ""
	}
	peer = peer.Unmap()
	for _, prefix := range p.trusted {
		if !prefix.Contains(peer) {
			continue
		}
		// 单层代理必须覆盖这个头；不解析调用方可追加的转发链或端口。
		values := r.Header.Values("X-Real-IP")
		if len(values) != 1 || len(values[0]) > 45 {
			break
		}
		client, err := netip.ParseAddr(values[0])
		if err == nil && client.Zone() == "" {
			return client.Unmap().String()
		}
		break
	}
	return peer.String()
}
