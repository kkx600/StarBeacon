// Package outbound 为连接器固定解析目标与网络边界，不继承宿主代理配置。
package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var ErrTarget = errors.New("目标地址不在连接器允许范围内")

type Policy struct {
	PrivateNetworks []netip.Prefix
	Development     bool
	PrivateOnly     bool
	Roots           *x509.CertPool
	lookup          func(context.Context, string) ([]netip.Addr, error)
}

func ParseNetworks(value string) ([]netip.Prefix, error) {
	result := []netip.Prefix{}
	if value == "" {
		return result, nil
	}
	items := strings.Split(value, ",")
	if len(items) > 32 {
		return nil, ErrTarget
	}
	for _, item := range items {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
			return nil, ErrTarget
		}
		result = append(result, prefix)
	}
	return result, nil
}

func (p Policy) Allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip == netip.MustParseAddr("100.100.100.200") || ip == netip.MustParseAddr("fd00:ec2::254") || netip.MustParsePrefix("240.0.0.0/4").Contains(ip) {
		return false
	}
	if p.PrivateOnly && !ip.IsPrivate() && !ip.IsLoopback() {
		return false
	}
	for _, prefix := range p.PrivateNetworks {
		if prefix.Contains(ip) {
			return true
		}
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !netip.MustParsePrefix("100.64.0.0/10").Contains(ip) && !netip.MustParsePrefix("0.0.0.0/8").Contains(ip)
}

func (p Policy) URL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 4096 || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.Hostname() == "" || strings.ContainsAny(raw, "\x00\r\n") || (u.Scheme != "https" && !(p.Development && u.Scheme == "http")) {
		return nil, ErrTarget
	}
	if u.Port() != "" {
		port, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil || port == 0 {
			return nil, ErrTarget
		}
	}
	return u, nil
}

func (p Policy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, ErrTarget
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, ErrTarget
	}
	if number, err := strconv.ParseUint(port, 10, 16); err != nil || number == 0 {
		return nil, ErrTarget
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		lookup := p.lookup
		if lookup == nil {
			lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
				return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			}
		}
		ips, err = lookup(ctx, host)
		if err != nil {
			return nil, ErrTarget
		}
	}
	if len(ips) == 0 || len(ips) > 16 {
		return nil, ErrTarget
	}
	// 校验全部 DNS 答案后直接连接 IP，连接过程不会再次解析域名。
	for _, ip := range ips {
		if !p.Allowed(ip) {
			return nil, ErrTarget
		}
	}
	dialer := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 15 * time.Second}
	for _, ip := range ips {
		if (network == "tcp4" && !ip.Is4()) || (network == "tcp6" && !ip.Is6()) {
			continue
		}
		connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			if deadline, ok := ctx.Deadline(); ok {
				_ = connection.SetDeadline(deadline)
			}
			return connection, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.New("连接器无法连接目标服务")
}

func (p Policy) TLSConfig(host string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: p.Roots}
}

func (p Policy) HTTPClient() *http.Client {
	return &http.Client{
		Timeout:       15 * time.Second,
		Transport:     &http.Transport{DialContext: p.DialContext, Proxy: nil, TLSClientConfig: p.TLSConfig(""), TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 32768, MaxConnsPerHost: 4, MaxIdleConns: 8, IdleConnTimeout: 30 * time.Second, DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
