package outbound

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestTargetPolicyAndExplicitPrivateRanges(t *testing.T) {
	policy := Policy{}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "::1", "fc00::1", "169.254.169.254", "fe80::1", "0.0.0.0", "224.0.0.1", "100.64.0.1", "::ffff:127.0.0.1"} {
		if policy.Allowed(netip.MustParseAddr(ip)) {
			t.Fatal("默认允许受限地址", ip)
		}
	}
	if policy.Allowed(netip.Addr{}) || !policy.Allowed(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("地址边界错误")
	}
	for _, invalid := range []string{"wrong", "10.0.0.1/24", "::ffff:127.0.0.1/128"} {
		if _, err := ParseNetworks(invalid); err != ErrTarget {
			t.Fatal("接受错误网段", invalid)
		}
	}
	networks, err := ParseNetworks("127.0.0.0/8, ::1/128")
	if err != nil {
		t.Fatal(err)
	}
	policy.PrivateNetworks = networks
	if !policy.Allowed(netip.MustParseAddr("::1")) || !policy.Allowed(netip.MustParseAddr("127.0.0.1")) || policy.Allowed(netip.MustParseAddr("169.254.169.254")) {
		t.Fatal("授权范围无效")
	}
	for _, raw := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/#secret", "https:opaque", "https://example.com:0", "https://example.com:99999", "https://example.com\n"} {
		if _, err := policy.URL(raw); err != ErrTarget {
			t.Fatal("接受无效目标", raw)
		}
	}
	if _, err := policy.URL("https://example.com/hook?key=secret"); err != nil {
		t.Fatal(err)
	}
}

func TestDNSMixedTargetsAndDialRestrictions(t *testing.T) {
	policy := Policy{lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, nil
	}}
	if _, err := policy.DialContext(context.Background(), "tcp", "mixed.example:443"); err != ErrTarget {
		t.Fatal("DNS 混合答案绕过限制")
	}
	for _, address := range []string{"example.com", "example.com:0", "example.com:65536", "127.0.0.1:443"} {
		if _, err := policy.DialContext(context.Background(), "tcp", address); err != ErrTarget {
			t.Fatal("目标未拒绝", address, err)
		}
	}
	if _, err := policy.DialContext(context.Background(), "udp", "example.com:443"); err != ErrTarget {
		t.Fatal("网络模式未限制")
	}
	policy.lookup = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("DNS 失败") }
	if _, err := policy.DialContext(context.Background(), "tcp", "unknown.example:443"); err != ErrTarget {
		t.Fatal("解析失败未拒绝")
	}
}

func TestHTTPRedirectAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:9/secret", http.StatusFound)
	}))
	defer server.Close()
	networks, _ := ParseNetworks("127.0.0.0/8")
	policy := Policy{PrivateNetworks: networks, Development: true}
	client := policy.HTTPClient()
	defer client.CloseIdleConnections()
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 302 {
		t.Fatal("连接器跟随了跳转")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	cancel()
	_, err = policy.DialContext(ctx, "tcp", server.Listener.Addr().String())
	if err == nil {
		t.Fatal("已取消的连接仍启动")
	}
	if _, err := policy.DialContext(context.Background(), "tcp6", net.JoinHostPort("127.0.0.1", "9")); err == nil {
		t.Fatal("网络家族错误")
	}
}

func TestPrivateModelPolicyCannotUsePublicOrMetadataRanges(t *testing.T) {
	networks, err := ParseNetworks("0.0.0.0/0,::/0")
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{PrivateNetworks: networks, PrivateOnly: true}
	for _, address := range []string{"8.8.8.8", "2001:4860:4860::8888", "100.100.100.200", "fd00:ec2::254", "240.0.0.1", "169.254.169.254"} {
		if policy.Allowed(netip.MustParseAddr(address)) {
			t.Fatal("内网模型策略越过网络边界", address)
		}
	}
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "::1", "fd12::1"} {
		if !policy.Allowed(netip.MustParseAddr(address)) {
			t.Fatal("明确授权的内网地址被拒绝", address)
		}
	}
	policy.PrivateNetworks = nil
	if policy.Allowed(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("内网地址未要求授权网段")
	}
	policy.PrivateOnly = false
	policy.PrivateNetworks = networks
	for _, address := range []string{"100.100.100.200", "fd00:ec2::254", "240.0.0.1"} {
		if policy.Allowed(netip.MustParseAddr(address)) {
			t.Fatal("元数据／保留地址被网段配置绕过", address)
		}
	}
}
