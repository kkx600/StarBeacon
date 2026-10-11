package clientip

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDirectPeerAndTrustedProxyBoundary(t *testing.T) {
	policy, err := Parse("127.0.0.1/32, ::1/128, 192.0.2.0/24,127.0.0.1/32")
	if err != nil || len(policy.trusted) != 3 {
		t.Fatal("可信代理名单未规范化", err)
	}
	for _, tc := range []struct {
		peer, header, want string
		trusted            bool
		duplicate          bool
	}{
		{"127.0.0.1:1234", "198.51.100.20", "127.0.0.1", false, false},
		{"192.0.3.1:1234", "198.51.100.20", "192.0.3.1", true, false},
		{"192.0.2.9:1234", "198.51.100.20", "198.51.100.20", true, false},
		{"[::1]:1234", "2001:db8::1", "2001:db8::1", true, false},
		{"[::ffff:127.0.0.1]:1234", "::ffff:198.51.100.20", "198.51.100.20", true, false},
		{"127.0.0.1:1234", "", "127.0.0.1", true, false},
		{"127.0.0.1:1234", "198.51.100.20, 198.51.100.21", "127.0.0.1", true, false},
		{"127.0.0.1:1234", "198.51.100.20:80", "127.0.0.1", true, false},
		{"127.0.0.1:1234", " 198.51.100.20", "127.0.0.1", true, false},
		{"127.0.0.1:1234", "fe80::1%eth0", "127.0.0.1", true, false},
		{"127.0.0.1:1234", "198.51.100.20", "127.0.0.1", true, true},
		{"127.0.0.1:1234", strings.Repeat("x", 46), "127.0.0.1", true, false},
		{"invalid", "198.51.100.20", "", true, false},
		{"invalid:80", "198.51.100.20", "", true, false},
		{"[fe80::1%eth0]:1234", "198.51.100.20", "", true, false},
	} {
		t.Run(tc.peer+"/"+tc.header, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.peer
			if tc.header != "" {
				r.Header.Set("X-Real-IP", tc.header)
			}
			if tc.duplicate {
				r.Header.Add("X-Real-IP", "203.0.113.21")
			}
			r.Header.Set("X-Forwarded-For", "203.0.113.42")
			r.Header.Set("Forwarded", "for=203.0.113.43")
			selected := Policy{}
			if tc.trusted {
				selected = policy
			}
			if got := selected.Resolve(r); got != tc.want {
				t.Fatalf("客户端地址 %q，预期 %q", got, tc.want)
			}
		})
	}
}

func TestTrustedProxyConfigurationCannotTrustArbitraryHosts(t *testing.T) {
	if p, err := Parse(""); err != nil || len(p.trusted) != 0 {
		t.Fatal("默认配置不应信任代理")
	}
	for _, value := range []string{"127.0.0.1", "localhost/32", "0.0.0.0/0", "::/0", "127.0.0.1/24", "::ffff:127.0.0.1/128", "192.0.2.0/24,", strings.Repeat("127.0.0.1/32,", 33), strings.Repeat(" ", 2049)} {
		if p, err := Parse(value); err == nil || len(p.trusted) != 0 {
			t.Fatal("非法配置部分生效", value)
		}
	}
}
