package mcpaccess

import (
	"reflect"
	"testing"
	"time"
)

func TestExplicitScopeAndIdentityTuple(t *testing.T) {
	now := time.Now().UTC()
	good := Change{ID: "mcp_client", Name: "调查助手", Subject: "user|1", OAuthClientID: "desktop-agent", Scopes: []string{"sensors:read", "alerts:read"}, Enabled: true, ExpiresAt: now.Add(180 * 24 * time.Hour), RequestsPerMinute: 60}
	if err := good.Validate(now); err != nil || good.Scopes[0] != "alerts:read" {
		t.Fatal(err, good)
	}
	traffic := good
	traffic.Scopes = []string{"traffic:read"}
	if err := traffic.Validate(now); err != nil || len(Intersect([]string{"alerts:read"}, traffic.Scopes)) != 0 || len(Intersect([]string{"traffic:read"}, good.Scopes)) != 0 {
		t.Fatal("协议权限被告警权限隐式授予", err)
	}
	for name, change := range map[string]func(*Change){
		"无身份": func(c *Change) { c.ID = "" }, "无名称": func(c *Change) { c.Name = "" }, "控制字符": func(c *Change) { c.Subject = "user\n" }, "无效 UTF8": func(c *Change) { c.Subject = string([]byte{255}) }, "替换字符": func(c *Change) { c.OAuthClientID = "app�" }, "修订": func(c *Change) { c.ExpectedRevision = -1 }, "低预算": func(c *Change) { c.RequestsPerMinute = 0 }, "高预算": func(c *Change) { c.RequestsPerMinute = 121 }, "已过期": func(c *Change) { c.ExpiresAt = now }, "过长有效期": func(c *Change) { c.ExpiresAt = now.Add(3651 * 24 * time.Hour) }, "无权限": func(c *Change) { c.Scopes = nil }, "重复权限": func(c *Change) { c.Scopes = []string{"alerts:read", "alerts:read"} }, "写权限": func(c *Change) { c.Scopes = []string{"response:execute"} },
	} {
		t.Run(name, func(t *testing.T) {
			c := good
			c.Scopes = append([]string(nil), good.Scopes...)
			change(&c)
			if c.Validate(now) == nil {
				t.Fatal("无效授权被接受")
			}
		})
	}
	base := TupleHash("https://issuer", "subject", "app")
	if len(base) != 64 || base == TupleHash("https://issuer", "subject", "another-app") || TupleHash("a", "b|c", "d") == TupleHash("a|b", "c", "d") {
		t.Fatal("身份三元组发生歧义或应用权限复用")
	}
	if !reflect.DeepEqual(Intersect([]string{"alerts:read", "alerts:read", "response:execute"}, []string{"sensors:read", "alerts:read", "alerts:read"}), []string{"alerts:read"}) {
		t.Fatal("范围交集不正确")
	}
	for _, value := range []string{"", " x", "x ", "x\x00", string([]byte{255}), "�"} {
		if ValidText(value, 512) {
			t.Fatal("非规范身份文本被接受")
		}
	}
}
