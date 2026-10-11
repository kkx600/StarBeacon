package notify_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/outbound"
)

func TestConfigurationRejectsInvalidTargetsAndCredentials(t *testing.T) {
	base := fixtureConfig("webhook", "https://example.invalid/receive")
	for name, change := range map[string]func(*notify.Config){
		"empty_name":         func(c *notify.Config) { c.Name = "" },
		"name_space":         func(c *notify.Config) { c.Name = " title" },
		"name_control":       func(c *notify.Config) { c.Name = "title\n" },
		"empty_severity":     func(c *notify.Config) { c.Severities = nil },
		"unknown_severity":   func(c *notify.Config) { c.Severities = []string{"critical"} },
		"duplicate_severity": func(c *notify.Config) { c.Severities = []string{"high", "high"} },
		"secret_control":     func(c *notify.Config) { c.Secret = "secret\n" },
		"token_oversize":     func(c *notify.Config) { c.Token = strings.Repeat("a", 4097) },
		"muted_zero":         func(c *notify.Config) { c.MutedUntil = new(time.Time) },
		"muted_limit":        func(c *notify.Config) { at := time.Now().Add(366 * 24 * time.Hour); c.MutedUntil = &at },
		"plaintext":          func(c *notify.Config) { c.Endpoint = "http://example.invalid" },
		"url_credentials":    func(c *notify.Config) { c.Endpoint = "https://user:password@example.invalid" },
		"foreign_smtp":       func(c *notify.Config) { c.SMTPHost = "mail.example.invalid" },
		"foreign_recipient":  func(c *notify.Config) { c.Recipients = []string{"mail@example.invalid"} },
		"unsupported_kind":   func(c *notify.Config) { c.Kind = "sms" },
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			change(&config)
			if config.Validate(outbound.Policy{}) == nil {
				t.Fatal("非法渠道配置被接受")
			}
		})
	}
	for _, target := range []string{"logs.example.invalid", "logs.example.invalid:abc", "logs.example.invalid:0", "logs.example.invalid:65536", ":6514", "bad/host:6514"} {
		if fixtureConfig("syslog_tls", target).Validate(outbound.Policy{}) == nil {
			t.Fatalf("非法端口或主机被接受：%s", target)
		}
	}
	if fixtureConfig("syslog_tcp", "logs.example.invalid:514").Validate(outbound.Policy{}) == nil {
		t.Fatal("生产模式允许了明文 Syslog")
	}
	config := fixtureConfig("syslog_tcp", "logs.example.invalid:514")
	if config.Validate(outbound.Policy{Development: true}) != nil || config.Public().Target != config.Endpoint {
		t.Fatal("开发 Syslog 目标处理错误")
	}
	config.Secret = "irrelevant"
	if config.Validate(outbound.Policy{Development: true}) == nil {
		t.Fatal("Syslog 接受了无效凭据字段")
	}
	encoded, err := notify.Encode(base)
	if err != nil || !strings.Contains(string(encoded), "receive") {
		t.Fatal("渠道配置不能编码")
	}
	if result := (notify.Sender{}).Send(context.Background(), notify.Config{}, fixtureMessage()); result.Code != "invalid_config" {
		t.Fatal("投递未拒绝非法配置")
	}
}

func TestSummaryBatchRejectsInjectionDuplicatesAndUnknownIdentity(t *testing.T) {
	valid := notify.Summary{ID: "event_owned", SensorID: "sensor_owned", Timestamp: time.Now(), Severity: "high", RuleID: "1234", RuleName: "规则命中"}
	if notify.ValidateBatch("tenant_owned", "batch_owned", []notify.Summary{valid}) != nil {
		t.Fatal("合法摘要被拒绝")
	}
	for _, ids := range [][2]string{{"", "batch_owned"}, {"tenant_owned", "../batch"}} {
		if !errors.Is(notify.ValidateBatch(ids[0], ids[1], nil), notify.ErrBatch) {
			t.Fatal("空批次绕过身份检查")
		}
	}
	for name, change := range map[string]func(*notify.Summary){
		"identity":     func(a *notify.Summary) { a.SensorID = "../other" },
		"timestamp":    func(a *notify.Summary) { a.Timestamp = time.Time{} },
		"time_range":   func(a *notify.Summary) { a.Timestamp = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC) },
		"severity":     func(a *notify.Summary) { a.Severity = "critical" },
		"rule_id":      func(a *notify.Summary) { a.RuleID = strings.Repeat("x", 65) },
		"rule_name":    func(a *notify.Summary) { a.RuleName = "title\nAuthorization: secret" },
		"invalid_utf8": func(a *notify.Summary) { a.RuleName = string([]byte{255}) },
	} {
		t.Run(name, func(t *testing.T) {
			alert := valid
			change(&alert)
			if !errors.Is(notify.ValidateBatch("tenant_owned", "batch_owned", []notify.Summary{alert}), notify.ErrBatch) {
				t.Fatal("非法摘要被接受")
			}
		})
	}
	for _, alerts := range [][]notify.Summary{{valid, valid}, make([]notify.Summary, 501)} {
		if notify.ValidateBatch("tenant_owned", "batch_owned", alerts) == nil {
			t.Fatal("重复或超量摘要被接受")
		}
	}
}

func TestEmailAddressesTLSAndRecipientBounds(t *testing.T) {
	base := notify.Config{Name: "邮件", Kind: "email", Severities: []string{"high"}, SMTPHost: "smtp.example.invalid", SMTPPort: 587, From: "sender@example.invalid", Recipients: []string{"user@example.invalid"}}
	if base.Validate(outbound.Policy{}) != nil || base.Public().Target != base.SMTPHost {
		t.Fatal("邮件基础配置被拒绝")
	}
	for name, change := range map[string]func(*notify.Config){
		"empty_host":          func(c *notify.Config) { c.SMTPHost = "" },
		"host_path":           func(c *notify.Config) { c.SMTPHost = "host/path" },
		"host_port":           func(c *notify.Config) { c.SMTPHost = "host:587" },
		"invalid_port":        func(c *notify.Config) { c.SMTPPort = 0 },
		"http_endpoint":       func(c *notify.Config) { c.Endpoint = "https://example.invalid" },
		"display_from":        func(c *notify.Config) { c.From = "Sender <sender@example.invalid>" },
		"invalid_from":        func(c *notify.Config) { c.From = "invalid" },
		"empty_recipients":    func(c *notify.Config) { c.Recipients = nil },
		"duplicate_recipient": func(c *notify.Config) { c.Recipients = []string{"user@example.invalid", "user@example.invalid"} },
		"bad_recipient":       func(c *notify.Config) { c.Recipients = []string{"invalid"} },
		"display_recipient":   func(c *notify.Config) { c.Recipients = []string{"User <user@example.invalid>"} },
		"recipient_limit":     func(c *notify.Config) { c.Recipients = make([]string, 101) },
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			change(&config)
			if config.Validate(outbound.Policy{}) == nil {
				t.Fatal("非法邮件配置被接受")
			}
		})
	}
	base.SMTPHost = "2001:db8::1"
	if base.Validate(outbound.Policy{}) != nil {
		t.Fatal("IPv6 SMTP 主机被拒绝")
	}
	message := fixtureMessage()
	message.Alerts = make([]notify.Summary, 11)
	if !strings.Contains(message.Text(), "其他告警") {
		t.Fatal("多告警批次未提示详情入口")
	}
}
