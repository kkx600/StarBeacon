package notify_test

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/outbound"
)

func fixtureMessage() notify.Message {
	return notify.Message{ID: "delivery_owned_fixture", TenantID: "tenant_owned_fixture", BatchID: "batch_owned_fixture", CreatedAt: time.Now().UTC(), Alerts: []notify.Summary{{ID: "event_owned_fixture", SensorID: "sensor_owned_fixture", Timestamp: time.Now().UTC(), Severity: "high", RuleID: "100001", RuleName: "HTTP 验收"}}}
}
func fixtureConfig(kind, endpoint string) notify.Config {
	return notify.Config{Name: "验收通知", Kind: kind, Enabled: true, Severities: []string{"high"}, Endpoint: endpoint}
}
func fixturePolicy(server *httptest.Server) outbound.Policy {
	networks, _ := outbound.ParseNetworks("127.0.0.0/8")
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	return outbound.Policy{PrivateNetworks: networks, Roots: pool}
}
func hmacValue(key, value string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(value))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func TestBotPayloadSignaturesAndBusinessAcknowledgments(t *testing.T) {
	for _, kind := range []string{"wecom", "dingtalk", "feishu", "webhook"} {
		t.Run(kind, func(t *testing.T) {
			captured := make(chan error, 1)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data, err := io.ReadAll(r.Body)
				if err != nil {
					captured <- err
					return
				}
				var payload map[string]any
				if err := json.Unmarshal(data, &payload); err != nil {
					captured <- err
					return
				}
				if r.Header.Get("Idempotency-Key") != fixtureMessage().ID {
					captured <- fmt.Errorf("缺少稳定投递标识")
					return
				}
				switch kind {
				case "feishu":
					stamp, _ := payload["timestamp"].(string)
					if payload["msg_type"] != "text" || stamp == "" || payload["sign"] != hmacValue(stamp+"\nfixture-sign-secret", "") {
						captured <- fmt.Errorf("飞书签名不一致")
						return
					}
				case "dingtalk":
					stamp := r.URL.Query().Get("timestamp")
					if payload["msgtype"] != "text" || payload["msgUuid"] != fixtureMessage().ID || r.URL.Query().Get("sign") != hmacValue("fixture-sign-secret", stamp+"\nfixture-sign-secret") {
						captured <- fmt.Errorf("钉钉签名不一致")
						return
					}
				case "wecom":
					if payload["msgtype"] != "text" {
						captured <- fmt.Errorf("企业微信消息类型不一致")
						return
					}
				case "webhook":
					if r.Header.Get("Authorization") != "Bearer fixture-token" || r.Header.Get("X-StarBeacon-Signature") != "sha256="+hmacValue("fixture-sign-secret", string(data)) {
						captured <- fmt.Errorf("Webhook 签名不一致")
						return
					}
				}
				captured <- nil
				if kind == "feishu" {
					_, _ = io.WriteString(w, `{"code":0,"StatusCode":0}`)
				} else {
					_, _ = io.WriteString(w, `{"errcode":0}`)
				}
			}))
			defer server.Close()
			config := fixtureConfig(kind, server.URL+"/owned-fixture?key=fixture-token")
			config.Secret = "fixture-sign-secret"
			config.Token = "fixture-token"
			outcome := (notify.Sender{Policy: fixturePolicy(server)}).Send(context.Background(), config, fixtureMessage())
			if outcome.State != "accepted" || outcome.Code != "provider_accepted" || outcome.ObservedAt.IsZero() {
				t.Fatal("有效业务回执未受理", outcome)
			}
			if err := <-captured; err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(config.Public())
			if strings.Contains(string(encoded), "fixture-token") || strings.Contains(string(encoded), "fixture-sign-secret") || strings.Contains(string(encoded), "owned-fixture") {
				t.Fatal("渠道视图泄露凭据")
			}
		})
	}
}

func TestHTTP200IsNotSufficientAndLostAcknowledgmentIsNotRetried(t *testing.T) {
	tests := []struct {
		status            int
		body, kind, state string
	}{
		{200, `{"errcode":1,"errmsg":"fixture credential rejected"}`, "wecom", "failed"},
		{200, `{}`, "wecom", "uncertain"},
		{200, `not-json`, "feishu", "uncertain"},
		{200, `{"code":0,"StatusCode":1}`, "feishu", "uncertain"},
		{200, `{"StatusCode":0}`, "feishu", "accepted"},
		{429, `{}`, "dingtalk", "retry"},
		{503, `{}`, "webhook", "uncertain"},
		{302, `{}`, "webhook", "failed"},
		{400, `{}`, "webhook", "failed"},
		{200, strings.Repeat("x", 65537), "wecom", "uncertain"},
	}
	for i, fixture := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(fixture.status)
				_, _ = io.WriteString(w, fixture.body)
			}))
			defer server.Close()
			result := (notify.Sender{Policy: fixturePolicy(server)}).Send(context.Background(), fixtureConfig(fixture.kind, server.URL), fixtureMessage())
			if result.State != fixture.state {
				t.Fatal("错误受理状态", result)
			}
			encoded, _ := json.Marshal(result)
			if strings.Contains(string(encoded), "fixture credential rejected") {
				t.Fatal("服务商回执中的凭据被透传")
			}
		})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = connection.Close()
		}
	}))
	defer server.Close()
	result := (notify.Sender{Policy: fixturePolicy(server)}).Send(context.Background(), fixtureConfig("webhook", server.URL), fixtureMessage())
	if result.State != "uncertain" {
		t.Fatal("丢失确认后不能自动重发", result)
	}
	result = (notify.Sender{Policy: outbound.Policy{}}).Send(context.Background(), fixtureConfig("webhook", server.URL), fixtureMessage())
	if result.State != "failed" || result.Code != "target_denied" {
		t.Fatal("受限连接未拒绝", result)
	}
}

func TestSyslogTLSFrameUsesByteLength(t *testing.T) {
	certificate := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer certificate.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", certificate.TLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	frames := make(chan []byte, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			frames <- nil
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(connection)
		prefix, err := reader.ReadString(' ')
		if err != nil {
			frames <- nil
			return
		}
		size, err := strconv.Atoi(strings.TrimSpace(prefix))
		if err != nil || size > 8192 {
			frames <- nil
			return
		}
		data := make([]byte, size)
		_, err = io.ReadFull(reader, data)
		if err != nil {
			frames <- nil
			return
		}
		frames <- data
	}()
	result := (notify.Sender{Policy: fixturePolicy(certificate)}).Send(context.Background(), fixtureConfig("syslog_tls", listener.Addr().String()), fixtureMessage())
	if result.State != "transport_written" || result.Code != "storage_acknowledgment_unavailable" {
		t.Fatal("Syslog 写入被误认落盘", result)
	}
	select {
	case frame := <-frames:
		if !strings.HasPrefix(string(frame), "<134>1 ") || !strings.Contains(string(frame), "HTTP 验收") {
			t.Fatal("RFC 5424 帧内容错误")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("未接收 Syslog 帧")
	}
}

func TestEmailUsesTLSAndStableMessageID(t *testing.T) {
	certificate := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer certificate.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", certificate.TLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan string, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			received <- ""
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(4 * time.Second))
		reader := bufio.NewReader(connection)
		_, _ = io.WriteString(connection, "220 owned-fixture ESMTP\r\n")
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"):
				_, _ = io.WriteString(connection, "250-owned-fixture\r\n250 AUTH PLAIN\r\n")
			case strings.HasPrefix(line, "AUTH PLAIN"):
				_, _ = io.WriteString(connection, "235 2.7.0 authenticated\r\n")
			case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"), strings.HasPrefix(line, "NOOP"), strings.HasPrefix(line, "RSET"):
				_, _ = io.WriteString(connection, "250 2.0.0 ok\r\n")
			case strings.HasPrefix(line, "DATA"):
				_, _ = io.WriteString(connection, "354 end with dot\r\n")
				var body strings.Builder
				for {
					data, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if data == ".\r\n" {
						break
					}
					body.WriteString(data)
				}
				received <- body.String()
				_, _ = io.WriteString(connection, "250 2.0.0 queued\r\n")
			case strings.HasPrefix(line, "QUIT"):
				_, _ = io.WriteString(connection, "221 2.0.0 bye\r\n")
				return
			default:
				_, _ = io.WriteString(connection, "500 unsupported\r\n")
			}
		}
	}()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	number, _ := strconv.Atoi(port)
	config := notify.Config{Name: "邮件验收", Kind: "email", Enabled: true, Severities: []string{"high"}, SMTPHost: host, SMTPPort: number, SMTPUser: "fixture-sender", SMTPPass: "fixture-password", From: "security@example.invalid", Recipients: []string{"recipient@example.invalid"}, ImplicitTLS: true}
	message := fixtureMessage()
	message.Recipient = config.Recipients[0]
	result := (notify.Sender{Policy: fixturePolicy(certificate)}).Send(context.Background(), config, message)
	if result.State != "accepted" || result.Code != "smtp_accepted" {
		t.Fatal("TLS 邮件未受理", result)
	}
	select {
	case body := <-received:
		if !strings.Contains(body, "<"+message.ID+"@starbeacon.local>") {
			t.Fatal("邮件缺少稳定标识")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SMTP 未接收邮件")
	}
	message.Recipient = "other@example.invalid"
	if result := (notify.Sender{Policy: fixturePolicy(certificate)}).Send(context.Background(), config, message); result.Code != "invalid_recipient" {
		t.Fatal("接收人越界", result)
	}
}

func TestNotificationSummaryDoesNotForwardOriginalPayload(t *testing.T) {
	alert := model.Alert{EventID: "event", SensorID: "sensor", Timestamp: time.Now(), Severity: "high"}
	alert.Event.Kind = "alert"
	alert.Event.Original = `{"password":"secret"}`
	alert.Rule.Name = "rule\n" + strings.Repeat("名", 300)
	alert.HTTP.Path = "/private?token=secret"
	alert.Source.IP = "192.0.2.1"
	summaries := notify.Summaries([]model.Alert{alert, {}})
	data, _ := json.Marshal(summaries)
	if len(summaries) != 1 || len([]rune(summaries[0].RuleName)) != 256 || strings.Contains(string(data), "secret") || strings.Contains(string(data), "192.0.2.1") || strings.Contains(summaries[0].RuleName, "\n") {
		t.Fatal("通知未遵守字段白名单")
	}
	config := fixtureConfig("webhook", "https://example.invalid")
	if len(config.Select(append(summaries, notify.Summary{Severity: "unknown"}))) != 1 {
		t.Fatal("严重性过滤错误")
	}
	message := fixtureMessage()
	message.Test = true
	if !strings.Contains(message.Text(), "渠道测试") {
		t.Fatal("测试消息未说明用途")
	}
}
