package notify_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/outbound"
)

func TestLogStreamsRequireExplicitSyslogAuthorization(t *testing.T) {
	legacy := fixtureConfig("webhook", "https://example.invalid")
	if !legacy.Accepts("alerts") || legacy.Accepts("operations") || len(legacy.Public().Streams) != 1 {
		t.Fatal("历史渠道改变了数据外发范围")
	}
	for _, streams := range [][]string{{}, {"operations"}, {"alerts", "logins"}, {"unknown"}, {"alerts", "alerts"}, {"alerts", "operations", "logins", "alerts"}} {
		c := legacy
		c.Streams = streams
		if c.Validate(outbound.Policy{}) == nil {
			t.Fatal("非 Syslog 渠道或无效类别被接受", streams)
		}
	}
	config := fixtureConfig("syslog_tls", "logs.example.invalid:6514")
	config.Streams = []string{"operations", "logins"}
	config.Severities = nil
	if config.Validate(outbound.Policy{}) != nil || len(config.Select(fixtureMessage().Alerts)) != 0 {
		t.Fatal("审计专用渠道混入安全告警")
	}
	public := config.Public()
	public.Streams[0] = "alerts"
	if config.Accepts("alerts") {
		t.Fatal("公开配置改变了持久配置")
	}
	config.Streams = append(config.Streams, "alerts")
	if config.Validate(outbound.Policy{}) == nil {
		t.Fatal("告警订阅没有要求告警级别")
	}
	config.Severities = []string{"high"}
	if config.Validate(outbound.Policy{}) != nil {
		t.Fatal("合法组合被拒绝")
	}
}

func auditMessage() notify.Message {
	m := fixtureMessage()
	m.Alerts = []notify.Summary{}
	m.CreatedAt = time.Date(2026, 10, 4, 1, 2, 3, 123456789, time.UTC)
	m.Logs = []notify.AuditLog{{ID: "9223372036854775807", Stream: "operations", Actor: "user_owned", Action: "inventory.groups.save", ObjectID: "group_owned", RequestID: "req_owned", SourceIP: "192.0.2.11", UserAgent: "验收客户端", Timestamp: m.CreatedAt}}
	return m
}

func TestAuditMessagesRejectUnsafeOrUnsubscribedMaterial(t *testing.T) {
	config := fixtureConfig("syslog_tls", "logs.example.invalid:6514")
	config.Streams = []string{"operations", "logins"}
	for name, change := range map[string]func(*notify.Message){
		"empty_tenant": func(m *notify.Message) { m.TenantID = "" }, "bad_batch": func(m *notify.Message) { m.BatchID = "bad/batch" }, "date": func(m *notify.Message) { m.CreatedAt = time.Time{} },
		"mixed": func(m *notify.Message) { m.Alerts = fixtureMessage().Alerts }, "test": func(m *notify.Message) { m.Test = true }, "limit": func(m *notify.Message) { m.Logs = make([]notify.AuditLog, 101) },
		"id": func(m *notify.Message) { m.Logs[0].ID = "01" }, "id_negative": func(m *notify.Message) { m.Logs[0].ID = "-1" }, "id_overflow": func(m *notify.Message) { m.Logs[0].ID = "9223372036854775808" }, "duplicate": func(m *notify.Message) { m.Logs = append(m.Logs, m.Logs[0]) },
		"stream": func(m *notify.Message) { m.Logs[0].Stream = "alerts" }, "timestamp": func(m *notify.Message) { m.Logs[0].Timestamp = time.Time{} }, "actor": func(m *notify.Message) { m.Logs[0].Actor = "" }, "control": func(m *notify.Message) { m.Logs[0].Action = "action\nsecret" },
		"object": func(m *notify.Message) { m.Logs[0].ObjectID = strings.Repeat("x", 1025) }, "operation_success": func(m *notify.Message) { m.Logs[0].Success = new(bool) }, "operation_phase": func(m *notify.Message) { m.Logs[0].Phase = "password_verification" },
		"login_success": func(m *notify.Message) { m.Logs[0].Stream = "logins" }, "login_action": func(m *notify.Message) {
			m.Logs[0].Stream = "logins"
			m.Logs[0].Success = new(bool)
			m.Logs[0].Phase = "password_verification"
		},
		"login_object": func(m *notify.Message) {
			m.Logs[0].Stream = "logins"
			m.Logs[0].Success = new(bool)
			m.Logs[0].Action = "auth.password_verification"
			m.Logs[0].Phase = "password_verification"
		},
		"ip": func(m *notify.Message) { m.Logs[0].SourceIP = "device.local" }, "ip_zone": func(m *notify.Message) { m.Logs[0].SourceIP = "fe80::1%eth0" }, "ip_mapped": func(m *notify.Message) { m.Logs[0].SourceIP = "::ffff:192.0.2.11" },
	} {
		t.Run(name, func(t *testing.T) {
			m := auditMessage()
			change(&m)
			out := (notify.Sender{}).Send(context.Background(), config, m)
			if out.State != "failed" || out.Code != "invalid_config" {
				t.Fatal("无效审计尝试建立外部连接", out)
			}
		})
	}
	config.Kind = "webhook"
	config.Endpoint = "https://example.invalid"
	config.Streams = nil
	if out := (notify.Sender{}).Send(context.Background(), config, auditMessage()); out.Code != "invalid_config" {
		t.Fatal("审计被发送到普通办公渠道")
	}
}

func TestSyslogAuditTLSFramesHaveMicrosecondTimestampAndUTF8BOM(t *testing.T) {
	certificate := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer certificate.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", certificate.TLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	frames := make(chan [][]byte, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			frames <- nil
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(4 * time.Second))
		reader := bufio.NewReader(connection)
		var items [][]byte
		for range 2 {
			prefix, err := reader.ReadString(' ')
			if err != nil {
				frames <- nil
				return
			}
			size, err := strconv.Atoi(strings.TrimSpace(prefix))
			if err != nil || size < 1 || size > 8192 {
				frames <- nil
				return
			}
			data := make([]byte, size)
			if _, err = io.ReadFull(reader, data); err != nil {
				frames <- nil
				return
			}
			items = append(items, data)
		}
		frames <- items
	}()
	m := auditMessage()
	login := m.Logs[0]
	login.Stream = "logins"
	login.Action = "auth.password_verification"
	login.ObjectID = ""
	login.Success = new(bool)
	login.Phase = "password_verification"
	m.Logs = append(m.Logs, login)
	config := fixtureConfig("syslog_tls", listener.Addr().String())
	config.Streams = []string{"operations", "logins"}
	outcome := (notify.Sender{Policy: fixturePolicy(certificate)}).Send(context.Background(), config, m)
	if outcome.State != "transport_written" || outcome.Frames != 2 || outcome.FramesWritten != 2 {
		t.Fatal("审计分帧或确认状态错误", outcome)
	}
	select {
	case items := <-frames:
		if len(items) != 2 {
			t.Fatal("未读取完整分帧")
		}
		for i, raw := range items {
			parts := strings.SplitN(string(raw), " ", 8)
			if len(parts) != 8 || parts[1] != "2026-10-04T01:02:03.123456Z" || parts[5] != m.Logs[i].Stream || !strings.HasPrefix(parts[7], "\xef\xbb\xbf") {
				t.Fatal("RFC 5424 头或编码声明无效")
			}
			var decoded struct {
				notify.Message
				Sequence int `json:"sequence"`
				Total    int `json:"total"`
			}
			if json.Unmarshal([]byte(strings.TrimPrefix(parts[7], "\xef\xbb\xbf")), &decoded) != nil || decoded.Sequence != i+1 || decoded.Total != 2 || len(decoded.Logs) != 1 || decoded.Logs[0].ID != m.Logs[i].ID || decoded.Logs[0].UserAgent != "验收客户端" {
				t.Fatal("审计帧数据不完整")
			}
		}
	case <-time.After(4 * time.Second):
		t.Fatal("TLS 日志服务器未接收到消息")
	}
}
