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
	"github.com/kkx600/StarBeacon/internal/qualityevent"
)

func qualityMessage() notify.Message {
	m := fixtureMessage()
	m.Alerts = []notify.Summary{}
	m.BatchID = "quality_" + strings.Repeat("a", 56)
	m.Quality = []notify.QualitySummary{{ID: strings.Repeat("a", 64), SensorID: "probe_owned", Timestamp: time.Now().UTC(), Kind: "limitation", Title: qualityevent.Title("limitation")}}
	return m
}

func TestQualityNotificationRequiresExplicitSubscriptionAndBoundedSummary(t *testing.T) {
	m := qualityMessage()
	c := fixtureConfig("webhook", "https://example.invalid")
	if c.Accepts("quality") {
		t.Fatal("历史渠道隐式外发质量事件")
	}
	if result := (notify.Sender{}).Send(context.Background(), c, m); result.Code != "invalid_config" {
		t.Fatal(result)
	}
	c.Streams = []string{"quality"}
	c.Severities = nil
	if c.Validate(outbound.Policy{}) != nil || notify.ValidateQuality(m.TenantID, m.BatchID, m.Quality) != nil {
		t.Fatal("拒绝显式质量订阅")
	}
	if err := notify.ValidateQuality("bad/id", m.BatchID, m.Quality); err == nil {
		t.Fatal("接受无效租户")
	}
	if err := notify.ValidateQuality(m.TenantID, m.BatchID, nil); err == nil {
		t.Fatal("接受空批次")
	}
	for _, change := range []func(*notify.Message){func(m *notify.Message) { m.BatchID = "other" }, func(m *notify.Message) { m.Quality[0].ID = strings.Repeat("g", 64) }, func(m *notify.Message) { m.Quality[0].SensorID = "" }, func(m *notify.Message) { m.Quality[0].Timestamp = time.Time{} }, func(m *notify.Message) { m.Quality[0].Kind = "safe" }, func(m *notify.Message) { m.Quality[0].Title = "secret" }, func(m *notify.Message) {
		m.Quality[0].Kind = "interval_clear"
		m.Quality[0].Title = qualityevent.Title("interval_clear")
		m.Quality[0].Reminder = true
	}, func(m *notify.Message) { m.Test = true }, func(m *notify.Message) { m.Alerts = fixtureMessage().Alerts }, func(m *notify.Message) { m.Logs = auditMessage().Logs }} {
		v := qualityMessage()
		change(&v)
		if result := (notify.Sender{}).Send(context.Background(), c, v); result.Code != "invalid_config" {
			t.Fatal("接受无效或混合质量通知", result)
		}
	}
	if text := m.Text(); !strings.Contains(text, "检测质量") || !strings.Contains(text, "区间") || strings.Contains(text, "配置摘要") {
		t.Fatal(text)
	}
}

func TestQualityOfficeNotificationsUseExistingAuthenticatedTransports(t *testing.T) {
	for _, kind := range []string{"webhook", "wecom", "dingtalk", "feishu"} {
		t.Run(kind, func(t *testing.T) {
			received := make(chan string, 1)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				received <- string(b)
				if kind == "feishu" {
					_, _ = io.WriteString(w, `{"code":0}`)
				} else {
					_, _ = io.WriteString(w, `{"errcode":0}`)
				}
			}))
			defer server.Close()
			c := fixtureConfig(kind, server.URL)
			c.Streams = []string{"quality"}
			c.Severities = nil
			m := qualityMessage()
			r := (notify.Sender{Policy: fixturePolicy(server)}).Send(context.Background(), c, m)
			if r.State != "accepted" {
				t.Fatal(r)
			}
			b := <-received
			if !strings.Contains(b, "检测区间存在限制") || strings.Contains(b, "config_sha256") || strings.Contains(b, "counters") || strings.Contains(b, "event.original") {
				t.Fatal("摘要外发范围不符", b)
			}
			if kind == "webhook" {
				var got notify.Message
				if json.Unmarshal([]byte(b), &got) != nil || len(got.Quality) != 1 || len(got.Alerts) != 0 {
					t.Fatal("质量通知信封错误")
				}
			}
		})
	}
}

func TestQualitySyslogUsesSingleUTF8FrameAndDoesNotClaimStorage(t *testing.T) {
	certificate := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer certificate.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", certificate.TLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	frames := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			frames <- ""
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(conn)
		prefix, err := reader.ReadString(' ')
		size, _ := strconv.Atoi(strings.TrimSpace(prefix))
		if err != nil || size < 1 || size > 8192 {
			frames <- ""
			return
		}
		data := make([]byte, size)
		_, err = io.ReadFull(reader, data)
		if err != nil {
			frames <- ""
			return
		}
		frames <- string(data)
	}()
	c := fixtureConfig("syslog_tls", listener.Addr().String())
	c.Streams = []string{"quality"}
	c.Severities = nil
	result := (notify.Sender{Policy: fixturePolicy(certificate)}).Send(context.Background(), c, qualityMessage())
	if result.State != "transport_written" || result.Frames != 1 || result.FramesWritten != 1 {
		t.Fatal(result)
	}
	if frame := <-frames; !strings.Contains(frame, "StarBeacon - quality - \xef\xbb\xbf") || !strings.Contains(frame, `"quality"`) {
		t.Fatal("质量事件分帧错误", frame)
	}
}
