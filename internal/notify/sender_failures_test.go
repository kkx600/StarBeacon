package notify_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/outbound"
)

func smtpFailureFixture(t *testing.T, mode string) (notify.Config, outbound.Policy, <-chan struct{}) {
	t.Helper()
	certificate := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(certificate.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		if mode != "starttls" && mode != "no_starttls" {
			encrypted := tls.Server(connection, certificate.TLS)
			if encrypted.Handshake() != nil {
				return
			}
			connection = encrypted
		}
		reader := bufio.NewReader(connection)
		_, _ = io.WriteString(connection, "220 owned-fixture ESMTP\r\n")
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"):
				if mode == "ehlo_drop" {
					return
				}
				if mode == "starttls" {
					_, _ = io.WriteString(connection, "250-owned-fixture\r\n250 STARTTLS\r\n")
				} else {
					_, _ = io.WriteString(connection, "250-owned-fixture\r\n250 AUTH PLAIN\r\n")
				}
			case strings.HasPrefix(line, "STARTTLS"):
				_, _ = io.WriteString(connection, "220 begin TLS\r\n")
				encrypted := tls.Server(connection, certificate.TLS)
				if encrypted.Handshake() != nil {
					return
				}
				connection = encrypted
				reader = bufio.NewReader(connection)
			case strings.HasPrefix(line, "AUTH"):
				if mode == "auth_reject" {
					_, _ = io.WriteString(connection, "535 5.7.8 rejected\r\n")
				} else {
					_, _ = io.WriteString(connection, "235 2.7.0 authenticated\r\n")
				}
			case strings.HasPrefix(line, "MAIL FROM"):
				switch mode {
				case "mail_temporary":
					_, _ = io.WriteString(connection, "450 4.0.0 try later\r\n")
				case "mail_reject":
					_, _ = io.WriteString(connection, "550 5.0.0 rejected\r\n")
				default:
					_, _ = io.WriteString(connection, "250 2.0.0 ok\r\n")
				}
			case strings.HasPrefix(line, "RCPT TO"):
				if mode == "recipient_reject" {
					_, _ = io.WriteString(connection, "550 5.1.1 rejected\r\n")
				} else {
					_, _ = io.WriteString(connection, "250 2.0.0 ok\r\n")
				}
			case strings.HasPrefix(line, "DATA"):
				if mode == "data_reject" {
					_, _ = io.WriteString(connection, "550 5.0.0 rejected\r\n")
					continue
				}
				_, _ = io.WriteString(connection, "354 end with dot\r\n")
				for {
					data, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if data == ".\r\n" {
						break
					}
				}
				if mode == "ack_drop" {
					return
				}
				_, _ = io.WriteString(connection, "250 2.0.0 queued\r\n")
			case strings.HasPrefix(line, "RSET"):
				if mode == "reset_reject" {
					_, _ = io.WriteString(connection, "550 5.0.0 reset failed\r\n")
				} else {
					_, _ = io.WriteString(connection, "250 2.0.0 ok\r\n")
				}
			case strings.HasPrefix(line, "NOOP"):
				_, _ = io.WriteString(connection, "250 2.0.0 ok\r\n")
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
	config := notify.Config{Name: "邮件验收", Kind: "email", Enabled: true, Severities: []string{"high"}, SMTPHost: host, SMTPPort: number, From: "security@example.invalid", Recipients: []string{"recipient@example.invalid"}, ImplicitTLS: mode != "starttls" && mode != "no_starttls"}
	if mode == "auth_reject" {
		config.SMTPUser, config.SMTPPass = "owned", "owned"
	}
	return config, fixturePolicy(certificate), done
}

func TestSMTPRejectionAndLostAcceptanceHaveDistinctRetryStates(t *testing.T) {
	for _, tc := range []struct{ mode, state, code string }{
		{"mail_reject", "failed", "smtp_rejected"}, {"mail_temporary", "retry", "smtp_rejected"},
		{"recipient_reject", "failed", "smtp_rejected"}, {"data_reject", "failed", "smtp_rejected"},
		{"ack_drop", "uncertain", "smtp_result_unknown"}, {"reset_reject", "accepted", "smtp_accepted"},
		{"auth_reject", "failed", "smtp_setup_failed"}, {"ehlo_drop", "failed", "smtp_setup_failed"},
		{"no_starttls", "failed", "smtp_setup_failed"}, {"starttls", "accepted", "smtp_accepted"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			config, policy, done := smtpFailureFixture(t, tc.mode)
			message := fixtureMessage()
			message.Recipient = config.Recipients[0]
			out := (notify.Sender{Policy: policy}).Send(context.Background(), config, message)
			if out.State != tc.state || out.Code != tc.code {
				t.Fatal("SMTP 失败边界与投递状态不符", out)
			}
			select {
			case <-done:
			case <-time.After(4 * time.Second):
				t.Fatal("SMTP 连接未释放")
			}
		})
	}
}

func TestSenderRejectsOversizedUnencodableAndUnavailableTargets(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("非法消息不应触达目标") }))
	defer server.Close()
	for _, kind := range []string{"webhook", "syslog_tls"} {
		for _, mode := range []string{"size", "invalid_time"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				config := fixtureConfig(kind, server.URL)
				var listener net.Listener
				if kind == "syslog_tls" {
					var err error
					listener, err = tls.Listen("tcp", "127.0.0.1:0", server.TLS)
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					config.Endpoint = listener.Addr().String()
					go func() {
						c, e := listener.Accept()
						if e == nil {
							defer c.Close()
							_ = c.SetDeadline(time.Now().Add(time.Second))
							_, _ = io.Copy(io.Discard, c)
						}
					}()
				}
				message := fixtureMessage()
				if mode == "size" {
					message.Alerts[0].RuleName = strings.Repeat("名", 70000)
				} else {
					message.CreatedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
				}
				out := (notify.Sender{Policy: fixturePolicy(server)}).Send(context.Background(), config, message)
				if out.State != "failed" || (out.Code != "message_too_large" && out.Code != "invalid_message") {
					t.Fatal("非法消息发送结果不正确", out)
				}
			})
		}
	}
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := closed.Addr().String()
	_ = closed.Close()
	policy := fixturePolicy(server)
	for _, kind := range []string{"syslog_tls", "webhook", "email"} {
		t.Run(kind+"/connect", func(t *testing.T) {
			config := fixtureConfig(kind, "https://"+endpoint)
			message := fixtureMessage()
			if kind == "syslog_tls" {
				config.Endpoint = endpoint
			}
			if kind == "email" {
				host, port, _ := net.SplitHostPort(endpoint)
				number, _ := strconv.Atoi(port)
				config.Endpoint = ""
				config.SMTPHost = host
				config.SMTPPort = number
				config.From = "security@example.invalid"
				config.Recipients = []string{"recipient@example.invalid"}
				message.Recipient = config.Recipients[0]
				config.ImplicitTLS = true
			}
			out := (notify.Sender{Policy: policy}).Send(context.Background(), config, message)
			if out.State != "retry" || out.Code != "connection_failed" {
				t.Fatal("未建立连接不应标记受理", out)
			}
			out = (notify.Sender{Policy: outbound.Policy{}}).Send(context.Background(), config, message)
			if out.State != "failed" || out.Code != "target_denied" {
				t.Fatal("越权目标未拒绝", out)
			}
			if kind == "email" {
				message.Recipient = ""
				if out = (notify.Sender{Policy: policy}).Send(context.Background(), config, message); out.Code != "invalid_recipient" {
					t.Fatal(out)
				}
			}
		})
	}
}
