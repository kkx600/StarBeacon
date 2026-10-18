package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/outbound"
	mail "github.com/wneessen/go-mail"
)

type Outcome struct {
	State         string    `json:"state"`
	Code          string    `json:"code"`
	HTTPStatus    int       `json:"http_status,omitempty"`
	ProviderCode  *int      `json:"provider_code,omitempty"`
	DurationMS    int64     `json:"duration_ms"`
	ObservedAt    time.Time `json:"observed_at"`
	Frames        int       `json:"frames,omitempty"`
	FramesWritten int       `json:"frames_written,omitempty"`
}

type Sender struct{ Policy outbound.Policy }

func (s Sender) Send(ctx context.Context, config Config, message Message) (out Outcome) {
	started := time.Now()
	defer func() { out.DurationMS = time.Since(started).Milliseconds(); out.ObservedAt = time.Now().UTC() }()
	if config.Validate(s.Policy) != nil || message.ID == "" || len(message.Alerts) > contract.MaxBatchRecords || !validAuditLogs(config, message) || !validQuality(config, message) {
		return Outcome{State: "failed", Code: "invalid_config"}
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	switch config.Kind {
	case "email":
		return s.email(ctx, config, message)
	case "syslog_tls", "syslog_tcp":
		return s.syslog(ctx, config, message)
	default:
		return s.webhook(ctx, config, message)
	}
}

func signature(key, value string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(value))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (s Sender) webhook(ctx context.Context, config Config, message Message) Outcome {
	target, err := s.Policy.URL(config.Endpoint)
	if err != nil {
		return Outcome{State: "failed", Code: "target_denied"}
	}
	var payload any = message
	switch config.Kind {
	case "wecom":
		payload = map[string]any{"msgtype": "text", "text": map[string]string{"content": message.Text()}}
	case "dingtalk":
		payload = map[string]any{"msgtype": "text", "msgUuid": message.ID, "text": map[string]string{"content": message.Text()}}
		if config.Secret != "" {
			stamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
			query := target.Query()
			query.Set("timestamp", stamp)
			query.Set("sign", signature(config.Secret, stamp+"\n"+config.Secret))
			target.RawQuery = query.Encode()
		}
	case "feishu":
		fields := map[string]any{"msg_type": "text", "content": map[string]string{"text": message.Text()}}
		if config.Secret != "" {
			stamp := strconv.FormatInt(time.Now().Unix(), 10)
			fields["timestamp"] = stamp
			fields["sign"] = signature(stamp+"\n"+config.Secret, "")
		}
		payload = fields
	}
	data, err := json.Marshal(payload)
	if err != nil || len(data) > 65536 {
		return Outcome{State: "failed", Code: "message_too_large"}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(data))
	if err != nil {
		return Outcome{State: "failed", Code: "invalid_config"}
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Set("Idempotency-Key", message.ID)
	request.Header.Set("User-Agent", "StarBeacon-Notification/1")
	if config.Kind == "webhook" {
		if config.Token != "" {
			request.Header.Set("Authorization", "Bearer "+config.Token)
		}
		if config.Secret != "" {
			request.Header.Set("X-StarBeacon-Signature", "sha256="+signature(config.Secret, string(data)))
		}
	}
	var written atomic.Bool
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{WroteHeaders: func() { written.Store(true) }}))
	client := s.Policy.HTTPClient()
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(err, outbound.ErrTarget) {
			return Outcome{State: "failed", Code: "target_denied"}
		}
		if written.Load() {
			return Outcome{State: "uncertain", Code: "acknowledgment_lost"}
		}
		return Outcome{State: "retry", Code: "connection_failed"}
	}
	defer response.Body.Close()
	out := Outcome{State: "failed", Code: "provider_rejected", HTTPStatus: response.StatusCode}
	if response.StatusCode == http.StatusTooManyRequests {
		out.State = "retry"
		out.Code = "provider_rate_limited"
		return out
	}
	if response.StatusCode >= 500 || response.StatusCode == http.StatusRequestTimeout {
		out.State = "uncertain"
		out.Code = "provider_result_unknown"
		return out
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return out
	}
	if config.Kind == "webhook" {
		out.State = "accepted"
		out.Code = "provider_accepted"
		return out
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(body) > 65536 {
		out.State = "uncertain"
		out.Code = "invalid_acknowledgment"
		return out
	}
	var acknowledgment struct {
		ErrCode    *int `json:"errcode"`
		Code       *int `json:"code"`
		StatusCode *int `json:"StatusCode"`
	}
	if json.Unmarshal(body, &acknowledgment) != nil {
		out.State = "uncertain"
		out.Code = "invalid_acknowledgment"
		return out
	}
	if config.Kind == "feishu" {
		out.ProviderCode = acknowledgment.Code
		if out.ProviderCode == nil {
			out.ProviderCode = acknowledgment.StatusCode
		}
		if acknowledgment.Code != nil && acknowledgment.StatusCode != nil && *acknowledgment.Code != *acknowledgment.StatusCode {
			out.State = "uncertain"
			out.Code = "invalid_acknowledgment"
			return out
		}
	} else {
		out.ProviderCode = acknowledgment.ErrCode
	}
	if out.ProviderCode == nil {
		out.State = "uncertain"
		out.Code = "invalid_acknowledgment"
		return out
	}
	if *out.ProviderCode == 0 {
		out.State = "accepted"
		out.Code = "provider_accepted"
	}
	return out
}

func (s Sender) syslog(ctx context.Context, config Config, message Message) Outcome {
	connection, err := s.Policy.DialContext(ctx, "tcp", config.Endpoint)
	if err != nil {
		if errors.Is(err, outbound.ErrTarget) {
			return Outcome{State: "failed", Code: "target_denied"}
		}
		return Outcome{State: "retry", Code: "connection_failed"}
	}
	defer connection.Close()
	rawConnection := connection
	stop := context.AfterFunc(ctx, func() { _ = rawConnection.Close() })
	defer stop()
	if config.Kind == "syslog_tls" {
		host, _, _ := net.SplitHostPort(config.Endpoint)
		encrypted := tls.Client(connection, s.Policy.TLSConfig(host))
		if encrypted.HandshakeContext(ctx) != nil {
			return Outcome{State: "failed", Code: "tls_verification_failed"}
		}
		connection = encrypted
		defer encrypted.Close()
	}
	// 每条业务记录单独分帧，避免批次超过接收器的单消息限制。
	count := max(1, len(message.Alerts), len(message.Logs), len(message.Quality))
	frames := make([][]byte, 0, count)
	for index := range count {
		item := message
		if len(message.Alerts) != 0 {
			item.Alerts = message.Alerts[index : index+1]
		}
		msgID := "alert"
		if len(message.Quality) != 0 {
			item.Quality = message.Quality[index : index+1]
			msgID = "quality"
		}
		if len(message.Logs) != 0 {
			item.Logs = message.Logs[index : index+1]
			msgID = item.Logs[0].Stream
		}
		data, err := json.Marshal(struct {
			Message
			Sequence int `json:"sequence"`
			Total    int `json:"total"`
		}{item, index + 1, count})
		if err != nil {
			return Outcome{State: "failed", Code: "invalid_message"}
		}
		// RFC 5425 以 UTF-8 字节数分帧，不能使用字符数。
		// RFC 5424 时间最多六位小数；中文 JSON 使用 UTF-8 BOM 声明编码。
		stamp := message.CreatedAt.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.999999Z07:00")
		packet := fmt.Sprintf("<134>1 %s - StarBeacon - %s - \xef\xbb\xbf%s", stamp, msgID, data)
		if len(packet) > 8192 {
			return Outcome{State: "failed", Code: "message_too_large"}
		}
		frames = append(frames, []byte(strconv.Itoa(len(packet))+" "+packet))
	}
	out := Outcome{State: "transport_written", Code: "storage_acknowledgment_unavailable", Frames: count}
	for _, frame := range frames {
		written, err := connection.Write(frame)
		if err != nil || written != len(frame) {
			out.State, out.Code = "uncertain", "transport_result_unknown"
			return out
		}
		out.FramesWritten++
	}
	return out
}

func (s Sender) email(ctx context.Context, config Config, message Message) Outcome {
	if message.Recipient == "" {
		return Outcome{State: "failed", Code: "invalid_recipient"}
	}
	allowed := false
	for _, recipient := range config.Recipients {
		if message.Recipient == recipient {
			allowed = true
		}
	}
	if !allowed {
		return Outcome{State: "failed", Code: "invalid_recipient"}
	}
	msg := mail.NewMsg()
	if msg.From(config.From) != nil || msg.To(message.Recipient) != nil {
		return Outcome{State: "failed", Code: "invalid_recipient"}
	}
	if len(message.Quality) > 0 {
		msg.Subject("星烽 StarBeacon 探针检测质量")
	} else {
		msg.Subject("星烽 StarBeacon 安全告警")
	}
	msg.SetMessageIDWithValue(message.ID + "@starbeacon.local")
	msg.SetBodyString(mail.TypeTextPlain, message.Text())
	var connected atomic.Bool
	var stop func() bool
	var activeConnection net.Conn
	defer func() {
		if activeConnection != nil {
			_ = activeConnection.Close()
		}
		if stop != nil {
			stop()
		}
	}()
	options := []mail.Option{mail.WithPort(config.SMTPPort), mail.WithTimeout(15 * time.Second), mail.WithTLSPolicy(mail.TLSMandatory), mail.WithTLSConfig(s.Policy.TLSConfig(config.SMTPHost)), mail.WithDialContextFunc(func(dialContext context.Context, network, address string) (net.Conn, error) {
		connection, err := s.Policy.DialContext(dialContext, network, address)
		if err != nil {
			return nil, err
		}
		connected.Store(true)
		activeConnection = connection
		// 库的拨号上下文在完成握手后会取消；整个投递使用外层任务上下文。
		stop = context.AfterFunc(ctx, func() { _ = connection.Close() })
		if config.ImplicitTLS {
			encrypted := tls.Client(connection, s.Policy.TLSConfig(config.SMTPHost))
			if err := encrypted.HandshakeContext(dialContext); err != nil {
				_ = connection.Close()
				return nil, err
			}
			return encrypted, nil
		}
		return connection, nil
	})}
	if config.ImplicitTLS {
		options = append(options, mail.WithSSL())
	}
	if config.SMTPUser != "" {
		auth := mail.SMTPAuthAutoDiscover
		// 自定义拨号已完成隐式 TLS；PLAIN 仍由库验证连接为 TLS，不能降级明文。
		if config.ImplicitTLS {
			auth = mail.SMTPAuthPlain
		}
		options = append(options, mail.WithSMTPAuth(auth), mail.WithUsername(config.SMTPUser), mail.WithPassword(config.SMTPPass))
	}
	host := config.SMTPHost
	if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	client, err := mail.NewClient(host, options...)
	if err != nil {
		return Outcome{State: "failed", Code: "invalid_config"}
	}
	smtpClient, err := client.DialToSMTPClientWithContext(ctx)
	if err != nil {
		if errors.Is(err, outbound.ErrTarget) {
			return Outcome{State: "failed", Code: "target_denied"}
		}
		if !connected.Load() || ctx.Err() != nil {
			return Outcome{State: "retry", Code: "connection_failed"}
		}
		return Outcome{State: "failed", Code: "smtp_setup_failed"}
	}
	defer client.CloseWithSMTPClient(smtpClient)
	err = client.SendWithSMTPClient(smtpClient, msg)
	if err != nil {
		var failure *mail.SendError
		if errors.As(err, &failure) {
			if failure.Reason == mail.ErrSMTPReset {
				return Outcome{State: "accepted", Code: "smtp_accepted"}
			}
			if failure.Reason == mail.ErrSMTPMailFrom || failure.Reason == mail.ErrSMTPRcptTo || failure.Reason == mail.ErrSMTPData || failure.Reason == mail.ErrConnCheck {
				state := "failed"
				if failure.IsTemp() {
					state = "retry"
				}
				return Outcome{State: state, Code: "smtp_rejected"}
			}
		}
		return Outcome{State: "uncertain", Code: "smtp_result_unknown"}
	}
	return Outcome{State: "accepted", Code: "smtp_accepted"}
}

func (c Config) Select(alerts []Summary) []Summary {
	selected := make([]Summary, 0, len(alerts))
	if !c.Accepts("alerts") {
		return selected
	}
	for _, alert := range alerts {
		if slices.Contains(c.Severities, alert.Severity) {
			selected = append(selected, alert)
		}
	}
	return selected
}
