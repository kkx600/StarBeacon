// Package notify 以脱敏摘要投递通知，接收确认与最终送达分别记录。
package notify

import (
	"encoding/json"
	"errors"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/outbound"
)

var ErrConfig = errors.New("通知渠道配置无效")
var ErrBatch = errors.New("通知批次无效")

type Config struct {
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Streams     []string   `json:"streams,omitempty"`
	Enabled     bool       `json:"enabled"`
	Severities  []string   `json:"severities"`
	Endpoint    string     `json:"endpoint"`
	Secret      string     `json:"secret"`
	Token       string     `json:"token"`
	SMTPHost    string     `json:"smtp_host"`
	SMTPPort    int        `json:"smtp_port"`
	SMTPUser    string     `json:"smtp_user"`
	SMTPPass    string     `json:"smtp_password"`
	From        string     `json:"from"`
	Recipients  []string   `json:"recipients"`
	ImplicitTLS bool       `json:"implicit_tls"`
	MutedUntil  *time.Time `json:"muted_until"`
}

type Channel struct {
	ID         string     `json:"id"`
	Revision   int64      `json:"revision"`
	Name       string     `json:"name"`
	Kind       string     `json:"kind"`
	Streams    []string   `json:"streams"`
	Enabled    bool       `json:"enabled"`
	Severities []string   `json:"severities"`
	Target     string     `json:"target"`
	HasSecret  bool       `json:"has_secret"`
	MutedUntil *time.Time `json:"muted_until"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

func plain(value string, maximum int) bool {
	return utf8.ValidString(value) && len([]rune(value)) <= maximum && strings.IndexFunc(value, unicode.IsControl) < 0
}

func (c Config) Validate(policy outbound.Policy) error {
	if !ValidStreams(c.Kind, c.LogStreams()) || strings.TrimSpace(c.Name) != c.Name || c.Name == "" || !plain(c.Name, 128) || c.Accepts("alerts") && len(c.Severities) == 0 || len(c.Severities) > 4 || !plain(c.Secret, 1024) || !plain(c.Token, 4096) || !plain(c.SMTPUser, 320) || !plain(c.SMTPPass, 1024) {
		return ErrConfig
	}
	seen := map[string]bool{}
	for _, severity := range c.Severities {
		if seen[severity] || (severity != "high" && severity != "medium" && severity != "low" && severity != "unknown") {
			return ErrConfig
		}
		seen[severity] = true
	}
	if c.MutedUntil != nil && (c.MutedUntil.IsZero() || c.MutedUntil.After(time.Now().Add(365*24*time.Hour))) {
		return ErrConfig
	}
	switch c.Kind {
	case "email":
		if c.SMTPHost == "" || !plain(c.SMTPHost, 253) || strings.ContainsAny(c.SMTPHost, "/@ ") || c.SMTPPort < 1 || c.SMTPPort > 65535 || c.Endpoint != "" || len(c.Recipients) == 0 || len(c.Recipients) > 100 {
			return ErrConfig
		}
		if strings.Contains(c.SMTPHost, ":") && net.ParseIP(c.SMTPHost) == nil {
			return ErrConfig
		}
		from, err := mail.ParseAddress(c.From)
		if err != nil || from.Address != c.From || !plain(c.From, 320) {
			return ErrConfig
		}
		seen := map[string]bool{}
		for _, recipient := range c.Recipients {
			address, err := mail.ParseAddress(recipient)
			if err != nil || address.Address != recipient || !plain(recipient, 320) || seen[recipient] {
				return ErrConfig
			}
			seen[recipient] = true
		}
	case "webhook", "wecom", "dingtalk", "feishu":
		if _, err := policy.URL(c.Endpoint); err != nil {
			return err
		}
		if c.SMTPHost != "" || len(c.Recipients) != 0 {
			return ErrConfig
		}
	case "syslog_tls", "syslog_tcp":
		host, port, err := net.SplitHostPort(c.Endpoint)
		number, portError := strconv.Atoi(port)
		if err != nil || portError != nil || number < 1 || number > 65535 || host == "" || !plain(c.Endpoint, 320) || strings.ContainsAny(host, "/@ ") || (c.Kind == "syslog_tcp" && !policy.Development) {
			return ErrConfig
		}
		if c.Token != "" || c.Secret != "" || c.SMTPHost != "" || len(c.Recipients) != 0 {
			return ErrConfig
		}
	default:
		return ErrConfig
	}
	return nil
}

func (c Config) Public() Channel {
	target := c.SMTPHost
	if c.Kind != "email" {
		if strings.HasPrefix(c.Kind, "syslog_") {
			target = c.Endpoint
		} else if u, err := (outbound.Policy{Development: true}).URL(c.Endpoint); err == nil {
			target = u.Scheme + "://" + u.Host
		}
	}
	return Channel{Name: c.Name, Kind: c.Kind, Streams: c.LogStreams(), Enabled: c.Enabled, Severities: append([]string{}, c.Severities...), Target: target, HasSecret: c.Endpoint != "" || c.Secret != "" || c.Token != "" || c.SMTPPass != "", MutedUntil: c.MutedUntil}
}

type Summary struct {
	ID        string    `json:"id"`
	SensorID  string    `json:"sensor_id"`
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
	RuleID    string    `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
}

func ValidateBatch(tenant, batch string, alerts []Summary) error {
	if !contract.ValidID(tenant) || !contract.ValidID(batch) || len(alerts) > contract.MaxBatchRecords {
		return ErrBatch
	}
	seen := map[string]bool{}
	for _, alert := range alerts {
		if !contract.ValidID(alert.ID) || seen[alert.ID] || !contract.ValidID(alert.SensorID) || !plain(alert.RuleID, 64) || !plain(alert.RuleName, 256) || alert.Timestamp.Year() < 1970 || alert.Timestamp.Year() > 2262 {
			return ErrBatch
		}
		if alert.Severity != "high" && alert.Severity != "medium" && alert.Severity != "low" && alert.Severity != "unknown" {
			return ErrBatch
		}
		seen[alert.ID] = true
	}
	return nil
}

func Summaries(alerts []model.Alert) []Summary {
	out := make([]Summary, 0, len(alerts))
	for _, alert := range alerts {
		if alert.Event.Kind != "alert" {
			continue
		}
		// 通知不携带正文、URL、载荷或 IP；详情由具有当前授权的用户在平台内查看。
		name := strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return ' '
			}
			return r
		}, alert.Rule.Name)
		out = append(out, Summary{ID: alert.EventID, SensorID: alert.SensorID, Timestamp: alert.Timestamp, Severity: alert.Severity, RuleID: alert.Rule.ID, RuleName: string([]rune(name)[:min(256, len([]rune(name)))])})
	}
	return out
}

type Message struct {
	ID        string           `json:"delivery_id"`
	TenantID  string           `json:"tenant_id"`
	BatchID   string           `json:"batch_id"`
	CreatedAt time.Time        `json:"created_at"`
	Alerts    []Summary        `json:"alerts"`
	Logs      []AuditLog       `json:"logs,omitempty"`
	Quality   []QualitySummary `json:"quality,omitempty"`
	Recipient string           `json:"-"`
	Test      bool             `json:"test"`
}

func (m Message) Text() string {
	if m.Test {
		return "星烽 StarBeacon 通知渠道测试。该消息用于验证渠道受理情况。"
	}
	var output strings.Builder
	if len(m.Quality) > 0 {
		output.WriteString("星烽 StarBeacon 探针检测质量\n")
		for _, q := range m.Quality {
			output.WriteString(q.Title + " · " + q.SensorID + " · " + q.ID + "\n")
		}
		output.WriteString("本消息反映冻结区间的观测，不表示单流覆盖、攻击结果或完整恢复。\n投递标识：" + m.ID)
		return output.String()
	}
	output.WriteString("星烽 StarBeacon 安全告警\n")
	for _, alert := range m.Alerts[:min(10, len(m.Alerts))] {
		output.WriteString(alert.Severity + " · " + alert.RuleName + " · " + alert.ID + "\n")
	}
	if len(m.Alerts) > 10 {
		output.WriteString("该批次还有其他告警，请在平台告警中心查看。\n")
	}
	output.WriteString("投递标识：" + m.ID)
	return output.String()
}

func Encode(config Config) ([]byte, error) { return json.Marshal(config) }
