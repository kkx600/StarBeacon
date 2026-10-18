package notify

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

// 未配置日志类别的历史渠道仅投递告警，审计外发需要管理员明确选择。
func (c Config) LogStreams() []string {
	if c.Streams == nil {
		return []string{"alerts"}
	}
	return slices.Clone(c.Streams)
}

func (c Config) Accepts(stream string) bool { return slices.Contains(c.LogStreams(), stream) }

func ValidStreams(kind string, streams []string) bool {
	if len(streams) == 0 || len(streams) > 4 {
		return false
	}
	seen := map[string]bool{}
	for _, stream := range streams {
		if seen[stream] || !slices.Contains([]string{"alerts", "operations", "logins", "quality"}, stream) || stream != "alerts" && stream != "quality" && !strings.HasPrefix(kind, "syslog_") {
			return false
		}
		seen[stream] = true
	}
	return true
}

// 审计投递只包含明确白名单字段，不包含请求正文、操作原因、密码或配置凭据。
type AuditLog struct {
	ID        string    `json:"id"`
	Stream    string    `json:"stream"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	ObjectID  string    `json:"object_id"`
	RequestID string    `json:"request_id"`
	SourceIP  string    `json:"source_ip"`
	UserAgent string    `json:"user_agent"`
	Timestamp time.Time `json:"timestamp"`
	Success   *bool     `json:"success,omitempty"`
	Phase     string    `json:"phase,omitempty"`
	Truncated bool      `json:"truncated"`
}

func validAuditLogs(config Config, message Message) bool {
	if len(message.Logs) == 0 {
		return true
	}
	if len(message.Logs) > 100 || len(message.Alerts) != 0 || len(message.Quality) != 0 || message.Test || !strings.HasPrefix(config.Kind, "syslog_") || !contract.ValidID(message.TenantID) || !contract.ValidID(message.BatchID) || message.CreatedAt.Year() < 1970 || message.CreatedAt.Year() > 2262 {
		return false
	}
	seen := map[string]bool{}
	for _, log := range message.Logs {
		id, err := strconv.ParseInt(log.ID, 10, 64)
		key := log.Stream + "/" + log.ID
		if err != nil || id < 1 || strconv.FormatInt(id, 10) != log.ID || seen[key] || !config.Accepts(log.Stream) || log.Timestamp.Year() < 1970 || log.Timestamp.Year() > 2262 || log.Actor == "" || !plain(log.Actor, 256) || log.Action == "" || !plain(log.Action, 128) || !plain(log.ObjectID, 1024) || !plain(log.RequestID, 128) || !plain(log.SourceIP, 45) || !plain(log.UserAgent, 512) {
			return false
		}
		if log.Stream == "operations" {
			if log.Success != nil || log.Phase != "" {
				return false
			}
		} else if log.Stream != "logins" || log.Success == nil || log.Action != "auth.password_verification" || log.ObjectID != "" || log.Phase != "password_verification" {
			return false
		}
		if log.SourceIP != "" {
			ip, err := netip.ParseAddr(log.SourceIP)
			if err != nil || ip.Zone() != "" || ip.Unmap().String() != log.SourceIP {
				return false
			}
		}
		seen[key] = true
	}
	return true
}
