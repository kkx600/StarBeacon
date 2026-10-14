package protocolcap

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
)

var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Validate 保持上报为有界观测；探针不能把效果资格、文件提取或外部连接器自行上报为已验收。
func (r Report) Validate() error {
	bad := errors.New("协议能力观测格式无效")
	if r.SchemaVersion != SchemaVersion || r.ObservedAt.IsZero() || len(r.Protocols) > 160 || len(r.Limits) > 7 {
		return bad
	}
	if r.State == "pending" || r.State == "unavailable" {
		if r.Source != "unavailable" || r.CaptureActive || r.EngineVersion != "" || r.EngineSHA256 != "" || r.ConfigSHA256 != "" || len(r.Protocols) != 0 || len(r.Limits) != 0 {
			return bad
		}
		switch r.ErrorCode {
		case "inspection_pending", "engine_not_configured", "engine_isolation_unavailable", "engine_version_mismatch", "native_protocol_inventory_unavailable", "protocol_configuration_unavailable", "protocol_configuration_unsupported", "protocol_observation_changed", "protocol_inspection_cancelled":
			return nil
		}
		return bad
	}
	if r.State != "observed" || r.EngineVersion != "8.0.7" || !digest.MatchString(r.EngineSHA256) || !digest.MatchString(r.ConfigSHA256) || r.ErrorCode != "" || len(r.Protocols) == 0 || len(r.Limits) != 7 {
		return bad
	}
	if r.Source != "managed_configuration" && r.Source != "offline_template" || r.CaptureActive && r.Source != "managed_configuration" {
		return bad
	}
	seen := map[string]bool{}
	for _, row := range r.Protocols {
		if !protocolName.MatchString(row.Protocol) || seen[row.Protocol] || row.Name == "" || len(row.Name) > 64 || strings.IndexFunc(row.Name, unicode.IsControl) >= 0 || len(row.Bindings) > 2 || row.FileExtraction != "not_implemented" || row.ExternalLogs != "not_implemented" || row.Qualification != "not_qualified" {
			return bad
		}
		seen[row.Protocol] = true
		if !oneOf(row.Recognition, "unknown", "partial", "disabled", "unlisted", "detection_only", "configured", "native_listed") || !oneOf(row.Transactions, "unknown", "partial", "disabled", "configured", "not_configured") || !oneOf(row.OnlineRules, "requires_validation", "disabled") || !oneOf(row.PacketForensics, "packet_headers_only", "not_implemented") {
			return bad
		}
		bindings := map[string]bool{}
		for _, binding := range row.Bindings {
			if bindings[binding.Transport] || !oneOf(binding.Transport, "tcp", "udp", "unknown") || !oneOf(binding.Mode, "yes", "no", "detection-only", "unknown") {
				return bad
			}
			bindings[binding.Transport] = true
		}
	}
	limits := map[string]bool{}
	for _, limit := range r.Limits {
		if limits[limit.Key] || !oneOf(limit.Key, "flow.memcap", "stream.memcap", "stream.reassembly.memcap", "stream.reassembly.depth", "defrag.memcap", "app-layer.protocols.http.libhtp.default-config.request-body-limit", "app-layer.protocols.http.libhtp.default-config.response-body-limit") || limit.Value != "" && !sizeValue.MatchString(limit.Value) {
			return bad
		}
		limits[limit.Key] = true
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
