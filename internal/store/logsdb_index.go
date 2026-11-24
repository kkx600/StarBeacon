package store

import (
	"bytes"
	"encoding/json"
	"strings"
)

func sameIndexSettings(actual, want map[string]any, exact bool) bool {
	if exact && len(actual) != len(want) {
		return false
	}
	for name, value := range want {
		got, _ := json.Marshal(actual[name])
		expected, _ := json.Marshal(value)
		if !bytes.Equal(got, expected) {
			return false
		}
	}
	return true
}

func (t sharedTemplate) settings() map[string]any {
	if t.sortTime == "" {
		return nil
	}
	return map[string]any{
		"index.mode": "logsdb", "index.codec": "best_compression",
		"index.mapping.source.mode":                              "stored",
		"index.sort.field":                                       []string{"tenant_id", "sensor_id", t.sortTime},
		"index.sort.order":                                       []string{"asc", "asc", "desc"},
		"index.mapping.ignore_malformed":                         "false",
		"index.mapping.total_fields.ignore_dynamic_beyond_limit": "false",
	}
}

// 仅展示的字段仍保存在 _source 中。查询目录使用的字段保留原有类型和分析器。
func logsDBMapping(base string, fields []string, syslog bool) string {
	var mapping struct {
		Dynamic    string         `json:"dynamic"`
		Properties map[string]any `json:"properties"`
	}
	if err := json.Unmarshal([]byte(base), &mapping); err != nil {
		panic(err)
	}
	for _, path := range fields {
		parts := strings.Split(path, ".")
		properties := mapping.Properties
		for _, part := range parts[:len(parts)-1] {
			properties = properties[part].(map[string]any)["properties"].(map[string]any)
		}
		field := properties[parts[len(parts)-1]].(map[string]any)
		field["index"], field["doc_values"] = false, false
	}
	if syslog {
		mapping.Properties["@timestamp"] = map[string]any{"type": "date_nanos"}
		parsed := mapping.Properties["parsed"].(map[string]any)["properties"].(map[string]any)
		standard := parsed["message"].(map[string]any)["fields"].(map[string]any)
		standard["standard"] = map[string]any{"type": "match_only_text"}
	}
	raw, err := json.Marshal(mapping)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

var contextLogsDBMapping = logsDBMapping(mapping, []string{
	"schema_version", "source_offset", "sequence", "raw_sha256",
	"application.schema_version", "application.state_sha256", "application.raw_sha256", "application.product_name",
	"application.result.schema_version", "application.result.origin", "application.result.protocol", "application.result.reason",
	"application.result.evaluated_at", "application.result.observation_sha256", "application.result.rule_count",
	"application.result.matched_rule_count", "application.result.limited",
}, false)

var logsLogsDBMapping = logsDBMapping(logMapping, []string{
	"message_truncated", "schema_version", "sensor_registration_id", "sequence", "payload_sha256",
	"record.schema_version", "record.source_epoch", "record.source_sequence", "record.observed_at", "record.raw_sha256",
	"record.binding.source_name", "record.binding.config_sha256", "record.binding.transport",
	"record.binding.format", "record.binding.timezone", "record.binding.year_policy",
	"record.peer.port", "record.peer.certificate_sha256",
	"parsed.parser_version", "parsed.reason", "parsed.time_quality", "parsed.source_time", "parsed.priority", "parsed.facility",
	"parsed.process_id", "parsed.message_id", "parsed.message_utf8",
}, true)
