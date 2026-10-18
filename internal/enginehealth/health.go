// Package enginehealth 定义原生检测引擎的只读观测；文件摘要不代表内存规则摘要。
package enginehealth

import (
	"regexp"
	"time"
)

const Schema = "1"

var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Report struct {
	SchemaVersion string    `json:"schema_version"`
	State         string    `json:"state"`
	Source        string    `json:"source"`
	ObservedAt    time.Time `json:"observed_at"`
	Code          string    `json:"code,omitempty"`
	PID           int32     `json:"pid,omitempty"`
	StartedAt     time.Time `json:"started_at,omitempty"`
	ConfigSHA256  string    `json:"config_sha256,omitempty"`
	RulesSHA256   string    `json:"rules_sha256,omitempty"`
	FileRuleCount int       `json:"file_rule_count,omitempty"`
	RulesLoaded   int       `json:"rules_loaded,omitempty"`
	RulesFailed   int       `json:"rules_failed"`
}

// Gate 只承认发布完成后的新观测；缺报或执行互斥等待不能被推定为健康。
func Gate(r *Report, expected string, now, after time.Time) string {
	if r == nil || r.SchemaVersion != Schema || r.ObservedAt.IsZero() || r.ObservedAt.Before(after) || now.Sub(r.ObservedAt) > 90*time.Second || r.ObservedAt.After(now.Add(5*time.Second)) {
		return "waiting_for_engine"
	}
	if r.State == "pending" || r.State == "unconfigured" {
		return "waiting_for_engine"
	}
	if r.State != "observed" || r.Code != "" || (r.Source != "managed_process" && r.Source != "registered_process") || r.PID < 1 || r.StartedAt.IsZero() || r.StartedAt.After(r.ObservedAt) || !digest.MatchString(r.ConfigSHA256) || !digest.MatchString(expected) || r.RulesSHA256 != expected || r.FileRuleCount < 1 || r.RulesLoaded != r.FileRuleCount || r.RulesFailed != 0 {
		return "engine_health_failed"
	}
	return ""
}
