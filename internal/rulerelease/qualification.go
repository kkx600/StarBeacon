// Package rulerelease 核对完整规则包的装载与正反样本证据，不推断未测试流量的检测效果。
package rulerelease

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
)

var ErrQualification = errors.New("发布需要同一探针、注册代次、规则修订与检测配置的有效装载和正反样本回执")
var ErrReconciliation = errors.New("待核实规则事务或当前设备摘要不匹配，请刷新探针状态并核对实际规则")

type Evidence struct {
	Command control.Command
	Receipt control.Receipt
}

type result struct {
	EngineVersion      string `json:"engine_version"`
	PackageID          string `json:"package_id"`
	Revision           int64  `json:"revision"`
	SHA256             string `json:"sha256"`
	RulesSHA256        string `json:"rules_sha256"`
	ConfigSHA256       string `json:"config_sha256"`
	ProfileSHA256      string `json:"profile_sha256"`
	Syntax             string `json:"syntax"`
	Replay             string `json:"replay"`
	RuleMode           string `json:"rule_mode"`
	SampleSHA256       string `json:"sample_sha256"`
	Alerts             *int64 `json:"alert_count"`
	Packets            string `json:"packets_processed"`
	Anomalies          int64  `json:"anomaly_count"`
	Profile            string `json:"profile"`
	ChecksumValidation *bool  `json:"checksum_validation"`
	SampleMetadata     *struct {
		Packets   int64 `json:"packets"`
		Truncated int64 `json:"truncated_packets"`
	} `json:"sample_metadata"`
	ResourceLimit string `json:"resource_limit"`
}

func digest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}

// 探针身份及命令签名由持久层核验；这里只接受已结束的精确回执，且资格在一天内有效。
func Qualify(p control.RulePackage, evidence [3]Evidence, expected string, now time.Time) (*control.RuleAuthorization, error) {
	if !digest(expected) {
		return nil, ErrQualification
	}
	var values [3]result
	var receiptHashes [3]string
	var sampleHashes [2]string
	for i, source := range evidence {
		c, r := source.Command, source.Receipt
		if c.ID == "" || r.CommandID != c.ID || r.State != "succeeded" || r.Code != "" || r.StartedAt.IsZero() || r.FinishedAt == nil || r.FinishedAt.Before(r.StartedAt) || r.StartedAt.Before(c.IssuedAt.Add(-time.Minute)) || r.StartedAt.After(c.ExpiresAt) || r.FinishedAt.After(now.Add(time.Minute)) || r.FinishedAt.Before(now.Add(-24*time.Hour)) || c.IssuedAt.After(now.Add(time.Minute)) {
			return nil, ErrQualification
		}
		if i > 0 && (c.TenantID != evidence[0].Command.TenantID || c.SensorID != evidence[0].Command.SensorID || c.RegistrationID != evidence[0].Command.RegistrationID || c.ID == evidence[0].Command.ID || (i == 2 && c.ID == evidence[1].Command.ID)) {
			return nil, ErrQualification
		}
		var rules control.RulePackage
		if i == 0 {
			if c.Kind != "rules.validate" || json.Unmarshal(c.Payload, &rules) != nil {
				return nil, ErrQualification
			}
		} else {
			var replay control.Replay
			if c.Kind != "rules.replay" || json.Unmarshal(c.Payload, &replay) != nil || replay.RuleMode != "package" || replay.Package == nil {
				return nil, ErrQualification
			}
			rules = *replay.Package
			sampleHashes[i-1] = replay.SampleSHA256
		}
		if rules.PackageID != p.PackageID || rules.Revision != p.Revision || rules.SHA256 != p.SHA256 || rules.Text != p.Text || rules.EngineVersion != p.EngineVersion || json.Unmarshal(r.Result, &values[i]) != nil {
			return nil, ErrQualification
		}
		v := values[i]
		if v.PackageID != p.PackageID || v.Revision != p.Revision || v.EngineVersion != p.EngineVersion || !digest(v.ConfigSHA256) || !digest(v.ProfileSHA256) || v.ResourceLimit != "" {
			return nil, ErrQualification
		}
		if i == 0 {
			if v.Syntax != "passed" || v.Replay != "not_run" || v.SHA256 != p.SHA256 {
				return nil, ErrQualification
			}
		} else {
			packets, err := strconv.ParseUint(v.Packets, 10, 64)
			if err != nil || packets == 0 || packets > 1000000 || v.Replay != "completed" || v.RuleMode != "package" || v.Profile != "offline-bounded-v1" || v.ChecksumValidation == nil || !*v.ChecksumValidation || v.SampleMetadata == nil || v.SampleMetadata.Packets != int64(packets) || v.SampleMetadata.Truncated != 0 || v.RulesSHA256 != p.SHA256 || v.SampleSHA256 != sampleHashes[i-1] || !digest(v.SampleSHA256) || v.Alerts == nil || *v.Alerts < 0 || v.Anomalies != 0 || v.ConfigSHA256 != values[0].ConfigSHA256 || v.ProfileSHA256 != values[0].ProfileSHA256 {
				return nil, ErrQualification
			}
			if (i == 1 && *v.Alerts == 0) || (i == 2 && *v.Alerts != 0) {
				return nil, ErrQualification
			}
		}
		var err error
		receiptRaw, _ := json.Marshal(r)
		receiptHashes[i], err = control.JSONDigest(receiptRaw)
		if err != nil {
			return nil, ErrQualification
		}
	}
	if sampleHashes[0] == sampleHashes[1] {
		return nil, ErrQualification
	}
	a := &control.RuleAuthorization{ValidationTaskID: evidence[0].Command.ID, PositiveReplayTaskID: evidence[1].Command.ID, NegativeReplayTaskID: evidence[2].Command.ID, ExpectedRulesSHA256: expected, ConfigSHA256: values[0].ConfigSHA256, ProfileSHA256: values[0].ProfileSHA256, ValidationReceiptSHA256: receiptHashes[0], PositiveReceiptSHA256: receiptHashes[1], NegativeReceiptSHA256: receiptHashes[2]}
	if err := a.Validate(); err != nil {
		return nil, ErrQualification
	}
	return a, nil
}
