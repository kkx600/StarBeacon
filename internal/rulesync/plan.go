// Package rulesync 定义固定授权修订的规则同步；未知执行结果不自动重试。
package rulesync

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/contract"
)

var ErrInput = errors.New("规则同步参数无效，请核对目标、规则修订及正反样本")
var ErrQuota = errors.New("规则同步计划数量或操作频率已达到上限")

const MaxRevision int64 = 1<<53 - 1

type Spec struct {
	Name             string `json:"name"`
	Enabled          bool   `json:"enabled"`
	SensorID         string `json:"sensor_id"`
	RegistrationID   string `json:"registration_id"`
	PackageID        string `json:"package_id"`
	PackageRevision  int64  `json:"package_revision"`
	PositiveSampleID string `json:"positive_sample_id"`
	NegativeSampleID string `json:"negative_sample_id"`
	IntervalSeconds  int    `json:"interval_seconds"`
}

func (s Spec) Validate() error {
	if !utf8.ValidString(s.Name) || strings.TrimSpace(s.Name) != s.Name || utf8.RuneCountInString(s.Name) < 1 || utf8.RuneCountInString(s.Name) > 128 || strings.ContainsFunc(s.Name, unicode.IsControl) || !contract.ValidID(s.SensorID) || !contract.ValidID(s.RegistrationID) || !contract.ValidID(s.PackageID) || s.PackageRevision < 1 || s.PackageRevision > MaxRevision || !contract.ValidID(s.PositiveSampleID) || !contract.ValidID(s.NegativeSampleID) || s.PositiveSampleID == s.NegativeSampleID || s.IntervalSeconds < 30 || s.IntervalSeconds > 3600 {
		return ErrInput
	}
	return nil
}

type Change struct {
	ID               string `json:"id"`
	ExpectedRevision int64  `json:"expected_revision"`
	Spec             Spec   `json:"spec"`
}

func (c Change) Validate() error {
	if !contract.ValidID(c.ID) || c.ExpectedRevision < 0 || c.ExpectedRevision >= MaxRevision {
		return ErrInput
	}
	return c.Spec.Validate()
}

type Plan struct {
	ID                string    `json:"id"`
	Revision          int64     `json:"revision"`
	Spec              Spec      `json:"spec"`
	CreatedBy         string    `json:"created_by"`
	UpdatedAt         time.Time `json:"updated_at"`
	NextAt            time.Time `json:"next_at"`
	ProcessedRevision int64     `json:"processed_revision"`
	Run               *Run      `json:"run,omitempty"`
}

type Run struct {
	ID             string     `json:"id"`
	PlanRevision   int64      `json:"plan_revision"`
	Spec           Spec       `json:"spec"`
	CreatedBy      string     `json:"created_by"`
	State          string     `json:"state"`
	Code           string     `json:"code"`
	Stage          int        `json:"stage"`
	Tasks          [4]string  `json:"tasks"`
	ExpectedSHA256 string     `json:"expected_sha256"`
	CreatedAt      time.Time  `json:"created_at"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
	ExpiresAt      time.Time  `json:"expires_at"`
}

func Terminal(state string) bool {
	return state == "succeeded" || state == "blocked" || state == "paused"
}

// 每步只提交一个持久任务；发布资格仍由任务事务核对全部签名回执。
func Kind(stage int) string {
	if stage < 0 || stage > 3 {
		return ""
	}
	return [4]string{"rules.validate", "rules.replay", "rules.replay", "rules.apply"}[stage]
}

func State(stage int) string {
	if stage < 0 || stage > 3 {
		return "blocked"
	}
	return [4]string{"validating", "positive_replay", "negative_replay", "applying"}[stage]
}

// 成功回执中的实际摘要和重载结果必须与批准修订一致，不能仅信任任务终态。
func Applied(raw json.RawMessage, sha string) bool {
	var v struct {
		SHA256    string          `json:"sha256"`
		Active    string          `json:"active_sha256"`
		Syntax    string          `json:"syntax"`
		AppliedAt time.Time       `json:"applied_at"`
		Ruleset   json.RawMessage `json:"engine_ruleset"`
	}
	if len(sha) != 64 || json.Unmarshal(raw, &v) != nil || v.Syntax != "passed" || v.Active != sha || v.SHA256 != sha || v.AppliedAt.IsZero() {
		return false
	}
	var stats []struct {
		Loaded *int64 `json:"rules_loaded"`
		Failed *int64 `json:"rules_failed"`
	}
	return json.Unmarshal(v.Ruleset, &stats) == nil && len(stats) == 1 && stats[0].Loaded != nil && stats[0].Failed != nil && *stats[0].Loaded > 0 && *stats[0].Failed == 0
}
