package decision

import (
	"context"
	"slices"
	"time"

	"github.com/kkx600/StarBeacon/internal/assessment"
	"github.com/kkx600/StarBeacon/internal/contract"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/triage"
)

// 持续策略只处理当前维护者在本修订启用后创建的指定模型研判，不补做历史处置。
type ContinuousConfig struct {
	ProviderID       string           `json:"provider_id"`
	ProviderRevision int64            `json:"provider_revision"`
	Automatic        *AutomaticConfig `json:"automatic,omitempty"`
	Trigger          *TriageTrigger   `json:"trigger,omitempty"`
}

// 自动研判许可与设备执行许可独立，默认不向模型提交新告警。
type TriageTrigger struct {
	Severities        []string `json:"severities"`
	MaxDailyJobs      int      `json:"max_daily_jobs"`
	AllowModelContext bool     `json:"allow_model_context"`
}

func (t TriageTrigger) Validate() error {
	if len(t.Severities) < 1 || len(t.Severities) > 4 || t.MaxDailyJobs < 1 || t.MaxDailyJobs > 1000 || !t.AllowModelContext {
		return ErrInput
	}
	seen := map[string]bool{}
	for _, s := range t.Severities {
		if !slices.Contains([]string{"critical", "high", "medium", "low"}, s) || seen[s] {
			return ErrInput
		}
		seen[s] = true
	}
	return nil
}

type AutomaticConfig struct {
	SensorID                string `json:"sensor_id"`
	RegistrationID          string `json:"registration_id"`
	ConnectorID             string `json:"connector_id"`
	ConfigSHA256            string `json:"config_sha256"`
	TTLSeconds              int    `json:"ttl_seconds"`
	CooldownSeconds         int    `json:"cooldown_seconds"`
	MaxHourlyActions        int    `json:"max_hourly_actions"`
	AcceptUncalibratedScore bool   `json:"accept_uncalibrated_score"`
}

func (c ContinuousConfig) Validate(mode string) error {
	if !contract.ValidID(c.ProviderID) || c.ProviderRevision < 1 || c.ProviderRevision > 9007199254740991 {
		return ErrInput
	}
	if c.Trigger != nil && (mode != "automatic" || c.Trigger.Validate() != nil) {
		return ErrInput
	}
	if mode == "approval" && c.Automatic == nil {
		return nil
	}
	if mode != "automatic" || c.Automatic == nil {
		return ErrInput
	}
	a := c.Automatic
	if !contract.ValidID(a.SensorID) || !contract.ValidID(a.RegistrationID) || !contract.ValidID(a.ConnectorID) || !assessment.ValidDigest(a.ConfigSHA256) || a.TTLSeconds < 30 || a.TTLSeconds > responseapi.MaxTTLSeconds || a.CooldownSeconds < a.TTLSeconds || a.CooldownSeconds > 86400 || a.MaxHourlyActions < 1 || a.MaxHourlyActions > 100 || !a.AcceptUncalibratedScore {
		return ErrInput
	}
	return nil
}

const ContinuousSchema = "decision-continuous.v1"

// 连续判断、策略授权与设备效果独立记录；queued 仅表示签名任务已受理。
type ContinuousRecord struct {
	SchemaVersion    string           `json:"schema_version"`
	TenantID         string           `json:"tenant_id"`
	ID               string           `json:"id"`
	CreatedBy        string           `json:"created_by"`
	EvaluationID     string           `json:"evaluation_id"`
	EvaluationSHA256 string           `json:"evaluation_sha256"`
	PolicyID         string           `json:"policy_id"`
	PolicyRevision   int64            `json:"policy_revision"`
	DefinitionSHA256 string           `json:"definition_sha256"`
	TriageID         string           `json:"triage_id"`
	EventID          string           `json:"event_id"`
	RawSHA256        string           `json:"raw_sha256"`
	TargetIP         string           `json:"target_ip"`
	Config           ContinuousConfig `json:"config"`
	State            string           `json:"state"`
	Code             string           `json:"code"`
	TaskID           string           `json:"task_id"`
	CreatedAt        time.Time        `json:"created_at"`
	ExpiresAt        time.Time        `json:"expires_at"`
	SHA256           string           `json:"sha256"`
}

func (r ContinuousRecord) Seal() (ContinuousRecord, error) {
	mode := "approval"
	if r.Config.Automatic != nil {
		mode = "automatic"
	}
	if r.SchemaVersion != ContinuousSchema || !contract.ValidID(r.TenantID) || !contract.ValidID(r.ID) || !contract.ValidID(r.CreatedBy) || !contract.ValidID(r.EvaluationID) || !assessment.ValidDigest(r.EvaluationSHA256) || !contract.ValidID(r.PolicyID) || r.PolicyRevision < 1 || r.PolicyRevision > MaxRevision || !assessment.ValidDigest(r.DefinitionSHA256) || !contract.ValidID(r.TriageID) || !contract.ValidID(r.EventID) || !assessment.ValidDigest(r.RawSHA256) || r.Config.Validate(mode) != nil || r.CreatedAt.IsZero() || r.CreatedAt.Location() != time.UTC || r.ExpiresAt.Location() != time.UTC || !r.ExpiresAt.After(r.CreatedAt) || r.TargetIP != "" && !responseapi.ValidTarget(r.TargetIP) {
		return ContinuousRecord{}, ErrSource
	}
	if r.State == "queued" {
		if mode != "automatic" || r.Code != "policy_authorized" || !contract.ValidID(r.TaskID) || r.TargetIP == "" {
			return ContinuousRecord{}, ErrSource
		}
	} else if r.State == "awaiting_confirmation" {
		if mode != "approval" || r.Code != "manual_confirmation_required" || r.TaskID != "" {
			return ContinuousRecord{}, ErrSource
		}
	} else if r.State != "skipped" || r.TaskID != "" || !slices.Contains([]string{"policy_not_matched", "model_binding_changed", "score_below_threshold", "conclusion_not_eligible", "evidence_limited", "references_incomplete", "sensor_binding_changed", "evidence_changed", "target_cooldown", "event_already_authorized", "hourly_quota", "device_unavailable", "target_protected", "task_conflict", "tenant_quota"}, r.Code) {
		return ContinuousRecord{}, ErrSource
	}
	r.SHA256 = ""
	r.SHA256 = Digest(r)
	return r, nil
}

// 阈值、结论与出处是固定门槛；CEL 返回 true 不能跳过这些条件。
func AutomaticIntent(ctx context.Context, policy Record, job triage.Job, evidence triage.Evidence, now time.Time) (responseapi.Intent, string, error) {
	if policy.Validate() != nil || policy.Definition.Mode != "automatic" {
		return responseapi.Intent{}, "", ErrInput
	}
	result, err := Evaluate(ctx, policy, job, now)
	if err != nil {
		return responseapi.Intent{}, "", err
	}
	if result.Status != "matched" {
		return responseapi.Intent{}, "policy_not_matched", nil
	}
	c, a := policy.Definition.Continuous, policy.Definition.Continuous.Automatic
	if job.Request.ProviderID != c.ProviderID || job.Request.ProviderRevision != c.ProviderRevision {
		return responseapi.Intent{}, "model_binding_changed", nil
	}
	sealed, err := triage.Seal(evidence)
	if err != nil || sealed.SHA256 != evidence.SHA256 || sealed.SHA256 != result.EvidenceSHA256 {
		return responseapi.Intent{}, "evidence_changed", nil
	}
	if job.Answer.Confidence < policy.Definition.Threshold {
		return responseapi.Intent{}, "score_below_threshold", nil
	}
	if job.Answer.Verdict != "confirmed" || job.Answer.Outcome != "attempt" || job.Answer.Recommendation != "block_source" {
		return responseapi.Intent{}, "conclusion_not_eligible", nil
	}
	if sealed.Limited {
		return responseapi.Intent{}, "evidence_limited", nil
	}
	for _, id := range []string{"source.ip", "rule.id"} {
		if !slices.Contains(job.Answer.References, id) {
			return responseapi.Intent{}, "references_incomplete", nil
		}
	}
	facts := map[string]string{}
	for _, f := range sealed.Facts {
		facts[f.ID] = f.Value
	}
	if facts["sensor.id"] != a.SensorID || facts["sensor.registration"] != a.RegistrationID {
		return responseapi.Intent{}, "sensor_binding_changed", nil
	}
	intent := responseapi.Intent{ConnectorID: a.ConnectorID, ConfigSHA256: a.ConfigSHA256, TargetIP: result.TargetIP, TTLSeconds: a.TTLSeconds, Reason: "决策策略 " + policy.ID + " 修订自动授权；模型分数未经校准"}
	if err := intent.Validate("response.block"); err != nil {
		return responseapi.Intent{}, "", err
	}
	return intent, "policy_authorized", nil
}
