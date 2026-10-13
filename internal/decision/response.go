package decision

import (
	"context"
	"time"

	"github.com/kkx600/StarBeacon/internal/assessment"
	"github.com/kkx600/StarBeacon/internal/contract"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/triage"
)

const ResponseSchema = "decision-response.v1"

// 人工确认与影子判断分别留档；目标只能来自原评估，调用方不能替换为其他 IP。
type ResponseRequest struct {
	EvaluationSHA256 string `json:"evaluation_sha256"`
	SensorID         string `json:"sensor_id"`
	RegistrationID   string `json:"registration_id"`
	ConnectorID      string `json:"connector_id"`
	ConfigSHA256     string `json:"config_sha256"`
	TTLSeconds       int    `json:"ttl_seconds"`
	Reason           string `json:"reason"`
	Confirmed        bool   `json:"confirmed"`
}

func (r ResponseRequest) Validate() error {
	if !assessment.ValidDigest(r.EvaluationSHA256) || !contract.ValidID(r.SensorID) || !contract.ValidID(r.RegistrationID) || !contract.ValidID(r.ConnectorID) || !assessment.ValidDigest(r.ConfigSHA256) || r.TTLSeconds < 30 || r.TTLSeconds > responseapi.MaxTTLSeconds || !text(r.Reason, 500, true, false) || !r.Confirmed {
		return ErrInput
	}
	return nil
}

// 提交时重新核对当前策略、原研判与实际告警白名单；历史匹配不能替代当前执行资格。
func ResponseIntent(ctx context.Context, e Evaluation, policy Record, job triage.Job, evidence triage.Evidence, request ResponseRequest, now time.Time) (responseapi.Intent, error) {
	// 自动模式使用独立持续授权，人工入口不得为同一策略建立第二条执行路径。
	if policy.Definition.Mode == "automatic" || e.Policy.Definition.Mode == "automatic" {
		return responseapi.Intent{}, ErrPermission
	}
	sealed, err := e.Seal()
	if request.Validate() != nil || err != nil || sealed.SHA256 != e.SHA256 || request.EvaluationSHA256 != e.SHA256 || now.IsZero() || e.Result.EvaluatedAt.After(now) || !e.ExpiresAt.After(now) || e.Result.Status != "matched" || e.Result.CandidateAction != "block_source" || e.Result.TargetIP == "" || policy.Validate() != nil || policy.TenantID != e.TenantID || policy.ID != e.Policy.ID || policy.Revision != e.Policy.Revision || policy.DefinitionSHA256 != e.Policy.DefinitionSHA256 || !policy.Active || job.ID != e.Result.TriageID || job.Evidence.SHA256 != e.Result.EvidenceSHA256 {
		return responseapi.Intent{}, ErrSource
	}
	current, err := triage.Seal(evidence)
	if err != nil || current.SHA256 != evidence.SHA256 || current.SHA256 != e.Result.EvidenceSHA256 {
		return responseapi.Intent{}, ErrSource
	}
	work, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	result, err := Evaluate(work, policy, job, now)
	if err != nil || result.Status != "matched" || result.TargetIP != e.Result.TargetIP || result.EvidenceSHA256 != current.SHA256 {
		return responseapi.Intent{}, ErrSource
	}
	result.EvaluatedAt = e.Result.EvaluatedAt
	if Digest(result) != Digest(e.Result) {
		return responseapi.Intent{}, ErrSource
	}
	intent := responseapi.Intent{ConnectorID: request.ConnectorID, ConfigSHA256: request.ConfigSHA256, TargetIP: e.Result.TargetIP, TTLSeconds: request.TTLSeconds, Reason: request.Reason}
	if err := intent.Validate("response.block"); err != nil {
		return responseapi.Intent{}, err
	}
	return intent, nil
}

type ResponseRecord struct {
	SchemaVersion    string          `json:"schema_version"`
	TenantID         string          `json:"tenant_id"`
	ID               string          `json:"id"`
	CreatedBy        string          `json:"created_by"`
	CreatedAt        time.Time       `json:"created_at"`
	ExpiresAt        time.Time       `json:"expires_at"`
	EvaluationID     string          `json:"evaluation_id"`
	EvaluationSHA256 string          `json:"evaluation_sha256"`
	PolicyID         string          `json:"policy_id"`
	PolicyRevision   int64           `json:"policy_revision"`
	DefinitionSHA256 string          `json:"definition_sha256"`
	TriageID         string          `json:"triage_id"`
	EvidenceSHA256   string          `json:"evidence_sha256"`
	TargetIP         string          `json:"target_ip"`
	Request          ResponseRequest `json:"request"`
	TaskID           string          `json:"task_id"`
	SHA256           string          `json:"sha256"`
}

func (r ResponseRecord) Seal() (ResponseRecord, error) {
	if r.SchemaVersion != ResponseSchema || !contract.ValidID(r.TenantID) || !contract.ValidID(r.ID) || !contract.ValidID(r.CreatedBy) || r.CreatedAt.IsZero() || r.CreatedAt.Location() != time.UTC || !r.ExpiresAt.After(r.CreatedAt) || r.ExpiresAt.Location() != time.UTC || !contract.ValidID(r.EvaluationID) || !assessment.ValidDigest(r.EvaluationSHA256) || !contract.ValidID(r.PolicyID) || r.PolicyRevision < 1 || r.PolicyRevision > MaxRevision || !assessment.ValidDigest(r.DefinitionSHA256) || !contract.ValidID(r.TriageID) || !assessment.ValidDigest(r.EvidenceSHA256) || !responseapi.ValidTarget(r.TargetIP) || r.Request.Validate() != nil || r.Request.EvaluationSHA256 != r.EvaluationSHA256 || !contract.ValidID(r.TaskID) {
		return ResponseRecord{}, ErrSource
	}
	r.SHA256 = ""
	r.SHA256 = Digest(r)
	return r, nil
}
