// Package decision 对冻结研判材料执行有界影子策略，不持有设备写入权限。
package decision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/triage"
)

const (
	Schema          = "decision-policy.v1"
	ResultSchema    = "decision-shadow.v1"
	MaxPolicies     = 64
	MaxRevision     = 1000000
	MaxDailyChanges = 1024
	MaxCost         = 1000
)

var (
	ErrInput      = errors.New("决策策略输入无效")
	ErrMode       = errors.New("当前执行资格只支持影子评估")
	ErrPermission = errors.New("决策策略操作权限已撤回")
	ErrQuota      = errors.New("决策策略数量或变更额度已达上限")
	ErrSource     = errors.New("研判材料与来源摘要不一致")
)

// 只注册标量事实；没有自定义函数、宏、网络、文件或设备操作。
var environment = sync.OnceValues(func() (*cel.Env, error) {
	return cel.NewEnv(cel.ClearMacros(), cel.ParserExpressionSizeLimit(2048), cel.ParserRecursionLimit(32), cel.ParserErrorRecoveryLimit(8),
		cel.Variable("confidence", cel.DoubleType), cel.Variable("threshold", cel.DoubleType),
		cel.Variable("verdict", cel.StringType), cel.Variable("outcome", cel.StringType), cel.Variable("recommendation", cel.StringType),
		cel.Variable("protocol", cel.StringType), cel.Variable("reference_count", cel.IntType), cel.Variable("missing_count", cel.IntType),
		cel.Variable("evidence_limited", cel.BoolType), cel.Variable("needs_review", cel.BoolType))
})

func text(value string, limit int, required, multiline bool) bool {
	return utf8.ValidString(value) && value == strings.TrimSpace(value) && (!required || value != "") && len([]rune(value)) <= limit && strings.IndexFunc(value, func(c rune) bool { return unicode.IsControl(c) && !(multiline && (c == '\n' || c == '\t')) }) < 0
}

func Compile(expression string) (cel.Program, error) {
	if !text(expression, 2048, true, true) || len(expression) > 2048 {
		return nil, ErrInput
	}
	env, err := environment()
	if err != nil {
		return nil, err
	}
	ast, issues := env.Compile(expression)
	if issues.Err() != nil || !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, ErrInput
	}
	return env.Program(ast, cel.CostLimit(MaxCost), cel.InterruptCheckFrequency(1))
}

type Definition struct {
	SchemaVersion     string   `json:"schema_version"`
	Mode              string   `json:"mode"`
	Expression        string   `json:"expression"`
	Threshold         float64  `json:"threshold"`
	CandidateAction   string   `json:"candidate_action"`
	MaxAgeSeconds     int      `json:"max_age_seconds"`
	ProtectedPrefixes []string `json:"protected_prefixes"`
}

func (d Definition) Validate() error {
	if !slices.Contains([]string{"shadow", "approval", "automatic"}, d.Mode) {
		return ErrInput
	}
	if d.Mode != "shadow" {
		return ErrMode
	}
	if d.SchemaVersion != Schema || math.IsNaN(d.Threshold) || math.IsInf(d.Threshold, 0) || d.Threshold <= 0 || d.Threshold > 1 || !slices.Contains([]string{"investigate", "notify", "block_source"}, d.CandidateAction) || d.MaxAgeSeconds < 60 || d.MaxAgeSeconds > 86400 || d.ProtectedPrefixes == nil || len(d.ProtectedPrefixes) > 32 {
		return ErrInput
	}
	seen := map[string]bool{}
	for _, value := range d.ProtectedPrefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() || prefix.String() != value || seen[value] {
			return ErrInput
		}
		seen[value] = true
	}
	_, err := Compile(d.Expression)
	return err
}

func Digest(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

type Change struct {
	ID               string     `json:"id"`
	ExpectedRevision int64      `json:"expected_revision"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	Active           *bool      `json:"active"`
	Definition       Definition `json:"definition"`
}

func (c Change) Validate() error {
	if !contract.ValidID(c.ID) || c.ExpectedRevision < 0 || c.ExpectedRevision >= MaxRevision || !text(c.Name, 128, true, false) || !text(c.Description, 1000, false, false) || c.Active == nil || c.ExpectedRevision == 0 && !*c.Active {
		return ErrInput
	}
	return c.Definition.Validate()
}

type Record struct {
	TenantID         string     `json:"tenant_id"`
	ID               string     `json:"id"`
	Revision         int64      `json:"revision"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	Active           bool       `json:"active"`
	Definition       Definition `json:"definition"`
	DefinitionSHA256 string     `json:"definition_sha256"`
	CreatedBy        string     `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
	ExpiresAt        time.Time  `json:"expires_at"`
}

func (r Record) Validate() error {
	if !contract.ValidID(r.TenantID) || !contract.ValidID(r.ID) || !contract.ValidID(r.CreatedBy) || r.Revision < 1 || r.Revision > MaxRevision || !text(r.Name, 128, true, false) || !text(r.Description, 1000, false, false) || r.CreatedAt.IsZero() || !r.ExpiresAt.After(r.CreatedAt) || r.DefinitionSHA256 != Digest(r.Definition) {
		return ErrInput
	}
	return r.Definition.Validate()
}

type ListQuery struct {
	Cursor, Keyword, Active string
	Limit                   int
}

func (q ListQuery) Validate() error {
	if q.Limit < 1 || q.Limit > 100 || q.Cursor != "" && !contract.ValidID(q.Cursor) || !text(q.Keyword, 128, false, false) || q.Active != "" && q.Active != "true" && q.Active != "false" {
		return ErrInput
	}
	return nil
}

type Page struct {
	Items      []Record `json:"items"`
	NextCursor string   `json:"next_cursor"`
}

type EvaluateRequest struct {
	ExpectedRevision int64  `json:"expected_revision"`
	TriageID         string `json:"triage_id"`
}

func (r EvaluateRequest) Validate() error {
	if r.ExpectedRevision < 1 || r.ExpectedRevision > MaxRevision || !contract.ValidID(r.TriageID) {
		return ErrInput
	}
	return nil
}

type Result struct {
	SchemaVersion       string    `json:"schema_version"`
	PolicyID            string    `json:"policy_id"`
	PolicyRevision      int64     `json:"policy_revision"`
	DefinitionSHA256    string    `json:"definition_sha256"`
	TriageID            string    `json:"triage_id"`
	ProviderID          string    `json:"provider_id"`
	ProviderRevision    int64     `json:"provider_revision"`
	EventID             string    `json:"event_id"`
	RawSHA256           string    `json:"raw_sha256"`
	EvidenceSHA256      string    `json:"evidence_sha256"`
	EvaluatedAt         time.Time `json:"evaluated_at"`
	Status              string    `json:"status"`
	Confidence          *float64  `json:"confidence"`
	ConfidenceKind      string    `json:"confidence_kind"`
	CandidateAction     string    `json:"candidate_action"`
	TargetIP            string    `json:"target_ip"`
	ExecutionAuthorized bool      `json:"execution_authorized"`
	Reasons             []string  `json:"reasons"`
	Limitations         []string  `json:"limitations"`
	Cost                *uint64   `json:"cost"`
}

func Evaluate(ctx context.Context, policy Record, job triage.Job, now time.Time) (Result, error) {
	if policy.Validate() != nil || now.IsZero() || !contract.ValidID(job.ID) || job.Request.Validate() != nil || job.Template != triage.TemplateVersion || job.Request.EventID != job.Evidence.EventID || job.Request.RawSHA256 != job.Evidence.RawSHA256 || job.ConfidenceKind != "self_reported" {
		return Result{}, ErrSource
	}
	sealed, err := triage.Seal(job.Evidence)
	if err != nil || sealed.SHA256 != job.Evidence.SHA256 {
		return Result{}, ErrSource
	}
	result := Result{SchemaVersion: ResultSchema, PolicyID: policy.ID, PolicyRevision: policy.Revision, DefinitionSHA256: policy.DefinitionSHA256, TriageID: job.ID, ProviderID: job.Request.ProviderID, ProviderRevision: job.Request.ProviderRevision, EventID: job.Request.EventID, RawSHA256: job.Request.RawSHA256, EvidenceSHA256: sealed.SHA256, EvaluatedAt: now.UTC(), Status: "abstained", ConfidenceKind: "self_reported", CandidateAction: policy.Definition.CandidateAction, Reasons: []string{}, Limitations: append(slices.Clone(sealed.Limitations), "影子评估不创建通知、研判修改或设备动作", "模型自报分数未获得场景校准资格")}
	if !policy.Active {
		result.Reasons = append(result.Reasons, "policy_inactive")
	}
	if job.State != "succeeded" || job.Result.State != "succeeded" || job.CancelRequested || job.Answer == nil || !job.ExpiresAt.After(now) {
		result.Reasons = append(result.Reasons, "triage_not_eligible")
	}
	age := now.Sub(sealed.ObservedAt)
	if age < 0 || age > time.Duration(policy.Definition.MaxAgeSeconds)*time.Second {
		result.Reasons = append(result.Reasons, "evidence_outside_window")
	}
	if len(result.Reasons) > 0 {
		return result, nil
	}
	raw, _ := json.Marshal(job.Answer)
	answer, err := triage.DecodeAnswer(string(raw), sealed)
	if err != nil {
		return Result{}, ErrSource
	}
	result.Confidence = &answer.Confidence
	facts := map[string]string{}
	for _, fact := range sealed.Facts {
		facts[fact.ID] = fact.Value
	}
	if policy.Definition.CandidateAction == "block_source" {
		address, err := netip.ParseAddr(facts["source.ip"])
		if err != nil || !address.IsGlobalUnicast() || address.Is4In6() {
			result.Reasons = append(result.Reasons, "source_identity_unavailable")
			return result, nil
		}
		result.TargetIP = address.String()
		for _, value := range policy.Definition.ProtectedPrefixes {
			prefix, _ := netip.ParsePrefix(value)
			if prefix.Contains(address) {
				result.Status = "protected"
				result.Reasons = append(result.Reasons, "protected_source")
				return result, nil
			}
		}
	}
	program, err := Compile(policy.Definition.Expression)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	out, details, err := program.ContextEval(ctx, map[string]any{"confidence": answer.Confidence, "threshold": policy.Definition.Threshold, "verdict": answer.Verdict, "outcome": answer.Outcome, "recommendation": answer.Recommendation, "protocol": facts["network.protocol"], "reference_count": int64(len(answer.References)), "missing_count": int64(len(answer.Missing)), "evidence_limited": sealed.Limited, "needs_review": answer.NeedsReview})
	if details != nil {
		result.Cost = details.ActualCost()
	}
	if err != nil || types.IsError(out) || types.IsUnknown(out) {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		result.Reasons = append(result.Reasons, "expression_evaluation_failed")
		return result, nil
	}
	result.Status = "not_matched"
	result.Reasons = append(result.Reasons, "expression_not_matched")
	if out == types.True {
		result.Status = "matched"
		result.Reasons[0] = "expression_matched"
	}
	return result, nil
}
