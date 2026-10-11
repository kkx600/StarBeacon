package decision

import (
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/kkx600/StarBeacon/internal/assessment"
	"github.com/kkx600/StarBeacon/internal/contract"
)

const EvaluationSchema = "decision-evaluation.v1"

// 档案只保存判断结果及策略快照，不复制研判原文、原始载荷或提供方凭据。
type Evaluation struct {
	SchemaVersion string    `json:"schema_version"`
	TenantID      string    `json:"tenant_id"`
	ID            string    `json:"id"`
	CreatedBy     string    `json:"created_by"`
	ExpiresAt     time.Time `json:"expires_at"`
	Policy        Record    `json:"policy"`
	Result        Result    `json:"result"`
	SHA256        string    `json:"sha256"`
}

func (e Evaluation) Seal() (Evaluation, error) {
	r := e.Result
	if e.SchemaVersion != EvaluationSchema || !contract.ValidID(e.ID) || !contract.ValidID(e.TenantID) || !contract.ValidID(e.CreatedBy) || e.Policy.TenantID != e.TenantID || e.Policy.Validate() != nil || !e.ExpiresAt.After(r.EvaluatedAt) || r.EvaluatedAt.IsZero() || r.SchemaVersion != ResultSchema || r.PolicyID != e.Policy.ID || r.PolicyRevision != e.Policy.Revision || r.DefinitionSHA256 != e.Policy.DefinitionSHA256 || r.CandidateAction != e.Policy.Definition.CandidateAction || !contract.ValidID(r.TriageID) || !contract.ValidID(r.ProviderID) || r.ProviderRevision < 1 || r.ProviderRevision > 9007199254740991 || !contract.ValidID(r.EventID) || !assessment.ValidDigest(r.RawSHA256) || !assessment.ValidDigest(r.EvidenceSHA256) || r.ConfidenceKind != "self_reported" || r.ExecutionAuthorized || len(r.Limitations) != 7 || len(r.Reasons) < 1 || len(r.Reasons) > 3 || !slices.Contains([]string{"matched", "not_matched", "protected", "abstained"}, r.Status) {
		return Evaluation{}, ErrSource
	}
	for _, value := range r.Limitations {
		if !text(value, 256, true, false) {
			return Evaluation{}, ErrSource
		}
	}
	if e.Policy.CreatedAt.After(r.EvaluatedAt) || r.Limitations[5] != "影子评估不创建通知、研判修改或设备动作" || r.Limitations[6] != "模型自报分数未获得场景校准资格" || r.Cost != nil && *r.Cost > 9007199254740991 {
		return Evaluation{}, ErrSource
	}
	seen := map[string]bool{}
	for _, value := range r.Reasons {
		if seen[value] || !slices.Contains([]string{"policy_inactive", "triage_not_eligible", "evidence_outside_window", "source_identity_unavailable", "protected_source", "expression_evaluation_failed", "expression_matched", "expression_not_matched"}, value) {
			return Evaluation{}, ErrSource
		}
		seen[value] = true
	}
	if r.Confidence != nil && (math.IsNaN(*r.Confidence) || math.IsInf(*r.Confidence, 0) || *r.Confidence < 0 || *r.Confidence > 1) {
		return Evaluation{}, ErrSource
	}
	if r.TargetIP != "" {
		address, err := netip.ParseAddr(r.TargetIP)
		if err != nil || !address.IsGlobalUnicast() || address.Is4In6() || address.String() != r.TargetIP || r.CandidateAction != "block_source" {
			return Evaluation{}, ErrSource
		}
	}
	if r.Status == "matched" || r.Status == "not_matched" {
		reason := "expression_matched"
		if r.Status == "not_matched" {
			reason = "expression_not_matched"
		}
		if !e.Policy.Active || r.Confidence == nil || r.Cost == nil || *r.Cost > MaxCost || len(r.Reasons) != 1 || r.Reasons[0] != reason || r.CandidateAction == "block_source" && r.TargetIP == "" {
			return Evaluation{}, ErrSource
		}
	} else if r.Status == "protected" {
		if !e.Policy.Active || r.Confidence == nil || r.Cost != nil || r.TargetIP == "" || len(r.Reasons) != 1 || r.Reasons[0] != "protected_source" {
			return Evaluation{}, ErrSource
		}
		address, _ := netip.ParseAddr(r.TargetIP)
		if !slices.ContainsFunc(e.Policy.Definition.ProtectedPrefixes, func(value string) bool { prefix, _ := netip.ParsePrefix(value); return prefix.Contains(address) }) {
			return Evaluation{}, ErrSource
		}
	} else if slices.ContainsFunc(r.Reasons, func(v string) bool {
		return v == "expression_matched" || v == "expression_not_matched" || v == "protected_source"
	}) {
		return Evaluation{}, ErrSource
	}
	e.SHA256 = ""
	e.SHA256 = Digest(e)
	return e, nil
}

type EvaluationRequest struct {
	PolicyID         string `json:"policy_id"`
	ExpectedRevision int64  `json:"expected_revision"`
	TriageID         string `json:"triage_id"`
}

func (r EvaluationRequest) Validate() error {
	if !contract.ValidID(r.PolicyID) {
		return ErrInput
	}
	return (EvaluateRequest{ExpectedRevision: r.ExpectedRevision, TriageID: r.TriageID}).Validate()
}

type EvaluationQuery struct {
	Cursor, PolicyID, TriageID, Status string
	Limit                              int
}

func (q EvaluationQuery) Validate() error {
	if q.Limit < 1 || q.Limit > 100 || q.Cursor != "" && !contract.ValidID(q.Cursor) || q.PolicyID != "" && !contract.ValidID(q.PolicyID) || q.TriageID != "" && !contract.ValidID(q.TriageID) || q.Status != "" && !slices.Contains([]string{"matched", "not_matched", "protected", "abstained"}, q.Status) {
		return ErrInput
	}
	return nil
}

type EvaluationPage struct {
	Items      []Evaluation `json:"items"`
	NextCursor string       `json:"next_cursor"`
}
