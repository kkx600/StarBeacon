package decision

import (
	"errors"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/kkx600/StarBeacon/internal/assessment"
	"github.com/kkx600/StarBeacon/internal/triage"
)

type Level string

const (
	Observe     Level = "observe"
	Approval    Level = "approval"
	Conditional Level = "conditional"
	Full        Level = "full"

	ConfirmationWindow = 15 * time.Minute
	MaxSmallBlock      = 2 * 60 * 60
)

var (
	ErrShadowRequired = errors.New("提高自动化级别前需要通过同一场景的影子评估")
	ErrPlanClosed     = errors.New("处置方案已关闭或确认时限已过")
)

func (l Level) rank() int {
	return slices.Index([]Level{Observe, Approval, Conditional, Full}, l)
}

func (l Level) Valid() bool { return l.rank() >= 0 }

func (l Level) Below(other Level) bool { return l.rank() < other.rank() }

type AutomationSettings struct {
	Revision int64 `json:"revision"`
	Ceiling  Level `json:"ceiling"`
	Paused   bool  `json:"paused"`
}

func DefaultAutomationSettings() AutomationSettings { return AutomationSettings{Ceiling: Approval} }

func (s AutomationSettings) Effective(level Level) Level {
	ceiling := s.Ceiling
	if s.Paused && Approval.Below(ceiling) {
		ceiling = Approval
	}
	if level.Below(ceiling) {
		return level
	}
	return ceiling
}

type AutomationChange struct {
	ExpectedRevision int64 `json:"expected_revision"`
	Ceiling          Level `json:"ceiling"`
	Paused           *bool `json:"paused"`
}

func (c AutomationChange) Valid() bool {
	return c.ExpectedRevision >= 0 && c.ExpectedRevision < 9007199254740991 && c.Ceiling.Valid() && c.Paused != nil
}

type SceneLevel struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Revision             int64  `json:"revision"`
	Active               bool   `json:"active"`
	Level                Level  `json:"level"`
	Effective            Level  `json:"effective"`
	SmallBlockMaxSeconds int    `json:"small_block_max_seconds"`
}

type AutomationState struct {
	Settings AutomationSettings `json:"settings"`
	Scenes   []SceneLevel       `json:"scenes"`
}

func (d Definition) Level() Level {
	if d.AutomationLevel != "" {
		return d.AutomationLevel
	}
	switch d.Mode {
	case "automatic":
		return Full
	case "approval":
		return Approval
	default:
		return Observe
	}
}

func (d Definition) ShadowCriteria() Definition {
	d.Mode = "shadow"
	d.AutomationLevel = ""
	d.SmallBlockMaxSeconds = 0
	d.Continuous = nil
	return d
}

func (d Definition) SmallBlockLimit() int {
	if d.SmallBlockMaxSeconds == 0 {
		return MaxSmallBlock
	}
	return d.SmallBlockMaxSeconds
}

// 内部、共享地址及租户资产一律按高影响处理；场景只能收紧默认的小影响时限。
func (d Definition) SmallSourceBlock(target string, ttl int, managed bool) bool {
	addr, err := netip.ParseAddr(target)
	return err == nil && addr.IsGlobalUnicast() && !addr.Is4In6() && !addr.IsPrivate() &&
		!netip.MustParsePrefix("100.64.0.0/10").Contains(addr) && !managed && ttl > 0 && ttl <= d.SmallBlockLimit()
}

type PlanSummary struct {
	Level          Level      `json:"level"`
	Impact         string     `json:"impact"`
	Action         string     `json:"action"`
	Confidence     float64    `json:"confidence"`
	Verdict        string     `json:"verdict"`
	Outcome        string     `json:"outcome"`
	References     []string   `json:"references"`
	Missing        []string   `json:"missing"`
	EvidenceSHA256 string     `json:"evidence_sha256"`
	ConfirmUntil   *time.Time `json:"confirm_until,omitempty"`
}

func SummarizePlan(level Level, action, evidenceSHA256 string, answer triage.Answer) *PlanSummary {
	impact := "none"
	if action == "block_source" {
		impact = "high"
	}
	return &PlanSummary{Level: level, Impact: impact, Action: action, Confidence: answer.Confidence,
		Verdict: answer.Verdict, Outcome: answer.Outcome, References: append([]string{}, answer.References...),
		Missing: append([]string{}, answer.Missing...), EvidenceSHA256: evidenceSHA256}
}

func (p PlanSummary) valid() bool {
	if !p.Level.Valid() || !slices.Contains([]string{"investigate", "notify", "block_source"}, p.Action) ||
		!slices.Contains([]string{"confirmed", "undetermined", "false_positive"}, p.Verdict) ||
		!slices.Contains([]string{"attempt", "unknown"}, p.Outcome) || math.IsNaN(p.Confidence) || p.Confidence < 0 || p.Confidence > 1 ||
		p.References == nil || len(p.References) > 8 || p.Missing == nil || len(p.Missing) > 8 || !assessment.ValidDigest(p.EvidenceSHA256) {
		return false
	}
	if p.Action == "block_source" {
		return p.Impact == "small" || p.Impact == "high"
	}
	return p.Impact == "none"
}

type RejectPlan struct {
	PlanSHA256 string `json:"plan_sha256"`
	Reason     string `json:"reason"`
}

func (r RejectPlan) Valid() bool {
	return assessment.ValidDigest(r.PlanSHA256) && text(r.Reason, 500, true, false)
}

type PlanReview struct {
	State      string    `json:"state"`
	PlanSHA256 string    `json:"plan_sha256"`
	ActorID    string    `json:"actor_id"`
	Reason     string    `json:"reason"`
	ReviewedAt time.Time `json:"reviewed_at"`
}

type PlanItem struct {
	Run       ContinuousRecord `json:"run"`
	State     string           `json:"state"`
	TaskID    string           `json:"task_id"`
	TaskState string           `json:"task_state"`
	Review    *PlanReview      `json:"review,omitempty"`
}

type PlanPage struct {
	Items      []PlanItem `json:"items"`
	NextCursor string     `json:"next_cursor"`
}
