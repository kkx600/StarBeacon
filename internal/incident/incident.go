// Package incident 定义人工事件调查；调查结论不改写检测事实，也不证明设备已执行响应。
package incident

import (
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/assessment"
	"github.com/kkx600/StarBeacon/internal/contract"
)

var ErrInput = errors.New("安全事件输入无效")

const MaxRevision = 1000
const MaxAlerts = 16

type AlertRef struct {
	EventID string `json:"event_id"`
	SHA256  string `json:"raw_sha256"`
}

type AlertEvidence struct {
	AlertRef
	SensorID   string    `json:"sensor_id"`
	ObservedAt time.Time `json:"observed_at"`
	EventTime  time.Time `json:"event_time"`
}

type Closure struct {
	Reason       string   `json:"reason"`
	RootCause    string   `json:"root_cause"`
	Impact       string   `json:"impact"`
	Remediation  string   `json:"remediation"`
	Verification string   `json:"verification"`
	Evidence     []string `json:"evidence"`
}

type Spec struct {
	Title    string   `json:"title"`
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Status   string   `json:"status"`
	Summary  string   `json:"summary"`
	OwnerID  string   `json:"owner_id"`
	Closure  *Closure `json:"closure"`
}

func Text(v string, limit int, multiline bool) bool {
	return utf8.ValidString(v) && strings.TrimSpace(v) == v && len([]rune(v)) <= limit && strings.IndexFunc(v, func(r rune) bool { return unicode.IsControl(r) && !(multiline && (r == '\n' || r == '\t')) }) == -1
}

func (s Spec) Validate() error {
	if s.Title == "" || !Text(s.Title, 120, false) || s.Summary == "" || !Text(s.Summary, 4096, true) || (s.OwnerID != "" && !contract.ValidID(s.OwnerID)) || !slices.Contains([]string{"network_intrusion", "malware", "exposure", "abnormal", "other"}, s.Category) || !slices.Contains([]string{"low", "medium", "high", "critical"}, s.Severity) || !slices.Contains([]string{"open", "investigating", "closed"}, s.Status) {
		return ErrInput
	}
	if s.Status != "closed" {
		if s.Closure != nil {
			return ErrInput
		}
		return nil
	}
	if s.OwnerID == "" || s.Closure == nil {
		return ErrInput
	}
	c := s.Closure
	if !slices.Contains([]string{"resolved", "false_positive"}, c.Reason) || c.Evidence == nil || len(c.Evidence) > 8 || (c.Reason == "resolved" && len(c.Evidence) == 0) {
		return ErrInput
	}
	for _, v := range []string{c.RootCause, c.Impact, c.Remediation, c.Verification} {
		if v == "" || !Text(v, 2048, true) {
			return ErrInput
		}
	}
	seen := map[string]bool{}
	for _, v := range c.Evidence {
		if v == "" || !Text(v, 256, false) || seen[v] {
			return ErrInput
		}
		seen[v] = true
	}
	return nil
}

func ValidateRefs(refs []AlertRef) error {
	if refs == nil || len(refs) > 8 {
		return ErrInput
	}
	seen := map[string]bool{}
	for _, r := range refs {
		if !contract.ValidID(r.EventID) || !assessment.ValidDigest(r.SHA256) || seen[r.EventID] {
			return ErrInput
		}
		seen[r.EventID] = true
	}
	return nil
}

type Create struct {
	Spec   Spec       `json:"spec"`
	Alerts []AlertRef `json:"alerts"`
}

func (c Create) Validate() error {
	if c.Spec.Status != "open" || c.Spec.Validate() != nil {
		return ErrInput
	}
	return ValidateRefs(c.Alerts)
}

type Change struct {
	ExpectedRevision int64      `json:"expected_revision"`
	Spec             Spec       `json:"spec"`
	Note             string     `json:"note"`
	AddAlerts        []AlertRef `json:"add_alerts"`
}

func (c Change) Validate() error {
	if c.ExpectedRevision < 1 || c.ExpectedRevision > MaxRevision || c.Note == "" || !Text(c.Note, 2048, true) || c.Spec.Validate() != nil {
		return ErrInput
	}
	return ValidateRefs(c.AddAlerts)
}

type Record struct {
	ID         string          `json:"id"`
	Revision   int64           `json:"revision"`
	Spec       Spec            `json:"spec"`
	OwnerName  string          `json:"owner_name"`
	Alerts     []AlertEvidence `json:"alerts"`
	Note       string          `json:"note"`
	ActorID    string          `json:"actor_id"`
	ActorName  string          `json:"actor_name"`
	CreatedAt  time.Time       `json:"created_at"`
	RecordedAt time.Time       `json:"recorded_at"`
	ExpiresAt  time.Time       `json:"expires_at"`
}

func (r Record) Validate() error {
	if !contract.ValidID(r.ID) || r.Revision < 1 || r.Revision > MaxRevision || r.Spec.Validate() != nil || !contract.ValidID(r.ActorID) || r.ActorName == "" || !Text(r.ActorName, 64, false) || r.Note == "" || !Text(r.Note, 2048, true) || r.CreatedAt.IsZero() || r.RecordedAt.Before(r.CreatedAt) || !r.ExpiresAt.After(r.RecordedAt) || r.Alerts == nil || len(r.Alerts) > MaxAlerts {
		return ErrInput
	}
	if (r.Spec.OwnerID == "" && r.OwnerName != "") || (r.Spec.OwnerID != "" && (r.OwnerName == "" || !Text(r.OwnerName, 64, false))) {
		return ErrInput
	}
	seen := map[string]bool{}
	for _, a := range r.Alerts {
		if !contract.ValidID(a.EventID) || !assessment.ValidDigest(a.SHA256) || !contract.ValidID(a.SensorID) || a.EventTime.IsZero() || a.ObservedAt.IsZero() || seen[a.EventID] {
			return ErrInput
		}
		seen[a.EventID] = true
	}
	return nil
}

type Query struct {
	Status   string
	Severity string
	Before   string
}

func (q Query) Validate() error {
	if (q.Status != "" && !slices.Contains([]string{"open", "investigating", "closed"}, q.Status)) || (q.Severity != "" && !slices.Contains([]string{"low", "medium", "high", "critical"}, q.Severity)) || (q.Before != "" && !contract.ValidID(q.Before)) {
		return ErrInput
	}
	return nil
}

type Page struct {
	Items []Record `json:"items"`
	Next  string   `json:"next_cursor"`
}
type Assignee struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
