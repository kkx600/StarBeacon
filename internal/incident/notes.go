package incident

import (
	"errors"
	"slices"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

var ErrNoteInput = errors.New("调查笔记参数无效")

const MaxNotes = 128

// NoteSpec 保存纯文本调查材料；撤回不会删除原笔记及历史。
type NoteSpec struct {
	Title            string `json:"title"`
	Body             string `json:"body"`
	Status           string `json:"status"`
	WithdrawalReason string `json:"withdrawal_reason"`
}

func (s NoteSpec) Validate() error {
	if s.Title == "" || !Text(s.Title, 120, false) || s.Body == "" || !Text(s.Body, 8192, true) || !slices.Contains([]string{"active", "withdrawn"}, s.Status) {
		return ErrNoteInput
	}
	if s.Status == "withdrawn" {
		if s.WithdrawalReason == "" || !Text(s.WithdrawalReason, 2048, true) {
			return ErrNoteInput
		}
	} else if s.WithdrawalReason != "" {
		return ErrNoteInput
	}
	return nil
}

type NoteCreate struct {
	IncidentRevision int64    `json:"incident_revision"`
	Spec             NoteSpec `json:"spec"`
}

func (c NoteCreate) Validate() error {
	if c.IncidentRevision < 1 || c.IncidentRevision > MaxRevision || c.Spec.Status != "active" || c.Spec.Validate() != nil {
		return ErrNoteInput
	}
	return nil
}

type NoteChange struct {
	IncidentRevision int64    `json:"incident_revision"`
	ExpectedRevision int64    `json:"expected_revision"`
	Spec             NoteSpec `json:"spec"`
	Reason           string   `json:"reason"`
}

func (c NoteChange) Validate() error {
	if c.IncidentRevision < 1 || c.IncidentRevision > MaxRevision || c.ExpectedRevision < 1 || c.ExpectedRevision > MaxRevision || c.Reason == "" || !Text(c.Reason, 2048, true) || c.Spec.Validate() != nil {
		return ErrNoteInput
	}
	return nil
}

type NoteRecord struct {
	ID               string    `json:"id"`
	IncidentID       string    `json:"incident_id"`
	IncidentRevision int64     `json:"incident_revision"`
	Revision         int64     `json:"revision"`
	Spec             NoteSpec  `json:"spec"`
	AuthorID         string    `json:"author_id"`
	AuthorName       string    `json:"author_name"`
	Reason           string    `json:"reason"`
	ActorID          string    `json:"actor_id"`
	ActorName        string    `json:"actor_name"`
	CreatedAt        time.Time `json:"created_at"`
	RecordedAt       time.Time `json:"recorded_at"`
	ExpiresAt        time.Time `json:"expires_at"`
}

func (r NoteRecord) Validate() error {
	if !contract.ValidID(r.ID) || !contract.ValidID(r.IncidentID) || r.IncidentRevision < 1 || r.IncidentRevision > MaxRevision || r.Revision < 1 || r.Revision > MaxRevision || r.Spec.Validate() != nil || !contract.ValidID(r.AuthorID) || r.AuthorName == "" || !Text(r.AuthorName, 64, false) || r.ActorID != r.AuthorID || r.ActorName == "" || !Text(r.ActorName, 64, false) || r.Reason == "" || !Text(r.Reason, 2048, true) || r.CreatedAt.IsZero() || r.RecordedAt.Before(r.CreatedAt) || !r.ExpiresAt.After(r.RecordedAt) {
		return ErrNoteInput
	}
	return nil
}

type NotePage struct {
	Items []NoteRecord `json:"items"`
	Next  string       `json:"next_cursor"`
}

type NoteQuery struct {
	Status string
	Before string
}

func (q NoteQuery) Validate() error {
	if q.Status != "" && !slices.Contains([]string{"active", "withdrawn"}, q.Status) || q.Before != "" && !contract.ValidID(q.Before) {
		return ErrNoteInput
	}
	return nil
}
