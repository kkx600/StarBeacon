package incident

import (
	"errors"
	"slices"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

var ErrTaskInput = errors.New("调查任务参数无效")

const MaxTasks = 128

type TaskSpec struct {
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Status      string     `json:"status"`
	Priority    string     `json:"priority"`
	AssigneeID  string     `json:"assignee_id"`
	DueAt       *time.Time `json:"due_at"`
	Resolution  string     `json:"resolution"`
}

func (s TaskSpec) Validate() error {
	if s.Title == "" || !Text(s.Title, 120, false) || s.Description == "" || !Text(s.Description, 4096, true) || !slices.Contains([]string{"open", "in_progress", "completed", "cancelled"}, s.Status) || !slices.Contains([]string{"low", "medium", "high"}, s.Priority) || s.AssigneeID != "" && !contract.ValidID(s.AssigneeID) {
		return ErrTaskInput
	}
	if s.DueAt != nil && (s.DueAt.IsZero() || s.DueAt.UTC().Year() < 2000 || s.DueAt.UTC().Year() > 2100) {
		return ErrTaskInput
	}
	if (s.Status == "in_progress" || s.Status == "completed") && s.AssigneeID == "" {
		return ErrTaskInput
	}
	if s.Status == "completed" || s.Status == "cancelled" {
		if s.Resolution == "" || !Text(s.Resolution, 2048, true) {
			return ErrTaskInput
		}
	} else if s.Resolution != "" {
		return ErrTaskInput
	}
	return nil
}

type TaskCreate struct {
	IncidentRevision int64    `json:"incident_revision"`
	Spec             TaskSpec `json:"spec"`
}

func (c TaskCreate) Validate() error {
	if c.IncidentRevision < 1 || c.IncidentRevision > MaxRevision || c.Spec.Status != "open" || c.Spec.Validate() != nil {
		return ErrTaskInput
	}
	return nil
}

type TaskChange struct {
	IncidentRevision int64    `json:"incident_revision"`
	ExpectedRevision int64    `json:"expected_revision"`
	Spec             TaskSpec `json:"spec"`
	Note             string   `json:"note"`
}

func (c TaskChange) Validate() error {
	if c.IncidentRevision < 1 || c.IncidentRevision > MaxRevision || c.ExpectedRevision < 1 || c.ExpectedRevision > MaxRevision || c.Note == "" || !Text(c.Note, 2048, true) || c.Spec.Validate() != nil {
		return ErrTaskInput
	}
	return nil
}

type TaskRecord struct {
	ID               string    `json:"id"`
	IncidentID       string    `json:"incident_id"`
	IncidentRevision int64     `json:"incident_revision"`
	Revision         int64     `json:"revision"`
	Spec             TaskSpec  `json:"spec"`
	AssigneeName     string    `json:"assignee_name"`
	Note             string    `json:"note"`
	ActorID          string    `json:"actor_id"`
	ActorName        string    `json:"actor_name"`
	CreatedAt        time.Time `json:"created_at"`
	RecordedAt       time.Time `json:"recorded_at"`
	ExpiresAt        time.Time `json:"expires_at"`
}

func (r TaskRecord) Validate() error {
	if !contract.ValidID(r.ID) || !contract.ValidID(r.IncidentID) || r.IncidentRevision < 1 || r.IncidentRevision > MaxRevision || r.Revision < 1 || r.Revision > MaxRevision || r.Spec.Validate() != nil || !contract.ValidID(r.ActorID) || r.ActorName == "" || !Text(r.ActorName, 64, false) || r.Note == "" || !Text(r.Note, 2048, true) || r.CreatedAt.IsZero() || r.RecordedAt.Before(r.CreatedAt) || !r.ExpiresAt.After(r.RecordedAt) {
		return ErrTaskInput
	}
	if r.Spec.AssigneeID == "" && r.AssigneeName != "" || r.Spec.AssigneeID != "" && (r.AssigneeName == "" || !Text(r.AssigneeName, 64, false)) {
		return ErrTaskInput
	}
	return nil
}

type TaskPage struct {
	Items []TaskRecord `json:"items"`
	Next  string       `json:"next_cursor"`
}

type TaskQuery struct {
	Status string
	Before string
}

func (q TaskQuery) Validate() error {
	if q.Status != "" && !slices.Contains([]string{"open", "in_progress", "completed", "cancelled"}, q.Status) || q.Before != "" && !contract.ValidID(q.Before) {
		return ErrTaskInput
	}
	return nil
}
