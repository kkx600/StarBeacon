package assistant

import (
	"strconv"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

// PlanSpec 将日、周、月计划绑定到自然周期；模型授权只适用于该修订的周期统计。
type PlanSpec struct {
	Name             string `json:"name"`
	Kind             string `json:"kind"`
	Timezone         string `json:"timezone"`
	At               string `json:"at"`
	Enabled          bool   `json:"enabled"`
	ProviderID       string `json:"provider_id"`
	ProviderRevision int64  `json:"provider_revision"`
	AllowContext     bool   `json:"allow_context"`
}

func (s PlanSpec) Validate() error {
	if !cleanText(s.Name, 80, false) || s.Name == "" || strings.ContainsAny(s.Name, "\n\t") || (s.Kind != "daily" && s.Kind != "weekly" && s.Kind != "monthly") || len(s.Timezone) > 128 || s.Timezone == "" || s.Timezone == "Local" || strings.Contains(s.Timezone, "..") {
		return ErrInput
	}
	if _, err := time.LoadLocation(s.Timezone); err != nil {
		return ErrInput
	}
	clock, err := time.Parse("15:04", s.At)
	if err != nil || clock.Format("15:04") != s.At {
		return ErrInput
	}
	if s.ProviderID == "" {
		if s.ProviderRevision != 0 || s.AllowContext {
			return ErrInput
		}
	} else if !contract.ValidID(s.ProviderID) || s.ProviderRevision < 1 || s.ProviderRevision >= 1<<53 || !s.AllowContext {
		return ErrInput
	}
	return nil
}

func nominalDate(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func (s PlanSpec) anchor(now time.Time, zone *time.Location) time.Time {
	date := nominalDate(now.In(zone))
	if s.Kind == "weekly" {
		date = date.AddDate(0, 0, -(int(date.Weekday())+6)%7)
	} else if s.Kind == "monthly" {
		date = time.Date(date.Year(), date.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
	return date
}

func (s PlanSpec) step(date time.Time, direction int) time.Time {
	if s.Kind == "monthly" {
		return date.AddDate(0, direction, 0)
	}
	days := direction
	if s.Kind == "weekly" {
		days *= 7
	}
	return date.AddDate(0, 0, days)
}

// calendarSlot 在重复时刻取首次，在跳过时刻取当日后续首个有效分钟。
// 完全不存在的自然日没有槽位，不把另一天伪装为该日。
func (s PlanSpec) calendarSlot(date time.Time, zone *time.Location) (time.Time, bool) {
	hour, _ := strconv.Atoi(s.At[:2])
	minute, _ := strconv.Atoi(s.At[3:])
	minimum := hour*60 + minute
	base := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, zone)
	for candidate, end := base.Add(-12*time.Hour), base.Add(36*time.Hour); candidate.Before(end); candidate = candidate.Add(time.Minute) {
		local := candidate.In(zone)
		if local.Year() == date.Year() && local.Month() == date.Month() && local.Day() == date.Day() && local.Hour()*60+local.Minute() >= minimum && local.Second() == 0 {
			return candidate.UTC(), true
		}
	}
	return time.Time{}, false
}

func (s PlanSpec) Next(now time.Time) (time.Time, error) {
	if s.Validate() != nil || now.IsZero() {
		return time.Time{}, ErrInput
	}
	zone, _ := time.LoadLocation(s.Timezone)
	date := s.anchor(now, zone)
	for range 4 {
		if slot, ok := s.calendarSlot(date, zone); ok && slot.After(now) {
			return slot, nil
		}
		date = s.step(date, 1)
	}
	return time.Time{}, ErrInput
}

// Latest 返回已经到期的最近槽位；停机期间只生成最近完整周期，缺口由运行记录保留。
func (s PlanSpec) Latest(now time.Time) (time.Time, error) {
	if s.Validate() != nil || now.IsZero() {
		return time.Time{}, ErrInput
	}
	zone, _ := time.LoadLocation(s.Timezone)
	date := s.anchor(now, zone)
	for range 4 {
		if slot, ok := s.calendarSlot(date, zone); ok && !slot.After(now) {
			return slot, nil
		}
		date = s.step(date, -1)
	}
	return time.Time{}, ErrInput
}

func (s PlanSpec) RequestAt(due time.Time) (Request, error) {
	if s.Validate() != nil || due.IsZero() {
		return Request{}, ErrInput
	}
	zone, _ := time.LoadLocation(s.Timezone)
	date := nominalDate(due.In(zone))
	slot, ok := s.calendarSlot(date, zone)
	if !ok || !slot.Equal(due) || !s.anchor(due, zone).Equal(date) {
		return Request{}, ErrInput
	}
	period := s.step(date, -1).Format("2006-01-02")
	return (Request{Kind: s.Kind, Period: period, Timezone: s.Timezone, ProviderID: s.ProviderID, ProviderRevision: s.ProviderRevision, AllowContext: s.AllowContext}).Normalize(due)
}

type PlanChange struct {
	ID               string   `json:"id"`
	ExpectedRevision int64    `json:"expected_revision"`
	Spec             PlanSpec `json:"spec"`
}

type Plan struct {
	ID        string     `json:"id"`
	Revision  int64      `json:"revision"`
	Spec      PlanSpec   `json:"spec"`
	NextAt    *time.Time `json:"next_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type PlanArgs struct {
	TenantID string    `json:"tenant_id"`
	PlanID   string    `json:"plan_id"`
	Revision int64     `json:"revision"`
	DueAt    time.Time `json:"due_at"`
}

func (PlanArgs) Kind() string { return "starbeacon.report_plan" }

func (a PlanArgs) Validate() error {
	if !contract.ValidID(a.TenantID) || !contract.ValidID(a.PlanID) || a.Revision < 1 || a.Revision >= 1<<53 || a.DueAt.IsZero() {
		return ErrInput
	}
	return nil
}

type PlanRun struct {
	ID            string     `json:"id"`
	PlanRevision  int64      `json:"plan_revision"`
	DueAt         time.Time  `json:"due_at"`
	EffectiveAt   time.Time  `json:"effective_at"`
	SkippedFrom   *time.Time `json:"skipped_from"`
	SkippedUntil  *time.Time `json:"skipped_until"`
	Request       Request    `json:"request"`
	State         string     `json:"state"`
	Code          string     `json:"code"`
	AnalysisID    string     `json:"analysis_id"`
	AnalysisState string     `json:"analysis_state"`
	CreatedAt     time.Time  `json:"created_at"`
	FinishedAt    *time.Time `json:"finished_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
}

type PlanLease struct {
	Args    PlanArgs
	RunID   string
	OwnerID string
	Request Request
	Execute bool
}
