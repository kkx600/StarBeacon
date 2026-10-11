// Package assessment 保存人工研判与处置记录，不改变原始检测事实或替代设备回执。
package assessment

import (
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrInput = errors.New("告警研判输入无效")

func ValidDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

type Spec struct {
	Status   string   `json:"status"`
	Verdict  string   `json:"verdict"`
	Outcome  string   `json:"outcome"`
	Note     string   `json:"note"`
	Evidence []string `json:"evidence"`
}

func Default() Spec {
	return Spec{Status: "open", Verdict: "unreviewed", Outcome: "unknown", Evidence: []string{}}
}

func clean(value string, limit int, multiline bool) bool {
	return utf8.ValidString(value) && strings.TrimSpace(value) == value && len([]rune(value)) <= limit && strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsControl(r) && !(multiline && (r == '\n' || r == '\t'))
	}) == -1
}

func (s Spec) Validate() error {
	if !slices.Contains([]string{"open", "investigating", "closed"}, s.Status) || !slices.Contains([]string{"unreviewed", "suspicious", "false_positive", "confirmed"}, s.Verdict) || !slices.Contains([]string{"unknown", "attempt", "success", "prevented"}, s.Outcome) || s.Note == "" || !clean(s.Note, 2048, true) || s.Evidence == nil || len(s.Evidence) > 8 {
		return ErrInput
	}
	if (s.Status == "closed" && s.Verdict != "false_positive" && s.Verdict != "confirmed") || (s.Verdict != "confirmed" && s.Outcome != "unknown") || ((s.Outcome == "success" || s.Outcome == "prevented") && len(s.Evidence) == 0) {
		return ErrInput
	}
	seen := map[string]bool{}
	for _, reference := range s.Evidence {
		if reference == "" || !clean(reference, 256, false) || seen[reference] {
			return ErrInput
		}
		seen[reference] = true
	}
	return nil
}

type Change struct {
	ExpectedRevision int64 `json:"expected_revision"`
	Spec             Spec  `json:"spec"`
	Claim            bool  `json:"claim"`
}

func (c Change) Validate() error {
	if c.ExpectedRevision < 0 || c.ExpectedRevision >= (1<<53)-1 {
		return ErrInput
	}
	return c.Spec.Validate()
}

type Record struct {
	EventID   string     `json:"event_id"`
	SHA256    string     `json:"raw_sha256"`
	Revision  int64      `json:"revision"`
	Spec      Spec       `json:"spec"`
	OwnerID   string     `json:"owner_id"`
	OwnerName string     `json:"owner_name"`
	AnalystID string     `json:"analyst_id"`
	Analyst   string     `json:"analyst"`
	Basis     string     `json:"basis"`
	UpdatedAt *time.Time `json:"updated_at"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type HistoryPage struct {
	Items []Record `json:"items"`
	Next  string   `json:"next_cursor"`
}
