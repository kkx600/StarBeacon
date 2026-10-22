// Package correlation 对固定检索快照执行有界的正向窗口回测，不推断缺失事件或授予处置权限。
package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/searchfilter"
)

const (
	Schema          = "correlation-rule.v1"
	ResultSchema    = "correlation-backtest.v1"
	MaxRules        = 128
	MaxRevision     = 1000000
	MaxDailyChanges = 2048
	MaxFacts        = 5000
	MaxGroups       = 512
	MaxEvidence     = 8
)

var (
	ErrInput      = errors.New("关联规则或回测范围无效")
	ErrQuota      = errors.New("关联规则、回测窗口或证据数量超过上限")
	ErrLimit      = errors.New("关联回测的事件或分组数量超过上限")
	ErrPermission = errors.New("关联规则权限已变化")
	ErrSource     = errors.New("关联回测的来源不完整或身份不一致")
)

type Definition struct {
	SchemaVersion string `json:"schema_version"`
	Dataset       string `json:"dataset"`
	Filter        string `json:"filter"`
	GroupBy       string `json:"group_by"`
	Metric        string `json:"metric"`
	DistinctField string `json:"distinct_field"`
	WindowSeconds int    `json:"window_seconds"`
	Threshold     int    `json:"threshold"`
}

func Text(value string, maximum int, required bool) bool {
	return utf8.ValidString(value) && value == strings.TrimSpace(value) && (!required || value != "") && len([]rune(value)) <= maximum && strings.IndexFunc(value, unicode.IsControl) == -1
}

func (d Definition) Validate() error {
	if d.SchemaVersion != Schema || d.Dataset != "alerts" || !Text(d.Filter, 4096, false) || !slices.Contains([]string{"source.ip", "destination.ip", "rule.id"}, d.GroupBy) || !slices.Contains([]string{"count", "distinct"}, d.Metric) || d.WindowSeconds < 15 || d.WindowSeconds > 3600 || d.Threshold < 2 || d.Threshold > MaxFacts {
		return ErrInput
	}
	if d.Metric == "count" && d.DistinctField != "" || d.Metric == "distinct" && (!slices.Contains([]string{"source.ip", "destination.ip", "source.port", "destination.port", "rule.id"}, d.DistinctField) || d.DistinctField == d.GroupBy) {
		return ErrInput
	}
	if _, err := searchfilter.Compile(d.Filter); err != nil {
		return errors.Join(ErrInput, err)
	}
	return nil
}

func Digest(value any) string {
	raw, _ := json.Marshal(value)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
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
	if !contract.ValidID(c.ID) || c.ExpectedRevision < 0 || c.ExpectedRevision >= MaxRevision || !Text(c.Name, 128, true) || !Text(c.Description, 1000, false) || c.Active == nil {
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
	if !contract.ValidID(r.TenantID) || !contract.ValidID(r.ID) || !contract.ValidID(r.CreatedBy) || r.Revision < 1 || r.Revision > MaxRevision || !Text(r.Name, 128, true) || !Text(r.Description, 1000, false) || r.DefinitionSHA256 != Digest(r.Definition) || r.CreatedAt.IsZero() || !r.ExpiresAt.After(r.CreatedAt) {
		return ErrSource
	}
	if r.Definition.Validate() != nil {
		return ErrSource
	}
	return nil
}

type Query struct {
	Cursor  string `json:"cursor"`
	Keyword string `json:"keyword"`
	Active  string `json:"active"`
	Limit   int    `json:"limit"`
}

func (q Query) Validate() error {
	if q.Limit < 1 || q.Limit > 100 || q.Cursor != "" && (!Text(q.Cursor, 2048, true) || len(q.Cursor) > 2048) || !Text(q.Keyword, 128, false) || !slices.Contains([]string{"", "true", "false"}, q.Active) {
		return ErrInput
	}
	return nil
}

type Page struct {
	Items      []Record `json:"items"`
	NextCursor string   `json:"next_cursor"`
}

type Request struct {
	ExpectedRevision int64     `json:"expected_revision"`
	Start            time.Time `json:"start"`
	End              time.Time `json:"end"`
}

func (r Request) Validate(now time.Time) error {
	minimum := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if r.ExpectedRevision < 1 || r.ExpectedRevision > MaxRevision || r.Start.Before(minimum) || !r.End.After(r.Start) || r.End.Sub(r.Start) > time.Hour || r.End.After(now) || r.Start.Nanosecond() != 0 || r.End.Nanosecond() != 0 {
		return ErrInput
	}
	return nil
}
