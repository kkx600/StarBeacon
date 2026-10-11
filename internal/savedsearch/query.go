// Package savedsearch 定义可复用的事件查询，不保存结果、数据权限或可执行脚本。
package savedsearch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/searchfilter"
)

const Schema = "saved.search.v1"
const MaxRevision = 1000000
const MaxPerOwner = 200
const MaxPerTenant = 2000
const MaxDailyChanges = 10000

var (
	ErrInput      = errors.New("保存查询参数无效")
	ErrVersion    = errors.New("查询解析器版本不受支持")
	ErrQuota      = errors.New("保存查询或近期变更数量已达上限")
	ErrInactive   = errors.New("保存查询已停用")
	ErrPermission = errors.New("当前账号不能修改此查询")
)

func text(value string, limit int, required bool) bool {
	return utf8.ValidString(value) && len([]rune(value)) <= limit && value == strings.TrimSpace(value) && (!required || value != "") && strings.IndexFunc(value, unicode.IsControl) < 0
}

type Window struct {
	Mode  string     `json:"mode"`
	Hours int        `json:"hours,omitempty"`
	Start *time.Time `json:"start,omitempty"`
	End   *time.Time `json:"end,omitempty"`
}

func (w Window) Bounds(now time.Time) (time.Time, time.Time, error) {
	switch w.Mode {
	case "relative":
		if w.Start != nil || w.End != nil || (w.Hours != 24 && w.Hours != 168 && w.Hours != 720) || now.IsZero() || now.Year() < 1 || now.Year() > 9999 {
			return time.Time{}, time.Time{}, ErrInput
		}
		start := now.UTC().Add(-time.Duration(w.Hours) * time.Hour)
		if start.Year() < 1 {
			return time.Time{}, time.Time{}, ErrInput
		}
		return start, now.UTC(), nil
	case "absolute":
		if w.Hours != 0 || w.Start == nil || w.End == nil || w.Start.IsZero() || w.End.IsZero() || w.Start.Year() < 1 || w.End.Year() > 9999 || !w.End.After(*w.Start) || w.End.Sub(*w.Start) > 31*24*time.Hour {
			return time.Time{}, time.Time{}, ErrInput
		}
		return w.Start.UTC(), w.End.UTC(), nil
	default:
		return time.Time{}, time.Time{}, ErrInput
	}
}

type Terms struct {
	Keyword        string `json:"keyword"`
	SourceIP       string `json:"source_ip"`
	DestinationIP  string `json:"destination_ip"`
	Protocol       string `json:"protocol"`
	Method         string `json:"method"`
	Path           string `json:"path"`
	Severity       string `json:"severity"`
	Filter         string `json:"filter"`
	EventKind      string `json:"event_kind"`
	SensorID       string `json:"sensor_id"`
	RegistrationID string `json:"sensor_registration_id"`
	GenerationID   string `json:"source_generation_id"`
	FlowID         string `json:"flow_id"`
}

type Definition struct {
	SchemaVersion string `json:"schema_version"`
	ParserVersion string `json:"parser_version"`
	Dataset       string `json:"dataset"`
	Mode          string `json:"mode"`
	Window        Window `json:"window"`
	Terms         Terms  `json:"terms"`
}

func (d Definition) Validate() error {
	if d.SchemaVersion != Schema || (d.Dataset != "alerts" && d.Dataset != "context") || (d.Mode != "visual" && d.Mode != "advanced") {
		return ErrInput
	}
	if _, _, err := d.Window.Bounds(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		return err
	}
	if d.Mode == "visual" && d.Terms.Filter != "" {
		return ErrInput
	}
	if d.Dataset == "alerts" {
		if d.Terms.EventKind != "" || d.Terms.SensorID != "" || d.Terms.RegistrationID != "" || d.Terms.GenerationID != "" || d.Terms.FlowID != "" {
			return ErrInput
		}
		if d.Mode == "advanced" && (d.Terms.Keyword != "" || d.Terms.SourceIP != "" || d.Terms.DestinationIP != "" || d.Terms.Protocol != "" || d.Terms.Method != "" || d.Terms.Path != "" || d.Terms.Severity != "") {
			return ErrInput
		}
	}
	if d.Dataset == "context" && (d.Terms.Keyword != "" || d.Terms.Severity != "") {
		return ErrInput
	}
	if !text(d.ParserVersion, 32, true) {
		return ErrInput
	}
	if d.ParserVersion != searchfilter.Version {
		return ErrVersion
	}
	return nil
}

// 相对窗口在每次应用时解析；固定窗口保留原起止。查询执行仍经过原数据集的校验和授权。
func (d Definition) Query(now time.Time) (model.TrafficSearchRequest, error) {
	var q model.TrafficSearchRequest
	if err := d.Validate(); err != nil {
		return q, err
	}
	start, end, err := d.Window.Bounds(now)
	if err != nil {
		return q, err
	}
	t := d.Terms
	q.SearchRequest = model.SearchRequest{Start: start, End: end, Page: 1, PageSize: 20, Keyword: t.Keyword, SourceIP: t.SourceIP, DestinationIP: t.DestinationIP, Protocol: t.Protocol, Method: t.Method, Path: t.Path, Severity: t.Severity, Filter: t.Filter}
	q.EventKind, q.SensorID, q.RegistrationID, q.GenerationID, q.FlowID = t.EventKind, t.SensorID, t.RegistrationID, t.GenerationID, t.FlowID
	return q, nil
}

type Change struct {
	ID                   string     `json:"id"`
	ExpectedRevision     int64      `json:"expected_revision"`
	ExpectedGenerationID string     `json:"expected_generation_id"`
	Name                 string     `json:"name"`
	Description          string     `json:"description"`
	Visibility           string     `json:"visibility"`
	Active               *bool      `json:"active"`
	Definition           Definition `json:"definition"`
}

func (c Change) Validate() error {
	if !contract.ValidID(c.ID) || c.ExpectedRevision < 0 || c.ExpectedRevision >= MaxRevision || c.ExpectedRevision == 0 && c.ExpectedGenerationID != "" || c.ExpectedRevision > 0 && !contract.ValidID(c.ExpectedGenerationID) || !text(c.Name, 128, true) || !text(c.Description, 1000, false) || (c.Visibility != "personal" && c.Visibility != "team") || c.Active == nil || (c.ExpectedRevision == 0 && !*c.Active) {
		return ErrInput
	}
	return c.Definition.Validate()
}

// 对所有嵌套对象拒绝重复字段、大小写别名及额外字段，防止原请求绑定出现不同解释。
func (c *Change) UnmarshalJSON(raw []byte) error {
	fields := []string{"id", "expected_revision", "expected_generation_id", "name", "description", "visibility", "active", "definition", "schema_version", "parser_version", "dataset", "mode", "window", "hours", "start", "end", "terms", "keyword", "source_ip", "destination_ip", "protocol", "method", "path", "severity", "filter", "event_kind", "sensor_id", "sensor_registration_id", "source_generation_id", "flow_id"}
	if contract.JSONFields(string(raw), fields, 32768) != nil {
		return ErrInput
	}
	type plain Change
	var decoded plain
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(&decoded); err != nil {
		return ErrInput
	}
	*c = Change(decoded)
	return nil
}

func InputHash(c Change) string {
	raw, _ := json.Marshal(c)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

type Record struct {
	TenantID     string     `json:"tenant_id"`
	ID           string     `json:"id"`
	GenerationID string     `json:"generation_id"`
	OwnerID      string     `json:"owner_id"`
	Revision     int64      `json:"revision"`
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	Visibility   string     `json:"visibility"`
	Active       bool       `json:"active"`
	Definition   Definition `json:"definition"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	ExpiresAt    *time.Time `json:"expires_at"`
}

func (r Record) Validate() error {
	if !contract.ValidID(r.TenantID) || !contract.ValidID(r.OwnerID) || !contract.ValidID(r.GenerationID) || r.Revision < 1 || r.Revision > MaxRevision || r.CreatedAt.IsZero() || r.UpdatedAt.Before(r.CreatedAt) || r.Active && r.ExpiresAt != nil || !r.Active && (r.ExpiresAt == nil || !r.ExpiresAt.After(r.UpdatedAt)) {
		return ErrInput
	}
	// 回执可以达到最大修订，写入参数不能再次使用该修订。
	c := Change{ID: r.ID, ExpectedRevision: 1, ExpectedGenerationID: r.GenerationID, Name: r.Name, Description: r.Description, Visibility: r.Visibility, Active: &r.Active, Definition: r.Definition}
	err := c.Validate()
	if errors.Is(err, ErrVersion) {
		return nil
	}
	return err
}

type ListQuery struct {
	Dataset, Visibility, Active, Keyword, Cursor string
	Limit                                        int
}

func (q ListQuery) Validate() error {
	if q.Limit < 1 || q.Limit > 100 || !text(q.Keyword, 128, false) || q.Cursor != "" && !contract.ValidID(q.Cursor) || q.Dataset != "" && q.Dataset != "alerts" && q.Dataset != "context" || q.Visibility != "" && q.Visibility != "personal" && q.Visibility != "team" || q.Active != "" && q.Active != "true" && q.Active != "false" {
		return ErrInput
	}
	return nil
}

type Page struct {
	Items      []Record `json:"items"`
	NextCursor string   `json:"next_cursor"`
}

type Resolution struct {
	TenantID     string          `json:"tenant_id"`
	ID           string          `json:"id"`
	GenerationID string          `json:"generation_id"`
	Revision     int64           `json:"revision"`
	Definition   Definition      `json:"definition"`
	Query        json.RawMessage `json:"query"`
}
