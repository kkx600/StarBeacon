// Package playbook 定义防御响应的顺序编排、发布校验和人工步骤记录。
package playbook

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/assessment"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/response"
)

const (
	MaxSteps       = 16
	MaxRevision    = 256
	ApprovalWindow = 15 * time.Minute
	stepKeyPrefix  = "pb_step_"
)

var (
	ErrInput      = errors.New("编排输入无效")
	ErrPermission = errors.New("当前账号不能操作此编排")
	ErrNotReady   = errors.New("当前步骤的材料或回执尚未满足条件")
	ErrSource     = errors.New("编排绑定的修订或告警材料已变化")
	ErrLimit      = errors.New("编排数量或运行额度已达上限")
)

type ModelBinding struct {
	ID                string  `json:"id"`
	Revision          int64   `json:"revision"`
	MinimumConfidence float64 `json:"minimum_confidence"`
}

type PolicyBinding struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
}

type PluginBinding struct {
	Policy         PolicyBinding `json:"policy"`
	SensorID       string        `json:"sensor_id"`
	RegistrationID string        `json:"registration_id"`
	ConnectorID    string        `json:"connector_id"`
	ConfigSHA256   string        `json:"config_sha256"`
	TTLSeconds     int           `json:"ttl_seconds"`
}

type Step struct {
	Kind            string         `json:"kind"`
	Name            string         `json:"name"`
	Description     string         `json:"description"`
	MinimumSeverity string         `json:"minimum_severity,omitempty"`
	Model           *ModelBinding  `json:"model,omitempty"`
	Plugin          *PluginBinding `json:"plugin,omitempty"`
	Gateway         *PolicyBinding `json:"gateway,omitempty"`
}

type Definition struct {
	Name  string `json:"name"`
	Steps []Step `json:"steps"`
}

type Issue struct {
	Step int    `json:"step"`
	Code string `json:"code"`
}

type Record struct {
	ID                string     `json:"id"`
	OwnerID           string     `json:"owner_id"`
	Revision          int64      `json:"revision"`
	PublishedRevision int64      `json:"published_revision"`
	PublishedSHA256   string     `json:"published_sha256,omitempty"`
	Definition        Definition `json:"definition"`
	SHA256            string     `json:"sha256"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type Page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor"`
}

type Change struct {
	ExpectedRevision int64      `json:"expected_revision"`
	Definition       Definition `json:"definition"`
}

type Revision struct {
	Revision int64  `json:"revision"`
	SHA256   string `json:"sha256"`
}

type Start struct {
	Revision
	EventID   string `json:"event_id"`
	RawSHA256 string `json:"raw_sha256"`
}

type Alert struct {
	EventID        string `json:"event_id"`
	RawSHA256      string `json:"raw_sha256"`
	Severity       string `json:"severity"`
	SensorID       string `json:"sensor_id"`
	RegistrationID string `json:"registration_id"`
	SourceIP       string `json:"source_ip"`
	DestinationIP  string `json:"destination_ip"`
}

type Result struct {
	Kind       string     `json:"kind"`
	At         time.Time  `json:"at"`
	Reference  string     `json:"reference,omitempty"`
	TaskID     string     `json:"task_id,omitempty"`
	Outcome    string     `json:"outcome,omitempty"`
	LeaseUntil *time.Time `json:"lease_until,omitempty"`
}

type Run struct {
	ID         string `json:"id"`
	PlaybookID string `json:"playbook_id"`
	Revision
	Definition Definition `json:"definition"`
	Alert      Alert      `json:"alert"`
	Results    []Result   `json:"results"`
	StepKey    string     `json:"step_key,omitempty"`
	State      string     `json:"state"`
	CreatedAt  time.Time  `json:"created_at"`
}

type Acknowledge struct {
	Step      int  `json:"step"`
	Confirmed bool `json:"confirmed"`
}

func Digest(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func clean(s string, limit int, required bool) bool {
	return utf8.ValidString(s) && utf8.RuneCountInString(s) <= limit && (!required || strings.TrimSpace(s) != "") &&
		strings.IndexFunc(s, unicode.IsControl) == -1
}

func boundedRevision(n int64) bool { return n > 0 && n <= 9007199254740991 }

func (r Revision) Valid() bool {
	return r.Revision >= 1 && r.Revision <= MaxRevision && assessment.ValidDigest(r.SHA256)
}

func (r Start) Valid() bool {
	return r.Revision.Valid() && assessment.ValidDigest(r.EventID) && assessment.ValidDigest(r.RawSHA256)
}

func (p PolicyBinding) valid() bool { return contract.ValidID(p.ID) && boundedRevision(p.Revision) }

func (p PluginBinding) valid() bool {
	return p.Policy.valid() && contract.ValidID(p.SensorID) && contract.ValidID(p.RegistrationID) &&
		contract.ValidID(p.ConnectorID) && assessment.ValidDigest(p.ConfigSHA256) && p.TTLSeconds >= 30 && p.TTLSeconds <= response.MaxTTLSeconds
}

func (m ModelBinding) valid() bool {
	return contract.ValidID(m.ID) && boundedRevision(m.Revision) && !math.IsNaN(m.MinimumConfidence) &&
		m.MinimumConfidence > 0 && m.MinimumConfidence <= 1
}

func severityLevel(value string) int {
	switch value {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func (s Step) IsAction() bool { return s.Kind == "plugin" || s.Kind == "gateway" }

// 草稿可以保留待填写的绑定。发布前重新核对每个设备步骤的完整闭环。
func (d Definition) ValidDraft() bool {
	if !clean(d.Name, 128, true) || len(d.Steps) == 0 || len(d.Steps) > MaxSteps || d.Steps[0].Kind != "trigger" {
		return false
	}
	for i, s := range d.Steps {
		if !clean(s.Name, 128, true) || !clean(s.Description, 240, false) ||
			s.MinimumSeverity != "" && (s.Kind != "trigger" || severityLevel(s.MinimumSeverity) == 0) ||
			s.Model != nil && s.Kind != "triage" || s.Plugin != nil && s.Kind != "plugin" || s.Gateway != nil && s.Kind != "gateway" {
			return false
		}
		switch s.Kind {
		case "trigger":
			if i != 0 {
				return false
			}
		case "triage", "condition", "protection", "approval", "plugin", "gateway", "verify", "notify", "compensate":
		default:
			return false
		}
	}
	return true
}

func (d Definition) Issues() []Issue {
	issues := []Issue{}
	triage := false
	for i, s := range d.Steps {
		code := ""
		switch s.Kind {
		case "triage":
			if triage || s.Model == nil || !s.Model.valid() {
				code = "model_binding"
			}
			triage = true
		case "condition":
			if !triage {
				code = "triage_required"
			}
		case "plugin":
			if !triage || s.Plugin == nil || !s.Plugin.valid() {
				code = "plugin_binding"
			}
		case "gateway":
			if s.Gateway == nil || !s.Gateway.valid() {
				code = "gateway_binding"
			}
		case "protection", "approval", "verify", "compensate":
			delta := map[string]int{"protection": 2, "approval": 1, "verify": -1, "compensate": -2}[s.Kind]
			action := i + delta
			if action < 0 || action >= len(d.Steps) || !d.Steps[action].IsAction() {
				code = "unbound_guard"
			}
		}
		if code != "" {
			issues = append(issues, Issue{Step: i, Code: code})
		}
		if s.IsAction() && !d.guarded(i) {
			issues = append(issues, Issue{Step: i, Code: "action_guards"})
		}
	}
	return issues
}

func (d Definition) guarded(i int) bool {
	return i >= 2 && i+2 < len(d.Steps) && d.Steps[i-2].Kind == "protection" && d.Steps[i-1].Kind == "approval" &&
		d.Steps[i+1].Kind == "verify" && d.Steps[i+2].Kind == "compensate"
}

func BindAlert(d Definition, a model.Alert) (Alert, error) {
	return Alert{EventID: a.EventID, RawSHA256: a.RawSHA256, Severity: a.Severity, SensorID: a.SensorID,
		RegistrationID: a.RegistrationID, SourceIP: a.Source.IP, DestinationIP: a.Destination.IP}, checkAlert(d, a)
}

func checkAlert(d Definition, a model.Alert) error {
	if !assessment.ValidDigest(a.EventID) || !assessment.ValidDigest(a.RawSHA256) || !contract.ValidID(a.SensorID) ||
		!contract.ValidID(a.RegistrationID) || a.Event.Kind != "alert" || len(d.Steps) == 0 ||
		severityLevel(a.Severity) < severityLevel(d.Steps[0].MinimumSeverity) {
		return ErrSource
	}
	return nil
}

func (a Alert) Endpoints() (string, string, error) {
	source, sourceErr := netip.ParseAddr(a.SourceIP)
	destination, destErr := netip.ParseAddr(a.DestinationIP)
	if sourceErr != nil || destErr != nil || source.Zone() != "" || destination.Zone() != "" {
		return "", "", ErrSource
	}
	return source.Unmap().String(), destination.Unmap().String(), nil
}

// 步骤键只是原业务入口的幂等键。服务端仍核对运行、当前步骤和实际授权输入。
func StepKey(run string, index int) string { return stepKeyPrefix + run + "_" + strconv.Itoa(index) }

func ParseStepKey(key string) (id string, index int, guarded bool, err error) {
	value, guarded := strings.CutPrefix(key, stepKeyPrefix)
	if !guarded {
		return "", 0, false, nil
	}
	separator := strings.LastIndexByte(value, '_')
	if separator < 0 {
		return "", 0, true, ErrInput
	}
	id = value[:separator]
	index, err = strconv.Atoi(value[separator+1:])
	if err != nil || !contract.ValidID(id) || !strings.HasPrefix(id, "pbr_") || index < 1 || index >= MaxSteps || StepKey(id, index) != key {
		return "", 0, true, ErrInput
	}
	return id, index, true, nil
}

func (r Run) Current() (Step, bool) {
	index := len(r.Results)
	if r.State == "running" && index < len(r.Definition.Steps) {
		return r.Definition.Steps[index], true
	}
	return Step{}, false
}

func (r *Run) RefreshState() {
	r.State = "running"
	r.StepKey = ""
	switch r.Results[len(r.Results)-1].Outcome {
	case "triage_failed", "below_threshold", "condition_unmet", "protected", "authorization_denied", "receipt_unknown", "gateway_effect_unknown", "gateway_traffic_continued":
		r.State = "stopped"
	default:
		if len(r.Results) == len(r.Definition.Steps) {
			r.State = "completed"
		}
	}
	if s, ok := r.Current(); ok && (s.Kind == "triage" || s.IsAction()) {
		r.StepKey = StepKey(r.ID, len(r.Results))
	}
}

func (r Run) ApprovalActive(now time.Time) bool {
	i := len(r.Results) - 1
	return i >= 0 && r.Results[i].Kind == "approval" && !r.Results[i].At.After(now) && r.Results[i].At.Add(ApprovalWindow).After(now)
}
