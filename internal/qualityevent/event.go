// Package qualityevent 定义探针上报的冻结区间质量事件，不推断逐流检测覆盖或攻击结果。
package qualityevent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/detectionquality"
	"github.com/kkx600/StarBeacon/internal/model"
)

const Dataset = "starbeacon.sensor_quality"

var ErrEvent = errors.New("探针质量事件无效")

type Signal struct {
	Kind         string   `json:"kind"`
	Reasons      []string `json:"reasons"`
	Fingerprint  string   `json:"fingerprint"`
	PriorEventID string   `json:"prior_event_id,omitempty"`
	Reminder     bool     `json:"reminder,omitempty"`
}
type Event struct {
	SchemaVersion  int                     `json:"schema_version"`
	ID             string                  `json:"id"`
	TenantID       string                  `json:"tenant_id"`
	SensorID       string                  `json:"sensor_id"`
	RegistrationID string                  `json:"sensor_registration_id"`
	CreatedAt      time.Time               `json:"created_at"`
	Signal         Signal                  `json:"signal"`
	Report         detectionquality.Report `json:"report"`
}

// Observation 只采用托管捕获身份与实际配置一致的质量投影；外部 EVE 不建立质量历史。
func Observation(h model.HostHealth, now time.Time) (*detectionquality.Report, error) {
	if len(h.Capture) == 0 || string(h.Capture) == "null" {
		return nil, nil
	}
	var capture struct {
		Managed      bool                     `json:"managed"`
		ConfigSHA256 string                   `json:"config_sha256"`
		Quality      *detectionquality.Report `json:"quality"`
	}
	if json.Unmarshal(h.Capture, &capture) != nil {
		return nil, ErrEvent
	}
	if !capture.Managed || capture.Quality == nil {
		return nil, nil
	}
	r := capture.Quality
	if r.Validate() != nil {
		return nil, ErrEvent
	}
	if r.EngineRunID == "" || r.SampledAt == nil {
		return nil, nil
	}
	if r.ConfigSHA256 != capture.ConfigSHA256 || r.EvaluatedAt.After(now.Add(5*time.Second)) || r.EvaluatedAt.Before(now.Add(-time.Minute)) || r.EvaluatedAt.After(h.ObservedAt.Add(5*time.Second)) || r.ReceivedAt.After(h.ObservedAt.Add(5*time.Second)) {
		return nil, ErrEvent
	}
	return r, nil
}

func Classify(r detectionquality.Report) Signal {
	s := Signal{Kind: "quiet", Reasons: []string{}}
	if slices.Contains([]string{"counter_reset", "sample_gap", "stale", "stopped"}, r.State) {
		s.Kind = "uncertain"
		s.Reasons = []string{r.State}
	} else if r.State == "observed" {
		for _, f := range []detectionquality.Facet{r.Capture, r.Inspection, r.Alerting, r.Policy} {
			s.Reasons = append(s.Reasons, f.Reasons...)
		}
		if len(s.Reasons) > 0 {
			s.Kind = "limitation"
			if r.Capture.State != "limited" && r.Inspection.State != "limited" && r.Alerting.State != "limited" {
				s.Kind = "policy"
			}
		}
	}
	slices.Sort(s.Reasons)
	s.Fingerprint = hash(r.EngineRunID + "/" + r.ConfigSHA256 + "/" + s.Kind + "/" + strings.Join(s.Reasons, ","))
	return s
}

// Transition 仅记录原因或运行代次改变；相同问题的每次心跳不会产生重复事件。
// 未再报告增量只针对原有限制指标，不声明完整恢复或补回缺失报文。
func Transition(previous *Event, r detectionquality.Report) (Signal, bool) {
	s := Classify(r)
	if s.Kind == "quiet" {
		if previous == nil || previous.Signal.Kind == "quiet" || previous.Signal.Kind == "interval_clear" || previous.Signal.Kind == "observation_resumed" || r.State != "observed" {
			return s, false
		}
		if previous.Report.EngineRunID != r.EngineRunID || previous.Report.ConfigSHA256 != r.ConfigSHA256 || previous.Signal.Kind == "uncertain" {
			s.Kind = "observation_resumed"
			s.Reasons = []string{"continuous_interval"}
			s.PriorEventID = previous.ID
			s.Fingerprint = hash(s.Fingerprint + "/resumed/" + previous.ID)
			return s, true
		}
		for _, key := range previous.Signal.Reasons {
			found := false
			for _, c := range r.Counters {
				if c.Key == key && c.Delta != nil && *c.Delta == "0" {
					found = true
				}
			}
			if !found {
				return s, false
			}
		}
		s.Kind = "interval_clear"
		s.Reasons = slices.Clone(previous.Signal.Reasons)
		s.PriorEventID = previous.ID
		s.Fingerprint = hash(s.Fingerprint + "/clear/" + previous.ID + "/" + strings.Join(s.Reasons, ","))
		return s, true
	}
	return s, previous == nil || s.Fingerprint != previous.Signal.Fingerprint
}

func New(tenant, sensor, registration string, r detectionquality.Report, signal Signal, now time.Time) (Event, error) {
	e := Event{SchemaVersion: 1, TenantID: tenant, SensorID: sensor, RegistrationID: registration, CreatedAt: now.UTC(), Signal: signal, Report: r}
	if r.SampledAt == nil {
		return e, ErrEvent
	}
	e.ID = hash(tenant + "/" + sensor + "/" + registration + "/" + r.EngineRunID + "/" + r.SampledAt.UTC().Format(time.RFC3339Nano) + "/" + signal.Fingerprint + "/" + e.CreatedAt.Format(time.RFC3339Nano))
	if e.Validate() != nil {
		return Event{}, ErrEvent
	}
	return e, nil
}

func (e Event) Validate() error {
	if e.SchemaVersion != 1 || !contract.ValidID(e.TenantID) || !contract.ValidID(e.SensorID) || !contract.ValidID(e.RegistrationID) || e.Report.Validate() != nil || e.Report.SampledAt == nil || e.CreatedAt.Year() < 2000 || e.CreatedAt.Year() > 2100 || !slices.Contains([]string{"limitation", "policy", "uncertain", "interval_clear", "observation_resumed"}, e.Signal.Kind) || len(e.Signal.Reasons) == 0 || len(e.Signal.Reasons) > 25 {
		return ErrEvent
	}
	s := Classify(e.Report)
	if e.Signal.Kind == "interval_clear" || e.Signal.Kind == "observation_resumed" {
		if s.Kind != "quiet" || e.Report.State != "observed" || e.Signal.Reminder || !digest(e.Signal.PriorEventID) {
			return ErrEvent
		}
		if e.Signal.Kind == "observation_resumed" {
			if !slices.Equal(e.Signal.Reasons, []string{"continuous_interval"}) || e.Signal.Fingerprint != hash(s.Fingerprint+"/resumed/"+e.Signal.PriorEventID) {
				return ErrEvent
			}
		} else {
			for i, key := range e.Signal.Reasons {
				if i > 0 && e.Signal.Reasons[i-1] >= key {
					return ErrEvent
				}
				found := false
				for _, c := range e.Report.Counters {
					if c.Key == key && c.Kind == "counter" && c.Delta != nil && *c.Delta == "0" {
						found = true
					}
				}
				if !found {
					return ErrEvent
				}
			}
			if e.Signal.Fingerprint != hash(s.Fingerprint+"/clear/"+e.Signal.PriorEventID+"/"+strings.Join(e.Signal.Reasons, ",")) {
				return ErrEvent
			}
		}
	} else if e.Signal.PriorEventID != "" || s.Fingerprint != e.Signal.Fingerprint || s.Kind != e.Signal.Kind || !slices.Equal(s.Reasons, e.Signal.Reasons) {
		return ErrEvent
	}
	if e.ID != hash(e.TenantID+"/"+e.SensorID+"/"+e.RegistrationID+"/"+e.Report.EngineRunID+"/"+e.Report.SampledAt.UTC().Format(time.RFC3339Nano)+"/"+e.Signal.Fingerprint+"/"+e.CreatedAt.UTC().Format(time.RFC3339Nano)) {
		return ErrEvent
	}
	return nil
}

func (e Event) Document() model.Alert {
	raw, _ := json.Marshal(e)
	d := model.Alert{SchemaVersion: "1", EventID: e.ID, TenantID: e.TenantID, SensorID: e.SensorID, RegistrationID: e.RegistrationID, SourceGenerationID: e.Report.EngineRunID, SourceOffset: strconv.FormatInt(e.Report.SampledAt.UnixNano(), 10), Sequence: "0", RawSHA256: hash(string(raw)), Timestamp: e.CreatedAt, ObservedAt: *e.Report.ReceivedAt, ReceivedAt: e.CreatedAt, Severity: "unknown", EvidenceStatus: "sensor_interval_report"}
	d.Event.Kind = "quality"
	d.Event.Dataset = Dataset
	d.Event.Original = string(raw)
	d.Rule.ID = e.Signal.Kind
	d.Rule.Name = Title(e.Signal.Kind)
	return d
}
func Decode(d model.Alert) (Event, error) {
	var e Event
	if d.Event.Kind != "quality" || d.Event.Dataset != Dataset || len(d.Event.Original) > 32768 || json.Unmarshal([]byte(d.Event.Original), &e) != nil || e.Validate() != nil {
		return e, ErrEvent
	}
	want := e.Document()
	a, _ := json.Marshal(want)
	b, _ := json.Marshal(d)
	if string(a) != string(b) {
		return e, ErrEvent
	}
	return e, nil
}
func Title(kind string) string {
	switch kind {
	case "limitation":
		return "检测区间存在限制"
	case "policy":
		return "检测策略产生影响"
	case "uncertain":
		return "检测区间无法核对"
	case "interval_clear":
		return "原限制未再报告增量"
	case "observation_resumed":
		return "连续区间重新可观测"
	}
	return "检测质量事件"
}
func hash(value string) string { b := sha256.Sum256([]byte(value)); return hex.EncodeToString(b[:]) }
func digest(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == value
}
