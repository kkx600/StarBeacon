package qualityevent

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/detectionquality"
	"github.com/kkx600/StarBeacon/internal/model"
)

func nativeReport(t *testing.T, run string, changes map[string]uint64) detectionquality.Report {
	t.Helper()
	now := time.Now().UTC().Add(-10 * time.Second)
	var tr detectionquality.Tracker
	tr.Start(run, strings.Repeat("a", 64), now)
	values := func(changes map[string]uint64) map[string]any {
		root := map[string]any{}
		for _, c := range tr.Snapshot(now, true).Counters {
			parts := strings.Split(c.Key, ".")
			m := root
			for _, part := range parts[:len(parts)-1] {
				if m[part] == nil {
					m[part] = map[string]any{}
				}
				m = m[part].(map[string]any)
			}
			m[parts[len(parts)-1]] = changes[c.Key]
		}
		return root
	}
	for i, changed := range []map[string]uint64{nil, changes} {
		at := now.Add(time.Duration(i*5+1) * time.Second)
		raw, _ := json.Marshal(map[string]any{"event_type": "stats", "timestamp": at.Format(time.RFC3339Nano), "stats": values(changed)})
		tr.Observe(raw, at)
	}
	r := tr.Snapshot(now.Add(7*time.Second), true)
	if r.Validate() != nil {
		t.Fatal("原生夹具无效", r)
	}
	return r
}
func newEvent(t *testing.T, r detectionquality.Report, signal Signal) Event {
	t.Helper()
	e, err := New("tenant_owned", "sensor_owned", "reg_owned", r, signal, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestQualityEventTransitionsDoNotInventRecovery(t *testing.T) {
	quiet := nativeReport(t, "engine_owned", nil)
	if _, emit := Transition(nil, quiet); emit {
		t.Fatal("无问题基线产生事件")
	}
	r := nativeReport(t, "engine_owned", map[string]uint64{"capture.kernel_drops": 2, "detect.alerts_suppressed": 1})
	s, emit := Transition(nil, r)
	if !emit || s.Kind != "limitation" || strings.Join(s.Reasons, ",") != "capture.kernel_drops,detect.alerts_suppressed" {
		t.Fatal(s)
	}
	e := newEvent(t, r, s)
	if _, emit := Transition(&e, r); emit {
		t.Fatal("重复心跳形成重复事件")
	}
	if s := Classify(nativeReport(t, "engine_owned", map[string]uint64{"detect.alerts_suppressed": 1})); s.Kind != "policy" {
		t.Fatal(s)
	}
	for _, state := range []string{"counter_reset", "sample_gap", "stale", "stopped"} {
		r := quiet
		r.State = state
		s := Classify(r)
		if s.Kind != "uncertain" || len(s.Reasons) != 1 || s.Reasons[0] != state {
			t.Fatal(s)
		}
	}
	for _, state := range []string{"baseline", "unavailable"} {
		r := quiet
		r.State = state
		if _, emit := Transition(&e, r); emit {
			t.Fatal("非连续样本清除限制", state)
		}
	}
	missing := quiet
	missing.Counters = append([]detectionquality.Counter{}, quiet.Counters...)
	missing.Counters[1].Delta = nil
	if _, emit := Transition(&e, missing); emit {
		t.Fatal("缺测替代原限制的零增量")
	}
	clear, emit := Transition(&e, quiet)
	if !emit || clear.Kind != "interval_clear" || clear.PriorEventID != e.ID {
		t.Fatal(clear)
	}
	cleared := newEvent(t, quiet, clear)
	if _, emit := Transition(&cleared, quiet); emit {
		t.Fatal("重复清除")
	}
	restarted := nativeReport(t, "engine_restarted", nil)
	resumed, emit := Transition(&e, restarted)
	if !emit || resumed.Kind != "observation_resumed" {
		t.Fatal(resumed)
	}
	newEvent(t, restarted, resumed)
	uncertain := e
	uncertain.Signal.Kind = "uncertain"
	resumed, emit = Transition(&uncertain, quiet)
	if !emit || resumed.Kind != "observation_resumed" {
		t.Fatal(resumed)
	}
	observed := newEvent(t, quiet, resumed)
	if _, emit := Transition(&observed, quiet); emit {
		t.Fatal("重复恢复可观测事件")
	}
	s = Classify(r)
	s.Reminder = true
	newEvent(t, r, s)
	for _, kind := range []string{"limitation", "policy", "uncertain", "interval_clear", "observation_resumed", "other"} {
		if Title(kind) == "" {
			t.Fatal(kind)
		}
	}
}

func TestQualityEventCanonicalDocumentAndValidation(t *testing.T) {
	r := nativeReport(t, "engine_owned", map[string]uint64{"tcp.reassembly_gap": 1})
	e := newEvent(t, r, Classify(r))
	doc := e.Document()
	decoded, err := Decode(doc)
	if err != nil || decoded.ID != e.ID || doc.Sequence != "0" || doc.RawSHA256 == "" {
		t.Fatal(err)
	}
	for i, change := range []func(*model.Alert){func(d *model.Alert) { d.TenantID = "other" }, func(d *model.Alert) { d.Event.Kind = "alert" }, func(d *model.Alert) { d.Event.Dataset = "suricata.stats" }, func(d *model.Alert) { d.Event.Original = "{" }, func(d *model.Alert) { d.Event.Original = strings.Repeat("x", 32769) }, func(d *model.Alert) { d.Source.IP = "192.0.2.1" }, func(d *model.Alert) { d.RawSHA256 = "forged" }, func(d *model.Alert) { d.SourceOffset = "0" }} {
		d := doc
		change(&d)
		if _, err := Decode(d); err == nil {
			t.Errorf("接受篡改文档%d", i)
		}
	}
	clone := func() Event { raw, _ := json.Marshal(e); var c Event; _ = json.Unmarshal(raw, &c); return c }
	for i, change := range []func(*Event){func(e *Event) { e.SchemaVersion = 2 }, func(e *Event) { e.TenantID = "other" }, func(e *Event) { e.SensorID = "bad/id" }, func(e *Event) { e.RegistrationID = "" }, func(e *Event) { e.ID = "bad" }, func(e *Event) { e.CreatedAt = time.Time{} }, func(e *Event) { e.Report.Counters = nil }, func(e *Event) { e.Signal.Kind = "safe" }, func(e *Event) { e.Signal.Reasons = nil }, func(e *Event) { e.Signal.Fingerprint = "bad" }, func(e *Event) { e.Signal.PriorEventID = strings.Repeat("a", 64) }} {
		c := clone()
		change(&c)
		if c.Validate() == nil {
			t.Errorf("接受篡改事件%d", i)
		}
	}
	if _, err := New("tenant_owned", "sensor_owned", "reg_owned", detectionquality.Report{}, Signal{}, time.Now()); err == nil {
		t.Fatal("缺少样本身份")
	}
	quiet := nativeReport(t, "engine_owned", nil)
	clear, _ := Transition(&e, quiet)
	c := newEvent(t, quiet, clear)
	for _, change := range []func(*Event){func(e *Event) { e.Signal.PriorEventID = strings.Repeat("g", 64) }, func(e *Event) { e.Signal.Reminder = true }, func(e *Event) { e.Signal.Reasons = []string{"flow.active"} }, func(e *Event) { e.Signal.Reasons = []string{"tcp.reassembly_gap", "tcp.reassembly_gap"} }, func(e *Event) { e.Signal.Fingerprint = "bad" }} {
		v := c
		v.Signal.Reasons = append([]string{}, c.Signal.Reasons...)
		change(&v)
		if v.Validate() == nil {
			t.Fatal("接受伪造清除事件")
		}
	}
	resumed, _ := Transition(&e, nativeReport(t, "engine_other", nil))
	v := newEvent(t, nativeReport(t, "engine_other", nil), resumed)
	v.Signal.Reasons = []string{"wrong"}
	if v.Validate() == nil {
		t.Fatal("接受伪造重新可观测事件")
	}
}

func TestQualityHeartbeatRequiresManagedIdentityAndFreshEvaluation(t *testing.T) {
	now := time.Now().UTC()
	r := nativeReport(t, "engine_owned", map[string]uint64{"capture.errors": 1})
	capture := func(managed bool, r any, sha string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"managed": managed, "quality": r, "config_sha256": sha})
		return b
	}
	h := model.HostHealth{ObservedAt: now, Capture: capture(true, r, r.ConfigSHA256)}
	if got, err := Observation(h, now); err != nil || got == nil {
		t.Fatal(err)
	}
	for _, raw := range []json.RawMessage{nil, []byte("null"), capture(false, r, r.ConfigSHA256), capture(true, nil, r.ConfigSHA256)} {
		h.Capture = raw
		if got, err := Observation(h, now); err != nil || got != nil {
			t.Fatal("外部数据形成原生质量历史", err)
		}
	}
	for _, raw := range []json.RawMessage{[]byte("{"), capture(true, r, strings.Repeat("b", 64)), capture(true, map[string]string{"state": "safe"}, r.ConfigSHA256)} {
		h.Capture = raw
		if _, err := Observation(h, now); err == nil {
			t.Fatal("接受无效捕获报告")
		}
	}
	for _, at := range []time.Time{now.Add(2 * time.Minute), now.Add(-time.Minute)} {
		h.Capture = capture(true, r, r.ConfigSHA256)
		if _, err := Observation(h, at); err == nil {
			t.Fatal("接受过时或未来报告")
		}
	}
	h.ObservedAt = now.Add(-time.Hour)
	if _, err := Observation(h, now); err == nil {
		t.Fatal("接收与心跳时钟不一致")
	}
	var tr detectionquality.Tracker
	tr.Start("engine_unobserved", strings.Repeat("a", 64), now)
	h.ObservedAt = now
	h.Capture = capture(true, tr.Snapshot(now, true), strings.Repeat("a", 64))
	if got, err := Observation(h, now); err != nil || got != nil {
		t.Fatal("无原生样本形成历史", err)
	}
}
