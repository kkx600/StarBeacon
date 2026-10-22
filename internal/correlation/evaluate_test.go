package correlation

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/model"
)

func fixture() (Record, Request, time.Time) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	r := Record{TenantID: "tenant_test", ID: "correlation_test", Revision: 1, Name: "同源多目标活动", Active: true, CreatedBy: "user_test", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(180 * 24 * time.Hour), Definition: Definition{SchemaVersion: Schema, Dataset: "alerts", GroupBy: "source.ip", Metric: "count", WindowSeconds: 60, Threshold: 2}}
	r.DefinitionSHA256 = Digest(r.Definition)
	return r, Request{ExpectedRevision: 1, Start: now.Add(-time.Minute), End: now}, now
}

func alert(id string, at time.Time) model.Alert {
	v := model.Alert{TenantID: "tenant_test", EventID: id, SensorID: "sensor_test", RegistrationID: "registration_test", RawSHA256: strings.Repeat("a", 64), Timestamp: at}
	v.Event.Kind, v.Source.IP, v.Destination.IP, v.Destination.Port, v.Rule.ID = "alert", "192.0.2.1", "198.51.100.1", 443, "1000001"
	return v
}

func TestBacktestDeduplicatesAndKeepsStableWindowIdentity(t *testing.T) {
	r, q, now := fixture()
	a, b := alert("event_a", q.Start.Add(time.Second)), alert("event_b", q.Start.Add(2*time.Second))
	x, err := Evaluate(r, q, []model.Alert{a, b}, now)
	if err != nil || x.UniqueEvents != 2 || x.ThresholdWindows != 1 || len(x.Windows) != 1 || x.Windows[0].MetricValue != 2 || x.Windows[0].Status != "threshold_observed" || x.ExecutionAuthorized || x.SourceCoverage != "not_attested" {
		t.Fatalf("实际快照窗口：%+v %v", x, err)
	}
	y, err := Evaluate(r, q, []model.Alert{b, a, a}, now)
	if err != nil || y.DuplicateEvents != 1 || y.SnapshotSHA256 != x.SnapshotSHA256 || !reflect.DeepEqual(x.Windows, y.Windows) {
		t.Fatalf("顺序或重投改变结果：%+v %v", y, err)
	}
	c := alert("event_c", q.Start.Add(3*time.Second))
	z, err := Evaluate(r, q, []model.Alert{b, c, a}, now)
	if err != nil || z.Windows[0].DetectionID != x.Windows[0].DetectionID || z.Windows[0].EvidenceSHA256 == x.Windows[0].EvidenceSHA256 || z.SnapshotSHA256 == x.SnapshotSHA256 {
		t.Fatal("迟到补证据应改变证据修订，不能改变同一窗口身份", err)
	}
	a.RawSHA256 = strings.Repeat("b", 64)
	if _, err := Evaluate(r, q, []model.Alert{a, alert("event_a", a.Timestamp)}, now); !errors.Is(err, ErrSource) {
		t.Fatal("同一事件标识的冲突内容必须拒绝", err)
	}
}

func TestBacktestRejectsChangedRuleRevision(t *testing.T) {
	r, q, now := fixture()
	q.ExpectedRevision++
	if _, err := Evaluate(r, q, []model.Alert{alert("event_a", q.Start)}, now); !errors.Is(err, ErrInput) {
		t.Fatalf("回测继续使用与申请不同的修订：%v", err)
	}
}

func TestBacktestSeparatesProbeRegistrationAndPartialWindows(t *testing.T) {
	r, q, now := fixture()
	a, b := alert("event_a", q.Start.Add(time.Second)), alert("event_b", q.Start.Add(2*time.Second))
	b.RegistrationID = "registration_other"
	x, err := Evaluate(r, q, []model.Alert{a, b}, now)
	if err != nil || len(x.Windows) != 2 || x.ThresholdWindows != 0 {
		t.Fatal(x, err)
	}
	b.RegistrationID, b.SensorID = a.RegistrationID, "sensor_other"
	x, err = Evaluate(r, q, []model.Alert{a, b}, now)
	if err != nil || len(x.Windows) != 2 {
		t.Fatal(x, err)
	}
	b.SensorID = a.SensorID
	q.Start = q.Start.Add(time.Second)
	x, err = Evaluate(r, q, []model.Alert{a, b}, now)
	if err != nil || x.PartialWindows != 1 || x.ThresholdWindows != 0 || x.Windows[0].Status != "partial_window" || x.Windows[0].MetricValue != 2 {
		t.Fatal(x, err)
	}
	q.End = now.Add(-time.Second)
	x, err = Evaluate(r, q, []model.Alert{a, b}, now)
	if err != nil || x.PartialWindows != 1 {
		t.Fatal(x, err)
	}
}

func TestBacktestDistinctValuesDoNotCountMissingPorts(t *testing.T) {
	r, q, now := fixture()
	r.Definition.Metric, r.Definition.DistinctField = "distinct", "destination.port"
	r.DefinitionSHA256 = Digest(r.Definition)
	a, b, c := alert("event_a", q.Start), alert("event_b", q.Start.Add(time.Second)), alert("event_c", q.Start.Add(2*time.Second))
	c.Destination.Port = 0
	x, err := Evaluate(r, q, []model.Alert{a, b, c}, now)
	if err != nil || x.Windows[0].MetricValue != 1 || x.Windows[0].MissingMetric != 1 || x.ThresholdWindows != 0 {
		t.Fatal(x, err)
	}
	b.Destination.Port = 8443
	x, err = Evaluate(r, q, []model.Alert{a, b, c}, now)
	if err != nil || x.Windows[0].MetricValue != 2 || x.ThresholdWindows != 1 {
		t.Fatal(x, err)
	}
	for _, field := range []string{"source.port", "destination.ip", "rule.id"} {
		r.Definition.DistinctField = field
		r.DefinitionSHA256 = Digest(r.Definition)
		if _, err := Evaluate(r, q, []model.Alert{a, b, c}, now); err != nil {
			t.Fatal(field, err)
		}
	}
}

func TestBacktestHalfOpenWindowAndMissingGroup(t *testing.T) {
	r, q, now := fixture()
	q.Start = q.Start.Add(-time.Minute)
	a, b, c := alert("event_a", q.Start), alert("event_b", q.Start.Add(time.Minute)), alert("event_c", q.End.Add(-time.Nanosecond))
	x, err := Evaluate(r, q, []model.Alert{a, b, c}, now)
	if err != nil || len(x.Windows) != 2 || x.Windows[0].Count != 1 || x.Windows[1].Count != 2 {
		t.Fatal(x, err)
	}
	a.Source.IP = ""
	x, err = Evaluate(r, q, []model.Alert{a, b}, now)
	if err != nil || x.MissingGroup != 1 || len(x.Windows) != 1 {
		t.Fatal(x, err)
	}
	r.Definition.GroupBy = "destination.ip"
	r.DefinitionSHA256 = Digest(r.Definition)
	if _, err := Evaluate(r, q, []model.Alert{a, b}, now); err != nil {
		t.Fatal(err)
	}
	r.Definition.GroupBy = "rule.id"
	r.DefinitionSHA256 = Digest(r.Definition)
	a.Rule.ID, b.Rule.ID = "", ""
	x, err = Evaluate(r, q, []model.Alert{a, b}, now)
	if err != nil || x.MissingGroup != 2 || len(x.Windows) != 0 {
		t.Fatal(x, err)
	}
	if x, err := Evaluate(r, q, []model.Alert{}, now); err != nil || x.Windows == nil || x.UniqueEvents != 0 || x.SourceCoverage != "not_attested" {
		t.Fatal(x, err)
	}
}

func TestBacktestReturnsNoPartialResultWhenSourcesOrBudgetsFail(t *testing.T) {
	r, q, now := fixture()
	for _, mutate := range []func(*model.Alert){
		func(a *model.Alert) { a.TenantID = "other" }, func(a *model.Alert) { a.Event.Kind = "http" }, func(a *model.Alert) { a.Event.Original = "不应读取原文" }, func(a *model.Alert) { a.EventID = "/invalid" }, func(a *model.Alert) { a.SensorID = "" }, func(a *model.Alert) { a.RegistrationID = "" }, func(a *model.Alert) { a.RawSHA256 = "bad" }, func(a *model.Alert) { a.RawSHA256 = strings.Repeat("A", 64) }, func(a *model.Alert) { a.Source.IP = "::ffff:192.0.2.1" }, func(a *model.Alert) { a.Destination.IP = "bad" }, func(a *model.Alert) { a.Rule.ID = "\n" }, func(a *model.Alert) { a.Timestamp = q.End }, func(a *model.Alert) { a.Timestamp = q.Start.Add(-time.Nanosecond) },
	} {
		a := alert("event_bad", q.Start)
		mutate(&a)
		if x, err := Evaluate(r, q, []model.Alert{alert("event_ok", q.Start), a}, now); !errors.Is(err, ErrSource) || !reflect.DeepEqual(x, Result{}) {
			t.Fatalf("无效来源返回部分结果：%+v %v", x, err)
		}
	}
	if _, err := Evaluate(r, q, nil, now); !errors.Is(err, ErrInput) {
		t.Fatal(err)
	}
	if _, err := Evaluate(r, q, make([]model.Alert, MaxFacts+1), now); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	facts := make([]model.Alert, MaxGroups+1)
	for i := range facts {
		facts[i] = alert(fmt.Sprintf("event_%04d", i), q.Start)
		facts[i].Source.IP = fmt.Sprintf("10.0.%d.%d", i/256, i%256)
	}
	if x, err := Evaluate(r, q, facts, now); !errors.Is(err, ErrLimit) || !reflect.DeepEqual(x, Result{}) {
		t.Fatal(x, err)
	}
	r.Active = false
	if _, err := Evaluate(r, q, []model.Alert{}, now); !errors.Is(err, ErrInput) {
		t.Fatal(err)
	}
}

func TestBacktestEvidenceSamplesAreExplicitAndDigestAllFacts(t *testing.T) {
	r, q, now := fixture()
	facts := make([]model.Alert, MaxEvidence+2)
	for i := range facts {
		facts[i] = alert(fmt.Sprintf("event_%04d", i), q.Start)
	}
	x, err := Evaluate(r, q, facts, now)
	if err != nil || x.Windows[0].Count != len(facts) || len(x.Windows[0].Evidence) != MaxEvidence || !x.Windows[0].EvidenceTruncated {
		t.Fatal(x, err)
	}
	facts[len(facts)-1].RawSHA256 = strings.Repeat("b", 64)
	y, err := Evaluate(r, q, facts, now)
	if err != nil || y.Windows[0].EvidenceSHA256 == x.Windows[0].EvidenceSHA256 || !reflect.DeepEqual(y.Windows[0].Evidence, x.Windows[0].Evidence) {
		t.Fatal(y, err)
	}
	slices.Reverse(facts)
	z, err := Evaluate(r, q, facts, now)
	if err != nil || !reflect.DeepEqual(y, z) {
		t.Fatal(z, err)
	}
}
