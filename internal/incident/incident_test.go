package incident

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func openSpec() Spec {
	return Spec{Title: "异常请求调查", Category: "network_intrusion", Severity: "high", Status: "open", Summary: "核对告警来源及受影响业务。"}
}
func closedSpec() Spec {
	s := openSpec()
	s.Status = "closed"
	s.OwnerID = "user_owned"
	s.Closure = &Closure{Reason: "resolved", RootCause: "记录实际核对的根因。", Impact: "记录已确认和未知影响。", Remediation: "记录已执行的修复措施。", Verification: "依据复测证据记录验证。", Evidence: []string{"test:owned:verification"}}
	return s
}
func sampleRecord() Record {
	now := time.Now().UTC()
	return Record{ID: "incident_owned", Revision: 1, Spec: openSpec(), Alerts: []AlertEvidence{{AlertRef: AlertRef{EventID: "event_owned", SHA256: strings.Repeat("a", 64)}, SensorID: "sensor_owned", EventTime: now, ObservedAt: now}}, Note: "建立事件调查", ActorID: "user_owned", ActorName: "调查员", CreatedAt: now, RecordedAt: now, ExpiresAt: now.Add(180 * 24 * time.Hour)}
}
func clone[T any](value T) T {
	raw, _ := json.Marshal(value)
	var result T
	_ = json.Unmarshal(raw, &result)
	return result
}

func TestIncidentClosureRequiresAccountableAndReproducibleMaterial(t *testing.T) {
	if openSpec().Validate() != nil || closedSpec().Validate() != nil {
		t.Fatal("有效调查或结案被拒绝")
	}
	falsePositive := closedSpec()
	falsePositive.Closure.Reason = "false_positive"
	falsePositive.Closure.Evidence = []string{}
	if falsePositive.Validate() != nil {
		t.Fatal("有结构化核对说明的误报结案被拒绝")
	}
	for name, mutate := range map[string]func(*Spec){
		"空标题": func(s *Spec) { s.Title = "" }, "超长标题": func(s *Spec) { s.Title = strings.Repeat("字", 121) }, "控制字符": func(s *Spec) { s.Summary = "说明\r异常" }, "分类伪造": func(s *Spec) { s.Category = "attack_success" }, "严重度伪造": func(s *Spec) { s.Severity = "severe" }, "状态伪造": func(s *Spec) { s.Status = "auto_blocked" }, "空概述": func(s *Spec) { s.Summary = "" }, "非法责任人": func(s *Spec) { s.OwnerID = "other/tenant" }, "无责任人结案": func(s *Spec) { s.OwnerID = "" }, "缺少结案材料": func(s *Spec) { s.Closure = nil }, "原因伪造": func(s *Spec) { s.Closure.Reason = "safe" }, "根因缺失": func(s *Spec) { s.Closure.RootCause = "" }, "影响缺失": func(s *Spec) { s.Closure.Impact = "" }, "修复缺失": func(s *Spec) { s.Closure.Remediation = "" }, "复测缺失": func(s *Spec) { s.Closure.Verification = "" }, "缺少复测引用": func(s *Spec) { s.Closure.Evidence = []string{} }, "空引用数组": func(s *Spec) { s.Closure.Evidence = nil }, "重复引用": func(s *Spec) { s.Closure.Evidence = []string{"reference", "reference"} }, "空引用": func(s *Spec) { s.Closure.Evidence = []string{""} }, "引用控制字符": func(s *Spec) { s.Closure.Evidence = []string{"test\nnewline"} }, "引用超限": func(s *Spec) { s.Closure.Evidence = []string{strings.Repeat("a", 257)} }, "过多引用": func(s *Spec) { s.Closure.Evidence = make([]string, 9) }, "未关闭含结案材料": func(s *Spec) { s.Status = "investigating" },
	} {
		t.Run(name, func(t *testing.T) {
			s := clone(closedSpec())
			mutate(&s)
			if s.Validate() == nil {
				t.Fatal("不完整结案被接受")
			}
		})
	}
}

func TestIncidentRefsAndRecordedFactsNeverSubstituteRawTraffic(t *testing.T) {
	r := sampleRecord()
	if r.Validate() != nil {
		t.Fatal("有效调查记录被拒绝")
	}
	assigned := clone(r)
	assigned.Spec.OwnerID = "user_owned"
	assigned.OwnerName = "调查员"
	if assigned.Validate() != nil {
		t.Fatal("有效责任人被拒绝")
	}
	for name, mutate := range map[string]func(*Record){
		"记录身份": func(r *Record) { r.ID = "../unsafe" }, "非法修订": func(r *Record) { r.Revision = 0 }, "修订超限": func(r *Record) { r.Revision = MaxRevision + 1 }, "无实际操作人": func(r *Record) { r.ActorID = "" }, "无操作人姓名": func(r *Record) { r.ActorName = "" }, "无操作说明": func(r *Record) { r.Note = "" }, "操作人控制字符": func(r *Record) { r.ActorName = "\x00hidden" }, "时间缺失": func(r *Record) { r.CreatedAt = time.Time{} }, "记录早于创建": func(r *Record) { r.RecordedAt = r.CreatedAt.Add(-time.Second) }, "到期早于记录": func(r *Record) { r.ExpiresAt = r.RecordedAt }, "关联数组缺失": func(r *Record) { r.Alerts = nil }, "过多关联": func(r *Record) { r.Alerts = make([]AlertEvidence, MaxAlerts+1) }, "无责任人有姓名": func(r *Record) { r.OwnerName = "伪造" }, "责任人缺姓名": func(r *Record) { r.Spec.OwnerID = "user_owned" }, "原告警身份缺失": func(r *Record) { r.Alerts[0].EventID = "" }, "原始摘要缺失": func(r *Record) { r.Alerts[0].SHA256 = "" }, "探针身份缺失": func(r *Record) { r.Alerts[0].SensorID = "" }, "实际事件时间缺失": func(r *Record) { r.Alerts[0].EventTime = time.Time{} }, "实际观测时间缺失": func(r *Record) { r.Alerts[0].ObservedAt = time.Time{} }, "重复关联": func(r *Record) { r.Alerts = append(r.Alerts, r.Alerts[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			value := clone(r)
			mutate(&value)
			if value.Validate() == nil {
				t.Fatal("伪造或不完整调查依据被采用")
			}
		})
	}
	for _, refs := range [][]AlertRef{nil, {{EventID: "bad/id", SHA256: strings.Repeat("a", 64)}}, {{EventID: "event", SHA256: "missing"}}, {{EventID: "event", SHA256: strings.Repeat("A", 64)}}, {{EventID: "event", SHA256: strings.Repeat("a", 64)}, {EventID: "event", SHA256: strings.Repeat("b", 64)}}, make([]AlertRef, 9)} {
		if ValidateRefs(refs) == nil {
			t.Fatal("有歧义的关联输入被采用", refs)
		}
	}
	if ValidateRefs([]AlertRef{}) != nil {
		t.Fatal("无告警的人工调查被禁止")
	}
}

func TestIncidentChangeAndQueryBoundaries(t *testing.T) {
	create := Create{Spec: openSpec(), Alerts: []AlertRef{}}
	if create.Validate() != nil {
		t.Fatal("有效建立请求被拒绝")
	}
	create.Spec = closedSpec()
	if create.Validate() == nil {
		t.Fatal("直接创建已结案事件")
	}
	create.Spec = openSpec()
	create.Spec.Title = ""
	if create.Validate() == nil {
		t.Fatal("无标题建立事件")
	}
	change := Change{ExpectedRevision: 1, Spec: openSpec(), Note: "核对授权请求", AddAlerts: []AlertRef{}}
	if change.Validate() != nil {
		t.Fatal("有效操作被拒绝")
	}
	for _, bad := range []Change{{Spec: openSpec(), Note: "说明", AddAlerts: []AlertRef{}}, {ExpectedRevision: MaxRevision + 1, Spec: openSpec(), Note: "说明", AddAlerts: []AlertRef{}}, {ExpectedRevision: 1, Spec: openSpec(), AddAlerts: []AlertRef{}}, {ExpectedRevision: 1, Spec: openSpec(), Note: "说明", AddAlerts: nil}, {ExpectedRevision: 1, Spec: Spec{}, Note: "说明", AddAlerts: []AlertRef{}}} {
		if bad.Validate() == nil {
			t.Fatal("不完整变更被接受")
		}
	}
	for _, q := range []Query{{}, {Status: "investigating", Severity: "critical", Before: "incident_owned"}} {
		if q.Validate() != nil {
			t.Fatal("有效筛选被拒绝")
		}
	}
	for _, q := range []Query{{Status: "unknown"}, {Severity: "safe"}, {Before: "bad/identity"}} {
		if q.Validate() == nil {
			t.Fatal("非法筛选被接受")
		}
	}
	for _, value := range []string{" leading", "trailing ", "bad\x00text", string([]byte{0xff})} {
		if Text(value, 64, true) {
			t.Fatal("非法文本被接受")
		}
	}
	if !Text("中文\n说明\t字段", 20, true) || Text("说明\n换行", 20, false) {
		t.Fatal("多行文本语义不一致")
	}
}
