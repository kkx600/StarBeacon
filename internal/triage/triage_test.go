package triage

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/model"
)

func alertFixture() model.Alert {
	a := model.Alert{EventID: "event_owned", TenantID: "tenant_owned", SensorID: "sensor_owned", RegistrationID: "registration_owned", RawSHA256: strings.Repeat("a", 64), Timestamp: time.Date(2026, 10, 1, 12, 0, 0, 0, time.FixedZone("owned", 8*3600)), ObservedAt: time.Date(2026, 10, 1, 12, 0, 1, 0, time.FixedZone("owned", 8*3600)), Source: model.Endpoint{IP: "192.0.2.1"}, Destination: model.Endpoint{IP: "198.51.100.2"}}
	a.Event.Kind, a.Event.Original = "alert", `{"password":"must-not-send","payload":"sensitive"}`
	a.Network.Transport, a.Network.Protocol = "tcp", "http"
	a.Rule.ID, a.Rule.Name, a.Rule.Revision = "1000001", "路径检测", "1"
	a.HTTP.Method, a.HTTP.Path = "GET", "/.git/config"
	return a
}

func material(t *testing.T) Evidence {
	t.Helper()
	e, err := Freeze(alertFixture())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func request() Request {
	return Request{EventID: "event_owned", RawSHA256: strings.Repeat("a", 64), ProviderID: "provider_owned", ProviderRevision: 1, Note: "结合现有告警判断，并指出缺失证据", AllowContext: true}
}

func answerFixture() Answer {
	return Answer{Verdict: "confirmed", Outcome: "attempt", Confidence: 0.9, Reason: "请求路径与规则匹配，仍需核对是否为授权测试", References: []string{"rule.id", "http.path"}, CounterEvidence: []string{"授权测试可能产生同类请求，当前没有独立证据排除"}, Missing: []string{"终端和业务日志"}, Recommendation: "investigate", NeedsReview: true}
}

func encode(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestFreezePreservesObservedFactsAndExcludesPayload(t *testing.T) {
	a := alertFixture()
	e, err := Freeze(a)
	if err != nil || e.EventID != a.EventID || e.RawSHA256 != a.RawSHA256 || !e.ObservedAt.Equal(a.ObservedAt) || e.Limited || len(e.Facts) != 12 {
		t.Fatal("冻结材料或实际事实数量不准确", e, err)
	}
	b := encode(t, e)
	if strings.Contains(b, "must-not-send") || strings.Contains(b, "payload") || strings.Contains(b, a.TenantID) || strings.Contains(b, "+08:00") {
		t.Fatal("原始材料、租户或未归一化时间泄露到模型上下文", b)
	}
	again, err := Freeze(a)
	if err != nil || again.SHA256 != e.SHA256 {
		t.Fatal("相同观测生成不同材料摘要")
	}
	a.HTTP.Path += "changed"
	changed, err := Freeze(a)
	if err != nil || changed.SHA256 == e.SHA256 {
		t.Fatal("事实变化没有反映到摘要")
	}
	a = alertFixture()
	a.Rule.Name, a.HTTP.Hostname = strings.Repeat("规", 2049), "invalid\x00host"
	limited, err := Freeze(a)
	if err != nil || !limited.Limited || !strings.Contains(encode(t, limited), strings.Repeat("规", 2048)) || strings.Contains(encode(t, limited), "invalid") {
		t.Fatal("截断或缺省没有标明，或不可信控制字符仍被发送", err)
	}
	for name, mutate := range map[string]func(*model.Alert){
		"id": func(a *model.Alert) { a.EventID = "bad/id" }, "digest": func(a *model.Alert) { a.RawSHA256 = strings.Repeat("A", 64) },
		"kind": func(a *model.Alert) { a.Event.Kind = "http" }, "time": func(a *model.Alert) { a.Timestamp = time.Time{} }, "observed": func(a *model.Alert) { a.ObservedAt = time.Time{} },
		"sensor": func(a *model.Alert) { a.SensorID = "" }, "registration": func(a *model.Alert) { a.RegistrationID = "" }, "source": func(a *model.Alert) { a.Source.IP = "not-an-ip" }, "destination": func(a *model.Alert) { a.Destination.IP = "not-an-ip" },
	} {
		t.Run(name, func(t *testing.T) {
			a := alertFixture()
			mutate(&a)
			if _, err := Freeze(a); err == nil {
				t.Fatal("不完整事实被接受")
			}
		})
	}
	a = alertFixture()
	a.Rule.Name = string([]byte{255})
	if e, err := Freeze(a); err != nil || !e.Limited {
		t.Fatal("非法 UTF-8 没有作为缺失字段处理", err)
	}
}

func TestSealAndPromptRequireExactSourceAndFrozenDigest(t *testing.T) {
	e := material(t)
	r := request()
	prompt, err := Prompt(r, e)
	if err != nil || !strings.Contains(prompt, "http.path") || !strings.Contains(prompt, e.SHA256) || !strings.Contains(prompt, r.Note) {
		t.Fatal("材料未按冻结来源构造", err)
	}
	if len(InputHash(r)) != 64 || InputHash(r) != InputHash(r) || (Args{}).Kind() != "alert_triage" {
		t.Fatal("请求与队列标识无效")
	}
	for name, mutate := range map[string]func(*Request){
		"id": func(r *Request) { r.EventID = "bad/id" }, "digest": func(r *Request) { r.RawSHA256 = "bad" }, "provider": func(r *Request) { r.ProviderID = "bad/id" },
		"revision": func(r *Request) { r.ProviderRevision = 0 }, "revision-overflow": func(r *Request) { r.ProviderRevision = 9007199254740992 }, "consent": func(r *Request) { r.AllowContext = false },
		"note-length": func(r *Request) { r.Note = strings.Repeat("字", 2001) }, "note-control": func(r *Request) { r.Note = "control\x00" }, "note-utf8": func(r *Request) { r.Note = string([]byte{255}) },
	} {
		t.Run(name, func(t *testing.T) {
			v := r
			mutate(&v)
			if v.Validate() == nil {
				t.Fatal("错误请求被接受")
			}
			if _, err := Prompt(v, e); err == nil {
				t.Fatal("错误请求获得提示词")
			}
		})
	}
	for name, mutate := range map[string]func(*Evidence){
		"digest": func(e *Evidence) { e.RawSHA256 = "bad" }, "event": func(e *Evidence) { e.EventID = "bad/id" }, "observed": func(e *Evidence) { e.ObservedAt = time.Time{} },
		"empty": func(e *Evidence) { e.Facts = nil }, "too-many": func(e *Evidence) { e.Facts = append(e.Facts, make([]Fact, 18)...) }, "limitations": func(e *Evidence) { e.Limitations = []string{"arbitrary"} },
		"duplicate": func(e *Evidence) { e.Facts = append(e.Facts, e.Facts[0]) }, "unknown": func(e *Evidence) { e.Facts[0].ID = "unknown" }, "value": func(e *Evidence) { e.Facts[0].Value = "" }, "label": func(e *Evidence) { e.Facts[0].Label = "" },
		"missing-registration": func(e *Evidence) { e.Facts = e.Facts[1:] },
	} {
		t.Run(name, func(t *testing.T) {
			v := e
			v.Facts = slices.Clone(e.Facts)
			mutate(&v)
			if _, err := Seal(v); err == nil {
				t.Fatal("不完整证据被接受")
			}
		})
	}
	changed := e
	changed.Facts = slices.Clone(e.Facts)
	changed.Facts[0].Value = "changed"
	if _, err := Prompt(r, changed); err == nil {
		t.Fatal("摘要不匹配没有拒绝")
	}
	r.EventID = "another_event"
	if _, err := Prompt(r, e); err == nil {
		t.Fatal("材料与请求没有绑定")
	}
	r = request()
	r.RawSHA256 = strings.Repeat("b", 64)
	if _, err := Prompt(r, e); err == nil {
		t.Fatal("原始摘要与请求没有绑定")
	}
	// 材料可单独满足封存上限，但与用户说明和指令合并后仍需遵守共享 SDK 输入上限。
	large := e
	large.Facts = slices.Clone(e.Facts[:9])
	for i := range large.Facts {
		large.Facts[i].Value = strings.Repeat("a", 2048)
	}
	large, err = Seal(large)
	if err != nil {
		t.Fatal(err)
	}
	r = request()
	r.Note = strings.Repeat("中", 2000)
	if _, err := Prompt(r, large); err == nil {
		t.Fatal("超出共享模型输入上限的请求进入执行阶段")
	}
}

func TestAnswerRequiresCitationsAndNeverAuthorizesActions(t *testing.T) {
	e := material(t)
	base := answerFixture()
	decoded, err := DecodeAnswer(encode(t, base), e)
	if err != nil || decoded.Recommendation != "investigate" || !decoded.NeedsReview {
		t.Fatal("合法有引用研判被拒绝", err)
	}
	for _, kind := range []string{"undetermined", "suspicious", "false_positive", "confirmed"} {
		v := base
		v.Verdict = kind
		v.Outcome = "unknown"
		if _, err := DecodeAnswer(encode(t, v), e); err != nil {
			t.Fatal(kind, err)
		}
	}
	v := base
	v.Recommendation = "block_source"
	if _, err := DecodeAnswer(encode(t, v), e); err != nil {
		t.Fatal("最小范围建议被拒绝", err)
	}
	v = base
	v.Verdict = "undetermined"
	v.Outcome = "unknown"
	v.References = []string{}
	if _, err := DecodeAnswer(encode(t, v), e); err != nil {
		t.Fatal("允许证据不足拒绝判断", err)
	}
	for name, mutate := range map[string]func(*Answer){
		"verdict": func(a *Answer) { a.Verdict = "benign" }, "success": func(a *Answer) { a.Outcome = "success" }, "prevented": func(a *Answer) { a.Outcome = "prevented" }, "execute": func(a *Answer) { a.Recommendation = "execute" }, "review": func(a *Answer) { a.NeedsReview = false },
		"confidence-low": func(a *Answer) { a.Confidence = -0.1 }, "confidence-high": func(a *Answer) { a.Confidence = 1.1 }, "reason": func(a *Answer) { a.Reason = " " }, "reason-long": func(a *Answer) { a.Reason = strings.Repeat("字", 2001) }, "reason-control": func(a *Answer) { a.Reason = "\x00" },
		"unknown-reference": func(a *Answer) { a.References = []string{"invented.fact"} }, "duplicate-reference": func(a *Answer) { a.References = []string{"rule.id", "rule.id"} }, "missing-reference": func(a *Answer) { a.References = []string{} }, "null-reference": func(a *Answer) { a.References = nil }, "many-reference": func(a *Answer) { a.References = make([]string, 9) },
		"null-counter": func(a *Answer) { a.CounterEvidence = nil }, "null-missing": func(a *Answer) { a.Missing = nil }, "empty-item": func(a *Answer) { a.Missing = []string{" "} }, "long-item": func(a *Answer) { a.Missing = []string{strings.Repeat("字", 513)} }, "duplicate-item": func(a *Answer) { a.Missing = []string{"x", "x"} },
		"false-positive-attempt": func(a *Answer) { a.Verdict = "false_positive" }, "false-positive-no-counter": func(a *Answer) { a.Verdict = "false_positive"; a.Outcome = "unknown"; a.CounterEvidence = []string{} }, "suspicious-attempt": func(a *Answer) { a.Verdict = "suspicious" }, "block-no-counter": func(a *Answer) { a.Recommendation = "block_source"; a.CounterEvidence = []string{} }, "block-unconfirmed": func(a *Answer) { a.Verdict = "suspicious"; a.Outcome = "unknown"; a.Recommendation = "block_source" },
	} {
		t.Run(name, func(t *testing.T) {
			v := base
			mutate(&v)
			if _, err := DecodeAnswer(encode(t, v), e); err == nil {
				t.Fatal("无法追溯或越界输出被接受")
			}
		})
	}
	noSource := e
	noSource.Facts = []Fact{}
	for _, f := range e.Facts {
		if f.ID != "source.ip" {
			noSource.Facts = append(noSource.Facts, f)
		}
	}
	v = base
	v.Recommendation = "block_source"
	if _, err := DecodeAnswer(encode(t, v), noSource); err == nil {
		t.Fatal("没有实际源 IP 仍建议封禁")
	}
	encoded := encode(t, base)
	for _, bad := range []string{encoded + `{}`, strings.Replace(encoded, `"verdict":"confirmed"`, `"verdict":"confirmed","verdict":"false_positive"`, 1), strings.Replace(encoded, `"verdict"`, `"Verdict"`, 1), strings.Replace(encoded, `"needs_review":true`, `"needs_review":null`, 1), strings.Replace(encoded, `"confidence":0.9,`, "", 1), strings.Replace(encoded, `"confidence":0.9`, `"confidence":1e999`, 1), `null`, `[]`, `{"verdict":}`, string([]byte{255})} {
		if _, err := DecodeAnswer(bad, e); err == nil {
			t.Fatal("非唯一、缺少必填或非法输出被接受", bad)
		}
	}
}
