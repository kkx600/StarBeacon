package platform

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestContinuousDecisionHTTPContractRejectsNullBindingsAndInvalidLookups(t *testing.T) {
	a := &API{}
	for _, body := range []string{
		`{"definition":{"continuous":null}}`,
		`{"definition":{"continuous":{"provider_id":"provider_owned","provider_revision":1,"automatic":null}}}`,
		`{"definition":{"continuous":{"provider_id":"provider_owned","provider_revision":1,"trigger":null}}}`,
		`{"definition":{"continuous":{"provider_id":"provider_owned","provider_revision":1,"automatic":{"accept_uncalibrated_score":true,"accept_uncalibrated_score":false}}}}`,
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		a.validateDecisionPolicy(w, r)
		if w.Code != 400 {
			t.Fatal("空绑定或重复授权字段被接受", w.Code)
		}
	}
	d := policyDefinition()
	d.Mode = "approval"
	d.Continuous = &decision.ContinuousConfig{ProviderID: "provider_owned", ProviderRevision: 1}
	for _, mode := range []string{"approval", "automatic"} {
		d.Mode = mode
		if mode == "automatic" {
			d.CandidateAction = "block_source"
			d.Continuous.Automatic = &decision.AutomaticConfig{SensorID: "sensor_owned", RegistrationID: "registration_owned", ConnectorID: "connector_owned", ConfigSHA256: strings.Repeat("a", 64), TTLSeconds: 60, CooldownSeconds: 60, MaxHourlyActions: 1, AcceptUncalibratedScore: true}
			d.Continuous.Trigger = &decision.TriageTrigger{Severities: []string{"high"}, MaxDailyJobs: 10, AllowModelContext: true}
		}
		raw, err := json.Marshal(map[string]any{"definition": d})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/", strings.NewReader(string(raw)))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.validateDecisionPolicy(w, r)
		if w.Code != 200 {
			t.Fatal("合法持续模式被拒绝", mode, w.Code)
		}
	}
	for _, item := range []struct {
		id, query string
		want      int
	}{
		{"/", "", 400}, {"evaluation_owned", "?unknown=x", 400}, {"evaluation_owned", "", 503},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/"+item.query, nil)
		r.SetPathValue("id", item.id)
		a.continuousDecision(w, r)
		if w.Code != item.want {
			t.Fatal("持续授权详情边界错误", item, w.Code)
		}
	}
	if after, count, err := a.SweepContinuousDecisions(context.Background(), "tenant_owned"); err == nil || after != "tenant_owned" || count != 0 {
		t.Fatal("未就绪扫描跳过了游标或返回成功")
	}
	for _, item := range []struct {
		revision, query string
		want            int
	}{{"x", "", 400}, {"01", "", 400}, {"0", "", 400}, {"1000001", "", 400}, {"1", "?unknown=x", 400}, {"1", "?before=/", 400}, {"1", "?before=a&before=b", 400}, {"1", "", 503}} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/"+item.query, nil)
		r.SetPathValue("id", "policy_owned")
		r.SetPathValue("revision", item.revision)
		a.automaticTriages(w, r)
		if w.Code != item.want {
			t.Fatal("自动研判记录参数边界不正确", item, w.Code)
		}
	}
	if count, err := a.SweepAutomaticTriages(context.Background(), "tenant_owned"); err != nil || count != 0 {
		t.Fatal("未就绪扫描提交了收费作业")
	}
}

func policyDefinition() decision.Definition {
	return decision.Definition{SchemaVersion: decision.Schema, Mode: "shadow", Expression: "confidence >= threshold", Threshold: .9, CandidateAction: "investigate", MaxAgeSeconds: 3600, ProtectedPrefixes: []string{}}
}

func TestDecisionPolicyHTTPFieldsBudgetsModesAndAvailability(t *testing.T) {
	a := &API{}
	active := true
	c := decision.Change{ID: "policy_owned", Name: "影子策略", Active: &active, Definition: policyDefinition()}
	for _, item := range []struct {
		handler http.HandlerFunc
		input   any
		pathID  string
		want    int
	}{
		{a.saveDecisionPolicy, c, "", 503},
		{a.validateDecisionPolicy, map[string]any{"definition": c.Definition}, "", 200},
		{a.evaluateDecisionPolicy, decision.EvaluateRequest{ExpectedRevision: 1, TriageID: "triage_owned"}, c.ID, 503},
	} {
		raw, _ := json.Marshal(item.input)
		for _, body := range []string{"null", "[]", "{}", `{"definition":{"mode":"shadow","mode":"automatic"}}`, `{"Definition":{}}`, `{"definition":{"candidateAction":"investigate"}}`, `{"confidence":0.99}`, `{"unknown":true}`, strings.Repeat(" ", 16385) + string(raw), string(raw)} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Idempotency-Key", "policy_create")
			r.SetPathValue("id", item.pathID)
			item.handler(w, r)
			want := 400
			if body == string(raw) {
				want = item.want
			}
			if w.Code != want {
				t.Fatalf("严格字段或可用性错误：长度 %d，响应 %d，期望 %d", len(body), w.Code, want)
			}
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/?unknown=x", strings.NewReader(string(raw)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "policy_create")
		r.SetPathValue("id", item.pathID)
		item.handler(w, r)
		if w.Code != 400 {
			t.Fatal("未声明查询参数被接受")
		}
	}
	for _, mode := range []string{"approval", "automatic"} {
		d := policyDefinition()
		d.Mode = mode
		raw, _ := json.Marshal(map[string]any{"definition": d})
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(string(raw)))
		r.Header.Set("Content-Type", "application/json")
		a.validateDecisionPolicy(w, r)
		if w.Code != 409 {
			t.Fatal("执行资格未阻止模式切换")
		}
	}
	for _, body := range []decision.Change{{ID: c.ID, Name: c.Name, Active: &active, Definition: policyDefinition()}, {ID: c.ID, Name: c.Name, Active: &active, Definition: decision.Definition{}}} {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "/", strings.NewReader(string(raw)))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.saveDecisionPolicy(w, r)
		if w.Code != 400 {
			t.Fatal("缺少原提交键或定义仍提交")
		}
	}
	for _, url := range []string{"/?limit=x", "/?limit=0", "/?limit=101", "/?limit=020", "/?cursor=/", "/?active=yes", "/?keyword=x&keyword=y", "/?unknown=x"} {
		w := httptest.NewRecorder()
		a.decisionPolicies(w, httptest.NewRequest("GET", url, nil))
		if w.Code != 400 {
			t.Fatal("目录边界遗漏", url)
		}
	}
	q, err := decisionListQuery(httptest.NewRequest("GET", "/?limit=10&active=true&keyword=影子&cursor=policy_owned", nil))
	if err != nil || q.Limit != 10 || q.Keyword != "影子" || q.Cursor != c.ID {
		t.Fatal(q, err)
	}
	w := httptest.NewRecorder()
	a.decisionPolicies(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 503 {
		t.Fatal("存储不可用仍返回成功")
	}
	for _, value := range []string{"0", "01", "x", "1000001", "1"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		r.SetPathValue("id", c.ID)
		r.SetPathValue("revision", value)
		a.decisionPolicy(w, r)
		want := 400
		if value == "1" {
			want = 503
		}
		if w.Code != want {
			t.Fatal("修订格式或预算遗漏", value, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/?unknown=x", nil)
	r.SetPathValue("id", c.ID)
	r.SetPathValue("revision", "1")
	w = httptest.NewRecorder()
	a.decisionPolicy(w, r)
	if w.Code != 400 {
		t.Fatal("详情未声明查询被接受")
	}
}

func TestDecisionPolicyFailureResponsesKeepBusinessMeaning(t *testing.T) {
	for _, item := range []struct {
		err    error
		status int
		code   string
	}{
		{decision.ErrInput, 400, "invalid_decision_policy"}, {decision.ErrMode, 409, "decision_mode_unavailable"}, {decision.ErrPermission, 403, "decision_policy_forbidden"}, {decision.ErrQuota, 429, "decision_policy_quota"}, {store.ErrConflict, 409, "decision_policy_conflict"}, {pgx.ErrNoRows, 404, "not_found"}, {decision.ErrSource, 503, "decision_policy_unavailable"}, {errors.New("private_storage_information"), 503, "decision_policy_unavailable"},
	} {
		w := httptest.NewRecorder()
		decisionFailure(w, httptest.NewRequest("GET", "/", nil), item.err)
		var out struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if w.Code != item.status || out.Code != item.code || strings.Contains(w.Body.String(), "private_storage_information") {
			t.Fatal("错误或内部信息边界不一致", w.Body.String())
		}
	}
}
