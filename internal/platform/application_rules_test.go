package platform

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/application"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestApplicationRuleHTTPStrictFieldsBoundsAndUnavailableStorage(t *testing.T) {
	a := &API{}
	definition := application.Definition{SchemaVersion: application.Schema, ProductID: "owned", ProductName: "业务应用", CategoryID: "business", Protocols: []string{"http"}, Any: []application.Condition{{Field: "http.host", Op: "eq", Value: "owned.example"}}, All: []application.Condition{}, Exclude: []application.Condition{}}
	active := true
	change := application.Change{ID: "app_owned", Name: "业务应用规则", Active: &active, Definition: definition}
	observation := application.Observation{SchemaVersion: application.ObservationSchema, Protocol: "http", HTTPHost: "owned.example", TLSALPN: []string{}, DNSNames: []string{}}
	for _, item := range []struct {
		handler http.HandlerFunc
		input   any
	}{{a.saveApplicationRule, change}, {a.previewApplicationRule, map[string]any{"definition": definition, "observation": observation}}, {a.testApplicationRules, map[string]any{"observation": observation}}} {
		raw, _ := json.Marshal(item.input)
		for _, body := range []string{"null", "[]", "{}", `{"observation":{"protocol":"http","protocol":"tls"}}`, `{"Observation":{}}`, `{"observation":{"name":"not_an_observation_field"}}`, `{"unknown":true}`, strings.Repeat(" ", 32769) + string(raw), string(raw)} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Idempotency-Key", "app_http_create")
			item.handler(w, r)
			want := 400
			if body == string(raw) {
				want = 503
			}
			if w.Code != want {
				t.Fatalf("严格字段或缺失存储被忽略：材料长度 %d，响应 %d，期望 %d", len(body), w.Code, want)
			}
		}
	}
	for _, url := range []string{"/?limit=x", "/?limit=0", "/?limit=101", "/?limit=020", "/?cursor=/", "/?active=yes", "/?keyword=x&keyword=y", "/?unknown=x"} {
		w := httptest.NewRecorder()
		a.applicationRules(w, httptest.NewRequest("GET", url, nil))
		if w.Code != 400 {
			t.Fatal("非法目录条件进入存储", url)
		}
	}
	q, err := applicationListQuery(httptest.NewRequest("GET", "/?limit=10&active=true&keyword=业务&cursor=app_owned", nil))
	if err != nil || q.Limit != 10 || q.Keyword != "业务" || q.Cursor != "app_owned" {
		t.Fatal("合法目录条件解析失败", err)
	}
	w := httptest.NewRecorder()
	a.applicationRules(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 503 {
		t.Fatal("存储缺失返回目录成功")
	}
	for _, revision := range []string{"0", "01", "bad", "1000001", "1"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		r.SetPathValue("id", "app_owned")
		r.SetPathValue("revision", revision)
		a.applicationRule(w, r)
		want := 400
		if revision == "1" {
			want = 503
		}
		if w.Code != want {
			t.Fatal("修订边界或存储不可用被忽略", revision, w.Code)
		}
	}
}

func TestApplicationRuleErrorsKeepMeaningWithoutInternalDetails(t *testing.T) {
	for _, item := range []struct {
		err    error
		status int
		code   string
	}{{application.ErrInput, 400, "invalid_application_rule"}, {application.ErrQuota, 429, "application_rule_quota"}, {application.ErrPermission, 403, "application_rule_forbidden"}, {store.ErrConflict, 409, "application_rule_conflict"}, {pgx.ErrNoRows, 404, "not_found"}, {errors.New("private_database_information"), 503, "application_rule_unavailable"}} {
		w := httptest.NewRecorder()
		applicationFailure(w, httptest.NewRequest("GET", "/", nil), item.err)
		var response struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &response)
		if w.Code != item.status || response.Code != item.code || strings.Contains(w.Body.String(), "private_database_information") {
			t.Fatal("错误含义或内部信息不一致")
		}
	}
}
