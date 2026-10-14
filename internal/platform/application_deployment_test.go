package platform

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/application"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestApplicationDeploymentHTTPRejectsAmbiguousInputAndMissingDependencies(t *testing.T) {
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := &API{Signer: signer}
	input := application.DeploymentInput{ExpectedRegistrationID: "reg_owned", ExpectedStateSHA256: application.EmptyState().StateSHA256, RulesSHA256: application.EmptyState().RulesSHA256}
	raw, _ := json.Marshal(input)
	for _, body := range []string{`null`, `{}`, string(raw) + `{}`, strings.Replace(string(raw), `"rules_sha256":`, `"Rules_sha256":`, 1), strings.Replace(string(raw), `"rules_sha256":`, `"rules_sha256":"duplicate","rules_sha256":`, 1), strings.Replace(string(raw), `"expected_state_sha256":`, `"unknown":`, 1), string(raw)} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.SetPathValue("id", "sensor_owned")
		r.Header.Set("Idempotency-Key", "deploy_owned")
		r.Header.Set("Content-Type", "application/json")
		a.deployApplicationRules(w, r)
		want := 400
		if body == string(raw) {
			want = 503
		}
		if w.Code != want {
			t.Fatal("部署输入或不可用存储边界错误", w.Code, want)
		}
	}
	for _, target := range []string{"/?unknown=true", "/"} {
		w := httptest.NewRecorder()
		a.applicationSnapshot(w, httptest.NewRequest("GET", target, nil))
		want := 400
		if target == "/" {
			want = 503
		}
		if w.Code != want {
			t.Fatal("快照读取边界错误")
		}
	}
	a.Signer = nil
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(string(raw)))
	r.SetPathValue("id", "sensor_owned")
	r.Header.Set("Idempotency-Key", "deploy_owned")
	r.Header.Set("Content-Type", "application/json")
	a.deployApplicationRules(w, r)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "signer_unavailable") {
		t.Fatal("缺少签名仍提交")
	}
	w = httptest.NewRecorder()
	applicationFailure(w, r, store.ErrApplicationState)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "application_state_conflict") {
		t.Fatal("状态冲突被丢失")
	}
}
