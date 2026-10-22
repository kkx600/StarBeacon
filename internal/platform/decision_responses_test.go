package platform

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/watchlist"
)

func TestDecisionResponseHTTPStrictAuthorizationInput(t *testing.T) {
	a := &API{}
	input := decision.ResponseRequest{EvaluationSHA256: strings.Repeat("a", 64), SensorID: "sensor_owned", RegistrationID: "registration_owned", ConnectorID: "connector_owned", ConfigSHA256: strings.Repeat("b", 64), TTLSeconds: 300, Reason: "管理员确认异常通信", Confirmed: true}
	good, _ := json.Marshal(input)
	cases := []struct {
		body, key, id, query string
		duplicate            bool
		status               int
	}{
		{string(good), "response_owned", "evaluation_owned", "", false, 503},
		{"null", "response_owned", "evaluation_owned", "", false, 400},
		{"{}", "response_owned", "evaluation_owned", "", false, 400},
		{string(good) + ` {}`, "response_owned", "evaluation_owned", "", false, 400},
		{strings.Replace(string(good), `"confirmed":true`, `"confirmed":false`, 1), "response_owned", "evaluation_owned", "", false, 400},
		{strings.Replace(string(good), `"confirmed":true`, `"confirmed":true,"confirmed":true`, 1), "response_owned", "evaluation_owned", "", false, 400},
		{strings.Replace(string(good), `"confirmed":true`, `"Confirmed":true`, 1), "response_owned", "evaluation_owned", "", false, 400},
		{strings.Replace(string(good), `"confirmed":true`, `"confirmed":true,"target_ip":"198.51.100.10"`, 1), "response_owned", "evaluation_owned", "", false, 400},
		{strings.Repeat(" ", 8193) + string(good), "response_owned", "evaluation_owned", "", false, 400},
		{string(good), "", "evaluation_owned", "", false, 400},
		{string(good), "short", "evaluation_owned", "", false, 400},
		{string(good), "response_owned", "/", "", false, 400},
		{string(good), "response_owned", "evaluation_owned", "?target_ip=other", false, 400},
		{string(good), "response_owned", "evaluation_owned", "", true, 400},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/"+c.query, strings.NewReader(c.body))
		r.SetPathValue("id", c.id)
		r.Header.Set("Idempotency-Key", c.key)
		if c.duplicate {
			r.Header.Add("Idempotency-Key", c.key)
		}
		w := httptest.NewRecorder()
		a.createDecisionResponse(w, r)
		if w.Code != c.status {
			t.Fatalf("处置输入边界不同：%d，期望 %d", w.Code, c.status)
		}
	}
	for _, c := range []struct {
		id, query string
		status    int
	}{{"/", "", 400}, {"evaluation_owned", "?unknown=1", 400}, {"evaluation_owned", "", 503}} {
		r := httptest.NewRequest("GET", "/"+c.query, nil)
		r.SetPathValue("id", c.id)
		w := httptest.NewRecorder()
		a.decisionResponse(w, r)
		if w.Code != c.status {
			t.Fatal("处置读取边界不同", w.Code)
		}
	}
}

func TestDecisionResponseFailureDoesNotReportAccepted(t *testing.T) {
	for _, c := range []struct {
		err    error
		status int
		code   string
	}{
		{watchlist.ErrProtected, 409, "response_target_protected"},
		{errors.Join(response.ErrInput, watchlist.ErrProtected), 409, "response_target_protected"},
		{decision.ErrInput, 400, "invalid_decision_response"}, {response.ErrInput, 400, "invalid_decision_response"},
		{decision.ErrSource, 409, "decision_response_source_changed"}, {store.ErrAlertIdentity, 409, "decision_response_source_changed"},
		{store.ErrConflict, 409, "decision_response_conflict"}, {response.ErrUnavailable, 409, "response_device_unavailable"},
		{response.ErrQuota, 429, "response_quota_exhausted"}, {decision.ErrPermission, 403, "decision_response_forbidden"},
		{response.ErrPermission, 403, "decision_response_forbidden"}, {pgx.ErrNoRows, 404, "not_found"}, {errors.New("内部连接失败"), 503, "decision_response_unavailable"},
	} {
		w := httptest.NewRecorder()
		decisionResponseFailure(w, httptest.NewRequest("POST", "/", nil), c.err)
		if w.Code != c.status || !strings.Contains(w.Body.String(), c.code) {
			t.Fatal("处置错误状态不准确", w.Code, c.code)
		}
	}
}
