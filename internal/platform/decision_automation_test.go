package platform

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecisionAutomationHTTPBoundsAndUnavailableStorage(t *testing.T) {
	a := &API{}
	validChange := `{"expected_revision":0,"ceiling":"full","paused":false}`
	validRejection := `{"plan_sha256":"` + strings.Repeat("a", 64) + `","reason":"核对材料后驳回"}`
	for _, tc := range []struct {
		name, method, path, input string
		handler                   http.HandlerFunc
		status                    int
	}{
		{"当前设置", "GET", "/decision-automation", "", a.decisionAutomation, 503},
		{"多余参数", "GET", "/decision-automation?extra=1", "", a.decisionAutomation, 400},
		{"合法保存", "PUT", "/decision-automation", validChange, a.saveDecisionAutomation, 503},
		{"带参数保存", "PUT", "/decision-automation?expected_revision=0", validChange, a.saveDecisionAutomation, 400},
		{"级别未知", "PUT", "/decision-automation", `{"expected_revision":0,"ceiling":"automatic","paused":false}`, a.saveDecisionAutomation, 400},
		{"缺暂停字段", "PUT", "/decision-automation", `{"expected_revision":0,"ceiling":"observe"}`, a.saveDecisionAutomation, 400},
		{"空修订", "PUT", "/decision-automation", `{"expected_revision":null,"ceiling":"approval","paused":false}`, a.saveDecisionAutomation, 400},
		{"重复字段", "PUT", "/decision-automation", `{"expected_revision":0,"ceiling":"full","ceiling":"observe","paused":false}`, a.saveDecisionAutomation, 400},
		{"过大修订", "PUT", "/decision-automation", `{"expected_revision":9007199254740991,"ceiling":"full","paused":false}`, a.saveDecisionAutomation, 400},
		{"合法暂停", "POST", "/decision-automation/pause", "", a.pauseDecisionAutomation, 503},
		{"暂停含请求体", "POST", "/decision-automation/pause", "{}", a.pauseDecisionAutomation, 400},
		{"合法目录", "GET", "/decision-plans", "", a.decisionPlans, 503},
		{"目录超限", "GET", "/decision-plans?limit=140", "", a.decisionPlans, 400},
		{"未知目录", "GET", "/decision-plans?view=all", "", a.decisionPlans, 400},
		{"无效游标", "GET", "/decision-plans?cursor=%2F", "", a.decisionPlans, 400},
		{"合法驳回", "POST", "/decision-evaluations/evaluation_owned/response/reject", validRejection, a.rejectDecisionPlan, 503},
		{"空白原因", "POST", "/decision-evaluations/evaluation_owned/response/reject", strings.Replace(validRejection, "核对材料后驳回", " ", 1), a.rejectDecisionPlan, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.input))
			request.Header.Set("Content-Type", "application/json")
			request.SetPathValue("id", "evaluation_owned")
			response := httptest.NewRecorder()
			tc.handler(response, request)
			if response.Code != tc.status {
				t.Fatalf("HTTP %d，期望 %d，正文 %s", response.Code, tc.status, response.Body.String())
			}
		})
	}
}
