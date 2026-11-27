package platform

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPlaybookHTTPBoundsAndStorageAvailability(t *testing.T) {
	api := &API{}
	definition := `{"name":"人工核对","steps":[{"kind":"trigger","name":"告警","description":""}]}`
	change := `{"expected_revision":0,"definition":` + definition + `}`
	digest := strings.Repeat("a", 64)
	revision := `{"revision":1,"sha256":"` + digest + `"}`
	start := `{"revision":1,"sha256":"` + digest + `","event_id":"` + digest + `","raw_sha256":"` + digest + `"}`

	for _, tc := range []struct {
		name, method, query, key, body string
		handler                        http.HandlerFunc
		status                         int
	}{
		{"目录依赖", "GET", "", "", "", api.playbooks, 503},
		{"配置依赖", "GET", "", "", "", api.playbook, 503},
		{"目录拒绝额外参数", "GET", "?other=1", "", "", api.playbooks, 400},
		{"配置拒绝额外参数", "GET", "?revision=2", "", "", api.playbook, 400},
		{"缺少保存键", "POST", "", "", change, api.savePlaybook, 400},
		{"草稿依赖", "POST", "", "playbook_draft", change, api.savePlaybook, 503},
		{"拒绝超长草稿", "POST", "", "playbook_draft", strings.Repeat("x", 32769), api.savePlaybook, 400},
		{"校验依赖", "POST", "", "", definition, api.validatePlaybook, 503},
		{"拒绝嵌套重复键", "POST", "", "", strings.Replace(definition, `"kind":"trigger"`, `"kind":"trigger","kind":"trigger"`, 1), api.validatePlaybook, 400},
		{"拒绝异形配置", "POST", "", "", strings.Replace(definition, `"description":""`, `"description":"","model":{"kind":"trigger"}`, 1), api.validatePlaybook, 400},
		{"发布依赖", "POST", "", "", revision, api.publishPlaybook, 503},
		{"发布摘要必填", "POST", "", "", `{"revision":1}`, api.publishPlaybook, 400},
		{"告警来源依赖", "POST", "", "playbook_start", start, api.startPlaybook, 503},
		{"不接受原始载荷", "POST", "", "playbook_start", strings.TrimSuffix(start, "}") + `,"payload":"data"}`, api.startPlaybook, 400},
		{"运行列表依赖", "GET", "?limit=20", "", "", api.playbookRuns, 503},
		{"运行列表拒绝重复参数", "GET", "?cursor=a&cursor=b", "", "", api.playbookRuns, 400},
		{"本人运行依赖", "GET", "", "", "", api.playbookRun, 503},
		{"确认步骤依赖", "POST", "", "", `{"step":1,"confirmed":true}`, api.acknowledgePlaybook, 503},
		{"缺少确认", "POST", "", "", `{"step":1,"confirmed":false}`, api.acknowledgePlaybook, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/playbook"+tc.query, strings.NewReader(tc.body))
			req.SetPathValue("id", "pb_owned")
			req.Header.Set("Content-Type", "application/json")
			if tc.key != "" {
				req.Header.Set("Idempotency-Key", tc.key)
			}
			res := httptest.NewRecorder()
			tc.handler(res, req)
			if res.Code != tc.status {
				t.Fatalf("HTTP %d，期望 %d", res.Code, tc.status)
			}
		})
	}
}
