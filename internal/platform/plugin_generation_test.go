package platform

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPluginGenerationHTTPBoundsAndUnavailableDependency(t *testing.T) {
	api := &API{}
	const good = `{"provider_id":"provider","provider_revision":1,"device_type":"firewall","abilities":["health"],"documentation":"GET /health returns healthy","allow_context":true}`
	for _, tc := range []struct {
		key, body string
		status    int
	}{
		{"", good, 400},
		{"fixture_generation", strings.Replace(good, `"device_type":"firewall"`, `"device_type":"firewall","device_type":"edr"`, 1), 400},
		{"fixture_generation", strings.Replace(good, `"abilities"`, `"local_config_file":"/fixture","abilities"`, 1), 400},
		{"fixture_generation", strings.Replace(good, "GET /health returns healthy", "Authorization: Bearer SYNTHETIC_TEST_TOKEN", 1), 400},
		{"fixture_generation", strings.Replace(good, "GET /health returns healthy", strings.Repeat("x", 33*1024), 1), 400},
		{"fixture_generation", good, 503},
	} {
		req := httptest.NewRequest(http.MethodPost, "/response-plugin-generation/jobs", strings.NewReader(tc.body))
		req.Header.Set("Idempotency-Key", tc.key)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		api.createPluginGeneration(w, req)
		if w.Code != tc.status {
			t.Fatal("插件生成输入或依赖状态错误", w.Code)
		}
	}
	for _, query := range []string{"", "?unknown=1", "?before=a&before=b", "?limit=8", "?before=%xx"} {
		w := httptest.NewRecorder()
		api.pluginGenerations(w, httptest.NewRequest(http.MethodGet, "/response-plugin-generation/jobs"+query, nil))
		status := http.StatusBadRequest
		if query == "" {
			status = http.StatusServiceUnavailable
		}
		if w.Code != status {
			t.Fatal("生成记录查询未核对游标及分页", query, w.Code)
		}
	}
	for _, id := range []string{"bad/id", "valid_job"} {
		req := httptest.NewRequest(http.MethodGet, "/response-plugin-generation/jobs/id", nil)
		req.SetPathValue("id", id)
		w := httptest.NewRecorder()
		api.pluginGeneration(w, req)
		want := http.StatusBadRequest
		if id == "valid_job" {
			want = http.StatusServiceUnavailable
		}
		if w.Code != want {
			t.Fatal("生成详情未核对作业标识", w.Code)
		}
	}
}
