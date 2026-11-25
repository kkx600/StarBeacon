package platform

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestResponsePluginHTTPRejectsAmbiguousInputsAndUnavailableStorage(t *testing.T) {
	api := &API{}
	for _, query := range []string{"?after=broken%2Fpath", "?after=a&after=b", "?limit=01", "?limit=5", "?unknown=1", "?after=%xx"} {
		w := httptest.NewRecorder()
		api.responsePlugins(w, httptest.NewRequest("GET", "/response-plugins"+query, nil))
		if w.Code != 400 {
			t.Fatal("含糊分页仍进入存储", query, w.Code)
		}
	}
	w := httptest.NewRecorder()
	api.responsePlugins(w, httptest.NewRequest("GET", "/response-plugins?limit=10&after=owned", nil))
	if w.Code != 503 {
		t.Fatal("没有存储仍返回可用目录", w.Code)
	}
	for _, value := range []string{"", "01", "0", "33", "1"} {
		r := httptest.NewRequest("GET", "/response-plugins/plugin_owned/versions/"+value, nil)
		r.SetPathValue("id", "plugin_owned")
		r.SetPathValue("version", value)
		w := httptest.NewRecorder()
		api.responsePluginVersion(w, r)
		if value == "1" && w.Code != 503 || value != "1" && w.Code != 400 {
			t.Fatal("版本索引校验错误", value, w.Code)
		}
	}
	fixture, err := os.ReadFile("../response/testdata/owned_acl_template.json")
	if err != nil {
		t.Fatal(err)
	}
	body := append([]byte(`{"id":"plugin_owned","expected_version":0,"name":"设备草稿","device":"验收设备","template":`), fixture...)
	body = append(body, '}')
	for _, tc := range []struct {
		query   string
		keys    []string
		payload []byte
		status  int
	}{
		{"", nil, body, 400}, {"", []string{"too-short", "duplicate"}, body, 400},
		{"?activate=true", []string{"owned_template"}, body, 400},
		{"", []string{"owned_template"}, []byte(`{"state":"active"}`), 400},
		{"", []string{"owned_template"}, bytes.Replace(body, []byte(`"id":"plugin_owned"`), []byte(`"id":"plugin_owned","id":"other"`), 1), 400},
		{"", []string{"owned_template"}, body, 503},
	} {
		r := httptest.NewRequest(http.MethodPost, "/response-plugins"+tc.query, bytes.NewReader(tc.payload))
		r.Header.Set("Content-Type", "application/json")
		for _, key := range tc.keys {
			r.Header.Add("Idempotency-Key", key)
		}
		w := httptest.NewRecorder()
		api.saveResponsePlugin(w, r)
		if w.Code != tc.status || !strings.Contains(w.Body.String(), "response_plugin") {
			t.Fatal("插件草稿参数校验错误", w.Code, w.Body)
		}
	}
}
