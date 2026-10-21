package platform

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/response"
)

func TestSyslogHTTPStrictQueriesAndUnavailableDependencies(t *testing.T) {
	for _, query := range []string{"?limit=01", "?limit=bad", "?limit=0", "?limit=101", "?sensor_id=UPPER", "?source_id=a/b", "?cursor=bad", "?unknown=1", "?limit=20&limit=30", "?source_id=%zz"} {
		w := httptest.NewRecorder()
		(&API{}).syslogSources(w, httptest.NewRequest("GET", "/"+query, nil))
		if w.Code != 400 {
			t.Fatal(query, w.Code)
		}
	}
	for _, query := range []string{"", "?sensor_id=sensor_ok&source_id=edge&limit=100"} {
		w := httptest.NewRecorder()
		(&API{}).syslogSources(w, httptest.NewRequest("GET", "/"+query, nil))
		if w.Code != 503 {
			t.Fatal("来源依赖缺失伪装为空目录", w.Code)
		}
	}
	for _, query := range []string{"", "?partition=bad", "?partition=2026-10-21&other=1", "?partition=2026-10-21&partition=2026-10-22", "?partition=%zz"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/"+query, nil)
		r.SetPathValue("id", strings.Repeat("a", 64))
		(&API{}).logDetail(w, r)
		if w.Code != 400 {
			t.Fatal(query, w.Code)
		}
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/?partition=2026-10-21", nil)
	r.SetPathValue("id", strings.Repeat("a", 64))
	(&API{}).logDetail(w, r)
	if w.Code != 503 {
		t.Fatal("原文依赖缺失没有拒绝")
	}
	for _, id := range []string{"bad", strings.Repeat("z", 64)} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/?partition=2026-10-21", nil)
		r.SetPathValue("id", id)
		(&API{}).logDetail(w, r)
		if w.Code != 400 {
			t.Fatal("无效原文标识未拒绝")
		}
	}
	for _, body := range []string{`{`, `{"unexpected":true}`, func() string {
		raw, _ := json.Marshal(map[string]any{"start": time.Now().Add(-time.Hour), "end": time.Now(), "limit": 20})
		return string(raw)
	}()} {
		w := httptest.NewRecorder()
		(&API{}).searchLogs(w, httptest.NewRequest("POST", "/", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatal("无身份的日志请求未拒绝", w.Code)
		}
	}
	for _, err := range []error{response.ErrPermission, errors.New("依赖异常")} {
		w := httptest.NewRecorder()
		syslogFailure(w, httptest.NewRequest("GET", "/", nil), err)
		if err == response.ErrPermission && w.Code != 403 || err != response.ErrPermission && w.Code != 503 {
			t.Fatal("权限与存储错误没有区分")
		}
	}
}
