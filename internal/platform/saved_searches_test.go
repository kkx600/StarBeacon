package platform

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/savedsearch"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestSavedSearchHTTPInputVersionAndUnavailableStorage(t *testing.T) {
	a := &API{}
	good := `{"id":"query_1","expected_revision":0,"expected_generation_id":"","name":"入口","description":"","visibility":"personal","active":true,"definition":{"schema_version":"saved.search.v1","parser_version":"1.0","dataset":"alerts","mode":"visual","window":{"mode":"relative","hours":24},"terms":{}}}`
	for _, body := range []string{"null", "[]", "{}", `{"name":"a","name":"b"}`, good, strings.Replace(good, `"1.0"`, `"2.0"`, 1)} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/v1/saved-searches", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		a.saveSavedSearch(w, r)
		want := 400
		if body == good {
			want = 503
		} else if strings.Contains(body, `"2.0"`) {
			want = 409
		}
		if w.Code != want {
			t.Fatal("错误请求、版本或存储缺失被忽略", w.Code, body)
		}
	}
	for _, url := range []string{"/saved-searches?limit=x", "/saved-searches?limit=0", "/saved-searches?limit=101", "/saved-searches?cursor=a/b", "/saved-searches?dataset=packets", "/saved-searches?visibility=all", "/saved-searches?active=yes", "/saved-searches?keyword=a&keyword=b", "/saved-searches?script=x"} {
		w := httptest.NewRecorder()
		a.savedSearches(w, httptest.NewRequest("GET", url, nil))
		if w.Code != 400 {
			t.Fatal("非法目录条件进入存储", url)
		}
	}
	q, err := savedSearchListQuery(httptest.NewRequest("GET", "/saved-searches?dataset=context&visibility=team&active=false&keyword=office&cursor=query_1&limit=100", nil))
	if err != nil || q.Dataset != "context" || q.Visibility != "team" || q.Active != "false" || q.Cursor != "query_1" || q.Limit != 100 {
		t.Fatal("目录参数未完整读取")
	}
	for _, handler := range []http.HandlerFunc{a.savedSearches, a.savedSearch} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest("GET", "/", nil))
		if w.Code != 503 {
			t.Fatal("未配置存储返回空成功")
		}
	}
	for _, body := range []string{`{"parser_version":"1.0","dataset":"alerts","expected_revision":1,"expected_generation_id":"generation_1"}`, `{}`, `{"parser_version":"2.0"}`, `[]`, `{"script":"run"}`} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		a.resolveSavedSearch(w, r)
		want := 409
		if strings.Contains(body, `"1.0"`) {
			want = 503
		} else if strings.Contains(body, "script") || body == "[]" {
			want = 400
		}
		if w.Code != want {
			t.Fatal("应用查询错误状态不准确", w.Code, body)
		}
	}
}

func TestSavedSearchFailureDoesNotLeakStorageOrQueries(t *testing.T) {
	for _, item := range []struct {
		err    error
		status int
		code   string
	}{{savedsearch.ErrInput, 400, "invalid_saved_search"}, {savedsearch.ErrVersion, 409, "saved_search_version"}, {savedsearch.ErrPermission, 403, "saved_search_forbidden"}, {savedsearch.ErrQuota, 429, "saved_search_quota"}, {savedsearch.ErrInactive, 409, "saved_search_inactive"}, {store.ErrConflict, 409, "saved_search_conflict"}, {pgx.ErrNoRows, 404, "not_found"}, {errors.New("secret query contents"), 503, "saved_search_unavailable"}} {
		w := httptest.NewRecorder()
		savedSearchFailure(w, httptest.NewRequest("GET", "/", nil), item.err)
		var value struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &value)
		if w.Code != item.status || value.Code != item.code || strings.Contains(w.Body.String(), "secret query contents") {
			t.Fatal("错误语义或内部字段泄漏")
		}
	}
}
