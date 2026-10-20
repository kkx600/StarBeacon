package platform

import (
	"errors"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/response"
)

func catalogQueryURL() string {
	end := time.Now().UTC()
	return "/?" + url.Values{"start": {end.Add(-time.Hour).Format(time.RFC3339Nano)}, "end": {end.Format(time.RFC3339Nano)}}.Encode()
}

func TestResponseCatalogQueryAndUnavailableStorage(t *testing.T) {
	base := catalogQueryURL()
	for _, extra := range []string{"&limit=01", "&limit=abc", "&limit=0", "&limit=101", "&start=bad", "&end=bad", "&unknown=x", "&state=queued&state=failed", "&target_ip=10.0.0.0/8", "&cursor=bad", "&keyword=%zz", "&start=", "&state=queued%7Cdelivered"} {
		w := httptest.NewRecorder()
		(&API{}).responseActions(w, httptest.NewRequest("GET", base+extra, nil))
		if w.Code != 400 {
			t.Fatal("筛选未在存储前拒绝", extra, w.Code)
		}
	}
	for _, extra := range []string{"", "&sensor_id=sensor_ok&device_id=device_ok&kind=response.block&state=unknown&target_ip=10.20.2.10&limit=100"} {
		r := httptest.NewRequest("GET", base+extra, nil)
		q, err := responseCatalogQuery(r)
		if err != nil || q.Validate() != nil {
			t.Fatal("合法查询失败", err)
		}
		w := httptest.NewRecorder()
		(&API{}).responseActions(w, r)
		if w.Code != 503 {
			t.Fatal("存储未就绪被伪装为空结果", w.Code)
		}
	}
	for _, test := range []struct {
		id, query string
		status    int
	}{{"UPPER", "", 400}, {"task_ok", "?extra=x", 400}, {"task_ok", "", 503}} {
		r := httptest.NewRequest("GET", "/"+test.query, nil)
		r.SetPathValue("id", test.id)
		w := httptest.NewRecorder()
		(&API{}).responseAction(w, r)
		if w.Code != test.status {
			t.Fatal(test, w.Code)
		}
	}
	for _, test := range []struct {
		err    error
		status int
	}{{response.ErrPermission, 403}, {response.ErrInput, 503}, {errors.New("read"), 503}} {
		w := httptest.NewRecorder()
		responseCatalogReadFailure(w, httptest.NewRequest("GET", "/", nil), test.err)
		if w.Code != test.status {
			t.Fatal(test, w.Code)
		}
	}
}
