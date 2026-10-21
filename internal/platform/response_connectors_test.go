package platform

import (
	"net/http/httptest"
	"testing"
)

func TestResponseConnectorQueryAndDependency(t *testing.T) {
	for _, query := range []string{"?limit=01", "?limit=bad", "?limit=0", "?limit=101", "?sensor_id=UPPER", "?device_id=a/b", "?status=online", "?cursor=bad", "?origin=https://example.test", "?limit=20&limit=30", "?device_id=%zz"} {
		w := httptest.NewRecorder()
		(&API{}).responseConnectors(w, httptest.NewRequest("GET", "/"+query, nil))
		if w.Code != 400 {
			t.Fatal(query, w.Code)
		}
	}
	for _, query := range []string{"", "?sensor_id=sensor_ok&device_id=device_ok&status=ready&limit=100", "?status=unverified", "?status=unavailable"} {
		r := httptest.NewRequest("GET", "/"+query, nil)
		q, err := responseConnectorQuery(r)
		if err != nil || q.Validate() != nil {
			t.Fatal(query, err)
		}
		w := httptest.NewRecorder()
		(&API{}).responseConnectors(w, r)
		if w.Code != 503 {
			t.Fatal("依赖缺失伪装为空目录", w.Code)
		}
	}
}
