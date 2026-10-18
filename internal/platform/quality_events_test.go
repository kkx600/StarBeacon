package platform

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestQualityEventsQueryBoundsAndUnavailableService(t *testing.T) {
	valid := "start=2026-10-18T00:00:00Z&end=2026-10-18T01:00:00Z"
	for _, suffix := range []string{"", "&page=500", "&sensor_id=probe_owned&registration_id=reg_owned&kind=limitation"} {
		q, _, _, _, err := qualityQuery(httptest.NewRequest("GET", "/?"+valid+suffix, nil))
		if err != nil || q.PageSize != 20 {
			t.Fatal(err)
		}
	}
	for _, query := range []string{"", valid + "&page=0", valid + "&page=-1", valid + "&page=501", valid + "&page=01", valid + "&page=1&page=2", valid + "&page=bad", valid + "&tenant_id=other", valid + "&registration_id=reg_owned", valid + "&sensor_id=bad/id", valid + "&sensor_id=probe_owned&registration_id=bad/id", valid + "&kind=safe", strings.Replace(valid, "2026-10-18T00", "1999-10-18T00", 1), strings.Replace(valid, "2026-10-18T01", "2101-10-18T01", 1), strings.Replace(valid, "2026-10-18T01", "2026-11-19T01", 1), strings.Replace(valid, "2026-10-18T00", "not-a-date", 1)} {
		w := httptest.NewRecorder()
		(&API{}).qualityEvents(w, httptest.NewRequest("GET", "/?"+query, nil))
		if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_quality_query") {
			t.Fatal("无效查询进入依赖", query, w.Code)
		}
	}
	w := httptest.NewRecorder()
	(&API{}).qualityEvents(w, httptest.NewRequest("GET", "/?"+valid, nil))
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}
