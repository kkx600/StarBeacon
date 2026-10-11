package platform

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

func TestOverviewRejectsInvalidWindowAndUnavailableDependencies(t *testing.T) {
	api := &API{}
	for _, item := range []struct {
		body   string
		status int
	}{
		{`{}`, 400}, {`{"start":"invalid","end":"invalid"}`, 400}, {`{"start":"2026-10-02T00:00:00Z","end":"2026-10-02T00:00:00Z"}`, 400}, {`{"start":"2026-10-02T00:00:00Z","end":"2026-11-03T00:00:00Z"}`, 400}, {`{"start":"2026-10-02T00:00:00Z","end":"2026-10-03T00:00:00Z","tenant_id":"other"}`, 400}, {`{"start":"2026-10-02T00:00:00Z","end":"2026-10-03T00:00:00Z"}`, 503},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/v1/overview", bytes.NewBufferString(item.body))
		r.Header.Set("Content-Type", "application/json")
		api.overview(w, r)
		if w.Code != item.status {
			t.Fatalf("统计参数／依赖边界：%d %s", w.Code, w.Body.String())
		}
	}
}
