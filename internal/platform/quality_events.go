package platform

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerQualityEvents(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/sensors/quality-events", a.Auth.Require(false, a.qualityEvents))
}
func qualityQuery(r *http.Request) (model.SearchRequest, string, string, string, error) {
	q := model.SearchRequest{Page: 1, PageSize: 20}
	var sensor, registration, kind string
	for k, v := range r.URL.Query() {
		if len(v) != 1 {
			return q, "", "", "", store.ErrConflict
		}
		var err error
		switch k {
		case "start":
			q.Start, err = time.Parse(time.RFC3339Nano, v[0])
		case "end":
			q.End, err = time.Parse(time.RFC3339Nano, v[0])
		case "page":
			q.Page, err = strconv.Atoi(v[0])
			if err == nil && (q.Page < 1 || strconv.Itoa(q.Page) != v[0]) {
				err = store.ErrConflict
			}
		case "sensor_id":
			sensor = v[0]
		case "registration_id":
			registration = v[0]
		case "kind":
			kind = v[0]
		default:
			err = store.ErrConflict
		}
		if err != nil {
			return q, "", "", "", err
		}
	}
	if q.Start.Year() < 2000 || q.Start.Year() > 2100 || q.End.Year() < 2000 || q.End.Year() > 2100 || sensor != "" && !contract.ValidID(sensor) || registration != "" && (!contract.ValidID(registration) || sensor == "") || kind != "" && !slices.Contains([]string{"limitation", "policy", "uncertain", "interval_clear", "observation_resumed"}, kind) {
		return q, "", "", "", store.ErrConflict
	}
	return q, sensor, registration, kind, store.ValidateSearch(&q)
}
func (a *API) qualityEvents(w http.ResponseWriter, r *http.Request) {
	q, sensor, registration, kind, err := qualityQuery(r)
	if err != nil {
		httpapi.Fail(w, r, 400, "invalid_quality_query", "请核对时间窗口、探针、注册代次、事件类型和页码；时间须在 2000—2100 年内，窗口不超过 31 天，每页 20 条，最多检索前 10000 条")
		return
	}
	if a.ES == nil {
		httpapi.Fail(w, r, 503, "quality_unavailable", "质量事件检索服务暂不可用")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	page, err := a.ES.QualityEvents(ctx, httpapi.Principal(r).TenantID, sensor, registration, kind, q)
	if err != nil {
		httpapi.Fail(w, r, 503, "quality_unavailable", "未能完整核对质量事件；本次不提供部分结果，请稍后重试")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.JSON(w, 200, page)
}
