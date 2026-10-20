package platform

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/response"
)

func responseCatalogQuery(r *http.Request) (response.CatalogQuery, error) {
	q := response.CatalogQuery{Limit: 20}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return q, response.ErrInput
	}
	for key, v := range values {
		if len(v) != 1 {
			return q, response.ErrInput
		}
		switch key {
		case "start":
			q.Start, err = time.Parse(time.RFC3339Nano, v[0])
			q.Start = q.Start.UTC()
		case "end":
			q.End, err = time.Parse(time.RFC3339Nano, v[0])
			q.End = q.End.UTC()
		case "sensor_id":
			q.SensorID = v[0]
		case "kind":
			q.Kind = v[0]
		case "state":
			q.State = v[0]
		case "target_ip":
			q.TargetIP = v[0]
		case "device_id":
			q.DeviceID = v[0]
		case "cursor":
			q.Cursor = v[0]
		case "limit":
			q.Limit, err = strconv.Atoi(v[0])
			if err == nil && strconv.Itoa(q.Limit) != v[0] {
				err = response.ErrInput
			}
		default:
			return q, response.ErrInput
		}
		if err != nil {
			return q, response.ErrInput
		}
	}
	return q, q.Validate()
}

func responseCatalogFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, response.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_response_query", "请核对时间、探针、目标 IP、设备、任务状态及分页条件；时间窗口最多 31 天")
	case errors.Is(err, response.ErrPermission):
		httpapi.Fail(w, r, 403, "response_catalog_forbidden", "当前账号无权读取响应动作，请核对账号状态与权限")
	default:
		operationError(w, r, err)
	}
}

func responseCatalogReadFailure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, response.ErrPermission) {
		responseCatalogFailure(w, r, err)
		return
	}
	// 来源损坏属于服务端读取失败，不能误报为用户筛选参数错误。
	operationError(w, r, err)
}

func (a *API) responseActions(w http.ResponseWriter, r *http.Request) {
	q, err := responseCatalogQuery(r)
	if err != nil {
		responseCatalogFailure(w, r, err)
		return
	}
	if a.DB == nil {
		operationError(w, r, errors.New("响应动作存储不可用"))
		return
	}
	page, err := a.DB.ResponseActions(r.Context(), httpapi.Principal(r), q)
	if err != nil {
		responseCatalogReadFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, page)
}

func (a *API) responseAction(w http.ResponseWriter, r *http.Request) {
	if !contract.ValidID(r.PathValue("id")) || r.URL.RawQuery != "" {
		responseCatalogFailure(w, r, response.ErrInput)
		return
	}
	if a.DB == nil {
		operationError(w, r, errors.New("响应动作存储不可用"))
		return
	}
	task, err := a.DB.ResponseAction(r.Context(), httpapi.Principal(r), r.PathValue("id"))
	if err != nil {
		responseCatalogReadFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, task)
}
