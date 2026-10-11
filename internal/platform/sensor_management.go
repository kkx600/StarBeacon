package platform

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/sensormanagement"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerSensorManagement(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/sensor-groups", a.Auth.Require(false, a.sensorGroups))
	m.HandleFunc("POST /api/v1/sensor-groups", a.Auth.Require(true, a.saveSensorGroup))
	m.HandleFunc("PUT /api/v1/sensors/{id}/metadata", a.Auth.Require(true, a.saveSensorMetadata))
}

func sensorQuery(r *http.Request, groups bool) (sensormanagement.Query, error) {
	q := sensormanagement.Query{Limit: 20}
	values := r.URL.Query()
	for key, v := range values {
		if len(v) != 1 {
			return q, sensormanagement.ErrInput
		}
		switch key {
		case "cursor":
			q.Cursor = v[0]
		case "keyword":
			q.Keyword = v[0]
		case "limit":
			var err error
			q.Limit, err = strconv.Atoi(v[0])
			if err != nil {
				return q, sensormanagement.ErrInput
			}
		case "active":
			q.Active = v[0]
			if !groups {
				return q, sensormanagement.ErrInput
			}
		case "group_id":
			q.GroupID = v[0]
			if groups {
				return q, sensormanagement.ErrInput
			}
		case "status":
			q.Status = v[0]
			if groups {
				return q, sensormanagement.ErrInput
			}
		default:
			return q, sensormanagement.ErrInput
		}
	}
	return q, q.Validate(groups)
}

func sensorManagementFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, sensormanagement.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_sensor_management", "请核对名称、分组、修订和原请求键，且提交实际变更")
	case errors.Is(err, sensormanagement.ErrOccupied):
		httpapi.Fail(w, r, 409, "sensor_group_occupied", "分组仍有探针，请先迁移或移出全部成员后停用")
	case errors.Is(err, sensormanagement.ErrInactive):
		httpapi.Fail(w, r, 409, "sensor_group_inactive", "目标分组已停用，请刷新分组后选择")
	case errors.Is(err, sensormanagement.ErrQuota):
		httpapi.Fail(w, r, 429, "sensor_management_quota", "探针分组或最近 24 小时的管理操作已达上限")
	case errors.Is(err, store.ErrConflict):
		httpapi.Fail(w, r, 409, "sensor_management_conflict", "对象、注册代次、修订或请求输入已变化，或分组名称已占用，请刷新后核对")
	case errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "探针或分组不存在或不可访问")
	default:
		httpapi.Fail(w, r, 503, "sensor_management_unavailable", "探针管理数据服务暂不可用；提交结果未确认时请核对原提交")
	}
}

func (a *API) sensorManagementReady(w http.ResponseWriter, r *http.Request) bool {
	if a.DB != nil {
		return true
	}
	sensorManagementFailure(w, r, errors.New("探针管理存储不可用"))
	return false
}

func (a *API) sensorGroups(w http.ResponseWriter, r *http.Request) {
	q, err := sensorQuery(r, true)
	if err != nil {
		sensorManagementFailure(w, r, err)
		return
	}
	if !a.sensorManagementReady(w, r) {
		return
	}
	result, err := a.DB.SensorGroups(r.Context(), httpapi.Principal(r).TenantID, q)
	if err != nil {
		sensorManagementFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) saveSensorGroup(w http.ResponseWriter, r *http.Request) {
	var c sensormanagement.GroupChange
	if httpapi.Decode(w, r, &c) != nil || c.Validate() != nil {
		sensorManagementFailure(w, r, sensormanagement.ErrInput)
		return
	}
	if !a.sensorManagementReady(w, r) {
		return
	}
	result, err := a.DB.SaveSensorGroup(r.Context(), httpapi.Principal(r), r.Header.Get("Idempotency-Key"), c)
	if err != nil {
		sensorManagementFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) saveSensorMetadata(w http.ResponseWriter, r *http.Request) {
	var c sensormanagement.MetadataChange
	if httpapi.Decode(w, r, &c) != nil || c.Validate() != nil {
		sensorManagementFailure(w, r, sensormanagement.ErrInput)
		return
	}
	if !a.sensorManagementReady(w, r) {
		return
	}
	result, err := a.DB.SaveSensorMetadata(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.Header.Get("Idempotency-Key"), c)
	if err != nil {
		sensorManagementFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}
