package platform

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/response"
)

func responseConnectorQuery(r *http.Request) (response.ConnectorQuery, error) {
	q := response.ConnectorQuery{Limit: 20}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return q, response.ErrInput
	}
	for key, v := range values {
		if len(v) != 1 {
			return q, response.ErrInput
		}
		switch key {
		case "sensor_id":
			q.SensorID = v[0]
		case "device_id":
			q.DeviceID = v[0]
		case "status":
			q.Status = v[0]
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

func (a *API) responseConnectors(w http.ResponseWriter, r *http.Request) {
	q, err := responseConnectorQuery(r)
	if err != nil {
		httpapi.Fail(w, r, 400, "invalid_response_connector_query", "请核对探针、设备标识、设备核验状态和分页条件")
		return
	}
	if a.DB == nil {
		operationError(w, r, errors.New("联动设备存储不可用"))
		return
	}
	page, err := a.DB.ResponseConnectors(r.Context(), httpapi.Principal(r), q)
	if errors.Is(err, response.ErrPermission) {
		httpapi.Fail(w, r, 403, "response_connectors_forbidden", "当前账号无权读取联动设备，请核对账号状态与权限")
		return
	}
	if err != nil {
		operationError(w, r, err)
		return
	}
	httpapi.JSON(w, 200, page)
}
