package platform

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/sensormanagement"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestSensorManagementHTTPInputsAndUnavailableStorage(t *testing.T) {
	a := &API{}
	for _, item := range []struct {
		handler http.HandlerFunc
		body    string
	}{{a.saveSensorGroup, `{"id":"sg_owned","expected_revision":0,"name":"办公","description":"","active":true}`}, {a.saveSensorMetadata, `{"expected_revision":1,"registration_id":"reg_owned","name":"探针","group_id":"","site":"","description":""}`}} {
		for _, body := range []string{"null", "[]", "{}", `{"name":"a","name":"b"}`, `{"unexpected":true}`, item.body} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/api/v1/sensor-groups", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			item.handler(w, r)
			want := 400
			if body == item.body {
				want = 503
			}
			if w.Code != want {
				t.Fatal("无效参数或缺失存储被忽略", w.Code)
			}
		}
	}
	for _, target := range []string{"/sensors?limit=x", "/sensors?limit=0", "/sensors?limit=101", "/sensors?cursor=a/b", "/sensors?status=active", "/sensors?active=true", "/sensors?unknown=x", "/sensors?keyword=a&keyword=b"} {
		w := httptest.NewRecorder()
		a.sensors(w, httptest.NewRequest("GET", target, nil))
		if w.Code != 400 {
			t.Fatal("非法探针条件进入存储")
		}
	}
	for _, target := range []string{"/sensor-groups?group_id=x", "/sensor-groups?status=online", "/sensor-groups?active=yes"} {
		w := httptest.NewRecorder()
		a.sensorGroups(w, httptest.NewRequest("GET", target, nil))
		if w.Code != 400 {
			t.Fatal("非法分组条件进入存储")
		}
	}
	for _, handler := range []http.HandlerFunc{a.sensors, a.sensorGroups} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest("GET", "/", nil))
		if w.Code != 503 {
			t.Fatal("未配置存储返回空成功")
		}
	}
	for _, target := range []struct {
		url    string
		groups bool
	}{{"/sensors?cursor=probe_owned&keyword=office&limit=10&group_id=sg_owned&status=offline", false}, {"/sensor-groups?cursor=sg_owned&keyword=office&limit=100&active=false", true}} {
		q, err := sensorQuery(httptest.NewRequest("GET", target.url, nil), target.groups)
		if err != nil || q.Keyword != "office" || q.Cursor == "" {
			t.Fatal("合法条件未能解析")
		}
	}
}

func TestSensorManagementFailureMeaningDoesNotLeakInternals(t *testing.T) {
	for _, item := range []struct {
		err    error
		status int
		code   string
	}{{sensormanagement.ErrInput, 400, "invalid_sensor_management"}, {sensormanagement.ErrOccupied, 409, "sensor_group_occupied"}, {sensormanagement.ErrInactive, 409, "sensor_group_inactive"}, {sensormanagement.ErrQuota, 429, "sensor_management_quota"}, {store.ErrConflict, 409, "sensor_management_conflict"}, {pgx.ErrNoRows, 404, "not_found"}, {errors.New("private database detail"), 503, "sensor_management_unavailable"}} {
		w := httptest.NewRecorder()
		sensorManagementFailure(w, httptest.NewRequest("GET", "/", nil), item.err)
		var value struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &value)
		if w.Code != item.status || value.Code != item.code || strings.Contains(w.Body.String(), "private database detail") {
			t.Fatal("错误含义或敏感内部信息泄漏")
		}
	}
}
