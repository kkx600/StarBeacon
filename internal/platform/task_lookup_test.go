package platform

import (
	"net/http/httptest"
	"testing"
)

func TestTaskDetailRejectsInvalidIdentifiersAndQueryConditions(t *testing.T) {
	for _, input := range []struct{ id, query string }{{"", ""}, {"UPPER", ""}, {"bad/id", ""}, {"task_owned", "?sensor_id=other"}, {"task_owned", "?task_id=task_owned"}} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/"+input.query, nil)
		r.SetPathValue("id", input.id)
		(&API{}).task(w, r)
		if w.Code != 400 {
			t.Fatal("详情参数未在访问存储前拒绝", input, w.Code)
		}
	}
}
