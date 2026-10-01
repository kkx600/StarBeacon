package platform

import (
	"net/http"
	"strconv"
	"time"

	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) auditRecords(w http.ResponseWriter, r *http.Request, category string) {
	now := time.Now().UTC()
	q := store.AuditQuery{Start: now.AddDate(0, 0, -7), End: now, Limit: 50, Cursor: r.URL.Query().Get("cursor"), Action: r.URL.Query().Get("action"), Username: r.URL.Query().Get("username")}
	values := r.URL.Query()
	var e error
	if v := values.Get("start"); v != "" {
		q.Start, e = time.Parse(time.RFC3339Nano, v)
		if e != nil {
			httpapi.Fail(w, r, 400, "invalid_time", "日志开始时间无效")
			return
		}
	}
	if v := values.Get("end"); v != "" {
		q.End, e = time.Parse(time.RFC3339Nano, v)
		if e != nil {
			httpapi.Fail(w, r, 400, "invalid_time", "日志结束时间无效")
			return
		}
	}
	if v := values.Get("limit"); v != "" {
		q.Limit, e = strconv.Atoi(v)
		if e != nil {
			httpapi.Fail(w, r, 400, "invalid_limit", "日志页大小无效")
			return
		}
	}
	if v := values.Get("success"); v != "" {
		if v != "true" && v != "false" {
			httpapi.Fail(w, r, 400, "invalid_result", "登录验证结果筛选无效")
			return
		}
		success := v == "true"
		q.Success = &success
	}
	if e = q.Validate(); e != nil {
		httpapi.Fail(w, r, 400, "invalid_search", e.Error())
		return
	}
	result, e := a.DB.Audits(r.Context(), httpapi.Principal(r).TenantID, category, q)
	if e != nil {
		httpapi.Fail(w, r, 503, "audit_unavailable", "暂时无法读取日志")
		return
	}
	httpapi.JSON(w, 200, result)
}
func (a *API) audits(w http.ResponseWriter, r *http.Request)      { a.auditRecords(w, r, "operations") }
func (a *API) loginAudits(w http.ResponseWriter, r *http.Request) { a.auditRecords(w, r, "logins") }
