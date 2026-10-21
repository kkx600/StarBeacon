package platform

import (
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/syslogdata"
)

func syslogSourceQuery(r *http.Request) (syslogdata.SourceQuery, error) {
	q := syslogdata.SourceQuery{Limit: 20}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return q, syslogdata.ErrInput
	}
	for key, v := range values {
		if len(v) != 1 {
			return q, syslogdata.ErrInput
		}
		switch key {
		case "sensor_id":
			q.SensorID = v[0]
		case "source_id":
			q.SourceID = v[0]
		case "cursor":
			q.Cursor = v[0]
		case "limit":
			q.Limit, err = strconv.Atoi(v[0])
			if err != nil || strconv.Itoa(q.Limit) != v[0] {
				return q, syslogdata.ErrInput
			}
		default:
			return q, syslogdata.ErrInput
		}
	}
	return q, q.Validate()
}
func (a *API) registerSyslog(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/syslog/sources", a.Auth.Require(true, a.syslogSources))
	m.HandleFunc("POST /api/v1/logs/search", a.Auth.Require(true, a.searchLogs))
	m.HandleFunc("GET /api/v1/logs/{id}", a.Auth.Require(true, a.logDetail))
}
func (a *API) syslogSources(w http.ResponseWriter, r *http.Request) {
	q, err := syslogSourceQuery(r)
	if err != nil {
		httpapi.Fail(w, r, 400, "invalid_syslog_query", "请核对探针、来源和分页条件")
		return
	}
	if a.DB == nil {
		operationError(w, r, errors.New("日志来源目录不可用"))
		return
	}
	result, err := a.DB.SyslogSources(r.Context(), httpapi.Principal(r), q)
	if err != nil {
		syslogFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}
func (a *API) searchLogs(w http.ResponseWriter, r *http.Request) {
	var q syslogdata.SearchQuery
	u := httpapi.Principal(r)
	if httpapi.Decode(w, r, &q) != nil || q.Validate(u.TenantID) != nil {
		httpapi.Fail(w, r, 400, "invalid_log_query", "请核对时间范围（最多 31 天）、来源、正文和分页条件")
		return
	}
	if a.DB == nil || a.ES == nil {
		operationError(w, r, errors.New("日志检索不可用"))
		return
	}
	if err := a.DB.AuthorizeSyslog(r.Context(), u, "", ""); err != nil {
		syslogFailure(w, r, err)
		return
	}
	result, err := a.ES.SearchLogs(r.Context(), u.TenantID, q)
	if err != nil {
		syslogFailure(w, r, err)
		return
	}
	if err = a.DB.AuthorizeSyslog(r.Context(), u, "", ""); err != nil {
		syslogFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}
func (a *API) logDetail(w http.ResponseWriter, r *http.Request) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	partition := values.Get("partition")
	day, dateErr := time.Parse("2006-01-02", partition)
	id := r.PathValue("id")
	_, hashErr := hex.DecodeString(id)
	if err != nil || dateErr != nil || day.Format("2006-01-02") != partition || len(values) != 1 || len(values["partition"]) != 1 || len(id) != 64 || hashErr != nil {
		httpapi.Fail(w, r, 400, "invalid_log_detail", "日志标识或日期分区无效")
		return
	}
	if a.DB == nil || a.ES == nil {
		operationError(w, r, errors.New("日志原文不可用"))
		return
	}
	u := httpapi.Principal(r)
	if err := a.DB.AuthorizeSyslog(r.Context(), u, "", ""); err != nil {
		syslogFailure(w, r, err)
		return
	}
	result, err := a.ES.LogDetail(r.Context(), u.TenantID, partition, id)
	if errors.Is(err, pgx.ErrNoRows) {
		httpapi.Fail(w, r, 404, "log_not_found", "日志不存在、已到期或不可访问")
		return
	}
	if err != nil {
		syslogFailure(w, r, err)
		return
	}
	if err = a.DB.AuthorizeSyslog(r.Context(), u, id, httpapi.RequestID(r)); err != nil {
		syslogFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}
func syslogFailure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, response.ErrPermission) {
		httpapi.Fail(w, r, 403, "logs_forbidden", "当前账号无权读取安全日志，请核对账号状态与权限")
		return
	}
	operationError(w, r, err)
}
