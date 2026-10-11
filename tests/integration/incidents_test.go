//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/incident"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestIncidentsRealInvestigationAssignmentClosureAndTenantIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	aTenant, bTenant := store.RandomID("it_case_a_"), store.RandomID("it_case_b_")
	password := store.Token()
	for _, account := range []struct{ tenant, name, role string }{{aTenant, aTenant, "admin"}, {aTenant, aTenant + "_analyst", "admin"}, {aTenant, aTenant + "_viewer", "viewer"}, {bTenant, bTenant, "admin"}} {
		require(t, admin.Bootstrap(ctx, f.Owner, account.tenant, "事件调查验收", account.name, password, account.role))
	}
	u, _, err := f.Runtime.Password(ctx, aTenant)
	require(t, err)
	analyst, _, err := f.Runtime.Password(ctx, aTenant+"_analyst")
	require(t, err)
	foreign, _, err := f.Runtime.Password(ctx, bTenant)
	require(t, err)
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, err)
	require(t, es.EnsurePolicy(ctx))
	// PostgreSQL timestamptz 以微秒保存；目录与 JSON 的夹具时间必须遵循相同精度。
	now := time.Now().UTC().Truncate(time.Microsecond)
	indices := []string{}
	digest := control.Digest([]byte("owned-incident-alert"))
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 8*time.Second)
		defer stop()
		for _, index := range indices {
			r, err := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(clean))
			require(t, err)
			_ = r.Body.Close()
			if r.IsError() {
				t.Errorf("事件验收索引回收失败：%d", r.StatusCode)
			}
		}
	})
	for _, tenant := range []string{aTenant, bTenant} {
		index, indexErr := contract.IndexName(tenant, "alerts", now.Format("2006-01-02"))
		require(t, indexErr)
		require(t, es.EnsureIndex(ctx, index, now.Format("2006-01-02")))
		indices = append(indices, index)
		item := model.Alert{SchemaVersion: "alert.v1", EventID: "event_case_owned", TenantID: tenant, SensorID: "sensor_owned", Timestamp: now, ObservedAt: now, ReceivedAt: now, RawSHA256: digest, Severity: "high"}
		item.Event.Kind = "alert"
		item.Event.Original = `{"owned_original":"must_remain_in_es"}`
		for _, failure := range es.Bulk(ctx, index, []model.Alert{item}) {
			require(t, failure)
		}
		r, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
		require(t, err)
		_ = r.Body.Close()
	}
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, aTenant, password)
	other := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, analyst.Username, password)
	b := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, bTenant, password)
	viewer := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, aTenant+"_viewer", password)
	for _, path := range []string{"/incidents", "/incidents/assignees", "/incidents/incident_missing", "/incidents/incident_missing/history"} {
		viewer.request("GET", path, "", nil, nil, 403)
	}
	viewer.request("POST", "/incidents", "denied", map[string]any{}, nil, 403)
	var assignees struct {
		Items []incident.Assignee `json:"items"`
	}
	a.request("GET", "/incidents/assignees", "", nil, &assignees, 200)
	if len(assignees.Items) != 2 {
		t.Fatal("责任人列表包含只读或其他租户身份", assignees)
	}
	spec := incident.Spec{Title: "授权 HTTP 事件调查", Category: "network_intrusion", Severity: "high", Status: "open", Summary: "核对合法测试流量的检测事实与业务影响。", OwnerID: analyst.ID}
	input := incident.Create{Spec: spec, Alerts: []incident.AlertRef{{EventID: "event_case_owned", SHA256: digest}}}
	var first incident.Record
	a.request("POST", "/incidents", "case_create_owned", input, &first, 200)
	if first.Validate() != nil || first.Revision != 1 || first.OwnerName != analyst.Username || len(first.Alerts) != 1 || first.Alerts[0].SensorID != "sensor_owned" || first.ExpiresAt.Sub(first.RecordedAt) < 179*24*time.Hour {
		t.Fatal("事件、分派、证据或默认留存不完整", first)
	}
	var retried incident.Record
	a.request("POST", "/incidents", "case_create_owned", input, &retried, 200)
	if retried.ID != first.ID || retried.Revision != 1 || !retried.RecordedAt.Equal(first.RecordedAt) {
		t.Fatal("未知结果重试建立了重复事件")
	}
	// 冻结回执确认不再调用 ES；检索依赖退出或源告警到期不应造成重复升级。
	withoutSearch := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, aTenant, password)
	withoutSearch.request("POST", "/incidents", "case_create_owned", input, &retried, 200)
	if retried.ID != first.ID || retried.Revision != 1 {
		t.Fatal("原提交确认依赖再次检索原文")
	}
	withoutSearch.request("POST", "/incidents", "case_search_required", input, nil, 503)
	altered := input
	altered.Spec.Title = "不能用原请求更改事件"
	a.request("POST", "/incidents", "case_create_owned", altered, nil, 409)
	var linked struct {
		ID string `json:"related_incident_id"`
	}
	a.request("POST", "/incidents", "case_duplicate", input, &linked, 409)
	if linked.ID != first.ID {
		t.Fatal("同一告警重复升级没有指向既有调查")
	}
	b.request("GET", "/incidents/"+first.ID, "", nil, nil, 404)
	b.request("GET", "/incidents/"+first.ID+"/history", "", nil, nil, 404)
	var bFirst incident.Record
	bInput := input
	bInput.Spec.OwnerID = foreign.ID
	b.request("POST", "/incidents", "case_foreign", bInput, &bFirst, 200)
	if bFirst.ID == first.ID || bFirst.OwnerName != foreign.Username {
		t.Fatal("不同租户共享了事件身份或责任人")
	}
	bad := input
	bad.Alerts = []incident.AlertRef{{EventID: "event_missing", SHA256: digest}}
	a.request("POST", "/incidents", "case_missing", bad, nil, 404)
	bad.Alerts = []incident.AlertRef{{EventID: "event_case_owned", SHA256: strings.Repeat("b", 64)}}
	a.request("POST", "/incidents", "case_digest_conflict", bad, nil, 409)
	manual := incident.Create{Spec: spec, Alerts: []incident.AlertRef{}}
	manual.Spec.OwnerID = ""
	manual.Spec.Category = "other"
	manual.Spec.Title = "人工线索调查"
	var noAlert incident.Record
	a.request("POST", "/incidents", "case_manual", manual, &noAlert, 200)
	if len(noAlert.Alerts) != 0 {
		t.Fatal("人工线索产生了不存在的告警")
	}
	change := incident.Change{ExpectedRevision: 1, Spec: spec, Note: "责任人开始调查，确认实际告警来源。", AddAlerts: []incident.AlertRef{}}
	change.Spec.Status = "investigating"
	other.request("POST", "/incidents/"+first.ID, "case_investigate", change, &retried, 200)
	if retried.Revision != 2 || retried.ActorID != analyst.ID || retried.Spec.Status != "investigating" || !retried.CreatedAt.Equal(first.CreatedAt) {
		t.Fatal("调查操作缺少版本、操作人或原始创建时间")
	}
	a.request("POST", "/incidents/"+first.ID, "case_stale", change, nil, 409)
	change.ExpectedRevision = 2
	change.Spec.Status = "closed"
	change.Spec.Closure = &incident.Closure{Reason: "resolved", RootCause: "授权回放触发指定路径规则。", Impact: "只涉及专属测试数据，无生产影响。", Remediation: "核对规则和采集范围，恢复实际业务策略。", Verification: "复测请求及持久证据均可回读。", Evidence: []string{"owned:test:replay-result"}}
	change.Note = "记录结构化结案材料和复测依据。"
	a.request("POST", "/incidents/"+first.ID, "case_close", change, &retried, 200)
	if retried.Revision != 3 || retried.Spec.Closure == nil || retried.Spec.Status != "closed" {
		t.Fatal("有依据的结案未持久化")
	}
	var history incident.Page
	a.request("GET", "/incidents/"+first.ID+"/history", "", nil, &history, 200)
	if len(history.Items) != 3 || history.Items[0].Revision != 3 || history.Items[1].Spec.Status != "investigating" || history.Items[2].Spec.Status != "open" {
		t.Fatal("事件时间线覆盖了历史结论", history)
	}
	a.request("GET", "/incidents/"+first.ID+"/history?before=03", "", nil, nil, 400)
	a.request("GET", "/incidents/"+first.ID+"/history?before=2", "", nil, &history, 200)
	if len(history.Items) != 1 || history.Items[0].Revision != 1 {
		t.Fatal("历史续点边界无效")
	}
	change.ExpectedRevision = 3
	change.Spec.Status = "open"
	change.Spec.Closure = nil
	a.request("POST", "/incidents/"+first.ID, "case_bad_reopen", change, nil, 400)
	change.Spec.Status = "investigating"
	change.Note = "发现后续调查材料，重开调查；历史结案保留。"
	a.request("POST", "/incidents/"+first.ID, "case_reopen", change, &retried, 200)
	if retried.Revision != 4 || retried.Spec.Closure != nil {
		t.Fatal("重开调查覆盖了历史或沿用失效结案")
	}
	change.ExpectedRevision = 4
	change.AddAlerts = input.Alerts
	a.request("POST", "/incidents/"+first.ID, "case_duplicate_link", change, nil, 400)
	change.AddAlerts = []incident.AlertRef{}
	change.Spec.OwnerID = foreign.ID
	a.request("POST", "/incidents/"+first.ID, "case_cross_assignment", change, nil, 409)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE users SET active=false WHERE id=$1`, analyst.ID)
	require(t, err)
	change.Spec.OwnerID = analyst.ID
	a.request("POST", "/incidents/"+first.ID, "case_disabled_assignment", change, nil, 409)
	change.Spec.OwnerID = u.ID
	change.Note = "原责任人不可用，由当前值班管理员接管。"
	a.request("POST", "/incidents/"+first.ID, "case_takeover", change, &retried, 200)
	if retried.Revision != 5 || retried.OwnerName != u.Username {
		t.Fatal("责任人停用后的接管失败")
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE retention_policies SET days=9 WHERE tenant_id=$1 AND category='incidents'`, aTenant)
	require(t, err)
	manual.Spec.Title = "自定义留存调查"
	a.request("POST", "/incidents", "case_custom_retention", manual, &noAlert, 200)
	if noAlert.ExpiresAt.Sub(noAlert.RecordedAt) < 8*24*time.Hour || noAlert.ExpiresAt.Sub(noAlert.RecordedAt) > 10*24*time.Hour {
		t.Fatal("用户自定义保留期未生效")
	}
	var page incident.Page
	a.request("GET", "/incidents?status=investigating&severity=high", "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].ID != first.ID {
		t.Fatal("事件筛选没有在数据库正确执行")
	}
	a.request("GET", "/incidents?before="+bFirst.ID, "", nil, nil, 404)
	var raw string
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT string_agg(record::text,'') FROM incident_changes WHERE tenant_id=$1`, aTenant).Scan(&raw))
	if strings.Contains(raw, "must_remain_in_es") || strings.Contains(raw, "event.original") {
		t.Fatal("操作库复制了原始告警内容")
	}
	var facts model.SearchResult
	a.request("POST", "/alerts/search", "", model.SearchRequest{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}, &facts, 200)
	if facts.Total != 1 || facts.Items[0].RawSHA256 != digest || !strings.Contains(facts.Items[0].Event.Original, "must_remain_in_es") {
		t.Fatal("调查修改了原始检测事实")
	}
	_, err = f.Runtime.Pool.Exec(ctx, `UPDATE incident_changes SET record='{}' WHERE tenant_id=$1`, aTenant)
	if err == nil {
		t.Fatal("在线角色可以改写调查历史")
	}
	_, err = f.Runtime.Pool.Exec(ctx, `DELETE FROM incidents WHERE tenant_id=$1 AND id=$2`, aTenant, first.ID)
	if err != nil {
		require(t, err)
	}
	_, err = f.Runtime.Incident(ctx, u, first.ID)
	require(t, err)
	_, err = f.Runtime.ChangeIncident(ctx, analyst, first.ID, "inactive_actor", incident.Change{ExpectedRevision: 5, Spec: retried.Spec, Note: "失效账号不得改变调查", AddAlerts: []incident.AlertRef{}}, nil, "inactive_actor")
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("失效主体仍可提交调查", err)
	}
	var rows int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM incident_changes WHERE tenant_id=$1 AND incident_id=$2`, aTenant, first.ID).Scan(&rows))
	if rows != 5 {
		t.Fatal("拒绝或重试产生了额外调查历史", rows)
	}
	t.Run("active_history_and_expired_closure_cleanup", func(t *testing.T) {
		_, err = f.Owner.Pool.Exec(ctx, `UPDATE incident_changes SET expires_at=now()-interval '1 day' WHERE tenant_id=$1 AND incident_id=$2`, aTenant, first.ID)
		require(t, err)
		_, err = f.Runtime.SweepHistory(ctx)
		require(t, err)
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM incident_changes WHERE tenant_id=$1 AND incident_id=$2`, aTenant, first.ID).Scan(&rows))
		if rows != 5 {
			t.Fatal("未关闭事件的调查依据被提前回收")
		}
		expired := retried
		expired.Spec.Status = "closed"
		expired.Spec.Closure = &incident.Closure{Reason: "false_positive", RootCause: "授权测试", Impact: "专属数据", Remediation: "规则核对", Verification: "完成复测", Evidence: []string{}}
		expired.CreatedAt = now.Add(-12 * 24 * time.Hour)
		expired.RecordedAt = now.Add(-11 * 24 * time.Hour)
		expired.ExpiresAt = now.Add(-time.Hour)
		expiredRaw, _ := json.Marshal(expired)
		_, err = f.Owner.Pool.Exec(ctx, `UPDATE incidents SET state='closed',record=$3,created_at=$4,expires_at=$5 WHERE tenant_id=$1 AND id=$2`, aTenant, first.ID, expiredRaw, expired.CreatedAt, expired.ExpiresAt)
		require(t, err)
		a.request("GET", "/incidents/"+first.ID, "", nil, nil, 404)
		change = incident.Change{ExpectedRevision: 5, Spec: expired.Spec, Note: "到期记录不得重开", AddAlerts: []incident.AlertRef{}}
		a.request("POST", "/incidents/"+first.ID, "expired_case", change, nil, 410)
		for i := 0; i < 3; i++ {
			_, err = f.Runtime.SweepHistory(ctx)
			require(t, err)
		}
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE tenant_id=$1 AND id=$2`, aTenant, first.ID).Scan(&rows))
		if rows != 0 {
			t.Fatal("到期结案没有被实际回收")
		}
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM incident_alert_links WHERE tenant_id=$1 AND incident_id=$2`, aTenant, first.ID).Scan(&rows))
		if rows != 0 {
			t.Fatal("清理后的关联仍占用告警升级")
		}
	})
}
