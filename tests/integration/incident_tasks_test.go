//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/incident"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestIncidentTasksRealAssignmentIdempotencyClosureAndIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant, foreignTenant, password := store.RandomID("it_tasks_"), store.RandomID("it_tasks_b_"), store.Token()
	for _, account := range []struct{ tenant, name, role string }{{tenant, tenant, "admin"}, {tenant, tenant + "_worker", "admin"}, {tenant, tenant + "_viewer", "viewer"}, {foreignTenant, foreignTenant, "admin"}} {
		require(t, admin.Bootstrap(ctx, f.Owner, account.tenant, "协作任务验收", account.name, password, account.role))
	}
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	worker, _, err := f.Runtime.Password(ctx, tenant+"_worker")
	require(t, err)
	foreign, _, err := f.Runtime.Password(ctx, foreignTenant)
	require(t, err)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, tenant, password)
	b := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, foreignTenant, password)
	viewer := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, tenant+"_viewer", password)
	manual := incident.Create{Spec: incident.Spec{Title: "授权隔离环境调查", Category: "network_intrusion", Status: "open", Severity: "high", Summary: "核对实际检测事实与人工任务。", OwnerID: u.ID}, Alerts: []incident.AlertRef{}}
	var parent, other incident.Record
	a.request("POST", "/incidents", "tasks_parent", manual, &parent, 200)
	a.request("POST", "/incidents", "tasks_other", manual, &other, 200)
	root := "/incidents/" + parent.ID + "/tasks"
	for _, suffix := range []string{"", "/case_task_missing", "/case_task_missing/history"} {
		viewer.request("GET", root+suffix, "", nil, nil, 403)
		b.request("GET", root+suffix, "", nil, nil, 404)
	}
	due := time.Now().UTC().Add(time.Hour).Truncate(time.Nanosecond)
	input := incident.TaskCreate{IncidentRevision: parent.Revision, Spec: incident.TaskSpec{Title: "核对原始请求", Description: "读取保留中的请求与返回，记录核对依据。", Status: "open", Priority: "high", AssigneeID: worker.ID, DueAt: &due}}
	viewer.request("POST", root, "tasks_denied", input, nil, 403)
	b.request("POST", root, "tasks_foreign", input, nil, 404)
	// 审计不可写时任务和原请求历史必须一起回滚，不能留下半份协作记录。
	_, err = f.Owner.Pool.Exec(ctx, `REVOKE INSERT ON operation_audits FROM starbeacon_app`)
	require(t, err)
	a.request("POST", root, "tasks_audit_failure", input, nil, 503)
	var rolledBack int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM incident_tasks WHERE tenant_id=$1)+(SELECT count(*) FROM incident_task_changes WHERE tenant_id=$1)`, tenant).Scan(&rolledBack))
	if rolledBack != 0 {
		t.Fatal("审计失败留下了任务或原提交历史")
	}
	_, err = f.Owner.Pool.Exec(ctx, `GRANT INSERT ON operation_audits TO starbeacon_app`)
	require(t, err)
	var first, retry incident.TaskRecord
	a.request("POST", root, "tasks_create", input, &first, 200)
	if first.Validate() != nil || first.Revision != 1 || first.ActorID != u.ID || first.AssigneeName != worker.Username || !first.Spec.DueAt.Equal(due) || first.ExpiresAt.Sub(first.RecordedAt) < 179*24*time.Hour {
		t.Fatal("任务身份、精度或默认留存不完整", first)
	}
	a.request("POST", root, "tasks_create", input, &retry, 200)
	if retry.ID != first.ID || !retry.RecordedAt.Equal(first.RecordedAt) {
		t.Fatal("原提交重试产生重复任务或续期")
	}
	// 同一瞬时的时区表达属于相同输入，仍返回原始 UTC 回执。
	offset := due.In(time.FixedZone("owned", 8*3600))
	zoneInput := input
	zoneInput.Spec.DueAt = &offset
	a.request("POST", root, "tasks_create", zoneInput, &retry, 200)
	changedInput := input
	changedInput.Spec.Title = "其他工作"
	a.request("POST", root, "tasks_create", changedInput, nil, 409)
	badOwner := input
	badOwner.Spec.AssigneeID = foreign.ID
	a.request("POST", root, "tasks_bad_owner", badOwner, nil, 409)
	stale := input
	stale.IncidentRevision++
	a.request("POST", root, "tasks_stale_parent", stale, nil, 409)
	a.request("GET", "/incidents/"+other.ID+"/tasks/"+first.ID, "", nil, nil, 404)
	a.request("GET", "/incidents/"+other.ID+"/tasks?before="+first.ID, "", nil, nil, 404)
	a.request("POST", "/incidents/"+other.ID+"/tasks", "tasks_create", input, nil, 409)
	closure := manual.Spec
	closure.Status = "closed"
	closure.Closure = &incident.Closure{Reason: "false_positive", RootCause: "授权验证", Impact: "隔离环境", Remediation: "核对规则", Verification: "已核对测试事实", Evidence: []string{}}
	closeInput := incident.Change{ExpectedRevision: parent.Revision, Spec: closure, Note: "尝试结案", AddAlerts: []incident.AlertRef{}}
	a.request("POST", "/incidents/"+parent.ID, "tasks_pending_case", closeInput, nil, 409)
	change := incident.TaskChange{IncidentRevision: parent.Revision, ExpectedRevision: first.Revision, Spec: first.Spec, Note: "已分派并开始核对"}
	change.Spec.Status = "in_progress"
	a.request("POST", root+"/"+first.ID, "tasks_start", change, &retry, 200)
	if retry.Revision != 2 || retry.Spec.Status != "in_progress" || !retry.CreatedAt.Equal(first.CreatedAt) {
		t.Fatal("任务状态或稳定创建时间错误", retry)
	}
	a.request("POST", root+"/"+first.ID, "tasks_stale", change, nil, 409)
	change.ExpectedRevision, change.Spec.Status, change.Spec.Resolution = retry.Revision, "completed", "已核对原包和重放记录，材料引用 owned:inspection。"
	a.request("POST", root+"/"+first.ID, "tasks_complete", change, &retry, 200)
	var detail incident.TaskRecord
	a.request("GET", root+"/"+first.ID, "", nil, &detail, 200)
	if detail.Revision != 3 || detail.Spec.Resolution != change.Spec.Resolution {
		t.Fatal("任务详情没有返回完成依据")
	}
	var history incident.TaskPage
	a.request("GET", root+"/"+first.ID+"/history", "", nil, &history, 200)
	if len(history.Items) != 3 || history.Items[0].Revision != 3 || history.Items[2].Revision != 1 || history.Next != "" {
		t.Fatal("独立任务历史丢失或顺序错误", history)
	}
	a.request("GET", root+"/"+first.ID+"/history?before=2", "", nil, &history, 200)
	if len(history.Items) != 1 || history.Items[0].Revision != 1 {
		t.Fatal("任务历史续点错误")
	}
	a.request("GET", root+"?status=completed", "", nil, &history, 200)
	if len(history.Items) != 1 || history.Items[0].ID != first.ID {
		t.Fatal("任务状态筛选错误")
	}
	var closed incident.Record
	a.request("POST", "/incidents/"+parent.ID, "tasks_close_case", closeInput, &closed, 200)
	a.request("POST", root, "tasks_create", input, &retry, 200)
	a.request("POST", root+"/"+first.ID, "tasks_complete", change, &retry, 200)
	a.request("POST", root, "tasks_closed_create", input, nil, 409)
	change.ExpectedRevision = 3
	a.request("POST", root+"/"+first.ID, "tasks_closed_change", change, nil, 409)
	var reopened incident.Record
	a.request("POST", "/incidents/"+parent.ID, "tasks_reopen_case", incident.Change{ExpectedRevision: closed.Revision, Spec: incident.Spec{Title: manual.Spec.Title, Category: manual.Spec.Category, Status: "investigating", Severity: "high", Summary: manual.Spec.Summary, OwnerID: u.ID}, Note: "继续核对任务", AddAlerts: []incident.AlertRef{}}, &reopened, 200)
	change.IncidentRevision, change.Spec.Status, change.Spec.Resolution = reopened.Revision, "open", ""
	a.request("POST", root+"/"+first.ID, "tasks_reopen_task", change, &retry, 200)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE users SET active=false WHERE tenant_id=$1 AND id=$2`, tenant, worker.ID)
	require(t, err)
	change.ExpectedRevision, change.Spec.Status, change.Spec.Resolution = retry.Revision, "cancelled", "责任人已离岗，核对后取消此项工作。"
	a.request("POST", root+"/"+first.ID, "tasks_cancel_inactive", change, &retry, 200)
	if retry.AssigneeName != worker.Username {
		t.Fatal("取消任务丢失历史负责人")
	}
	input.Spec.AssigneeID = worker.ID
	a.request("POST", root, "tasks_inactive_owner", input, nil, 409) // 事件修订先于身份校验。
	input.IncidentRevision = reopened.Revision
	a.request("POST", root, "tasks_inactive_owner_current", input, nil, 409)
	_, err = f.Runtime.Pool.Exec(ctx, `UPDATE incident_task_changes SET record='{}' WHERE tenant_id=$1`, tenant)
	if err == nil {
		t.Fatal("运行账号可以改写任务历史")
	}
	require(t, f.Runtime.TenantTx(ctx, foreignTenant, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM incident_tasks WHERE tenant_id=$1`, tenant).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatal("RLS 泄露其他租户任务")
		}
		return nil
	}))
	_, err = f.Runtime.CreateIncidentTask(ctx, model.Principal{ID: worker.ID, TenantID: tenant, Role: "admin"}, parent.ID, "inactive_task_actor", input, "owned_task_audit")
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("失效主体仍可建立任务", err)
	}
	var audits, revisions int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action LIKE 'incidents.tasks.%'`, tenant).Scan(&audits))
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM incident_task_changes WHERE tenant_id=$1`, tenant).Scan(&revisions))
	if audits != 5 || revisions != 5 {
		t.Fatal("重试或拒绝产生额外历史／审计，或实际变更漏记", audits, revisions)
	}
	t.Log("真实 PostgreSQL／HTTP：任务分派、纳秒截止、原提交确认、修订冲突、结案互斥、重开、失效负责人取消、租户隔离与原子历史审计通过。")
}

func TestIncidentTasksRealPaginationQuotasAndProtectedRetention(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant := store.RandomID("it_task_budget_")
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "协作任务预算验收", tenant, store.Token(), "admin"))
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	parent, err := f.Runtime.CreateIncident(ctx, u, "budget_case", incident.Create{Spec: incident.Spec{Title: "任务预算与回收", Category: "other", Status: "open", Severity: "medium", Summary: "验证任务留存和预算。", OwnerID: u.ID}, Alerts: []incident.AlertRef{}}, nil, "owned_tasks")
	require(t, err)
	input := incident.TaskCreate{IncidentRevision: 1, Spec: incident.TaskSpec{Title: "核对线索", Description: "核对隔离环境材料。", Status: "open", Priority: "medium", AssigneeID: u.ID}}
	var first incident.TaskRecord
	for i := 0; i < 22; i++ {
		record, err := f.Runtime.CreateIncidentTask(ctx, u, parent.ID, fmt.Sprintf("budget_task_%d", i), input, "owned_tasks")
		require(t, err)
		if i == 0 {
			first = record
		}
	}
	page, err := f.Runtime.IncidentTasks(ctx, u, parent.ID, incident.TaskQuery{})
	require(t, err)
	if len(page.Items) != 20 || page.Next != page.Items[19].ID {
		t.Fatal("第一页没有真实续点")
	}
	second, err := f.Runtime.IncidentTasks(ctx, u, parent.ID, incident.TaskQuery{Before: page.Next})
	require(t, err)
	if len(second.Items) != 2 || second.Next != "" || second.Items[1].ID != first.ID {
		t.Fatal("第二页丢失或重复任务")
	}
	for i := 1; i <= 22; i++ {
		_, err = f.Runtime.ChangeIncidentTask(ctx, u, parent.ID, first.ID, fmt.Sprintf("history_%d", i), incident.TaskChange{IncidentRevision: 1, ExpectedRevision: int64(i), Spec: input.Spec, Note: "保留独立进展"}, "owned_tasks")
		require(t, err)
	}
	history, err := f.Runtime.IncidentTaskHistory(ctx, u, parent.ID, first.ID, "")
	require(t, err)
	if len(history.Items) != 20 || history.Next != "4" || history.Items[0].Revision != 23 {
		t.Fatal("历史分页不稳定", history.Next)
	}
	history, err = f.Runtime.IncidentTaskHistory(ctx, u, parent.ID, first.ID, history.Next)
	require(t, err)
	if len(history.Items) != 3 || history.Next != "" {
		t.Fatal("历史尾页丢失")
	}
	// 配额夹具在专属数据库直接构造计数，不调用实际任务执行或外部设备。
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO incident_tasks SELECT tenant_id,incident_id,'quota_'||n,revision,state,record,created_at,expires_at FROM incident_tasks CROSS JOIN generate_series(1,106) n WHERE tenant_id=$1 AND id=$2`, tenant, first.ID)
	require(t, err)
	_, err = f.Runtime.CreateIncidentTask(ctx, u, parent.ID, "over_case_quota", input, "owned_tasks")
	if !errors.Is(err, store.ErrIncidentTaskQuota) {
		t.Fatal("每事件 128 项预算未生效", err)
	}
	_, err = f.Owner.Pool.Exec(ctx, `DELETE FROM incident_tasks WHERE tenant_id=$1 AND id LIKE 'quota_%'`, tenant)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO incident_task_changes SELECT tenant_id,incident_id,task_id,n,created_by,'change','quota_'||n,input_hash,record,created_at,expires_at FROM incident_task_changes CROSS JOIN generate_series(24,1000) n WHERE tenant_id=$1 AND task_id=$2 AND revision=1`, tenant, first.ID)
	require(t, err)
	var raw []byte
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT record FROM incident_tasks WHERE tenant_id=$1 AND id=$2`, tenant, first.ID).Scan(&raw))
	var atLimit incident.TaskRecord
	require(t, json.Unmarshal(raw, &atLimit))
	atLimit.Revision = 1000
	raw, _ = json.Marshal(atLimit)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE incident_tasks SET revision=1000,record=$3 WHERE tenant_id=$1 AND id=$2`, tenant, first.ID, raw)
	require(t, err)
	_, err = f.Runtime.ChangeIncidentTask(ctx, u, parent.ID, first.ID, "over_revision_quota", incident.TaskChange{IncidentRevision: 1, ExpectedRevision: 1000, Spec: input.Spec, Note: "不能超过预算"}, "owned_tasks")
	if !errors.Is(err, store.ErrIncidentTaskQuota) {
		t.Fatal("单任务修订预算未生效", err)
	}
	// 日预算在真实历史表计数；已有同键回执应仍能确认，不额外消耗额度。
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO incident_task_changes SELECT c.tenant_id,c.incident_id,c.task_id,n,c.created_by,'change','daily_'||c.task_id||n,c.input_hash,c.record,c.created_at,c.expires_at FROM incident_task_changes c CROSS JOIN generate_series(24,823) n WHERE c.tenant_id=$1 AND c.revision=1 AND c.task_id IN(SELECT id FROM incident_tasks WHERE tenant_id=$1 AND id<>$2 ORDER BY id LIMIT 4)`, tenant, first.ID)
	require(t, err)
	_, err = f.Runtime.CreateIncidentTask(ctx, u, parent.ID, "over_daily_quota", input, "owned_tasks")
	if !errors.Is(err, store.ErrIncidentTaskQuota) {
		t.Fatal("UTC 日任务变更预算未生效", err)
	}
	_, err = f.Runtime.CreateIncidentTask(ctx, u, parent.ID, "budget_task_0", input, "owned_tasks")
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `DELETE FROM incident_task_changes WHERE tenant_id=$1 AND idempotency_key_hash LIKE 'daily_%'`, tenant)
	require(t, err)
	other, err := f.Runtime.CreateIncident(ctx, u, "other_budget_case", incident.Create{Spec: parent.Spec, Alerts: []incident.AlertRef{}}, nil, "owned_tasks")
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO incident_tasks SELECT tenant_id,$3,'tenant_quota_'||n,revision,state,record,created_at,expires_at FROM incident_tasks CROSS JOIN generate_series(1,9978) n WHERE tenant_id=$1 AND id=$2`, tenant, first.ID, other.ID)
	require(t, err)
	_, err = f.Runtime.CreateIncidentTask(ctx, u, parent.ID, "over_tenant_quota", input, "owned_tasks")
	if !errors.Is(err, store.ErrIncidentTaskQuota) {
		t.Fatal("租户任务总量预算未生效", err)
	}
	_, err = f.Owner.Pool.Exec(ctx, `DELETE FROM incident_tasks WHERE tenant_id=$1 AND id LIKE 'tenant_quota_%'`, tenant)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `DELETE FROM incident_changes WHERE tenant_id=$1 AND incident_id=$2`, tenant, other.ID)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `DELETE FROM incidents WHERE tenant_id=$1 AND id=$2`, tenant, other.ID)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE retention_policies SET days=9 WHERE tenant_id=$1 AND category='incidents'`, tenant)
	require(t, err)
	custom, err := f.Runtime.CreateIncidentTask(ctx, u, parent.ID, "custom_task_retention", input, "owned_tasks")
	require(t, err)
	if custom.ExpiresAt.Sub(custom.RecordedAt) < 8*24*time.Hour || custom.ExpiresAt.Sub(custom.RecordedAt) > 10*24*time.Hour {
		t.Fatal("自定义保留期没有固化到任务")
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE incident_task_changes SET expires_at=now()-interval '1 day' WHERE tenant_id=$1`, tenant)
	require(t, err)
	_, err = f.Runtime.SweepHistory(ctx)
	require(t, err)
	var count int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM incident_task_changes WHERE tenant_id=$1`, tenant).Scan(&count))
	if count != 1022 { // 22 次创建、22 次进展、977 条限额夹具、1 次自定义留存。
		t.Fatal("未关闭事件的任务历史被提前回收", count)
	}
	// 仅改变专属到期夹具，不改变服务器时钟；实际清理仍通过受限运行账号执行。
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE incidents SET state='closed',expires_at=now()-interval '1 day' WHERE tenant_id=$1;`, tenant)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE incident_changes SET expires_at=now()-interval '1 day' WHERE tenant_id=$1`, tenant)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE incident_tasks SET state='cancelled',expires_at=now()-interval '1 day' WHERE tenant_id=$1`, tenant)
	require(t, err)
	for i := 0; i < 8; i++ {
		_, err = f.Runtime.SweepHistory(ctx)
		require(t, err)
	}
	for _, table := range []string{"incident_task_changes", "incident_tasks", "incident_changes", "incidents"} {
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE tenant_id=$1`, tenant).Scan(&count))
		if count != 0 {
			t.Fatalf("%s 的到期记录未按子表先行回收：%d", table, count)
		}
	}
}
