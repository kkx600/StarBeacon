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
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestIncidentNotesRealAuthorCASIdempotencyAndClosedReadOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant, otherTenant, password := store.RandomID("it_notes_"), store.RandomID("it_notes_b_"), store.Token()
	for _, v := range []struct{ tenant, name, role string }{{tenant, tenant, "admin"}, {tenant, tenant + "_other", "admin"}, {tenant, tenant + "_viewer", "viewer"}, {otherTenant, otherTenant, "admin"}} {
		require(t, admin.Bootstrap(ctx, f.Owner, v.tenant, "调查笔记验收", v.name, password, v.role))
	}
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, tenant, password)
	b := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, otherTenant, password)
	c := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, tenant+"_other", password)
	viewer := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, tenant+"_viewer", password)
	create := incident.Create{Spec: incident.Spec{Title: "原始材料调查", Category: "other", Severity: "medium", Status: "open", Summary: "保留可复核的独立笔记。", OwnerID: u.ID}, Alerts: []incident.AlertRef{}}
	var parent, other incident.Record
	a.request("POST", "/incidents", "notes_parent", create, &parent, 200)
	a.request("POST", "/incidents", "notes_other", create, &other, 200)
	root := "/incidents/" + parent.ID + "/notes"
	input := incident.NoteCreate{IncidentRevision: parent.Revision, Spec: incident.NoteSpec{Title: "检查来源", Body: "查看实际会话材料，保留缺测说明。", Status: "active"}}
	for _, suffix := range []string{"", "/case_note_missing", "/case_note_missing/history"} {
		viewer.request("GET", root+suffix, "", nil, nil, 403)
		b.request("GET", root+suffix, "", nil, nil, 404)
	}
	viewer.request("POST", root, "notes_denied", input, nil, 403)
	_, err = f.Owner.Pool.Exec(ctx, `REVOKE INSERT ON operation_audits FROM starbeacon_app`)
	require(t, err)
	a.request("POST", root, "notes_audit_failure", input, nil, 503)
	var count int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM incident_notes WHERE tenant_id=$1)+(SELECT count(*) FROM incident_note_changes WHERE tenant_id=$1)`, tenant).Scan(&count))
	if count != 0 {
		t.Fatal("审计失败留下半份笔记")
	}
	_, err = f.Owner.Pool.Exec(ctx, `GRANT INSERT ON operation_audits TO starbeacon_app`)
	require(t, err)
	var first, retry incident.NoteRecord
	a.request("POST", root, "notes_create", input, &first, 200)
	if first.Validate() != nil || first.AuthorID != u.ID || first.ActorID != u.ID || first.Revision != 1 || first.ExpiresAt.Sub(first.RecordedAt) < 179*24*time.Hour {
		t.Fatal("笔记身份、修订或默认期限错误", first)
	}
	a.request("POST", root, "notes_create", input, &retry, 200)
	if retry.ID != first.ID || !retry.RecordedAt.Equal(first.RecordedAt) {
		t.Fatal("同键确认产生重复或续期")
	}
	changed := input
	changed.Spec.Body = "另一份材料"
	a.request("POST", root, "notes_create", changed, nil, 409)
	a.request("GET", "/incidents/"+other.ID+"/notes/"+first.ID, "", nil, nil, 404)
	a.request("GET", "/incidents/"+other.ID+"/notes?before="+first.ID, "", nil, nil, 404)
	c.request("GET", root+"/"+first.ID, "", nil, &retry, 200)
	change := incident.NoteChange{IncidentRevision: parent.Revision, ExpectedRevision: first.Revision, Spec: first.Spec, Reason: "补充实际来源"}
	change.Spec.Body = "已核对来源。\n未观察的攻击结果仍为未知。"
	c.request("POST", root+"/"+first.ID, "notes_other_author", change, nil, 403)
	a.request("POST", root+"/"+first.ID, "notes_change", change, &retry, 200)
	if retry.Revision != 2 || retry.AuthorID != first.AuthorID || retry.AuthorName != first.AuthorName || !retry.CreatedAt.Equal(first.CreatedAt) {
		t.Fatal("修改改变作者或创建时间")
	}
	a.request("POST", root+"/"+first.ID, "notes_stale", change, nil, 409)
	change.ExpectedRevision, change.Spec.Status, change.Spec.WithdrawalReason = 2, "withdrawn", "引用标识需要复核，原文仍保留"
	a.request("POST", root+"/"+first.ID, "notes_withdraw", change, &retry, 200)
	var history incident.NotePage
	a.request("GET", root+"?status=withdrawn", "", nil, &history, 200)
	if len(history.Items) != 1 || history.Items[0].ID != first.ID {
		t.Fatal("撤回筛选错误")
	}
	a.request("GET", root+"/"+first.ID+"/history", "", nil, &history, 200)
	if len(history.Items) != 3 || history.Items[0].Revision != 3 || history.Items[2].Spec.Body != first.Spec.Body {
		t.Fatal("撤回删除或改写旧材料")
	}
	a.request("GET", root+"/"+first.ID+"/history?before=2", "", nil, &history, 200)
	if len(history.Items) != 1 || history.Items[0].Revision != 1 {
		t.Fatal("历史续点错误")
	}
	closeSpec := parent.Spec
	closeSpec.Status = "closed"
	closeSpec.Closure = &incident.Closure{Reason: "false_positive", RootCause: "授权检查", Impact: "隔离环境", Remediation: "核对原文", Verification: "确认来源和缺口", Evidence: []string{}}
	var closed incident.Record
	a.request("POST", "/incidents/"+parent.ID, "notes_close", incident.Change{ExpectedRevision: parent.Revision, Spec: closeSpec, Note: "结束本次调查", AddAlerts: []incident.AlertRef{}}, &closed, 200)
	a.request("POST", root, "notes_create", input, &retry, 200)
	a.request("POST", root, "notes_closed_create", input, nil, 409)
	change.IncidentRevision, change.ExpectedRevision = closed.Revision, 3
	a.request("POST", root+"/"+first.ID, "notes_closed_change", change, nil, 409)
	a.request("GET", root+"/"+first.ID, "", nil, &retry, 200)
	_, err = f.Runtime.Pool.Exec(ctx, `UPDATE incident_note_changes SET record='{}' WHERE tenant_id=$1`, tenant)
	if err == nil {
		t.Fatal("运行角色可改写笔记历史")
	}
	require(t, f.Runtime.TenantTx(ctx, otherTenant, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM incident_notes WHERE tenant_id=$1`, tenant).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatal("RLS泄露其他租户笔记")
		}
		return nil
	}))
	var audits int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action LIKE 'incidents.notes.%'`, tenant).Scan(&audits))
	if audits != 3 {
		t.Fatal("拒绝、重试或失败产生多余审计", audits)
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE incidents SET expires_at=now()-interval '1 day' WHERE tenant_id=$1 AND id=$2`, tenant, parent.ID)
	require(t, err)
	for _, suffix := range []string{"", "/" + first.ID, "/" + first.ID + "/history"} {
		a.request("GET", root+suffix, "", nil, nil, 404)
	}
	a.request("POST", root, "notes_expired_parent", input, nil, 404)
	a.request("POST", root+"/"+first.ID, "notes_expired_parent_change", change, nil, 404)
	// 原请求只回读仍在自身期限内的旧回执，不续期也不生成新的笔记修订。
	a.request("POST", root, "notes_create", input, &retry, 200)
	if retry.ID != first.ID || !retry.RecordedAt.Equal(first.RecordedAt) {
		t.Fatal("父事件到期后原提交确认被改写")
	}
	t.Log("真实PG/HTTP：作者限定、CAS、原提交确认、撤回历史、闭案只读、租户与审计原子性通过。")
}

func TestIncidentNotesRealPaginationQuotasAndProtectedRetention(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant := store.RandomID("it_note_budget_")
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "笔记留存验收", tenant, store.Token(), "admin"))
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	parent, err := f.Runtime.CreateIncident(ctx, u, "note_budget_case", incident.Create{Spec: incident.Spec{Title: "笔记预算", Summary: "核对独立记录的预算与保护。", Category: "other", Severity: "medium", Status: "open", OwnerID: u.ID}, Alerts: []incident.AlertRef{}}, nil, "notes_budget")
	require(t, err)
	input := incident.NoteCreate{IncidentRevision: 1, Spec: incident.NoteSpec{Title: "来源核对", Body: "保留原始标识。", Status: "active"}}
	var first incident.NoteRecord
	for i := 0; i < 22; i++ {
		r, e := f.Runtime.CreateIncidentNote(ctx, u, parent.ID, fmt.Sprintf("notes_budget_%d", i), input, "notes_budget")
		require(t, e)
		if i == 0 {
			first = r
		}
	}
	page, err := f.Runtime.IncidentNotes(ctx, u, parent.ID, incident.NoteQuery{})
	require(t, err)
	if len(page.Items) != 20 || page.Next != page.Items[19].ID {
		t.Fatal("笔记首屏续点错误")
	}
	page, err = f.Runtime.IncidentNotes(ctx, u, parent.ID, incident.NoteQuery{Before: page.Next})
	require(t, err)
	if len(page.Items) != 2 || page.Next != "" || page.Items[1].ID != first.ID {
		t.Fatal("笔记续页丢失或重复")
	}
	for i := 1; i <= 22; i++ {
		_, err = f.Runtime.ChangeIncidentNote(ctx, u, parent.ID, first.ID, fmt.Sprintf("notes_revision_%d", i), incident.NoteChange{IncidentRevision: 1, ExpectedRevision: int64(i), Spec: input.Spec, Reason: "核对来源"}, "notes_budget")
		require(t, err)
	}
	history, err := f.Runtime.IncidentNoteHistory(ctx, u, parent.ID, first.ID, "")
	require(t, err)
	if len(history.Items) != 20 || history.Next != "4" {
		t.Fatal("笔记历史首屏错误", history.Next)
	}
	history, err = f.Runtime.IncidentNoteHistory(ctx, u, parent.ID, first.ID, history.Next)
	require(t, err)
	if len(history.Items) != 3 || history.Next != "" {
		t.Fatal("笔记历史尾页错误")
	}
	_, err = f.Runtime.IncidentNoteHistory(ctx, u, parent.ID, first.ID, "01")
	if !errors.Is(err, incident.ErrNoteInput) {
		t.Fatal("非规范历史修订被接受")
	}
	// 只在专属数据库构造计数夹具，不将这些行作为真实调查材料返回。
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO incident_notes SELECT tenant_id,incident_id,'note_quota_'||n,author_id,revision,state,record,created_at,expires_at FROM incident_notes CROSS JOIN generate_series(1,106) n WHERE tenant_id=$1 AND id=$2`, tenant, first.ID)
	require(t, err)
	_, err = f.Runtime.CreateIncidentNote(ctx, u, parent.ID, "notes_over_case", input, "notes_budget")
	if !errors.Is(err, store.ErrIncidentNoteQuota) {
		t.Fatal("每事件笔记预算未生效", err)
	}
	_, err = f.Owner.Pool.Exec(ctx, `DELETE FROM incident_notes WHERE tenant_id=$1 AND id LIKE 'note_quota_%'`, tenant)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE retention_policies SET days=9 WHERE tenant_id=$1 AND category='incidents'`, tenant)
	require(t, err)
	custom, err := f.Runtime.CreateIncidentNote(ctx, u, parent.ID, "notes_custom_retention", input, "notes_budget")
	require(t, err)
	if custom.ExpiresAt.Sub(custom.RecordedAt) < 8*24*time.Hour || custom.ExpiresAt.Sub(custom.RecordedAt) > 10*24*time.Hour {
		t.Fatal("自定义笔记期限未固化")
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE incident_note_changes SET expires_at=now()-interval '1 day' WHERE tenant_id=$1`, tenant)
	require(t, err)
	_, err = f.Runtime.SweepHistory(ctx)
	require(t, err)
	var count int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM incident_note_changes WHERE tenant_id=$1`, tenant).Scan(&count))
	if count != 45 {
		t.Fatal("活动事件笔记历史被提前回收", count)
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE incidents SET state='closed',expires_at=now()-interval '1 day' WHERE tenant_id=$1`, tenant)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE incident_changes SET expires_at=now()-interval '1 day' WHERE tenant_id=$1`, tenant)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE incident_notes SET expires_at=now()-interval '1 day' WHERE tenant_id=$1`, tenant)
	require(t, err)
	for i := 0; i < 8; i++ {
		_, err = f.Runtime.SweepHistory(ctx)
		require(t, err)
	}
	for _, table := range []string{"incident_note_changes", "incident_notes", "incident_changes", "incidents"} {
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE tenant_id=$1`, tenant).Scan(&count))
		if count != 0 {
			t.Fatal("到期笔记或父事件没有按引用顺序回收", table, count)
		}
	}
}

func TestIncidentNotesRealFailureBudgetsAndRevokedActor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant := store.RandomID("it_note_failures_")
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "笔记故障与预算", tenant, store.Token(), "admin"))
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	create := incident.Create{Spec: incident.Spec{Title: "独立故障验收", Summary: "使用专属数据库验证预算和事务失败。", Category: "other", Severity: "medium", Status: "open", OwnerID: u.ID}, Alerts: []incident.AlertRef{}}
	parent, err := f.Runtime.CreateIncident(ctx, u, "notes_failure_case", create, nil, "note_failures")
	require(t, err)
	other, err := f.Runtime.CreateIncident(ctx, u, "notes_other_case", create, nil, "note_failures")
	require(t, err)
	input := incident.NoteCreate{IncidentRevision: 1, Spec: incident.NoteSpec{Title: "核对", Body: "保留现场依据。", Status: "active"}}
	first, err := f.Runtime.CreateIncidentNote(ctx, u, parent.ID, "notes_failure_first", input, "note_failures")
	require(t, err)
	change := incident.NoteChange{IncidentRevision: 1, ExpectedRevision: 1000, Spec: first.Spec, Reason: "达到修订边界"}
	atLimit := first
	atLimit.Revision = 1000
	raw, _ := json.Marshal(atLimit)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE incident_notes SET revision=1000,record=$3 WHERE tenant_id=$1 AND id=$2`, tenant, first.ID, raw)
	require(t, err)
	_, err = f.Runtime.ChangeIncidentNote(ctx, u, parent.ID, first.ID, "notes_revision_limit", change, "note_failures")
	if !errors.Is(err, store.ErrIncidentNoteQuota) {
		t.Fatal("笔记修订上限未生效", err)
	}
	raw, _ = json.Marshal(first)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE incident_notes SET revision=1,record=$3 WHERE tenant_id=$1 AND id=$2`, tenant, first.ID, raw)
	require(t, err)
	// 私有计数夹具不作真实材料读取；使用另一父事件区分租户总额与单事件配额。
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO incident_notes SELECT tenant_id,$3,'tenant_note_quota_'||n,author_id,revision,state,record,created_at,expires_at FROM incident_notes CROSS JOIN generate_series(1,9999) n WHERE tenant_id=$1 AND id=$2`, tenant, first.ID, other.ID)
	require(t, err)
	_, err = f.Runtime.CreateIncidentNote(ctx, u, parent.ID, "notes_tenant_limit", input, "note_failures")
	if !errors.Is(err, store.ErrIncidentNoteQuota) {
		t.Fatal("租户笔记配额未生效", err)
	}
	_, err = f.Owner.Pool.Exec(ctx, `DELETE FROM incident_notes WHERE tenant_id=$1 AND id LIKE 'tenant_note_quota_%'`, tenant)
	require(t, err)
	for i := 0; i < 4; i++ {
		_, err = f.Runtime.CreateIncidentNote(ctx, u, parent.ID, fmt.Sprintf("notes_daily_head_%d", i), input, "note_failures")
		require(t, err)
	}
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO incident_note_changes SELECT tenant_id,incident_id,note_id,n,created_by,'change','daily_'||note_id||n,input_hash,record,created_at,expires_at FROM incident_note_changes CROSS JOIN generate_series(2,850) n WHERE tenant_id=$1 AND revision=1`, tenant)
	require(t, err)
	_, err = f.Runtime.CreateIncidentNote(ctx, u, parent.ID, "notes_daily_limit", input, "note_failures")
	if !errors.Is(err, store.ErrIncidentNoteQuota) {
		t.Fatal("笔记每日变更配额未生效", err)
	}
	confirmed, err := f.Runtime.CreateIncidentNote(ctx, u, parent.ID, "notes_failure_first", input, "note_failures")
	require(t, err)
	if confirmed.ID != first.ID || confirmed.Revision != 1 {
		t.Fatal("额度不足阻止了原提交确认")
	}
	_, err = f.Owner.Pool.Exec(ctx, `DELETE FROM incident_note_changes WHERE tenant_id=$1 AND idempotency_key_hash LIKE 'daily_%'`, tenant)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `REVOKE SELECT ON incident_note_changes FROM starbeacon_app`)
	require(t, err)
	if _, err = f.Runtime.IncidentNoteHistory(ctx, u, parent.ID, first.ID, ""); err == nil {
		t.Fatal("不可读取历史仍返回成功")
	}
	if _, err = f.Runtime.CreateIncidentNote(ctx, u, parent.ID, "notes_history_unavailable", input, "note_failures"); err == nil {
		t.Fatal("回执存储不可读取仍允许写入")
	}
	_, err = f.Owner.Pool.Exec(ctx, `GRANT SELECT ON incident_note_changes TO starbeacon_app; REVOKE SELECT ON incident_notes FROM starbeacon_app`)
	require(t, err)
	if _, err = f.Runtime.IncidentNotes(ctx, u, parent.ID, incident.NoteQuery{}); err == nil {
		t.Fatal("目录不可读仍报告成功")
	}
	if _, err = f.Runtime.IncidentNotes(ctx, u, parent.ID, incident.NoteQuery{Before: first.ID}); err == nil {
		t.Fatal("续点不可读仍报告成功")
	}
	if _, err = f.Runtime.IncidentNote(ctx, u, parent.ID, first.ID); err == nil {
		t.Fatal("详情不可读仍报告成功")
	}
	if _, err = f.Runtime.IncidentNoteHistory(ctx, u, parent.ID, first.ID, ""); err == nil {
		t.Fatal("历史绕过当前笔记核验")
	}
	change.ExpectedRevision = 1
	if _, err = f.Runtime.ChangeIncidentNote(ctx, u, parent.ID, first.ID, "notes_head_unavailable", change, "note_failures"); err == nil {
		t.Fatal("当前材料不可读仍接受变更")
	}
	if _, err = f.Runtime.CreateIncidentNote(ctx, u, parent.ID, "notes_budget_unavailable", input, "note_failures"); err == nil {
		t.Fatal("预算不可读仍接受变更")
	}
	_, err = f.Owner.Pool.Exec(ctx, `GRANT SELECT ON incident_notes TO starbeacon_app`)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE users SET active=false WHERE tenant_id=$1 AND id=$2`, tenant, u.ID)
	require(t, err)
	if _, err = f.Runtime.CreateIncidentNote(ctx, u, parent.ID, "notes_revoked", input, "note_failures"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("撤权主体仍可写笔记", err)
	}
	if _, err = f.Runtime.IncidentNote(ctx, u, parent.ID, first.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("撤权主体仍可读笔记", err)
	}
}
