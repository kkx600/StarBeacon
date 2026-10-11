//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/assessment"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/migrations"
)

func TestAlertAssessmentRealOwnershipHistoryAndImmutableEvidence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenants := []string{store.RandomID("it_assessment_a_"), store.RandomID("it_assessment_b_")}
	password := store.Token()
	for _, account := range []struct{ tenant, username, role string }{{tenants[0], tenants[0], "admin"}, {tenants[0], tenants[0] + "_other", "admin"}, {tenants[0], tenants[0] + "_viewer", "viewer"}, {tenants[1], tenants[1], "admin"}} {
		require(t, admin.Bootstrap(ctx, f.Owner, account.tenant, "告警研判验收", account.username, password, account.role))
	}
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, err)
	require(t, es.EnsurePolicy(ctx))
	now := time.Now().UTC()
	indices := []string{}
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 8*time.Second)
		defer stop()
		for _, index := range indices {
			r, err := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(clean))
			require(t, err)
			_ = r.Body.Close()
			if r.IsError() {
				t.Errorf("专属研判索引未能回收：%d", r.StatusCode)
			}
		}
	})
	digest := control.Digest([]byte("owned-assessment-fact"))
	for _, tenant := range tenants {
		index, indexErr := contract.IndexName(tenant, "alerts", now.Format("2006-01-02"))
		require(t, indexErr)
		require(t, es.EnsureIndex(ctx, index, now.Format("2006-01-02")))
		indices = append(indices, index)
		item := model.Alert{SchemaVersion: "alert.v1", EventID: "event_assessment", TenantID: tenant, SensorID: "probe_owned", Timestamp: now, ObservedAt: now, ReceivedAt: now, RawSHA256: digest, Severity: "high"}
		item.Event.Kind = "alert"
		item.Event.Original = `{"owned":true}`
		for _, err := range es.Bulk(ctx, index, []model.Alert{item}) {
			require(t, err)
		}
		r, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
		require(t, err)
		_ = r.Body.Close()
	}
	api := &platform.API{DB: f.Runtime, ES: es}
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, api, tenants[0], password)
	other := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, tenants[0]+"_other", password)
	b := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, tenants[1], password)
	viewer := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, tenants[0]+"_viewer", password)
	user, _, err := f.Runtime.Password(ctx, tenants[0])
	require(t, err)
	path := "/alerts/event_assessment/assessment?sha256=" + digest
	historyPath := "/alerts/event_assessment/assessment/history?sha256=" + digest
	var blank assessment.Record
	a.request("GET", path, "", nil, &blank, 200)
	if blank.Revision != 0 || blank.Basis != "unreviewed" || blank.Spec.Verdict != "unreviewed" {
		t.Fatal("未研判记录被显示为已处理", blank)
	}
	viewer.request("GET", path, "", nil, nil, 403)
	viewer.request("POST", path, "denied", assessment.Change{Spec: assessment.Spec{Status: "closed", Verdict: "false_positive", Outcome: "unknown", Note: "人工核对", Evidence: []string{}}}, nil, 403)
	a.request("GET", "/alerts/bad%20id/assessment?sha256="+digest, "", nil, nil, 400)
	a.request("GET", "/alerts/event_absent/assessment?sha256="+digest, "", nil, nil, 404)
	a.request("GET", "/alerts/event_assessment/assessment?sha256="+strings.Repeat("b", 64), "", nil, nil, 409)
	a.request("POST", path, "bad_input", map[string]any{"unexpected": "field"}, nil, 400)
	change := assessment.Change{Spec: assessment.Spec{Status: "closed", Verdict: "false_positive", Outcome: "unknown", Note: "已核对登记的业务请求与规则条件，保存人工误报判断。", Evidence: []string{"case:owned:business-baseline"}}, Claim: true}
	var first assessment.Record
	a.request("POST", path, "save_initial", change, &first, 200)
	if first.Revision != 1 || first.OwnerID != user.ID || first.Basis != "human" || first.UpdatedAt == nil || first.ExpiresAt == nil || first.ExpiresAt.Sub(*first.UpdatedAt) < 179*24*time.Hour || first.Spec.Verdict != "false_positive" {
		t.Fatal("研判、认领或默认留存不完整", first)
	}
	var retried assessment.Record
	a.request("POST", path, "save_initial", change, &retried, 200)
	if retried.Revision != 1 || retried.AnalystID != first.AnalystID || !retried.UpdatedAt.Equal(*first.UpdatedAt) {
		t.Fatal("原请求重试重复操作", retried)
	}
	changed := change
	changed.Spec.Note = "不能使用原请求键修改备注。"
	a.request("POST", path, "save_initial", changed, nil, 409)
	a.request("POST", path, "stale_revision", change, nil, 409)
	var foreign assessment.Record
	b.request("GET", path, "", nil, &foreign, 200)
	if foreign.Revision != 0 || foreign.Spec.Verdict != "unreviewed" {
		t.Fatal("研判记录跨租户泄露", foreign)
	}
	// 检索仍由 ES 执行；人工误报标记不删除、重写或抑制原始检测事件。
	var found model.SearchResult
	a.request("POST", "/alerts/search", "", model.SearchRequest{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}, &found, 200)
	if found.Total != 1 || len(found.Items) != 1 || found.Items[0].Event.Original != `{"owned":true}` || found.Items[0].RawSHA256 != digest {
		t.Fatal("人工判断改变了原始事实", found)
	}
	change.ExpectedRevision = 1
	change.Spec.Status = "investigating"
	change.Spec.Verdict = "confirmed"
	change.Spec.Outcome = "attempt"
	change.Spec.Note = "另一名管理员重开调查，确认有攻击尝试；成功与否仍待核实。"
	other.request("POST", path, "reopen_owned", change, &retried, 200)
	if retried.Revision != 2 || retried.OwnerID == first.OwnerID || retried.OwnerName != tenants[0]+"_other" || retried.Spec.Outcome != "attempt" {
		t.Fatal("重新研判没有保留当前操作人和认领信息", retried)
	}
	// 审计插入失败时，当前修订与历史也必须一起回滚。
	fault, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, "INSERT INTO operation_audits")
	api.DB = fault
	change.ExpectedRevision = 2
	change.Spec.Note = "受控事务失败后使用原请求重试。"
	change.Claim = false
	a.request("POST", path, "atomic_failure", change, nil, 503)
	if !tracer.fired.Load() {
		t.Fatal("事务故障未触发")
	}
	api.DB = f.Runtime
	a.request("GET", path, "", nil, &retried, 200)
	if retried.Revision != 2 {
		t.Fatal("审计失败留下无审计的研判", retried)
	}
	a.request("POST", path, "atomic_failure", change, &retried, 200)
	if retried.Revision != 3 || retried.OwnerName != tenants[0]+"_other" {
		t.Fatal("失败重试或保留认领人错误", retried)
	}
	for revision := int64(3); revision < 23; revision++ {
		change.ExpectedRevision = revision
		change.Spec.Note = fmt.Sprintf("调查记录 %d，攻击成功状态保持未知。", revision+1)
		a.request("POST", path, fmt.Sprintf("history_%d", revision), change, &retried, 200)
	}
	var history assessment.HistoryPage
	a.request("GET", historyPath, "", nil, &history, 200)
	if len(history.Items) != 20 || history.Next != "4" || history.Items[0].Revision != 23 || history.Items[19].Revision != 4 {
		t.Fatal("研判记录分页不稳定", history)
	}
	a.request("GET", historyPath+"&before="+history.Next, "", nil, &history, 200)
	if len(history.Items) != 3 || history.Next != "" || history.Items[2].Spec.Verdict != "false_positive" {
		t.Fatal("历史研判被覆盖", history)
	}
	a.request("GET", historyPath+"&before=01", "", nil, nil, 400)
	// 更新页面后，旧请求仍回读原保存结果，不重复历史和审计。
	a.request("POST", path, "save_initial", assessment.Change{Spec: first.Spec, Claim: true}, &retried, 200)
	if retried.Revision != 1 {
		t.Fatal("历史幂等请求没有返回原保存结果")
	}
	var audits int
	require(t, f.Owner.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action='alerts.assessment.save'`, user.TenantID).Scan(&audits)
	}))
	if audits != 23 {
		t.Fatal("幂等保存重复审计", audits)
	}
	require(t, f.Runtime.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		var canRewrite bool
		if err := tx.QueryRow(ctx, `SELECT has_table_privilege(current_user,'alert_assessment_changes','UPDATE')`).Scan(&canRewrite); err != nil {
			return err
		}
		if canRewrite {
			t.Fatal("运行角色可以改写研判历史")
		}
		for _, table := range []string{"alert_assessments", "alert_assessment_changes"} {
			tag, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE tenant_id=$1`, user.TenantID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 0 {
				t.Fatal("运行角色删除了未到期的研判记录", table)
			}
		}
		return nil
	}))
	if _, err := f.Runtime.SaveAlertAssessment(ctx, model.Principal{}, "event_assessment", digest, "key", change, ""); !errors.Is(err, assessment.ErrInput) {
		t.Fatal("无效身份未拒绝", err)
	}
	if _, err := f.Runtime.AlertAssessment(ctx, user, "bad/id", digest); !errors.Is(err, assessment.ErrInput) {
		t.Fatal("无效事件标识未拒绝", err)
	}
	if _, err := f.Runtime.AlertAssessmentHistory(ctx, user, "event_assessment", digest, "bad"); !errors.Is(err, assessment.ErrInput) {
		t.Fatal("无效历史游标未拒绝", err)
	}
	if _, err := f.Runtime.AlertAssessmentHistory(ctx, model.Principal{}, "event_assessment", digest, ""); !errors.Is(err, assessment.ErrInput) {
		t.Fatal("无效历史身份未拒绝", err)
	}
	if _, err := f.Runtime.AlertAssessment(ctx, user, "event_assessment", strings.Repeat("b", 64)); !errors.Is(err, store.ErrConflict) {
		t.Fatal("操作库身份冲突未拒绝", err)
	}
	broken, err := store.Open(ctx, f.RuntimeDSN)
	require(t, err)
	broken.Close()
	api.DB = broken
	a.request("GET", path, "", nil, nil, 503)
	a.request("GET", historyPath, "", nil, nil, 503)
	a.request("POST", path, "db_offline", change, nil, 503)
	api.DB = nil
	a.request("GET", path, "", nil, nil, 503)
	api.DB = f.Runtime
	api.ES = nil
	a.request("GET", path, "", nil, nil, 503)
	api.ES = es
	require(t, f.Owner.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE alert_assessments SET revision=1000,record=jsonb_set(record,'{revision}','1000') WHERE tenant_id=$1`, user.TenantID)
		return err
	}))
	a.request("POST", path, "http_revision_quota", assessment.Change{ExpectedRevision: 1000, Spec: change.Spec}, nil, 429)
	require(t, f.Owner.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE alert_assessments SET revision=23,record=jsonb_set(record,'{revision}','23') WHERE tenant_id=$1`, user.TenantID)
		return err
	}))
	// 只有原生可定位的唯一告警允许研判，多个分区出现相同身份时必须停止写入。
	duplicateDay := now.AddDate(0, 0, -1)
	duplicateIndex, indexErr := contract.IndexName(tenants[0], "alerts", duplicateDay.Format("2006-01-02"))
	require(t, indexErr)
	require(t, es.EnsureIndex(ctx, duplicateIndex, duplicateDay.Format("2006-01-02")))
	indices = append(indices, duplicateIndex)
	duplicate := found.Items[0]
	for _, err := range es.Bulk(ctx, duplicateIndex, []model.Alert{duplicate}) {
		require(t, err)
	}
	r, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(duplicateIndex), es.API.Indices.Refresh.WithContext(ctx))
	require(t, err)
	_ = r.Body.Close()
	a.request("POST", path, "duplicate_source", assessment.Change{ExpectedRevision: 23, Spec: change.Spec}, nil, 409)
	r, err = es.API.Indices.Delete([]string{duplicateIndex}, es.API.Indices.Delete.WithContext(ctx))
	require(t, err)
	_ = r.Body.Close()
	if r.IsError() {
		t.Fatal("身份冲突验收索引未能回收", r.StatusCode)
	}
	indices = indices[:len(indices)-1]
	// 清理固化期限后的操作记录，不影响 ES 原始证据。
	require(t, f.Owner.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE alert_assessment_changes SET expires_at=now()-interval '1 day' WHERE tenant_id=$1`, user.TenantID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE alert_assessments SET expires_at=now()-interval '1 day' WHERE tenant_id=$1`, user.TenantID)
		return err
	}))
	a.request("GET", path, "", nil, nil, 410)
	a.request("POST", path, "expired_current", assessment.Change{ExpectedRevision: 23, Spec: change.Spec}, nil, 410)
	a.request("POST", path, "save_initial", assessment.Change{Spec: first.Spec, Claim: true}, nil, 410)
	a.request("GET", historyPath, "", nil, &history, 200)
	if len(history.Items) != 0 {
		t.Fatal("历史列表返回了过期研判", history)
	}
	_, err = f.Runtime.SweepHistory(ctx)
	require(t, err)
	var remaining int
	require(t, f.Owner.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM alert_assessments WHERE tenant_id=$1)+(SELECT count(*) FROM alert_assessment_changes WHERE tenant_id=$1)`, user.TenantID).Scan(&remaining)
	}))
	if remaining != 0 {
		t.Fatal("过期研判没有回收", remaining)
	}
	a.request("GET", path, "", nil, &blank, 200)
	if blank.Revision != 0 || blank.Basis != "unreviewed" {
		t.Fatal("回收后的告警错误引用旧研判", blank)
	}
}

func TestAlertAssessmentQuotasRevocationAndExpiredRecords(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant, password := store.RandomID("it_assessment_limits_"), store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "研判边界验收", tenant, password, "admin"))
	user, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	digest := control.Digest([]byte("owned-assessment-limits"))
	change := assessment.Change{Spec: assessment.Spec{Status: "investigating", Verdict: "suspicious", Outcome: "unknown", Note: "边界验收，不作为真实攻击结论。", Evidence: []string{}}}
	first, err := f.Runtime.SaveAlertAssessment(ctx, user, "event_limits", digest, "first", change, "")
	require(t, err)
	// 已撤销的账号不能凭旧 Principal 创建研判；恢复账号不绕过修订检查。
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE users SET active=false WHERE id=$1`, user.ID)
	require(t, err)
	change.ExpectedRevision = first.Revision
	if _, err := f.Runtime.SaveAlertAssessment(ctx, user, "event_limits", digest, "revoked", change, ""); err == nil {
		t.Fatal("已撤销账号凭旧身份保存研判")
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE users SET active=true WHERE id=$1`, user.ID)
	require(t, err)
	// 专属数据库中的到期夹具保留物理行，核对尚未清理时的返回行为。
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE alert_assessments SET expires_at=now()-interval '1 minute' WHERE tenant_id=$1`, tenant)
		return err
	}))
	if _, err := f.Runtime.AlertAssessment(ctx, user, "event_limits", digest); !errors.Is(err, store.ErrAssessmentExpired) {
		t.Fatal("过期记录被伪装为从未研判", err)
	}
	if _, err := f.Runtime.SaveAlertAssessment(ctx, user, "event_limits", digest, "expired_current", change, ""); !errors.Is(err, store.ErrAssessmentExpired) {
		t.Fatal("过期当前记录仍接受写入", err)
	}
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE alert_assessment_changes SET expires_at=now()-interval '1 minute' WHERE tenant_id=$1`, tenant)
		return err
	}))
	if _, err := f.Runtime.SaveAlertAssessment(ctx, user, "event_limits", digest, "first", assessment.Change{Spec: first.Spec}, ""); !errors.Is(err, store.ErrAssessmentExpired) {
		t.Fatal("已过期的幂等结果仍可读取", err)
	}
	// 从研判分类恢复清理，核对迁移后的高位持久游标可以提交。
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO retention_maintenance(tenant_id,next_category) VALUES($1,17)`, tenant)
		return err
	}))
	_, err = f.Runtime.SweepHistory(ctx)
	require(t, err)
	var cursor int
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT next_category FROM retention_maintenance WHERE tenant_id=$1`, tenant).Scan(&cursor)
	}))
	if cursor != 17 {
		t.Fatal("研判分类续点未持久保存", cursor)
	}
	// 从父记录开始时，引用保护保留当前研判；下一轮才回收已无历史引用的记录。
	if _, err := f.Runtime.AlertAssessment(ctx, user, "event_limits", digest); !errors.Is(err, store.ErrAssessmentExpired) {
		t.Fatal("历史引用保护失效", err)
	}
	_, err = f.Runtime.SweepHistory(ctx)
	require(t, err)
	change.ExpectedRevision = 0
	first, err = f.Runtime.SaveAlertAssessment(ctx, user, "event_limits", digest, "after_cleanup", change, "")
	require(t, err)
	// 额度夹具只检查真实数据库限额，不作为历史研判或告警来源验收。
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE alert_assessments SET revision=1000,record=jsonb_set(record,'{revision}','1000') WHERE tenant_id=$1`, tenant)
		return err
	}))
	change.ExpectedRevision = 1000
	if _, err := f.Runtime.SaveAlertAssessment(ctx, user, "event_limits", digest, "event_quota", change, ""); !errors.Is(err, store.ErrAssessmentQuota) {
		t.Fatal("单告警修订额度未生效", err)
	}
	// 相同已保存请求不消耗额度，即使其后该告警已达到修订上限。
	if result, err := f.Runtime.SaveAlertAssessment(ctx, user, "event_limits", digest, "after_cleanup", assessment.Change{Spec: first.Spec}, ""); err != nil || result.Revision != 1 {
		t.Fatal("已保存请求被后续额度阻止", err, result.Revision)
	}
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO alert_assessment_changes(tenant_id,event_id,revision,created_by,idempotency_key_hash,input_hash,record,expires_at) SELECT $1,'quota_fixture_'||n,1,$2,'fixture_key_'||n,'fixture_hash','{}',now()+interval '1 day' FROM generate_series(1,9999) n`, tenant, user.ID)
		return err
	}))
	change.ExpectedRevision = 0
	if _, err := f.Runtime.SaveAlertAssessment(ctx, user, "event_daily_quota", digest, "day_quota", change, ""); !errors.Is(err, store.ErrAssessmentQuota) {
		t.Fatal("租户日额度未生效", err)
	}
	// 专属库模拟旧版本允许但没有对应分类的游标，在线清理拒绝异常而不触发进程 panic。
	_, err = f.Owner.Pool.Exec(ctx, `ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check; ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 1000)`)
	require(t, err)
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE retention_maintenance SET next_category=1000 WHERE tenant_id=$1`, tenant)
		return err
	}))
	if _, err := f.Runtime.SweepHistory(ctx); err == nil || !strings.Contains(err.Error(), "续点无效") {
		t.Fatal("异常分类续点未安全拒绝", err)
	}
	migration, err := migrations.FS.ReadFile("00020_history_cursor_bounds.sql")
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, strings.Split(string(migration), "-- +goose Down")[0])
	require(t, err)
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT next_category FROM retention_maintenance WHERE tenant_id=$1`, tenant).Scan(&cursor)
	}))
	if cursor != 0 {
		t.Fatal("旧异常续点没有由实际迁移恢复", cursor)
	}
	_, err = f.Runtime.SweepHistory(ctx)
	require(t, err)
}
