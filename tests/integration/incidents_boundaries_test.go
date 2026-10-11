//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/incident"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
)

func incidentSnapshot(t *testing.T, ctx context.Context, db *store.Postgres, tenant string) string {
	t.Helper()
	state := map[string]json.RawMessage{}
	require(t, db.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		for _, table := range []string{"incidents", "incident_changes", "incident_alert_links", "operation_audits"} {
			var raw []byte
			if err := tx.QueryRow(ctx, "SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY to_jsonb(v)::text),'[]'::jsonb) FROM (SELECT * FROM "+pgx.Identifier{table}.Sanitize()+" WHERE tenant_id=$1) v", tenant).Scan(&raw); err != nil {
				return err
			}
			state[table] = raw
		}
		return nil
	}))
	raw, err := json.Marshal(state)
	require(t, err)
	return string(raw)
}

func TestIncidentsTransactionsPaginationCorruptionAndQuotas(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant := store.RandomID("it_incident_bounds_")
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "调查事务验收", tenant, store.Token(), "admin"))
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	input := incident.Create{Spec: incident.Spec{Title: "专属事务调查", Category: "other", Severity: "medium", Status: "open", Summary: "记录可核对的事务测试。", OwnerID: u.ID}, Alerts: []incident.AlertRef{}}
	seed, err := f.Runtime.CreateIncident(ctx, u, "seed_owned", input, nil, "seed_owned")
	require(t, err)
	change := incident.Change{ExpectedRevision: 1, Spec: input.Spec, Note: "核对调查事务与来源。", AddAlerts: []incident.AlertRef{}}
	change.Spec.Status = "investigating"
	withSource := input
	withSource.Alerts = []incident.AlertRef{{EventID: "event_owned", SHA256: strings.Repeat("a", 64)}}
	frozen := []incident.AlertEvidence{{AlertRef: withSource.Alerts[0], SensorID: "sensor_owned", EventTime: time.Now().UTC(), ObservedAt: time.Now().UTC()}}
	changeSource := change
	changeSource.AddAlerts = withSource.Alerts
	type op struct {
		name     string
		prefixes []string
		run      func(*store.Postgres) error
	}
	ops := []op{
		{"create", []string{"SELECT pg_advisory_xact_lock", "SELECT input_hash,record", "SELECT incident_id FROM incident_alert_links", "SELECT (SELECT count(*)", "SELECT username FROM users", "SELECT clock_timestamp(),", "INSERT INTO incidents(", "INSERT INTO incident_alert_links(", "INSERT INTO incident_changes(", "INSERT INTO operation_audits"}, func(db *store.Postgres) error {
			_, e := db.CreateIncident(ctx, u, "create_fault", withSource, frozen, "create_fault")
			return e
		}},
		{"change", []string{"SELECT record,id,revision", "SELECT clock_timestamp()", "INSERT INTO incidents(", "INSERT INTO incident_alert_links(", "INSERT INTO incident_changes(", "INSERT INTO operation_audits"}, func(db *store.Postgres) error {
			_, e := db.ChangeIncident(ctx, u, seed.ID, "change_fault", changeSource, frozen, "change_fault")
			return e
		}},
		{"read", []string{"SELECT record,id,revision"}, func(db *store.Postgres) error { _, e := db.Incident(ctx, u, seed.ID); return e }},
		{"list", []string{"SELECT created_at FROM incidents", "SELECT record,id,revision"}, func(db *store.Postgres) error {
			_, e := db.Incidents(ctx, u, incident.Query{Before: seed.ID})
			return e
		}},
		{"history", []string{"SELECT state<>'closed'", "SELECT record,revision"}, func(db *store.Postgres) error { _, e := db.IncidentHistory(ctx, u, seed.ID, ""); return e }},
		{"owners", []string{"SELECT u.id,u.username"}, func(db *store.Postgres) error { _, e := db.IncidentAssignees(ctx, u); return e }},
		{"receipt", []string{"SELECT input_hash,record"}, func(db *store.Postgres) error {
			_, e := db.IncidentReceipt(ctx, u, "seed_owned", "create", store.IncidentCreateHash(input))
			return e
		}},
	}
	for _, operation := range ops {
		for i, prefix := range operation.prefixes {
			t.Run(fmt.Sprintf("%s/%02d", operation.name, i), func(t *testing.T) {
				before := incidentSnapshot(t, ctx, f.Owner, tenant)
				db, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
				if e := operation.run(db); e == nil || !tracer.fired.Load() {
					t.Fatalf("目标故障未执行或返回成功：%v", e)
				}
				if incidentSnapshot(t, ctx, f.Owner, tenant) != before {
					t.Fatal("中断留下半份事件、告警占位、历史或审计")
				}
			})
		}
	}
	viewer := u
	viewer.Role = "viewer"
	if _, e := f.Runtime.Incident(ctx, viewer, seed.ID); !errors.Is(e, incident.ErrInput) {
		t.Fatal("只读账号可取得调查", e)
	}
	if _, e := f.Runtime.Incidents(ctx, u, incident.Query{Status: "invalid"}); !errors.Is(e, incident.ErrInput) {
		t.Fatal("错误状态可查询", e)
	}
	if _, e := f.Runtime.IncidentAssignees(ctx, model.Principal{}); !errors.Is(e, incident.ErrInput) {
		t.Fatal("无身份可读取责任人", e)
	}
	if _, e := f.Runtime.IncidentHistory(ctx, u, "bad/id", ""); !errors.Is(e, incident.ErrInput) {
		t.Fatal("错误历史标识可查询", e)
	}
	if _, e := f.Runtime.CreateIncident(ctx, u, "bad/id", input, nil, ""); !errors.Is(e, incident.ErrInput) {
		t.Fatal("错误请求键可写入", e)
	}
	if _, e := f.Runtime.CreateIncident(ctx, u, "missing_facts", withSource, nil, ""); !errors.Is(e, incident.ErrInput) {
		t.Fatal("未核对来源可以关联", e)
	}
	brokenFacts := append([]incident.AlertEvidence{}, frozen...)
	brokenFacts[0].SensorID = ""
	if _, e := f.Runtime.CreateIncident(ctx, u, "bad_facts", withSource, brokenFacts, ""); !errors.Is(e, incident.ErrInput) {
		t.Fatal("损坏事实可关联", e)
	}
	if _, e := f.Runtime.ChangeIncident(ctx, u, "bad/id", "valid", change, nil, ""); !errors.Is(e, incident.ErrInput) {
		t.Fatal("错误事件可修改", e)
	}
	for _, value := range []struct{ key, operation, digest string }{{"bad/id", "create", store.IncidentCreateHash(input)}, {"valid", "foreign", store.IncidentCreateHash(input)}, {"valid", "create", "short"}} {
		if _, e := f.Runtime.IncidentReceipt(ctx, u, value.key, value.operation, value.digest); !errors.Is(e, incident.ErrInput) {
			t.Fatal("错误回执范围可访问", e)
		}
	}
	if _, e := f.Runtime.IncidentReceipt(ctx, u, "seed_owned", "create", strings.Repeat("0", 64)); !errors.Is(e, store.ErrConflict) {
		t.Fatal("原键输入变化未拒绝", e)
	}
	if _, e := f.Runtime.IncidentReceipt(ctx, u, "absent", "create", store.IncidentCreateHash(input)); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("不存在的回执未返回缺失", e)
	}

	// 通过真实写入形成跨页材料，核对稳定创建游标和连续调查修订。
	for i := 1; i <= 22; i++ {
		if _, e := f.Runtime.CreateIncident(ctx, u, fmt.Sprintf("create_page_%02d", i), input, nil, "page"); e != nil {
			t.Fatal(e)
		}
		change.ExpectedRevision = int64(i)
		if _, e := f.Runtime.ChangeIncident(ctx, u, seed.ID, fmt.Sprintf("change_page_%02d", i), change, nil, "page"); e != nil {
			t.Fatal(e)
		}
	}
	page, err := f.Runtime.Incidents(ctx, u, incident.Query{})
	require(t, err)
	if len(page.Items) != 20 || page.Next == "" {
		t.Fatal("列表缺少真实续点", page)
	}
	older, err := f.Runtime.Incidents(ctx, u, incident.Query{Before: page.Next})
	require(t, err)
	if len(older.Items) != 3 || older.Next != "" {
		t.Fatal("列表续页缺失或重复", older)
	}
	seen := map[string]bool{}
	for _, r := range append(page.Items, older.Items...) {
		if seen[r.ID] {
			t.Fatal("跨页重复")
		}
		seen[r.ID] = true
	}
	history, err := f.Runtime.IncidentHistory(ctx, u, seed.ID, "")
	require(t, err)
	if len(history.Items) != 20 || history.Next != "4" {
		t.Fatal("时间线续点错误", history)
	}
	oldHistory, err := f.Runtime.IncidentHistory(ctx, u, seed.ID, history.Next)
	require(t, err)
	if len(oldHistory.Items) != 3 || oldHistory.Items[2].Revision != 1 || oldHistory.Next != "" {
		t.Fatal("旧调查材料缺失或重复", oldHistory)
	}

	t.Run("corrupted_current_and_history_fail_closed", func(t *testing.T) {
		var saved []byte
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT record FROM incidents WHERE tenant_id=$1 AND id=$2`, tenant, seed.ID).Scan(&saved))
		_, e := f.Owner.Pool.Exec(ctx, `UPDATE incidents SET record='{}' WHERE tenant_id=$1 AND id=$2`, tenant, seed.ID)
		require(t, e)
		if _, e = f.Runtime.Incident(ctx, u, seed.ID); e == nil {
			t.Fatal("损坏当前事件可读取")
		}
		if _, e = f.Runtime.Incidents(ctx, u, incident.Query{Before: page.Next}); e == nil {
			t.Fatal("损坏目录可列出")
		}
		_, e = f.Owner.Pool.Exec(ctx, `UPDATE incidents SET record=$3 WHERE tenant_id=$1 AND id=$2`, tenant, seed.ID, saved)
		require(t, e)
		var original []byte
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT record FROM incident_changes WHERE tenant_id=$1 AND incident_id=$2 AND revision=23`, tenant, seed.ID).Scan(&original))
		_, e = f.Owner.Pool.Exec(ctx, `UPDATE incident_changes SET record='{}' WHERE tenant_id=$1 AND incident_id=$2 AND revision=23`, tenant, seed.ID)
		require(t, e)
		if _, e = f.Runtime.IncidentHistory(ctx, u, seed.ID, ""); e == nil {
			t.Fatal("损坏调查历史可读取")
		}
		if _, e = f.Runtime.IncidentReceipt(ctx, u, "change_page_22", "change", store.IncidentChangeHash(seed.ID, change)); e == nil {
			t.Fatal("损坏原回执可以确认")
		}
		_, e = f.Owner.Pool.Exec(ctx, `UPDATE incident_changes SET record=$3 WHERE tenant_id=$1 AND incident_id=$2 AND revision=23`, tenant, seed.ID, original)
		require(t, e)
		_, e = f.Owner.Pool.Exec(ctx, `UPDATE incident_changes SET expires_at=now()-interval '1 hour' WHERE tenant_id=$1 AND incident_id=$2 AND revision=23`, tenant, seed.ID)
		require(t, e)
		if _, e = f.Runtime.IncidentReceipt(ctx, u, "change_page_22", "change", store.IncidentChangeHash(seed.ID, change)); !errors.Is(e, store.ErrIncidentExpired) {
			t.Fatal("到期回执重新确认了写入", e)
		}
	})

	t.Run("revision_and_daily_budgets", func(t *testing.T) {
		latest, e := f.Runtime.Incident(ctx, u, seed.ID)
		require(t, e)
		latest.Revision = 1000
		raw, _ := json.Marshal(latest)
		_, e = f.Owner.Pool.Exec(ctx, `UPDATE incidents SET revision=1000,record=$3 WHERE tenant_id=$1 AND id=$2`, tenant, seed.ID, raw)
		require(t, e)
		change.ExpectedRevision = 1000
		if _, e = f.Runtime.ChangeIncident(ctx, u, seed.ID, "revision_quota", change, nil, ""); !errors.Is(e, store.ErrIncidentQuota) {
			t.Fatal("无界调查修订仍被接收", e)
		}
		// 专属配额夹具只用于拒绝测试，不作为真实业务吞吐或调查材料证据。
		_, e = f.Owner.Pool.Exec(ctx, `INSERT INTO incident_changes(tenant_id,incident_id,revision,created_by,operation,idempotency_key_hash,input_hash,record,created_at,expires_at) SELECT $1,'quota_case_'||i,1,$2,'create','quota_key_'||i,'fixture','{}',now(),now()+interval '180 days' FROM generate_series(1,4096) i`, tenant, u.ID)
		require(t, e)
		if _, e = f.Runtime.CreateIncident(ctx, u, "daily_quota", input, nil, ""); !errors.Is(e, store.ErrIncidentQuota) {
			t.Fatal("日变更额度未拒绝", e)
		}
		_, e = f.Owner.Pool.Exec(ctx, `DELETE FROM incident_changes WHERE tenant_id=$1 AND incident_id LIKE 'quota_case_%'`, tenant)
		require(t, e)
		_, e = f.Owner.Pool.Exec(ctx, `INSERT INTO incidents(tenant_id,id,revision,state,severity,record,created_at,expires_at) SELECT $1,'quota_case_'||i,1,'open','medium','{}',now(),now()+interval '180 days' FROM generate_series(1,10000) i`, tenant)
		require(t, e)
		if _, e = f.Runtime.CreateIncident(ctx, u, "case_quota", input, nil, ""); !errors.Is(e, store.ErrIncidentQuota) {
			t.Fatal("事件数量额度未拒绝", e)
		}
	})
}
