//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/jobs"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/triage"
	"github.com/riverqueue/river"
)

func TestAlertTriageDatabaseInterruptionPreservesFrozenJobsAndQueue(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
	defer stop()
	f := newIsolatedDatabase(t, ctx)
	tenant := store.RandomID("it_triage_failure_")
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "研判事务验收", tenant, store.Token(), "admin"))
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	vault, err := secrets.New(store.Token())
	require(t, err)
	policy := outbound.Policy{}
	_, err = f.Runtime.SaveModelProvider(ctx, u, store.ModelChange{ID: "provider_owned", ReplaceKey: true, Config: llm.Config{Name: "事务验收模型", Kind: "openai_responses", BaseURL: "https://models.example.com/v1", Model: "owned", Enabled: true, APIKey: "owned-key", MaxOutputTokens: 256, TimeoutSeconds: 5, DailyRequests: 1000}}, vault, policy, "seed")
	require(t, err)
	queue, err := jobs.NewAnalysis(f.Runtime, vault, policy)
	require(t, err)
	alert := model.Alert{EventID: "event_owned", RawSHA256: control.Digest([]byte("owned")), SensorID: "sensor_owned", RegistrationID: "registration_owned", Timestamp: time.Now().UTC(), ObservedAt: time.Now().UTC()}
	alert.Event.Kind = "alert"
	evidence, err := triage.Freeze(alert)
	require(t, err)
	input := triage.Request{EventID: alert.EventID, RawSHA256: alert.RawSHA256, ProviderID: "provider_owned", ProviderRevision: 1, AllowContext: true}
	snapshot := func() string {
		parts := []string{}
		require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
			for _, table := range []string{"alert_triage_jobs", "operation_audits", "alert_assessments", "alert_assessment_changes"} {
				var raw []byte
				if err := tx.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY to_jsonb(v)::text),'[]'::jsonb) FROM (SELECT * FROM `+pgx.Identifier{table}.Sanitize()+` WHERE tenant_id=$1) v`, tenant).Scan(&raw); err != nil {
					return err
				}
				parts = append(parts, string(raw))
			}
			var raw []byte
			if err := tx.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb) FROM (SELECT * FROM starbeacon_jobs.river_job WHERE args->>'tenant_id'=$1) v`, tenant).Scan(&raw); err != nil {
				return err
			}
			parts = append(parts, string(raw))
			return nil
		}))
		raw, _ := json.Marshal(parts)
		return store.Hash(string(raw))
	}
	type operation struct {
		name     string
		prefixes []string
		run      func(*store.Postgres, *river.Client[pgx.Tx]) error
	}
	check := func(ops []operation) {
		for _, op := range ops {
			for i, prefix := range op.prefixes {
				t.Run(fmt.Sprintf("%s/%02d", op.name, i), func(t *testing.T) {
					before := snapshot()
					db, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
					q, err := jobs.NewAnalysis(db, vault, policy)
					require(t, err)
					if err := op.run(db, q); err == nil || !tracer.fired.Load() {
						t.Fatalf("目标断连未发生或被当作成功: %v", err)
					}
					if before != snapshot() {
						t.Fatal("断连留下模型作业、队列、研判记录或审计变更")
					}
				})
			}
		}
	}
	check([]operation{{"create", []string{"SELECT pg_advisory_xact_lock", "UPDATE alert_triage_jobs SET state='uncertain'", "UPDATE alert_triage_jobs SET state='failed'", "SELECT request_hash FROM alert_triage_jobs", "SELECT public.lock_report_plan_owner", "SELECT revision FROM model_providers", "SELECT ciphertext", "SELECT count(*) FILTER", "SELECT count(*) FROM alert_triage_jobs", "INSERT INTO alert_triage_jobs", "UPDATE alert_triage_jobs SET river_job_id", "INSERT INTO operation_audits"}, func(db *store.Postgres, q *river.Client[pgx.Tx]) error {
		_, e := db.CreateAlertTriage(ctx, u, input, "fault_owned", evidence, q, vault, "fault_owned")
		return e
	}}})
	job, err := f.Runtime.CreateAlertTriage(ctx, u, input, "seed_job", evidence, queue, vault, "seed_job")
	require(t, err)
	var riverID int64
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT river_job_id FROM alert_triage_jobs WHERE tenant_id=$1 AND id=$2`, tenant, job.ID).Scan(&riverID)
	}))
	args := triage.Args{TenantID: tenant, JobID: job.ID}
	check([]operation{
		{"lookup", []string{"SELECT request_hash FROM alert_triage_jobs", "SELECT jsonb_build_object"}, func(db *store.Postgres, _ *river.Client[pgx.Tx]) error {
			_, e := db.ExistingAlertTriage(ctx, u, "seed_job", triage.InputHash(input))
			return e
		}},
		{"detail", []string{"SELECT jsonb_build_object"}, func(db *store.Postgres, _ *river.Client[pgx.Tx]) error {
			_, e := db.AlertTriage(ctx, u, job.ID)
			return e
		}},
		{"history", []string{"SELECT id,state,provider_id"}, func(db *store.Postgres, _ *river.Client[pgx.Tx]) error {
			_, e := db.AlertTriages(ctx, u, input.EventID, input.RawSHA256, "")
			return e
		}},
		{"cursor", []string{"SELECT created_at FROM alert_triage_jobs"}, func(db *store.Postgres, _ *river.Client[pgx.Tx]) error {
			_, e := db.AlertTriages(ctx, u, input.EventID, input.RawSHA256, job.ID)
			return e
		}},
		{"start", []string{"SELECT jsonb_build_object", "SELECT public.lock_report_plan_owner", "SELECT revision FROM model_providers", "SELECT ciphertext", "UPDATE alert_triage_jobs SET state='running'"}, func(db *store.Postgres, _ *river.Client[pgx.Tx]) error {
			_, e := db.StartAlertTriage(ctx, args, riverID, vault)
			return e
		}},
		{"cancel", []string{"SELECT state,river_job_id FROM alert_triage_jobs", "UPDATE alert_triage_jobs SET state='cancelled'", "INSERT INTO operation_audits"}, func(db *store.Postgres, q *river.Client[pgx.Tx]) error {
			_, e := db.CancelAlertTriage(ctx, u, job.ID, q, "cancel_fault")
			return e
		}},
	})
	lease, err := f.Runtime.StartAlertTriage(ctx, args, riverID, vault)
	require(t, err)
	if !lease.Execute {
		t.Fatal("有效研判未获得租约")
	}
	check([]operation{{"finish", []string{"UPDATE alert_triage_jobs SET state=$4"}, func(db *store.Postgres, _ *river.Client[pgx.Tx]) error {
		return db.FinishAlertTriage(ctx, tenant, lease, llm.Result{State: "failed", Code: "invalid_triage_output"}, nil)
	}}})
	require(t, f.Runtime.FinishAlertTriage(ctx, tenant, lease, llm.Result{State: "failed", Code: "invalid_triage_output"}, nil))
	t.Log("实际 PostgreSQL 断连回滚验证通过；本用例不启用模型出站请求。")
}
