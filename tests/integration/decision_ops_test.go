//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/platform"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
)

func TestDecisionOpsMetricsActivityAndObservationIsolation(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
	defer stop()
	f, candidate, signer, job, password := continuousAutomationFixture(t, ctx, "automatic", "", decision.Full)
	u := candidate.Principal
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)

	observed := job
	observed.Evidence.Facts = slices.Clone(job.Evidence.Facts)
	observed.Request.ObservationOnly = true
	observed = insertContinuousTriage(t, ctx, f, u, observed, "triage_copilot_owned", "event_copilot_owned", "192.0.2.35")
	candidates, err := f.Runtime.ContinuousDecisionCandidates(ctx, u.TenantID)
	require(t, err)
	if len(candidates) != 1 || candidates[0].TriageID != job.ID {
		t.Fatal("仅观察研判进入持续决策候选", candidates)
	}
	evidence, err := f.Runtime.CreateDecisionEvaluation(ctx, u, "ops_observation", decision.EvaluationRequest{
		PolicyID: candidate.Policy.ID, ExpectedRevision: candidate.Policy.Revision, TriageID: observed.ID,
	})
	require(t, err)
	if evidence.Result.Status != "abstained" {
		t.Fatal("仅观察研判可用来授权设备动作", evidence.Result)
	}
	_, run := completeContinuous(t, ctx, f, candidate, job, signer)
	if run.State != "queued" {
		t.Fatal("对照自动授权未受理", run)
	}
	databaseNow := time.Now().UTC()
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE alert_triage_jobs SET finished_at=$3,started_at=$3::timestamptz-interval '1.8 seconds' WHERE tenant_id=$1 AND id=$2`,
			u.TenantID, job.ID, databaseNow)
		return err
	}))
	var metrics decision.PlanMetrics
	client.request("GET", "/decision-plans/metrics?timezone=UTC", "", nil, &metrics, 200)
	if metrics.TriageCount != 1 || metrics.TriageMeanMS == nil || *metrics.TriageMeanMS != 1800 || metrics.Executed != 0 {
		t.Fatal("指标误把已签发当作设备已执行", metrics)
	}
	task := assertFrozenResponseProtection(t, ctx, f, u.TenantID, run.TaskID)
	action := task.ResponseAction
	identity := transport.SensorIdentity{TenantID: u.TenantID, SensorID: task.SensorID, RegistrationID: "registration_response"}
	receipt := func(id, state string) {
		t.Helper()
		delivery, err := f.Runtime.NextTask(ctx, identity)
		require(t, err)
		if delivery == nil || delivery.ID != id {
			t.Fatal("未投递预期任务", id)
		}
		now := time.Now().UTC()
		raw, err := json.Marshal(responseapi.Result{SchemaVersion: "response.result.v1", ConnectorID: action.ConnectorID,
			ConfigSHA256: action.ConfigSHA256, Verified: true, Effect: "not_observed",
			Observation: responseapi.Lease{SchemaVersion: responseapi.LeaseSchema, DeviceID: action.DeviceID, LeaseID: action.LeaseID,
				OwnerSHA256: action.OwnerSHA256, TargetIP: action.TargetIP, State: state, ExpiresAt: action.ExpiresAt, ObservedAt: now}})
		require(t, err)
		require(t, f.Runtime.SaveReceipt(ctx, identity, control.Receipt{CommandID: id, CommandSHA256: control.Digest(delivery.Command),
			State: "succeeded", Result: raw, StartedAt: now.Add(-time.Millisecond), FinishedAt: &now}))
	}
	receipt(task.ID, "active")
	client.request("GET", "/decision-plans/metrics?timezone=UTC", "", nil, &metrics, 200)
	if metrics.Automatic != 1 || metrics.Executed != 1 || metrics.Pending != 0 {
		t.Fatal("设备回读没有进入正确指标", metrics)
	}
	releaseID, err := f.Runtime.CreateResponseTask(ctx, u, task.SensorID, "ops_release", responseapi.Request{Kind: "response.revoke",
		Intent: responseapi.Intent{ConnectorID: action.ConnectorID, ConfigSHA256: action.ConfigSHA256, OriginalTaskID: task.ID, Reason: "实验回收原授权"}}, signer)
	require(t, err)
	receipt(releaseID, "revoked")
	var activity decision.ActivityPage
	client.request("GET", "/decision-plans/activity?limit=10", "", nil, &activity, 200)
	if len(activity.Items) < 2 || activity.Items[0].Kind != "release" || activity.Items[0].TaskID != releaseID {
		t.Fatal("解除回读缺失", activity)
	}
	activity, err = f.Runtime.DecisionPlanActivity(ctx, u, "", 1)
	require(t, err)
	if len(activity.Items) != 1 || activity.Items[0].TaskID != releaseID || activity.NextCursor == "" {
		t.Fatal("解除回读缺失或分页不正确", activity)
	}
	client.request("GET", "/decision-plans/activity?limit=10&cursor="+activity.NextCursor, "", nil, &activity, 200)
	if len(activity.Items) < 1 || activity.Items[0].Kind != "automatic" || activity.Items[0].TaskID != task.ID {
		t.Fatal("流水分页跳过原任务", activity)
	}
	otherName := store.RandomID("other_ops_")
	require(t, admin.Bootstrap(ctx, f.Owner, u.TenantID, "值守验收", otherName, password, "admin"))
	other := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, otherName, password)
	other.request("GET", "/decision-plans/metrics", "", nil, &metrics, 200)
	other.request("GET", "/decision-plans/activity", "", nil, &activity, 200)
	if metrics.TriageCount != 0 || metrics.TriageMeanMS != nil || metrics.Executed != 0 || len(activity.Items) != 0 {
		t.Fatal("同租户账号读取了他人的档案", metrics, activity)
	}

	for _, endpoint := range []struct{ path, query string }{
		{"/decision-plans/metrics", "WITH triage AS"},
		{"/decision-plans/activity", "WITH runs AS"},
	} {
		for _, prefix := range []string{"SELECT u.active,u.role", "SET LOCAL statement_timeout=", endpoint.query} {
			t.Run(endpoint.path+"/"+prefix, func(t *testing.T) {
				broken, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
				client := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: broken}, u.Username, password)
				client.request("GET", endpoint.path, "", nil, nil, 503)
				if !tracer.fired.Load() {
					t.Fatal("数据库断连未发生在预期查询")
				}
			})
		}
	}
}
