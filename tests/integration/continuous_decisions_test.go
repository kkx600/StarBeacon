//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/triage"
)

func continuousFixture(t *testing.T, ctx context.Context, mode string) (*isolatedDatabase, store.DecisionCandidate, ed25519.PrivateKey, triage.Job, string) {
	t.Helper()
	f, u, signer, input, password := responseTaskFixture(t, ctx)
	p, request := decisionArchiveFixture(t, ctx, f, u)
	job, err := f.Runtime.AlertTriage(ctx, u, request.TriageID)
	require(t, err)
	edit := decisionPolicyEdit(p)
	edit.Definition.Mode = mode
	edit.Definition.Continuous = &decision.ContinuousConfig{ProviderID: job.Request.ProviderID, ProviderRevision: 1}
	if mode == "automatic" {
		edit.Definition.Continuous.Automatic = &decision.AutomaticConfig{SensorID: "sensor_response", RegistrationID: "registration_response", ConnectorID: input.ConnectorID, ConfigSHA256: input.ConfigSHA256, TTLSeconds: 60, CooldownSeconds: 3600, MaxHourlyActions: 1, AcceptUncalibratedScore: true}
	}
	p, err = f.Runtime.SaveDecisionPolicy(ctx, u, "continuous_policy_enable", edit)
	require(t, err)
	job.Answer.Recommendation = "block_source"
	job.Answer.References = []string{"source.ip", "rule.id"}
	for i := range job.Evidence.Facts {
		switch job.Evidence.Facts[i].ID {
		case "sensor.id":
			job.Evidence.Facts[i].Value = "sensor_response"
		case "sensor.registration":
			job.Evidence.Facts[i].Value = "registration_response"
		}
	}
	job.Evidence, err = triage.Seal(job.Evidence)
	require(t, err)
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE model_providers SET public='{"enabled":true}' WHERE tenant_id=$1`, u.TenantID)
		return err
	}))
	job = insertContinuousTriage(t, ctx, f, u, job, "triage_continuous_first", "event_continuous_first", "192.0.2.10")
	return f, store.DecisionCandidate{Principal: u, Policy: p, TriageID: job.ID}, signer, job, password
}

// 固定研判只检验持久授权与事务边界；真实模型与采集器链路由进程用例另行验证。
func insertContinuousTriage(t *testing.T, ctx context.Context, f *isolatedDatabase, u model.Principal, source triage.Job, id, event, ip string) triage.Job {
	t.Helper()
	source.ID = id
	source.Request.EventID = event
	source.Request.RawSHA256 = store.Hash(event)
	source.Evidence.EventID = event
	source.Evidence.RawSHA256 = source.Request.RawSHA256
	for i := range source.Evidence.Facts {
		if source.Evidence.Facts[i].ID == "source.ip" {
			source.Evidence.Facts[i].Value = ip
		}
	}
	var err error
	source.Evidence, err = triage.Seal(source.Evidence)
	require(t, err)
	raw := func(v any) []byte { b, e := json.Marshal(v); require(t, e); return b }
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO alert_triage_jobs(tenant_id,id,created_by,event_id,raw_sha256,provider_id,provider_revision,request,request_hash,idempotency_key_hash,template,evidence,prompt,prompt_hash,answer,state,result,deadline) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'database-fixture-only',$9,$13,'succeeded',$14,now()+interval '1 hour')`, u.TenantID, id, u.ID, event, source.Request.RawSHA256, source.Request.ProviderID, source.Request.ProviderRevision, raw(source.Request), triage.InputHash(source.Request), store.Hash(id), source.Template, raw(source.Evidence), raw(source.Answer), raw(source.Result))
		return err
	}))
	source, err = f.Runtime.AlertTriage(ctx, u, id)
	require(t, err)
	return source
}

func completeContinuous(t *testing.T, ctx context.Context, f *isolatedDatabase, c store.DecisionCandidate, j triage.Job, signer ed25519.PrivateKey) (decision.Evaluation, decision.ContinuousRecord) {
	t.Helper()
	c.TriageID = j.ID
	e, err := f.Runtime.CreateDecisionEvaluation(ctx, c.Principal, c.Key(), decision.EvaluationRequest{PolicyID: c.Policy.ID, ExpectedRevision: c.Policy.Revision, TriageID: j.ID})
	require(t, err)
	r, err := f.Runtime.CompleteContinuousDecision(ctx, c, e.ID, j.Evidence, signer)
	require(t, err)
	return e, r
}

func TestContinuousDecisionsAtomicConcurrencyDuplicatesCooldownAndQuota(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f, c, signer, job, password := continuousFixture(t, ctx, "automatic")
	candidates, err := f.Runtime.ContinuousDecisionCandidates(ctx, c.Principal.TenantID)
	require(t, err)
	if len(candidates) != 1 || candidates[0].TriageID != job.ID {
		t.Fatal("补做了历史研判或丢失新作业", candidates)
	}
	e, err := f.Runtime.CreateDecisionEvaluation(ctx, c.Principal, c.Key(), decision.EvaluationRequest{PolicyID: c.Policy.ID, ExpectedRevision: 2, TriageID: job.ID})
	require(t, err)
	var wg sync.WaitGroup
	rows := make(chan decision.ContinuousRecord, 2)
	failures := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			r, err := f.Runtime.CompleteContinuousDecision(ctx, c, e.ID, job.Evidence, signer)
			rows <- r
			failures <- err
		})
	}
	wg.Wait()
	close(rows)
	close(failures)
	for err := range failures {
		require(t, err)
	}
	var first decision.ContinuousRecord
	for r := range rows {
		if first.ID != "" && r.ID != first.ID {
			t.Fatal("重复授权")
		}
		first = r
	}
	if first.State != "queued" || first.Code != "policy_authorized" || first.TaskID == "" || first.ExpiresAt.Sub(first.CreatedAt) != 180*24*time.Hour || e.Result.ExecutionAuthorized {
		t.Fatal("执行档案与判断结果混淆", first)
	}
	tasks, err := f.Runtime.Tasks(ctx, c.Principal.TenantID, "sensor_response")
	require(t, err)
	if len(tasks) != 1 || tasks[0].ID != first.TaskID || tasks[0].ResponseAction.TargetIP != "192.0.2.10" || tasks[0].ResponseAction.ExpiresAt.Sub(tasks[0].ResponseAction.RequestedAt) != 60*time.Second {
		t.Fatal("签名限时任务失去绑定", tasks)
	}
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, c.Principal.Username, password)
	var response struct {
		Item *decision.ContinuousRecord `json:"item"`
	}
	client.request("GET", "/decision-evaluations/"+e.ID+"/continuous", "", nil, &response, 200)
	if response.Item == nil || response.Item.SHA256 != first.SHA256 {
		t.Fatal("授权详情丢失")
	}
	client.request("GET", "/decision-evaluations/"+e.ID+"/continuous?unknown=true", "", nil, nil, 400)
	candidates, err = f.Runtime.ContinuousDecisionCandidates(ctx, c.Principal.TenantID)
	require(t, err)
	if len(candidates) != 0 {
		t.Fatal("已处理材料再次进入候选")
	}
	require(t, f.Owner.TenantTx(ctx, c.Principal.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sensor_tasks SET state='succeeded' WHERE tenant_id=$1`, c.Principal.TenantID)
		return err
	}))
	duplicate := insertContinuousTriage(t, ctx, f, c.Principal, job, "triage_continuous_duplicate", job.Request.EventID, "192.0.2.10")
	_, r := completeContinuous(t, ctx, f, c, duplicate, signer)
	if r.Code != "event_already_authorized" || r.TaskID != "" {
		t.Fatal("重复研判重复授权", r)
	}
	sameTarget := insertContinuousTriage(t, ctx, f, c.Principal, job, "triage_continuous_cooldown", "event_continuous_cooldown", "192.0.2.10")
	_, r = completeContinuous(t, ctx, f, c, sameTarget, signer)
	if r.Code != "target_cooldown" {
		t.Fatal("未执行目标冷却", r)
	}
	other := insertContinuousTriage(t, ctx, f, c.Principal, job, "triage_continuous_quota", "event_continuous_quota", "192.0.2.11")
	_, r = completeContinuous(t, ctx, f, c, other, signer)
	if r.Code != "hourly_quota" {
		t.Fatal("未执行每小时配额", r)
	}
}

func TestContinuousDecisionsReadinessSourceAndModelChangesFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name, code, sql string
		key             bool
	}{
		{"无签名服务", "device_unavailable", "", false},
		{"设备离线", "device_unavailable", `UPDATE sensors SET last_seen=now()-interval '1 minute' WHERE tenant_id=$1`, true},
		{"探针停用", "sensor_binding_changed", `UPDATE sensors SET active=false WHERE tenant_id=$1`, true},
		{"模型停用", "model_binding_changed", `UPDATE model_providers SET public='{"enabled":false}' WHERE tenant_id=$1`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			f, c, key, j, _ := continuousFixture(t, ctx, "automatic")
			if tc.sql != "" {
				require(t, f.Owner.TenantTx(ctx, c.Principal.TenantID, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, tc.sql, c.Principal.TenantID); return err }))
			}
			if !tc.key {
				key = nil
			}
			_, r := completeContinuous(t, ctx, f, c, j, key)
			if r.State != "skipped" || r.Code != tc.code {
				t.Fatal(r)
			}
			tasks, err := f.Runtime.Tasks(ctx, c.Principal.TenantID, "sensor_response")
			require(t, err)
			if len(tasks) != 0 {
				t.Fatal("拒绝后仍留下任务")
			}
		})
	}
}

func TestContinuousDecisionsRollbackIntegrityRetentionAndApproval(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f, c, signer, j, _ := continuousFixture(t, ctx, "automatic")
	e, err := f.Runtime.CreateDecisionEvaluation(ctx, c.Principal, c.Key(), decision.EvaluationRequest{PolicyID: c.Policy.ID, ExpectedRevision: c.Policy.Revision, TriageID: j.ID})
	require(t, err)
	for _, cut := range []string{"INSERT INTO sensor_tasks", "INSERT INTO decision_continuous_runs", "INSERT INTO operation_audits"} {
		broken, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, cut)
		_, err := broken.CompleteContinuousDecision(ctx, c, e.ID, j.Evidence, signer)
		broken.Close()
		if err == nil || !tracer.fired.Load() {
			t.Fatal("断连故障未触发", cut)
		}
		tasks, err := f.Runtime.Tasks(ctx, c.Principal.TenantID, "sensor_response")
		require(t, err)
		if len(tasks) != 0 {
			t.Fatal("事务回滚后仍可投递任务")
		}
	}
	changed := j.Evidence
	changed.RawSHA256 = strings.Repeat("d", 64)
	changed, err = triage.Seal(changed)
	require(t, err)
	r, err := f.Runtime.CompleteContinuousDecision(ctx, c, e.ID, changed, signer)
	require(t, err)
	if r.Code != "evidence_changed" {
		t.Fatal("当前告警变化仍授权", r)
	}
	require(t, f.Runtime.TenantTx(ctx, c.Principal.TenantID, func(tx pgx.Tx) error {
		var update bool
		if err := tx.QueryRow(ctx, `SELECT has_table_privilege(current_user,'decision_continuous_runs','UPDATE')`).Scan(&update); err != nil {
			return err
		}
		if update {
			t.Fatal("运行角色可改写历史")
		}
		tag, err := tx.Exec(ctx, `DELETE FROM decision_continuous_runs WHERE tenant_id=$1`, c.Principal.TenantID)
		if tag.RowsAffected() != 0 {
			t.Fatal("未到期档案被删除")
		}
		return err
	}))
	require(t, f.Owner.TenantTx(ctx, c.Principal.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE decision_continuous_runs SET record=jsonb_set(record,'{task_id}','"task_corrupt"') WHERE tenant_id=$1`, c.Principal.TenantID)
		return err
	}))
	if _, err := f.Runtime.ContinuousDecision(ctx, c.Principal, e.ID); !errors.Is(err, decision.ErrSource) {
		t.Fatal("损坏档案可读", err)
	}
	require(t, f.Owner.TenantTx(ctx, c.Principal.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE decision_continuous_runs SET created_at=now()-interval '181 days',expires_at=now()-interval '1 hour' WHERE tenant_id=$1`, c.Principal.TenantID)
		return err
	}))
	_, err = f.Runtime.SweepHistory(ctx)
	require(t, err)
	item, err := f.Runtime.ContinuousDecision(ctx, c.Principal, e.ID)
	require(t, err)
	if item != nil {
		t.Fatal("到期档案仍可访问")
	}
	f2, c2, _, j2, _ := continuousFixture(t, ctx, "approval")
	_, approval := completeContinuous(t, ctx, f2, c2, j2, nil)
	if approval.State != "awaiting_confirmation" || approval.TaskID != "" {
		t.Fatal("持续人工确认模式自动创建任务", approval)
	}
}
