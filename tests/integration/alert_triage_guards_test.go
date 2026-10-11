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
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/jobs"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/triage"
)

// 不启动队列消费者；核对实际数据库中的执行资格、租约和有界历史，不发送模型请求。
func TestAlertTriageExecutionGuardsAndBoundedHistory(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
	defer stop()
	f := newIsolatedDatabase(t, ctx)
	tenant := store.RandomID("it_triage_guard_")
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "研判执行资格验收", tenant, store.Token(), "admin"))
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	vault, err := secrets.New(store.Token())
	require(t, err)
	config := llm.Config{Name: "受控资格模型", Kind: "openai_responses", BaseURL: "https://models.example.com/v1", Model: "owned", Enabled: true, APIKey: "owned-key", MaxOutputTokens: 256, TimeoutSeconds: 5, DailyRequests: 10000}
	_, err = f.Runtime.SaveModelProvider(ctx, u, store.ModelChange{ID: "provider_owned", ReplaceKey: true, Config: config}, vault, outbound.Policy{}, "seed")
	require(t, err)
	queue, err := jobs.NewAnalysis(f.Runtime, vault, outbound.Policy{})
	require(t, err)
	now := time.Now().UTC()
	alert := model.Alert{EventID: "event_owned", RawSHA256: control.Digest([]byte("owned")), SensorID: "sensor_owned", RegistrationID: "registration_owned", Timestamp: now, ObservedAt: now}
	alert.Event.Kind = "alert"
	evidence, err := triage.Freeze(alert)
	require(t, err)
	input := triage.Request{EventID: alert.EventID, RawSHA256: alert.RawSHA256, ProviderID: "provider_owned", ProviderRevision: 1, AllowContext: true}
	create := func(key string) triage.Job {
		j, e := f.Runtime.CreateAlertTriage(ctx, u, input, key, evidence, queue, vault, key)
		require(t, e)
		return j
	}
	riverID := func(j triage.Job) int64 {
		var id int64
		require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT river_job_id FROM alert_triage_jobs WHERE tenant_id=$1 AND id=$2`, tenant, j.ID).Scan(&id)
		}))
		return id
	}
	exec := func(sql string, args ...any) {
		_, e := f.Owner.Pool.Exec(ctx, sql, args...)
		require(t, e)
	}
	var originalCipher string
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT ciphertext FROM model_provider_versions WHERE tenant_id=$1 AND provider_id='provider_owned' AND revision=1`, tenant).Scan(&originalCipher))
	for _, kind := range []string{"owner", "revision", "vault", "disabled", "prompt", "template", "queue_deadline"} {
		t.Run(kind, func(t *testing.T) {
			j := create("guard_" + kind)
			usedVault := vault
			switch kind {
			case "owner":
				exec(`UPDATE users SET active=false WHERE tenant_id=$1 AND id=$2`, tenant, u.ID)
			case "revision":
				exec(`UPDATE model_providers SET revision=2 WHERE tenant_id=$1 AND id='provider_owned'`, tenant)
			case "vault":
				usedVault, err = secrets.New(store.Token())
				require(t, err)
			case "disabled":
				disabled := config
				disabled.Enabled = false
				raw, e := llm.Encode(disabled)
				require(t, e)
				cipher, e := vault.Seal(tenant, "model", "provider_owned", 1, raw)
				require(t, e)
				exec(`UPDATE model_provider_versions SET ciphertext=$2 WHERE tenant_id=$1 AND provider_id='provider_owned' AND revision=1`, tenant, cipher)
			case "prompt":
				exec(`UPDATE alert_triage_jobs SET prompt=prompt||'changed' WHERE tenant_id=$1 AND id=$2`, tenant, j.ID)
			case "template":
				exec(`UPDATE alert_triage_jobs SET template='untrusted' WHERE tenant_id=$1 AND id=$2`, tenant, j.ID)
			case "queue_deadline":
				exec(`UPDATE alert_triage_jobs SET deadline=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, tenant, j.ID)
			}
			lease, e := f.Runtime.StartAlertTriage(ctx, triage.Args{TenantID: tenant, JobID: j.ID}, riverID(j), usedVault)
			require(t, e)
			if lease.Execute || lease.Token != "" {
				t.Fatal("失效资格获得了出站调用租约", kind)
			}
			// 夹具变更仅作用于专属数据库；恢复后才能检查作业和继续创建。
			exec(`UPDATE users SET active=true WHERE tenant_id=$1 AND id=$2`, tenant, u.ID)
			exec(`UPDATE model_providers SET revision=1 WHERE tenant_id=$1 AND id='provider_owned'`, tenant)
			exec(`UPDATE model_provider_versions SET ciphertext=$2 WHERE tenant_id=$1 AND provider_id='provider_owned' AND revision=1`, tenant, originalCipher)
			j, e = f.Runtime.AlertTriage(ctx, u, j.ID)
			require(t, e)
			want := map[string]string{"owner": "authorization_revoked", "revision": "provider_revision_changed", "vault": "provider_config_unavailable", "disabled": "provider_disabled", "prompt": "triage_input_invalid", "template": "triage_input_invalid", "queue_deadline": "queue_wait_expired"}[kind]
			if j.State != "failed" || j.Result.Code != want || j.Answer != nil || j.StartedAt != nil {
				t.Fatal("未执行作业被记为调用成功，或失败原因不准确", kind, j.State, j.Result.Code)
			}
		})
	}
	j := create("running_guard")
	args := triage.Args{TenantID: tenant, JobID: j.ID}
	if _, err := f.Runtime.StartAlertTriage(ctx, args, riverID(j)+1, vault); !errors.Is(err, store.ErrConflict) {
		t.Fatal("错误队列身份取得租约", err)
	}
	lease, err := f.Runtime.StartAlertTriage(ctx, args, riverID(j), vault)
	require(t, err)
	if !lease.Execute {
		t.Fatal("有效作业无法执行")
	}
	again, err := f.Runtime.StartAlertTriage(ctx, args, riverID(j), vault)
	require(t, err)
	if again.Execute {
		t.Fatal("同一作业获得第二个执行租约")
	}
	if err := f.Runtime.FinishAlertTriage(ctx, tenant, lease, llm.Result{State: "succeeded"}, nil); !errors.Is(err, triage.ErrOutput) {
		t.Fatal("空模型结果被当成成功", err)
	}
	bad := &triage.Answer{Verdict: "confirmed", Outcome: "success", Confidence: 1, Reason: "没有终端证据", References: []string{}, CounterEvidence: []string{}, Missing: []string{}, Recommendation: "block_source", NeedsReview: true}
	if err := f.Runtime.FinishAlertTriage(ctx, tenant, lease, llm.Result{State: "succeeded"}, bad); !errors.Is(err, triage.ErrOutput) {
		t.Fatal("无依据的成功与处置建议被保存", err)
	}
	wrong := lease
	wrong.Token = "different"
	if err := f.Runtime.FinishAlertTriage(ctx, tenant, wrong, llm.Result{State: "failed"}, nil); !errors.Is(err, store.ErrConflict) {
		t.Fatal("错误租约改写作业", err)
	}
	exec(`UPDATE alert_triage_jobs SET deadline=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, tenant, j.ID)
	j, err = f.Runtime.AlertTriage(ctx, u, j.ID)
	require(t, err)
	if j.State != "uncertain" || j.Result.Code != "provider_result_unknown" {
		t.Fatal("运行超时被降级为可再次计费的失败")
	}
	if err := f.Runtime.FinishAlertTriage(ctx, tenant, lease, llm.Result{State: "failed"}, nil); !errors.Is(err, store.ErrConflict) {
		t.Fatal("过期租约写入最终结果", err)
	}
	repeated := create("running_guard")
	if repeated.ID != j.ID || repeated.State != "uncertain" {
		t.Fatal("未知结果重试生成了另一项作业")
	}
	changed := input
	changed.Note = "不同请求"
	if _, err := f.Runtime.CreateAlertTriage(ctx, u, changed, "running_guard", evidence, queue, vault, "changed"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("相同幂等键接受不同输入", err)
	}
	for i := 0; i < 22; i++ {
		v := create(fmt.Sprintf("history_%02d", i))
		if _, err := f.Runtime.CancelAlertTriage(ctx, u, v.ID, nil, "missing_queue"); !errors.Is(err, store.ErrConflict) {
			t.Fatal("无队列撤销被标为完成", err)
		}
		_, err = f.Runtime.CancelAlertTriage(ctx, u, v.ID, queue, "cancel")
		require(t, err)
	}
	seen := map[string]bool{}
	cursor := ""
	for pageNo := 0; ; pageNo++ {
		page, e := f.Runtime.AlertTriages(ctx, u, input.EventID, input.RawSHA256, cursor)
		require(t, e)
		if len(page.Items) == 0 || len(page.Items) > 20 || (pageNo == 0 && page.Next == "") {
			t.Fatal("研判历史未按二十条上限分页", len(page.Items), page.Next)
		}
		for _, item := range page.Items {
			if seen[item.ID] {
				t.Fatal("翻页重复记录")
			}
			seen[item.ID] = true
		}
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}
	if len(seen) != 30 {
		t.Fatal("有界翻页丢失作业", len(seen))
	}
	if _, err := f.Runtime.AlertTriages(ctx, u, "other_event", input.RawSHA256, j.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("游标跨告警读取", err)
	}
	wrongInput := input
	wrongInput.ProviderRevision = 2
	if _, err := f.Runtime.CreateAlertTriage(ctx, u, wrongInput, "wrong_revision", evidence, queue, vault, "revision"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("创建使用过期模型修订", err)
	}
	// 合成到期前的终态行只用于额度边界；不代表吞吐或真实模型调用。
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO alert_triage_jobs(tenant_id,id,created_by,event_id,raw_sha256,provider_id,provider_revision,request,request_hash,idempotency_key_hash,template,evidence,prompt,prompt_hash,state,result,deadline) SELECT $1,'quota_'||n,$2,$3,$4,'provider_owned',1,$5,$6,'quota_'||n,$7,$8,'owned',$6,'cancelled','{"state":"cancelled","code":"cancelled_before_execution"}',now() FROM generate_series(1,1000) n`, tenant, u.ID, input.EventID, input.RawSHA256, mustTriageJSON(t, input), triage.InputHash(input), triage.TemplateVersion, mustTriageJSON(t, evidence))
	require(t, err)
	if _, err := f.Runtime.CreateAlertTriage(ctx, u, input, "daily_limit", evidence, queue, vault, "quota"); !errors.Is(err, store.ErrModelQuota) {
		t.Fatal("租户研判日额度被绕过", err)
	}
	t.Log("实际 PostgreSQL 与持久队列的资格、未知结果、二十条分页和日额度核对通过；没有发送模型请求。")
}

func mustTriageJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	require(t, err)
	return raw
}
