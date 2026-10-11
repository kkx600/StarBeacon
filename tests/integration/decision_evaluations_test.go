//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/triage"
)

// 固定材料只用于数据库事务与权限回归；实际模型和原生 ZIP 链路另行验收。
func decisionArchiveFixture(t *testing.T, ctx context.Context, f *isolatedDatabase, u model.Principal) (decision.Record, decision.EvaluationRequest) {
	t.Helper()
	p, err := f.Runtime.SaveDecisionPolicy(ctx, u, "policy_archive_create", decisionPolicyInput("policy_archive"))
	require(t, err)
	alert := model.Alert{EventID: "event_archive", RawSHA256: strings.Repeat("a", 64), SensorID: "sensor_owned", RegistrationID: "registration_owned", Timestamp: time.Now().UTC(), ObservedAt: time.Now().UTC(), Source: model.Endpoint{IP: "192.0.2.10"}}
	alert.Event.Kind = "alert"
	alert.Rule.ID = "1000001"
	evidence, err := triage.Freeze(alert)
	require(t, err)
	request := triage.Request{EventID: alert.EventID, RawSHA256: alert.RawSHA256, ProviderID: "provider_archive", ProviderRevision: 1, AllowContext: true}
	answer := triage.Answer{Verdict: "confirmed", Outcome: "attempt", Confidence: .87, Reason: "固定数据库测试材料", References: []string{"rule.id"}, CounterEvidence: []string{"授权测试未排除"}, Missing: []string{"终端证据"}, Recommendation: "investigate", NeedsReview: true}
	data := func(v any) []byte { raw, err := json.Marshal(v); require(t, err); return raw }
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO model_providers(tenant_id,id,revision,public) VALUES($1,'provider_archive',1,'{}');`, u.TenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO model_provider_versions(tenant_id,provider_id,revision,ciphertext,expires_at) VALUES($1,'provider_archive',1,'database-fixture-only',now()+interval '180 days')`, u.TenantID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO alert_triage_jobs(tenant_id,id,created_by,event_id,raw_sha256,provider_id,provider_revision,request,request_hash,idempotency_key_hash,template,evidence,prompt,prompt_hash,answer,state,result,deadline) VALUES($1,'triage_archive',$2,$3,$4,'provider_archive',1,$5,$6,$6,$7,$8,'fixture-only',$6,$9,'succeeded',$10,now()+interval '1 hour')`, u.TenantID, u.ID, alert.EventID, alert.RawSHA256, data(request), triage.InputHash(request), triage.TemplateVersion, data(evidence), data(answer), data(llm.Result{State: "succeeded"}))
		return err
	}))
	return p, decision.EvaluationRequest{PolicyID: p.ID, ExpectedRevision: p.Revision, TriageID: "triage_archive"}
}

func TestDecisionEvaluationArchiveHTTPIdempotencyIsolationAndHistory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, foreign, password := accountFixture(t, ctx)
	p, input := decisionArchiveFixture(t, ctx, f, u)
	on := true
	other, err := f.Runtime.CreateUser(ctx, u, "archive_other_user", accounts.Create{Username: "archive_other", Password: password, Role: "admin", Active: &on})
	require(t, err)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	b := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, foreign.Username, password)
	c := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, other.Username, password)
	var first, again decision.Evaluation
	a.request("POST", "/decision-evaluations", "archive_submit", input, &first, 200)
	a.request("POST", "/decision-evaluations", "archive_submit", input, &again, 200)
	sealed, err := first.Seal()
	require(t, err)
	if first.ID != again.ID || first.SHA256 != again.SHA256 || sealed.SHA256 != first.SHA256 || first.CreatedBy != u.ID || first.Result.Status != "matched" || first.Result.TargetIP != "192.0.2.10" || first.Result.ExecutionAuthorized || first.ExpiresAt.Sub(first.Result.EvaluatedAt) != 180*24*time.Hour {
		t.Fatal("持久判断与原提交不同")
	}
	for _, client := range []*liveHTTP{b, c} {
		client.request("GET", "/decision-evaluations/"+first.ID, "", nil, nil, 404)
		client.request("GET", "/decision-evaluations?cursor="+first.ID, "", nil, nil, 404)
		var page decision.EvaluationPage
		client.request("GET", "/decision-evaluations", "", nil, &page, 200)
		if len(page.Items) != 0 {
			t.Fatal("档案跨账号或租户泄露")
		}
	}
	noCSRF := *a
	noCSRF.csrf = ""
	noCSRF.request("POST", "/decision-evaluations", "archive_no_csrf", input, nil, 403)
	changed := input
	changed.ExpectedRevision++
	a.request("POST", "/decision-evaluations", "archive_submit", changed, nil, 409)
	for i := 0; i < 3; i++ {
		a.request("POST", "/decision-evaluations", fmt.Sprintf("archive_page_%d", i), input, &again, 200)
	}
	var page decision.EvaluationPage
	a.request("GET", "/decision-evaluations?limit=2&status=matched&policy_id="+p.ID, "", nil, &page, 200)
	if len(page.Items) != 2 || page.Items[0].ID != again.ID || page.NextCursor != page.Items[1].ID {
		t.Fatal("持久提交倒序或游标错误")
	}
	a.request("GET", "/decision-evaluations?limit=2&status=matched&cursor="+page.NextCursor, "", nil, &page, 200)
	if len(page.Items) != 2 || page.Items[1].ID != first.ID || page.NextCursor != "" {
		t.Fatal("下一页丢失或重复记录")
	}
	a.request("GET", "/decision-evaluations?status=protected", "", nil, &page, 200)
	if len(page.Items) != 0 {
		t.Fatal("结果筛选未生效")
	}
	off := false
	edit := decisionPolicyEdit(p)
	edit.Active = &off
	_, err = f.Runtime.SaveDecisionPolicy(ctx, u, "archive_policy_disable", edit)
	require(t, err)
	// 材料按自己的期限回收后，既有档案和原提交确认仍独立可访问。
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM alert_triage_jobs WHERE tenant_id=$1`, u.TenantID)
		return err
	}))
	a.request("POST", "/decision-evaluations", "archive_submit", input, &again, 200)
	a.request("GET", "/decision-evaluations/"+first.ID, "", nil, &again, 200)
	if again.SHA256 != first.SHA256 || again.Policy.Revision != 1 || !again.Policy.Active {
		t.Fatal("当前策略改写历史快照")
	}
	a.request("POST", "/decision-evaluations", "archive_after_disable", input, nil, 409)
}

func TestDecisionEvaluationConcurrencyRollbackAndStorageIntegrity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	f, u, _, _ := accountFixture(t, ctx)
	_, input := decisionArchiveFixture(t, ctx, f, u)
	var wg sync.WaitGroup
	rows := make(chan decision.Evaluation, 2)
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := f.Runtime.CreateDecisionEvaluation(ctx, u, "archive_concurrent", input)
			rows <- r
			errs <- e
		}()
	}
	wg.Wait()
	close(rows)
	close(errs)
	for err := range errs {
		require(t, err)
	}
	id := ""
	for row := range rows {
		if id != "" && id != row.ID {
			t.Fatal("同一并发提交生成多个档案")
		}
		id = row.ID
	}
	for _, cut := range []string{"SELECT input_hash FROM decision_evaluations", "SELECT $2::timestamptz", "INSERT INTO decision_evaluations", "INSERT INTO operation_audits"} {
		broken, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, cut)
		key := store.RandomID("archive_fault_")
		_, err := broken.CreateDecisionEvaluation(ctx, u, key, input)
		broken.Close()
		if err == nil || !tracer.fired.Load() {
			t.Fatal("事务断线没有触发", cut)
		}
		var n int
		require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM decision_evaluations WHERE tenant_id=$1 AND key_hash=$2`, u.TenantID, store.Hash(key)).Scan(&n)
		}))
		if n != 0 {
			t.Fatal("半提交档案残留")
		}
	}
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var update bool
		if err := tx.QueryRow(ctx, `SELECT has_table_privilege(current_user,'decision_evaluations','UPDATE')`).Scan(&update); err != nil {
			return err
		}
		if update {
			t.Fatal("运行角色可以修改历史档案")
		}
		return nil
	}))
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE decision_evaluations SET record=jsonb_set(record,'{sha256}','"broken"') WHERE tenant_id=$1 AND id=$2`, u.TenantID, id)
		return err
	}))
	if _, err := f.Runtime.DecisionEvaluation(ctx, u, id); err == nil {
		t.Fatal("摘要损坏的档案仍可读")
	}
	if _, err := f.Runtime.DecisionEvaluations(ctx, u, decision.EvaluationQuery{Limit: 20}); err == nil {
		t.Fatal("不完整目录仍返回成功")
	}
}

func TestDecisionEvaluationRetentionBudgetAndRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, _, _ := accountFixture(t, ctx)
	_, input := decisionArchiveFixture(t, ctx, f, u)
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE retention_policies SET days=7 WHERE tenant_id=$1 AND category='operations'`, u.TenantID)
		return err
	}))
	r, err := f.Runtime.CreateDecisionEvaluation(ctx, u, "archive_retention", input)
	require(t, err)
	if r.ExpiresAt.Sub(r.Result.EvaluatedAt) != 7*24*time.Hour {
		t.Fatal("自定义期限未固化")
	}
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO operation_audits(tenant_id,user_id,action,object_id,request_id,expires_at) SELECT $1,$2,'decision.policy.evaluate','quota','quota',now()+interval '180 days' FROM generate_series(1,1024)`, u.TenantID, u.ID)
		return err
	}))
	if _, err := f.Runtime.CreateDecisionEvaluation(ctx, u, "archive_excess", input); !errors.Is(err, decision.ErrQuota) {
		t.Fatal("评估预算未生效", err)
	}
	if repeated, err := f.Runtime.CreateDecisionEvaluation(ctx, u, "archive_retention", input); err != nil || repeated.ID != r.ID {
		t.Fatal("预算阻止原提交确认", err)
	}
	// 测试所有者只修改到期事实；到期档案不经读取或原请求复活。
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE decision_evaluations SET created_at=now()-interval '8 days',expires_at=now()-interval '1 hour' WHERE tenant_id=$1`, u.TenantID)
		return err
	}))
	if _, err := f.Runtime.DecisionEvaluation(ctx, u, r.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("到期档案仍可读", err)
	}
	if _, err := f.Runtime.CreateDecisionEvaluation(ctx, u, "archive_retention", input); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("原提交复活到期档案", err)
	}
	_, err = f.Runtime.SweepHistory(ctx)
	require(t, err)
	var n int
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM decision_evaluations WHERE tenant_id=$1`, u.TenantID).Scan(&n)
	}))
	if n != 0 {
		t.Fatal("到期档案未清理")
	}
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET active=false,revision=revision+1 WHERE tenant_id=$1 AND id=$2`, u.TenantID, u.ID)
		return err
	}))
	if _, err := f.Runtime.DecisionEvaluations(ctx, u, decision.EvaluationQuery{Limit: 20}); !errors.Is(err, decision.ErrPermission) {
		t.Fatal("停用账号仍可访问目录", err)
	}
	if _, err := f.Runtime.DecisionEvaluation(ctx, u, r.ID); !errors.Is(err, decision.ErrPermission) {
		t.Fatal("停用账号仍可读取档案", err)
	}
	if _, err := f.Runtime.CreateDecisionEvaluation(ctx, u, "archive_revoked", input); !errors.Is(err, decision.ErrPermission) {
		t.Fatal("停用账号仍可原提交确认", err)
	}
}
