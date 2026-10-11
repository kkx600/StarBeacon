//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
)

func decisionPolicyInput(id string) decision.Change {
	active := true
	return decision.Change{ID: id, Name: "攻击尝试影子策略", Description: "只评估冻结材料，不创建执行动作", Active: &active, Definition: decision.Definition{SchemaVersion: decision.Schema, Mode: "shadow", Expression: `confidence >= threshold && verdict == "confirmed"`, Threshold: .8, CandidateAction: "block_source", MaxAgeSeconds: 3600, ProtectedPrefixes: []string{}}}
}
func decisionPolicyEdit(record decision.Record) decision.Change {
	active := record.Active
	return decision.Change{ID: record.ID, ExpectedRevision: record.Revision, Name: record.Name, Description: record.Description, Active: &active, Definition: record.Definition}
}

func TestDecisionPolicyCASRetentionAndPermissionRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	f, u, _, _ := accountFixture(t, ctx)
	input := decisionPolicyInput("policy_concurrent")
	first, err := f.Runtime.SaveDecisionPolicy(ctx, u, "policy_initial", input)
	require(t, err)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			edit := decisionPolicyEdit(first)
			edit.Name = fmt.Sprintf("并发规则 %d", i)
			_, err := f.Runtime.SaveDecisionPolicy(ctx, u, fmt.Sprintf("policy_race_%d", i), edit)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	passed, conflicts := 0, 0
	for err := range results {
		if err == nil {
			passed++
		} else if errors.Is(err, store.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if passed != 1 || conflicts != 1 {
		t.Fatal("并发维护覆盖了他人修订")
	}
	var protected int64
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE decision_policy_revisions SET created_at=now()-interval '181 days',expires_at=now()-interval '1 hour' WHERE tenant_id=$1`, u.TenantID)
		return err
	}))
	_, err = f.Runtime.DecisionPolicy(ctx, u, input.ID, 1)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("已过期历史仍可读", err)
	}
	current, err := f.Runtime.DecisionPolicy(ctx, u, input.ID, 2)
	require(t, err)
	if current.Revision != 2 {
		t.Fatal("当前配置按历史期限失效")
	}
	_, err = f.Runtime.SweepHistory(ctx)
	require(t, err)
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM decision_policy_revisions WHERE tenant_id=$1`, u.TenantID).Scan(&protected)
	}))
	if protected != 1 {
		t.Fatal("未清理过期历史或清理了当前规则", protected)
	}
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET active=false,revision=revision+1 WHERE tenant_id=$1 AND id=$2`, u.TenantID, u.ID)
		return err
	}))
	if _, err := f.Runtime.DecisionPolicies(ctx, u, decision.ListQuery{Limit: 20}); !errors.Is(err, decision.ErrPermission) {
		t.Fatal("停用账号仍可读取规则", err)
	}
	if _, err := f.Runtime.SaveDecisionPolicy(ctx, u, "policy_after_revoke", decisionPolicyEdit(current)); !errors.Is(err, decision.ErrPermission) {
		t.Fatal("停用账号仍可保存规则", err)
	}
	if _, err := f.Runtime.EvaluateDecisionPolicy(ctx, u, input.ID, decision.EvaluateRequest{ExpectedRevision: 2, TriageID: "triage_owned"}); !errors.Is(err, decision.ErrPermission) {
		t.Fatal("停用账号仍可测试规则", err)
	}
	if _, err := f.Runtime.SaveDecisionPolicy(ctx, model.Principal{ID: u.ID, TenantID: u.TenantID, Role: "viewer"}, "policy_viewer", input); !errors.Is(err, decision.ErrPermission) {
		t.Fatal("直接存储调用绕过管理员检查", err)
	}
	if _, err := f.Runtime.DecisionPolicy(ctx, u, input.ID, 0); !errors.Is(err, decision.ErrInput) {
		t.Fatal("无效修订被存储接受", err)
	}
	if _, err := f.Runtime.DecisionPolicies(ctx, u, decision.ListQuery{}); !errors.Is(err, decision.ErrInput) {
		t.Fatal("无界目录被存储接受", err)
	}
	if _, err := f.Runtime.SaveDecisionPolicy(ctx, u, "/", input); !errors.Is(err, decision.ErrInput) {
		t.Fatal("无效幂等键被存储接受", err)
	}
}

func TestDecisionPolicyQuotaRollbackAndCorruptVersions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	f, u, _, password := accountFixture(t, ctx)
	for _, cut := range []string{"SET LOCAL lock_timeout", "SELECT pg_advisory_xact_lock", "SELECT u.active,u.role", "SELECT input_hash", "SELECT v.tenant_id,v.policy_id", "SELECT count(*) FROM decision_policies", "SELECT count(*) FROM decision_policy_revisions", "INSERT INTO decision_policy_revisions", "INSERT INTO decision_policies", "INSERT INTO operation_audits"} {
		broken, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, cut)
		input := decisionPolicyInput(store.RandomID("policy_fault_"))
		_, err := broken.SaveDecisionPolicy(ctx, u, store.RandomID("policy_change_"), input)
		broken.Close()
		if err == nil || !tracer.fired.Load() {
			t.Fatal("断线注入没有触发决策策略事务", cut)
		}
		var exists bool
		require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM decision_policies WHERE tenant_id=$1 AND id=$2) OR EXISTS(SELECT 1 FROM decision_policy_revisions WHERE tenant_id=$1 AND policy_id=$2)`, u.TenantID, input.ID).Scan(&exists)
		}))
		if exists {
			t.Fatal("半提交规则或修订残留", cut)
		}
	}
	c := decisionPolicyInput("policy_quota")
	first, err := f.Runtime.SaveDecisionPolicy(ctx, u, "policy_quota_initial", c)
	require(t, err)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE decision_policy_revisions SET definition_sha256=$2 WHERE tenant_id=$1 AND policy_id=$3`, u.TenantID, strings.Repeat("0", 64), first.ID)
		return err
	}))
	a.request("GET", "/decision-policies", "", nil, nil, 503)
	a.request("GET", "/decision-policies/policy_quota/revisions/1", "", nil, nil, 503)
	a.request("POST", "/decision-policies/policy_quota/evaluate", "", decision.EvaluateRequest{ExpectedRevision: 1, TriageID: "triage_owned"}, nil, 503)
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE decision_policy_revisions SET definition_sha256=$2 WHERE tenant_id=$1 AND policy_id=$3`, u.TenantID, first.DefinitionSHA256, first.ID)
		return err
	}))
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO decision_policies(tenant_id,id,revision,name,active) SELECT $1,'policy_limit_'||n,1,'额度规则',false FROM generate_series(1,$2) n`, u.TenantID, decision.MaxPolicies-1); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO decision_policy_revisions(tenant_id,policy_id,revision,name,description,active,definition,definition_sha256,created_by,key_hash,input_hash,expires_at) SELECT v.tenant_id,'policy_limit_'||n,1,'额度规则','',false,v.definition,v.definition_sha256,v.created_by,'limit_'||n,'limit_'||n,now()+interval '180 days' FROM decision_policy_revisions v CROSS JOIN generate_series(1,$2) n WHERE v.tenant_id=$1 AND v.policy_id=$3 AND v.revision=1`, u.TenantID, decision.MaxPolicies-1, c.ID)
		return err
	}))
	if _, err := f.Runtime.SaveDecisionPolicy(ctx, u, "policy_overquota", decisionPolicyInput("policy_extra")); !errors.Is(err, decision.ErrQuota) {
		t.Fatal("规则目录额度未生效", err)
	}
	edit := decisionPolicyEdit(first)
	edit.Name = "目录额度下编辑"
	second, err := f.Runtime.SaveDecisionPolicy(ctx, u, "policy_edit_at_quota", edit)
	require(t, err)
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO decision_policy_revisions(tenant_id,policy_id,revision,name,description,active,definition,definition_sha256,created_by,key_hash,input_hash,expires_at) SELECT v.tenant_id,v.policy_id,n+10,'变更额度材料','',false,v.definition,v.definition_sha256,v.created_by,'daily_'||n,'daily_'||n,now()+interval '180 days' FROM decision_policy_revisions v CROSS JOIN generate_series(1,$2) n WHERE v.tenant_id=$1 AND v.policy_id=$3 AND v.revision=1`, u.TenantID, decision.MaxDailyChanges, c.ID)
		return err
	}))
	edit = decisionPolicyEdit(second)
	edit.Name = "超出每日额度"
	if _, err := f.Runtime.SaveDecisionPolicy(ctx, u, "policy_daily_overquota", edit); !errors.Is(err, decision.ErrQuota) {
		t.Fatal("每日变更额度未生效", err)
	}
	// 额度不能影响已经持久确认的同一提交。
	if repeated, err := f.Runtime.SaveDecisionPolicy(ctx, u, "policy_quota_initial", c); err != nil || repeated.Revision != 1 {
		t.Fatal("额度阻止原请求确认", err)
	}
}
