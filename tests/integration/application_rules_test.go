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
	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/application"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
)

func applicationRuleInput(id string) application.Change {
	active := true
	return application.Change{ID: id, Name: "业务文件服务名称规则", Description: "可见域名验证，不执行网络动作", Active: &active, Definition: application.Definition{SchemaVersion: application.Schema, ProductID: "owned_files", ProductName: "业务文件服务", CategoryID: "cloud_storage", Protocols: []string{"http", "tls"}, Any: []application.Condition{{Field: "http.host", Op: "domain_suffix", Value: "files.example"}, {Field: "tls.sni", Op: "eq", Value: "files.example"}}, All: []application.Condition{}, Exclude: []application.Condition{}}}
}
func applicationRuleEdit(r application.Record) application.Change {
	active := r.Active
	return application.Change{ID: r.ID, ExpectedRevision: r.Revision, Name: r.Name, Description: r.Description, Active: &active, Definition: r.Definition}
}
func applicationObservation() application.Observation {
	return application.Observation{SchemaVersion: application.ObservationSchema, Protocol: "http", HTTPHost: "FILES.EXAMPLE.:443", HTTPMethod: "GET", HTTPPath: "/documents", TLSALPN: []string{}, DNSNames: []string{}}
}

func TestApplicationRulesHTTPIsolationVersionsVisibleMetadataAndAudit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	f, u, foreign, password := accountFixture(t, ctx)
	active := true
	viewerUser, err := f.Runtime.CreateUser(ctx, u, "application_viewer_create", accounts.Create{Username: "application_viewer", Password: password, Role: "viewer", Active: &active})
	require(t, err)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	b := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, foreign.Username, password)
	v := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, viewerUser.Username, password)
	c := applicationRuleInput("app_files")
	var first, replayed application.Record
	a.request("POST", "/application-rules", "app_create_files", c, &first, 200)
	a.request("POST", "/application-rules", "app_create_files", c, &replayed, 200)
	if first.Validate() != nil || first.TenantID != u.TenantID || first.Revision != 1 || first.CreatedBy != u.ID || !replayed.CreatedAt.Equal(first.CreatedAt) || first.ExpiresAt.Sub(first.CreatedAt) != 180*24*time.Hour {
		t.Fatal("不可变修订、租户、原提交或默认保留期不一致")
	}
	changed := c
	changed.Name = "不同输入"
	a.request("POST", "/application-rules", "app_create_files", changed, nil, 409)
	a.request("POST", "/application-rules", "", c, nil, 400)
	v.request("POST", "/application-rules", "app_viewer_save", c, nil, 403)
	noCSRF := *a
	noCSRF.csrf = ""
	noCSRF.request("POST", "/application-rules", "app_without_csrf", c, nil, 403)
	b.request("GET", "/application-rules/app_files/revisions/1", "", nil, nil, 404)
	v.request("GET", "/application-rules/app_files/revisions/1", "", nil, &replayed, 200)
	var page application.Page
	b.request("GET", "/application-rules", "", nil, &page, 200)
	if len(page.Items) != 0 {
		t.Fatal("其他租户看到了应用规则")
	}
	observation := applicationObservation()
	input := map[string]any{"observation": observation}
	var result application.Result
	a.request("POST", "/application-rules/test", "", input, &result, 200)
	if result.Status != "candidate" || result.MatchedRuleCount != 1 || result.Matches[0].RuleID != first.ID || result.Matches[0].Revision != 1 || result.ObservationSHA256 != application.Digest(observation) || result.Origin != "user_supplied_metadata" {
		t.Fatal("验证来源或实际规则不一致")
	}
	b.request("POST", "/application-rules/test", "", input, &result, 200)
	if result.Status != "unknown" || result.RuleCount != 0 {
		t.Fatal("测试材料跨租户匹配")
	}
	v.request("POST", "/application-rules/test", "", input, &result, 200)
	if result.Status != "candidate" {
		t.Fatal("只读用户无法验证可读规则")
	}
	observation.HTTPHost = "files.example.attacker.example"
	a.request("POST", "/application-rules/test", "", map[string]any{"observation": observation}, &result, 200)
	if result.Status != "unknown" {
		t.Fatal("欺骗域名后缀被识别")
	}
	observation = application.Observation{SchemaVersion: application.ObservationSchema, Protocol: "tls", TLSALPN: []string{}, DNSNames: []string{}}
	a.request("POST", "/application-rules/test", "", map[string]any{"observation": observation}, &result, 200)
	if result.Status != "unknown" || result.Reason != "metadata_unavailable" {
		t.Fatal("未观测到 SNI 仍推断产品")
	}
	other := applicationRuleInput("app_second")
	other.Definition.ProductID = "owned_second"
	other.Definition.ProductName = "另一业务产品"
	var second application.Record
	a.request("POST", "/application-rules", "app_create_second", other, &second, 200)
	a.request("POST", "/application-rules/test", "", input, &result, 200)
	if result.Status != "conflict" || result.MatchedRuleCount != 2 {
		t.Fatal("产品冲突被掩盖")
	}
	a.request("GET", "/application-rules?limit=1", "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].ID != first.ID || page.NextCursor != first.ID {
		t.Fatal("首个目录游标不一致")
	}
	a.request("GET", "/application-rules?limit=1&cursor="+page.NextCursor, "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].ID != second.ID || page.NextCursor != "" {
		t.Fatal("后续规则目录遗漏")
	}
	edited := applicationRuleEdit(second)
	off := false
	edited.Active = &off
	a.request("POST", "/application-rules", "app_disable_second", edited, &replayed, 200)
	a.request("POST", "/application-rules/test", "", input, &result, 200)
	if result.Status != "candidate" || result.RuleCount != 1 {
		t.Fatal("停用规则仍参与验证")
	}
	a.request("GET", "/application-rules/app_second/revisions/1", "", nil, &replayed, 200)
	if !replayed.Active || replayed.Definition.ProductID != "owned_second" {
		t.Fatal("历史修订被改写")
	}
	a.request("POST", "/application-rules", "app_create_second", other, &replayed, 200)
	if replayed.Revision != 1 {
		t.Fatal("原提交回执被最新修订覆盖")
	}
	a.request("POST", "/application-rules", "app_stale_second", edited, nil, 409)
	a.request("GET", "/application-rules?active=false&keyword=业务", "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].Active {
		t.Fatal("目录状态筛选不一致")
	}
	a.request("POST", "/application-rules", "app_no_change", applicationRuleEdit(page.Items[0]), nil, 400)
	a.request("GET", "/application-rules?unknown=x", "", nil, nil, 400)
	a.request("GET", "/application-rules?limit=20&limit=10", "", nil, nil, 400)
	for _, revision := range []string{"0", "01", "+1", "1000001", "invalid"} {
		a.request("GET", "/application-rules/app_files/revisions/"+revision, "", nil, nil, 400)
	}
	a.request("GET", "/application-rules/app_files/revisions/1?unexpected=1", "", nil, nil, 400)
	preview := c.Definition
	preview.ProductID = "unsaved_product"
	v.request("POST", "/application-rules/preview", "", map[string]any{"definition": preview, "observation": applicationObservation()}, &result, 200)
	if result.Status != "candidate" || result.Matches[0].RuleID != "candidate_rule" || result.Matches[0].ProductID != "unsaved_product" {
		t.Fatal("未保存规则验证与目录混淆")
	}
	a.request("GET", "/application-rules", "", nil, &page, 200)
	if len(page.Items) != 2 {
		t.Fatal("候选预览写入了正式规则")
	}
	var auditCount, leaked int
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE object_id LIKE '%files.example%' OR reason LIKE '%FILES.EXAMPLE%' OR reason LIKE '%documents%') FROM operation_audits WHERE tenant_id=$1 AND action LIKE 'application.rule.%'`, u.TenantID).Scan(&auditCount, &leaked)
	}))
	if auditCount < 10 || leaked != 0 {
		t.Fatal("验证与维护未审计或材料进入审计")
	}
}

func TestApplicationRuleCASRetentionAndPermissionRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	f, u, _, _ := accountFixture(t, ctx)
	input := applicationRuleInput("app_concurrent")
	first, err := f.Runtime.SaveApplicationRule(ctx, u, "app_initial", input)
	require(t, err)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			edit := applicationRuleEdit(first)
			edit.Name = fmt.Sprintf("并发规则 %d", i)
			_, err := f.Runtime.SaveApplicationRule(ctx, u, fmt.Sprintf("app_race_%d", i), edit)
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
		_, err := tx.Exec(ctx, `UPDATE application_rule_revisions SET created_at=now()-interval '181 days',expires_at=now()-interval '1 hour' WHERE tenant_id=$1`, u.TenantID)
		return err
	}))
	_, err = f.Runtime.ApplicationRule(ctx, u, input.ID, 1)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("已过期历史仍可读", err)
	}
	current, err := f.Runtime.ApplicationRule(ctx, u, input.ID, 2)
	require(t, err)
	if current.Revision != 2 {
		t.Fatal("当前配置按历史期限失效")
	}
	_, err = f.Runtime.SweepHistory(ctx)
	require(t, err)
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM application_rule_revisions WHERE tenant_id=$1`, u.TenantID).Scan(&protected)
	}))
	if protected != 1 {
		t.Fatal("未清理过期历史或清理了当前规则", protected)
	}
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET active=false,revision=revision+1 WHERE tenant_id=$1 AND id=$2`, u.TenantID, u.ID)
		return err
	}))
	if _, err := f.Runtime.ApplicationRules(ctx, u, application.ListQuery{Limit: 20}); !errors.Is(err, application.ErrPermission) {
		t.Fatal("停用账号仍可读取规则", err)
	}
	if _, err := f.Runtime.SaveApplicationRule(ctx, u, "app_after_revoke", applicationRuleEdit(current)); !errors.Is(err, application.ErrPermission) {
		t.Fatal("停用账号仍可保存规则", err)
	}
	if _, err := f.Runtime.TestApplicationRules(ctx, u, applicationObservation(), nil); !errors.Is(err, application.ErrPermission) {
		t.Fatal("停用账号仍可测试规则", err)
	}
	if _, err := f.Runtime.SaveApplicationRule(ctx, model.Principal{ID: u.ID, TenantID: u.TenantID, Role: "viewer"}, "app_viewer", input); !errors.Is(err, application.ErrPermission) {
		t.Fatal("直接存储调用绕过管理员检查", err)
	}
	if _, err := f.Runtime.ApplicationRule(ctx, u, input.ID, 0); !errors.Is(err, application.ErrInput) {
		t.Fatal("无效修订被存储接受", err)
	}
	if _, err := f.Runtime.ApplicationRules(ctx, u, application.ListQuery{}); !errors.Is(err, application.ErrInput) {
		t.Fatal("无界目录被存储接受", err)
	}
	if _, err := f.Runtime.SaveApplicationRule(ctx, u, "/", input); !errors.Is(err, application.ErrInput) {
		t.Fatal("无效幂等键被存储接受", err)
	}
}

func TestApplicationRuleQuotaRollbackAndCorruptVersions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	f, u, _, password := accountFixture(t, ctx)
	for _, cut := range []string{"SET LOCAL lock_timeout", "SELECT pg_advisory_xact_lock", "SELECT u.active,u.role", "SELECT input_hash", "SELECT v.tenant_id,v.rule_id", "SELECT count(*) FROM application_rules", "SELECT count(*) FROM application_rule_revisions", "INSERT INTO application_rule_revisions", "INSERT INTO application_rules", "INSERT INTO operation_audits"} {
		broken, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, cut)
		input := applicationRuleInput(store.RandomID("app_fault_"))
		_, err := broken.SaveApplicationRule(ctx, u, store.RandomID("app_change_"), input)
		broken.Close()
		if err == nil || !tracer.fired.Load() {
			t.Fatal("断线注入没有触发应用规则事务", cut)
		}
		var exists bool
		require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM application_rules WHERE tenant_id=$1 AND id=$2) OR EXISTS(SELECT 1 FROM application_rule_revisions WHERE tenant_id=$1 AND rule_id=$2)`, u.TenantID, input.ID).Scan(&exists)
		}))
		if exists {
			t.Fatal("半提交规则或修订残留", cut)
		}
	}
	c := applicationRuleInput("app_quota")
	first, err := f.Runtime.SaveApplicationRule(ctx, u, "app_quota_initial", c)
	require(t, err)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE application_rule_revisions SET definition_sha256=$2 WHERE tenant_id=$1 AND rule_id=$3`, u.TenantID, strings.Repeat("0", 64), first.ID)
		return err
	}))
	a.request("GET", "/application-rules", "", nil, nil, 503)
	a.request("GET", "/application-rules/app_quota/revisions/1", "", nil, nil, 503)
	a.request("POST", "/application-rules/test", "", map[string]any{"observation": applicationObservation()}, nil, 503)
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE application_rule_revisions SET definition_sha256=$2 WHERE tenant_id=$1 AND rule_id=$3`, u.TenantID, first.DefinitionSHA256, first.ID)
		return err
	}))
	broken, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, "INSERT INTO operation_audits")
	_, err = broken.TestApplicationRules(ctx, u, applicationObservation(), nil)
	broken.Close()
	if err == nil || !tracer.fired.Load() {
		t.Fatal("审计失败没有阻止验证回执", err)
	}
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO application_rules(tenant_id,id,revision,name,active) SELECT $1,'app_limit_'||n,1,'额度规则',false FROM generate_series(1,$2) n`, u.TenantID, application.MaxRules-1); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO application_rule_revisions(tenant_id,rule_id,revision,name,description,active,definition,definition_sha256,created_by,key_hash,input_hash,expires_at) SELECT v.tenant_id,'app_limit_'||n,1,'额度规则','',false,v.definition,v.definition_sha256,v.created_by,'limit_'||n,'limit_'||n,now()+interval '180 days' FROM application_rule_revisions v CROSS JOIN generate_series(1,$2) n WHERE v.tenant_id=$1 AND v.rule_id=$3 AND v.revision=1`, u.TenantID, application.MaxRules-1, c.ID)
		return err
	}))
	if _, err := f.Runtime.SaveApplicationRule(ctx, u, "app_overquota", applicationRuleInput("app_extra")); !errors.Is(err, application.ErrQuota) {
		t.Fatal("规则目录额度未生效", err)
	}
	edit := applicationRuleEdit(first)
	edit.Name = "目录额度下编辑"
	second, err := f.Runtime.SaveApplicationRule(ctx, u, "app_edit_at_quota", edit)
	require(t, err)
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO application_rule_revisions(tenant_id,rule_id,revision,name,description,active,definition,definition_sha256,created_by,key_hash,input_hash,expires_at) SELECT v.tenant_id,v.rule_id,n+10,'变更额度材料','',false,v.definition,v.definition_sha256,v.created_by,'daily_'||n,'daily_'||n,now()+interval '180 days' FROM application_rule_revisions v CROSS JOIN generate_series(1,$2) n WHERE v.tenant_id=$1 AND v.rule_id=$3 AND v.revision=1`, u.TenantID, application.MaxDailyChanges, c.ID)
		return err
	}))
	edit = applicationRuleEdit(second)
	edit.Name = "超出每日额度"
	if _, err := f.Runtime.SaveApplicationRule(ctx, u, "app_daily_overquota", edit); !errors.Is(err, application.ErrQuota) {
		t.Fatal("每日变更额度未生效", err)
	}
	// 额度不能影响已经持久确认的同一提交。
	if repeated, err := f.Runtime.SaveApplicationRule(ctx, u, "app_quota_initial", c); err != nil || repeated.Revision != 1 {
		t.Fatal("额度阻止原请求确认", err)
	}
}
