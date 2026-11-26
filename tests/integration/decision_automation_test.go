//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/inventory"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/platform"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/triage"
)

func boundDecisionRequest(run decision.ContinuousRecord) decision.ResponseRequest {
	b := run.Config.Automatic
	return decision.ResponseRequest{EvaluationSHA256: run.EvaluationSHA256, SensorID: b.SensorID, RegistrationID: b.RegistrationID,
		ConnectorID: b.ConnectorID, ConfigSHA256: b.ConfigSHA256, TTLSeconds: b.TTLSeconds, Reason: "值班员核对完整材料", Confirmed: true}
}

func TestDecisionAutomationDefaultCeilingPauseAndShadowQualification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, c, signer, job, password := continuousAutomationFixture(t, ctx, "automatic", "", "")
	u := c.Principal
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	var automation decision.AutomationState
	client.request("GET", "/decision-automation", "", nil, &automation, 200)
	if automation.Settings != decision.DefaultAutomationSettings() || len(automation.Scenes) != 1 ||
		automation.Scenes[0].Level != decision.Full || automation.Scenes[0].Effective != decision.Approval {
		t.Fatal("升级未压住历史自动级别", automation)
	}
	e, pending := completeContinuous(t, ctx, f, c, job, signer)
	if pending.State != "awaiting_confirmation" || pending.TaskID != "" || pending.Plan == nil ||
		pending.Plan.Level != decision.Approval || pending.Plan.EvidenceSHA256 != e.Result.EvidenceSHA256 || pending.Plan.ConfirmUntil == nil {
		t.Fatal("默认级别未生成有效待确认方案", pending)
	}
	var page decision.PlanPage
	client.request("GET", "/decision-plans?limit=10", "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].Run.SHA256 != pending.SHA256 || page.Items[0].State != pending.State || page.NextCursor != "" {
		t.Fatal("待确认目录失去原方案", page)
	}
	pause := decision.AutomationSettings{}
	client.request("POST", "/decision-automation/pause", "", nil, &pause, 200)
	client.request("POST", "/decision-automation/pause", "", nil, &pause, 200)
	if !pause.Paused || pause.Revision != 1 {
		t.Fatal("应急暂停不是幂等操作", pause)
	}
	off := false
	client.request("PUT", "/decision-automation", "", decision.AutomationChange{
		ExpectedRevision: 0, Ceiling: decision.Full, Paused: &off,
	}, nil, 409)
	req := boundDecisionRequest(pending)
	bad := req
	bad.TTLSeconds++
	if _, err := f.Runtime.CreateDecisionResponse(ctx, u, e.ID, "automation_changed_scope", bad, job.Evidence, signer); !errors.Is(err, decision.ErrSource) {
		t.Fatal("人工确认放宽了原方案期限", err)
	}
	setProviderEnabled := func(enabled bool) {
		t.Helper()
		require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE model_providers SET public=jsonb_build_object('enabled',$2::boolean) WHERE tenant_id=$1`, u.TenantID, enabled)
			return err
		}))
	}
	setProviderEnabled(false)
	if _, err := f.Runtime.CreateDecisionResponse(ctx, u, e.ID, "automation_revoked_model", req, job.Evidence, signer); !errors.Is(err, decision.ErrSource) {
		t.Fatal("模型已停用仍确认原计划", err)
	}
	setProviderEnabled(true)
	record, err := f.Runtime.CreateDecisionResponse(ctx, u, e.ID, "automation_confirm_scope", req, job.Evidence, signer)
	require(t, err)
	task := assertFrozenResponseProtection(t, ctx, f, u.TenantID, record.TaskID)
	if task.ResponseAction.ExpiresAt.Sub(task.ResponseAction.RequestedAt) != time.Minute {
		t.Fatal("确认未沿用原租约期限")
	}
	client.request("GET", "/decision-plans?view=history", "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].State != "confirmed" || page.Items[0].TaskState != "queued" || page.Items[0].TaskID != task.ID {
		t.Fatal("确认与设备签发的状态未关联", page)
	}
	saveAutomationCeiling(t, ctx, f, u, decision.Observe, false)
	again, err := f.Runtime.CreateDecisionResponse(ctx, u, e.ID, "automation_confirm_scope", req, job.Evidence, signer)
	require(t, err)
	if again.SHA256 != record.SHA256 || again.TaskID != task.ID {
		t.Fatal("上限变化改写了已签发授权")
	}
	observed := insertContinuousTriage(t, ctx, f, u, job, "triage_automation_observe", "event_automation_observe", "192.0.2.30")
	observation, run := completeContinuous(t, ctx, f, c, observed, signer)
	if run.Code != "observation_only" || run.Plan.Level != decision.Observe || run.TaskID != "" {
		t.Fatal("仅观察仍取得设备授权", run)
	}
	if _, err := f.Runtime.CreateDecisionResponse(ctx, u, observation.ID, "automation_observe_confirm", boundDecisionRequest(run), observed.Evidence, signer); !errors.Is(err, decision.ErrPermission) {
		t.Fatal("仅观察可以人工绕过", err)
	}
	proposed := decisionPolicyEdit(c.Policy)
	proposed.ID, proposed.ExpectedRevision = "policy_new_scene", 0
	if _, err := f.Runtime.SaveDecisionPolicy(ctx, u, "automation_new_auto", proposed); !errors.Is(err, decision.ErrShadowRequired) {
		t.Fatal("新场景以自动级别直接启用", err)
	}
	shadow := proposed
	shadow.Definition = proposed.Definition.ShadowCriteria()
	shadow.Definition.Continuous = &decision.ContinuousConfig{ProviderID: job.Request.ProviderID, ProviderRevision: job.Request.ProviderRevision}
	scene, err := f.Runtime.SaveDecisionPolicy(ctx, u, "automation_new_shadow", shadow)
	require(t, err)
	proposed.ExpectedRevision = scene.Revision
	if _, err := f.Runtime.SaveDecisionPolicy(ctx, u, "automation_unqualified", proposed); !errors.Is(err, decision.ErrShadowRequired) {
		t.Fatal("缺少同一场景影子结果仍能提高", err)
	}
	shadowJob := insertContinuousTriage(t, ctx, f, u, job, "triage_automation_shadow", "event_automation_shadow", "192.0.2.35")
	_, shadowRun := completeContinuous(t, ctx, f, store.DecisionCandidate{Principal: u, Policy: scene}, shadowJob, signer)
	if shadowRun.Code != "observation_only" {
		t.Fatal("新场景未保存可复核观察", shadowRun)
	}
	proposed.Definition.Expression = `confidence >= threshold && verdict == "confirmed" && reference_count > 0`
	if _, err := f.Runtime.SaveDecisionPolicy(ctx, u, "automation_changed_criteria", proposed); !errors.Is(err, decision.ErrShadowRequired) {
		t.Fatal("不同判断门槛复用了影子结果", err)
	}
	proposed.Definition.Expression, proposed.Definition.Threshold = "true", 0.95
	loose := proposed
	loose.Definition = proposed.Definition.ShadowCriteria()
	scene, err = f.Runtime.SaveDecisionPolicy(ctx, u, "automation_loose_shadow", loose)
	require(t, err)
	matched, err := f.Runtime.CreateDecisionEvaluation(ctx, u, "automation_loose_proof", decision.EvaluationRequest{
		PolicyID: scene.ID, ExpectedRevision: scene.Revision, TriageID: shadowJob.ID,
	})
	require(t, err)
	if matched.Result.Status != "matched" {
		t.Fatal("低置信度夹具须单独证明表达式已命中")
	}
	proposed.ExpectedRevision = scene.Revision
	if _, err := f.Runtime.SaveDecisionPolicy(ctx, u, "automation_loose_promotion", proposed); !errors.Is(err, decision.ErrShadowRequired) {
		t.Fatal("仅表达式命中的低置信度材料取得提级资格", err)
	}
	assertResponseProtectionCounts(t, ctx, f, u.TenantID, 1, 1)
}

func TestDecisionAutomationConditionalInternalAndProtectedDestination(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, c, signer, job, _ := continuousAutomationFixture(t, ctx, "automatic", decision.Conditional, decision.Conditional)
	u := c.Principal
	network, err := json.Marshal(inventory.Network{Name: "自有公网段", Prefix: "192.0.2.10/32", NetworkDomain: "验收", Purpose: "internal", Active: true})
	require(t, err)
	_, err = f.Runtime.SaveInventory(ctx, u, "networks", "network_owned", 0, network, "automation_inventory")
	require(t, err)
	_, internal := completeContinuous(t, ctx, f, c, job, signer)
	if internal.State != "awaiting_confirmation" || internal.Plan.Impact != "high" || internal.Plan.Level != decision.Conditional || internal.TaskID != "" {
		t.Fatal("条件自动误处置已登记的内网来源", internal)
	}
	asset, err := json.Marshal(inventory.Asset{Name: "自有公网资产", NetworkDomain: "验收", Criticality: "normal", Active: true,
		Interfaces: []inventory.Interface{{Name: "eth0", IPs: []string{"192.0.2.38"}}}})
	require(t, err)
	_, err = f.Runtime.SaveInventory(ctx, u, "assets", "asset_decision_owned", 0, asset, "automation_inventory")
	require(t, err)
	assetJob := insertContinuousTriage(t, ctx, f, u, job, "triage_automation_asset", "event_automation_asset", "192.0.2.38")
	_, assetPlan := completeContinuous(t, ctx, f, c, assetJob, signer)
	if assetPlan.State != "awaiting_confirmation" || assetPlan.Plan.Impact != "high" {
		t.Fatal("条件自动误处置自有资产接口", assetPlan)
	}
	page, err := f.Runtime.DecisionPlans(ctx, u, "pending", "", 1)
	require(t, err)
	if len(page.Items) != 1 || page.Items[0].Run.ID != internal.ID || page.NextCursor != internal.ID {
		t.Fatal("未按确认时限提供第一页", page)
	}
	page, err = f.Runtime.DecisionPlans(ctx, u, "pending", page.NextCursor, 1)
	require(t, err)
	if len(page.Items) != 1 || page.Items[0].Run.ID != assetPlan.ID || page.NextCursor != "" {
		t.Fatal("待确认游标未接续原页", page)
	}
	external := insertContinuousTriage(t, ctx, f, u, job, "triage_automation_external", "event_automation_external", "192.0.2.40")
	_, queued := completeContinuous(t, ctx, f, c, external, signer)
	if queued.State != "queued" || queued.Plan.Impact != "small" || queued.TaskID == "" {
		t.Fatal("合格外部来源未通过条件自动门槛", queued)
	}
	paused, err := f.Runtime.ChangeDecisionAutomation(ctx, u, nil)
	require(t, err)
	if !paused.Paused {
		t.Fatal("暂停未生效")
	}
	later := insertContinuousTriage(t, ctx, f, u, job, "triage_automation_paused", "event_automation_paused", "192.0.2.41")
	pendingEvaluation, pausedPlan := completeContinuous(t, ctx, f, c, later, signer)
	if pausedPlan.State != "awaiting_confirmation" || pausedPlan.Plan.Level != decision.Approval {
		t.Fatal("暂停后仍签发新自动任务", pausedPlan)
	}
	if _, err := f.Runtime.CreateDecisionResponse(ctx, u, pendingEvaluation.ID, "automation_shared_budget",
		boundDecisionRequest(pausedPlan), later.Evidence, signer); !errors.Is(err, responseapi.ErrQuota) {
		t.Fatal("人工确认可以绕过已经由自动处置耗尽的策略额度", err)
	}
	assertResponseProtectionCounts(t, ctx, f, u.TenantID, 1, 1)

	f2, c2, signer2, job2, _ := continuousAutomationFixture(t, ctx, "automatic", decision.Full, decision.Full)
	job2.Evidence.Facts = append(job2.Evidence.Facts, triage.Fact{ID: "destination.ip", Label: "目的 IP", Value: "198.51.100.22"})
	protected := insertContinuousTriage(t, ctx, f2, c2.Principal, job2, "triage_protected_destination", "event_protected_destination", "192.0.2.45")
	_, err = f2.Runtime.SaveWatchlist(ctx, c2.Principal, "protect_decision_destination",
		responseProtectionList("list_decision_destination", "198.51.100.22"))
	require(t, err)
	_, blocked := completeContinuous(t, ctx, f2, c2, protected, signer2)
	if blocked.Code != "target_protected" || blocked.TaskID != "" {
		t.Fatal("全自动未遵守目的端保护", blocked)
	}
	assertResponseProtectionCounts(t, ctx, f2, c2.Principal.TenantID, 0, 0)
}

func TestDecisionPlanRejectionFeedbackAndTimeoutNotice(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, c, signer, job, password := continuousAutomationFixture(t, ctx, "automatic", "", "")
	u := c.Principal
	e, pending := completeContinuous(t, ctx, f, c, job, signer)
	input := decision.RejectPlan{PlanSHA256: pending.SHA256, Reason: "核对业务证据后驳回，加入评测"}
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	foreign := true
	user, err := f.Runtime.CreateUser(ctx, u, "decision_plan_other", accounts.Create{Username: "decision_plan_other", Password: password, Role: "admin", Active: &foreign})
	require(t, err)
	other, _, err := f.Runtime.Password(ctx, user.Username)
	require(t, err)
	if _, err := f.Runtime.RejectDecisionPlan(ctx, other, e.ID, input); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("其他账号能驳回私有方案", err)
	}
	rejectPath := "/decision-evaluations/" + e.ID + "/response/reject"
	invalid := input
	invalid.PlanSHA256 = strings.Repeat("a", 64)
	client.request("POST", rejectPath, "", invalid, nil, 409)
	var review, repeated decision.PlanReview
	client.request("POST", rejectPath, "", input, &review, 200)
	client.request("POST", rejectPath, "", input, &repeated, 200)
	if review != repeated || review.State != "rejected" || review.ActorID != u.ID || review.Reason != input.Reason {
		t.Fatal("驳回回执不是原有反馈样本", review, repeated)
	}
	if _, err := f.Runtime.CreateDecisionResponse(ctx, u, e.ID, "rejected_plan_confirm", boundDecisionRequest(pending), job.Evidence, signer); !errors.Is(err, decision.ErrPlanClosed) {
		t.Fatal("驳回后仍能确认", err)
	}
	replica := insertContinuousTriage(t, ctx, f, u, job, "triage_rejected_event", job.Request.EventID, "192.0.2.10")
	saveAutomationCeiling(t, ctx, f, u, decision.Full, false)
	_, rerun := completeContinuous(t, ctx, f, c, replica, signer)
	if rerun.Code != "plan_already_recorded" || rerun.TaskID != "" {
		t.Fatal("重复研判复用了已驳回告警的授权", rerun)
	}
	var page decision.PlanPage
	client.request("GET", "/decision-plans?view=feedback", "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].Review == nil || page.Items[0].Run.Plan.EvidenceSHA256 != job.Evidence.SHA256 {
		t.Fatal("评测样本没有原始材料摘要", page)
	}
	assertResponseProtectionCounts(t, ctx, f, u.TenantID, 0, 0)

	saveAutomationCeiling(t, ctx, f, u, decision.Approval, false)
	later := insertContinuousTriage(t, ctx, f, u, job, "triage_expired_plan", "event_expired_plan", "192.0.2.76")
	expiring, run := completeContinuous(t, ctx, f, c, later, signer)
	run.CreatedAt = run.CreatedAt.Add(-16 * time.Minute)
	deadline := run.CreatedAt.Add(decision.ConfirmationWindow)
	run.Plan.ConfirmUntil = &deadline
	run, err = run.Seal()
	require(t, err)
	raw, err := json.Marshal(run)
	require(t, err)
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE decision_continuous_runs SET created_at=$3,confirmation_deadline=$4,record=$5
			WHERE tenant_id=$1 AND id=$2`, u.TenantID, run.ID, run.CreatedAt, deadline, raw)
		return err
	}))
	if _, err := f.Runtime.CreateDecisionResponse(ctx, u, expiring.ID, "expired_plan_confirm", boundDecisionRequest(run), later.Evidence, signer); !errors.Is(err, decision.ErrPlanClosed) {
		t.Fatal("超时方案仍能确认", err)
	}
	vault, err := secrets.New(store.Token())
	require(t, err)
	on := true
	_, err = f.Runtime.SaveNotificationChannel(ctx, u, store.ChannelChange{ID: "channel_plan_timeout", Name: "处置超时测试",
		Kind: "webhook", Enabled: &on, Streams: []string{"quality"}, Severities: []string{"high"},
		Connection: &notify.Config{Endpoint: "https://notify.example.com/acceptance"}}, vault, outbound.Policy{}, "decision_timeout_setup")
	require(t, err)
	for _, statement := range []string{"INSERT INTO decision_plan_reviews", "INSERT INTO operation_audits", "INSERT INTO notification_batches"} {
		fault, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, statement)
		err = fault.ExpireDecisionPlans(ctx, u.TenantID, vault)
		fault.Close()
		if err == nil || !tracer.fired.Load() {
			t.Fatal("通知失败没有触发事务回滚", statement, err)
		}
	}
	for range 2 {
		require(t, f.Runtime.ExpireDecisionPlans(ctx, u.TenantID, vault))
	}
	notice, err := f.Runtime.LeaseNotification(ctx, u.TenantID, vault)
	require(t, err)
	if notice.Message.DecisionTimeout == nil || notice.Message.DecisionTimeout.PlanID != run.ID ||
		!notice.Message.DecisionTimeout.ExpiredAt.Equal(deadline) || !strings.Contains(notice.Message.Text(), "已超过确认时限") {
		t.Fatal("过期通知没有绑定原方案", notice.Message)
	}
	deliveries, _, err := f.Runtime.NotificationDeliveries(ctx, u.TenantID, "", "", 20)
	require(t, err)
	if len(deliveries) != 1 || deliveries[0].RecordCount != 1 || deliveries[0].Stream != "quality" {
		t.Fatal("超时通知重复或未按值班渠道投递", deliveries)
	}
	history, err := f.Runtime.DecisionPlans(ctx, u, "history", "", 20)
	require(t, err)
	var expired bool
	for _, item := range history.Items {
		if item.Run.ID == run.ID {
			expired = item.State == "expired" && item.Review != nil && item.TaskID == ""
		}
	}
	if !expired {
		t.Fatal("通知后缺少独立过期档案", history)
	}
	assertResponseProtectionCounts(t, ctx, f, u.TenantID, 0, 0)
}

func TestDecisionPlanReviewRaceAndSettingsRollback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, c, signer, job, password := continuousAutomationFixture(t, ctx, "automatic", "", "")
	u := c.Principal
	on, off := true, false
	viewer, err := f.Runtime.CreateUser(ctx, u, "automation_viewer", accounts.Create{
		Username: "automation_viewer", Role: "viewer", Password: password, Active: &on,
	})
	require(t, err)
	view, _, err := f.Runtime.Password(ctx, viewer.Username)
	require(t, err)
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, view.Username, password)
	client.request("GET", "/decision-automation", "", nil, nil, 200)
	client.request("POST", "/decision-automation/pause", "", nil, nil, 403)
	client.request("PUT", "/decision-automation", "", decision.AutomationChange{Ceiling: decision.Full, Paused: &off}, nil, 403)
	e, pending := completeContinuous(t, ctx, f, c, job, signer)
	if copy, err := f.Runtime.DecisionPlans(ctx, view, "pending", "", 20); err != nil || len(copy.Items) != 0 {
		t.Fatal("只读用户取得其他账号的研判材料", copy, err)
	}
	if _, err := f.Runtime.DecisionPlans(ctx, u, "pending", "continuous_absent", 20); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("未核对分页游标归属", err)
	}
	change := decision.AutomationChange{Ceiling: decision.Full, Paused: &off}
	for _, statement := range []string{"SELECT revision,ceiling,paused FROM decision_automation_settings", "INSERT INTO decision_automation_settings", "INSERT INTO operation_audits"} {
		fault, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, statement)
		_, err := fault.ChangeDecisionAutomation(ctx, u, &change)
		fault.Close()
		if err == nil || !tracer.fired.Load() {
			t.Fatal("设置事务故障未触发", statement, err)
		}
		result, err := f.Runtime.DecisionAutomation(ctx, u)
		require(t, err)
		if result.Settings.Revision != 0 || result.Settings.Ceiling != decision.Approval {
			t.Fatal("失败的设置变更绕过了原上限", result)
		}
	}
	input := decision.RejectPlan{PlanSHA256: pending.SHA256, Reason: "原材料须进一步核实"}
	for _, statement := range []string{"INSERT INTO decision_plan_reviews", "INSERT INTO operation_audits"} {
		fault, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, statement)
		_, err = fault.RejectDecisionPlan(ctx, u, e.ID, input)
		fault.Close()
		if err == nil || !tracer.fired.Load() {
			t.Fatal("驳回事务异常未触发", statement, err)
		}
	}
	kept, err := f.Runtime.DecisionPlans(ctx, u, "pending", "", 20)
	require(t, err)
	if len(kept.Items) != 1 || kept.Items[0].Run.SHA256 != pending.SHA256 {
		t.Fatal("失败的驳回留下了部分提交", kept)
	}
	var confirmationErr, rejectionErr error
	var operations sync.WaitGroup
	operations.Go(func() {
		_, confirmationErr = f.Runtime.CreateDecisionResponse(ctx, u, e.ID, "automation_race_confirm", boundDecisionRequest(pending), job.Evidence, signer)
	})
	operations.Go(func() {
		_, rejectionErr = f.Runtime.RejectDecisionPlan(ctx, u, e.ID, input)
	})
	operations.Wait()
	history, err := f.Runtime.DecisionPlans(ctx, u, "history", "", 20)
	require(t, err)
	if len(history.Items) != 1 {
		t.Fatal("并发审核丢失方案", history)
	}
	switch {
	case confirmationErr == nil && errors.Is(rejectionErr, decision.ErrPlanClosed):
		if history.Items[0].State != "confirmed" {
			t.Fatal("签发成功但流水不是已确认", history)
		}
		assertResponseProtectionCounts(t, ctx, f, u.TenantID, 1, 1)
	case rejectionErr == nil && errors.Is(confirmationErr, decision.ErrPlanClosed):
		if history.Items[0].State != "rejected" {
			t.Fatal("驳回成功但流水不是已驳回", history)
		}
		assertResponseProtectionCounts(t, ctx, f, u.TenantID, 0, 0)
	default:
		t.Fatal("确认与驳回没有形成唯一结果", confirmationErr, rejectionErr)
	}
}

func TestDecisionAutomationUnavailableAndCorruptPlansFailClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, c, signer, job, _ := continuousAutomationFixture(t, ctx, "automatic", decision.Conditional, decision.Conditional)
	u := c.Principal
	e, err := f.Runtime.CreateDecisionEvaluation(ctx, u, c.Key(), decision.EvaluationRequest{
		PolicyID: c.Policy.ID, ExpectedRevision: c.Policy.Revision, TriageID: c.TriageID,
	})
	require(t, err)
	for _, prefix := range []string{
		"SELECT revision,ceiling,paused FROM decision_automation_settings",
		"SELECT revision,COALESCE((public->>'enabled')",
		"SELECT EXISTS(SELECT 1 FROM decision_continuous_runs v",
		"SELECT EXISTS(SELECT 1 FROM inventory_objects n",
	} {
		fault, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
		_, err := fault.CompleteContinuousDecision(ctx, c, e.ID, job.Evidence, signer)
		fault.Close()
		if err == nil || !tracer.fired.Load() {
			t.Fatal("依赖故障未中止原方案", prefix, err)
		}
		if run, err := f.Runtime.ContinuousDecision(ctx, u, e.ID); err != nil || run != nil {
			t.Fatal("失败事务残留处置档案", run, err)
		}
	}
	assertResponseProtectionCounts(t, ctx, f, u.TenantID, 0, 0)
	saveAutomationCeiling(t, ctx, f, u, decision.Approval, false)
	pending, err := f.Runtime.CompleteContinuousDecision(ctx, c, e.ID, job.Evidence, signer)
	require(t, err)
	if pending.State != "awaiting_confirmation" {
		t.Fatal("重试后未保留唯一待确认方案", pending)
	}
	for _, prefix := range []string{"SELECT revision,ceiling,paused FROM decision_automation_settings", "SELECT h.id,h.name,h.revision,h.active,v.definition"} {
		fault, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
		_, err := fault.DecisionAutomation(ctx, u)
		fault.Close()
		if err == nil || !tracer.fired.Load() {
			t.Fatal("设置读取故障被冒充为可用数据", prefix, err)
		}
	}
	fault, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, "SELECT v.tenant_id,v.id,v.created_by,v.evaluation_id")
	_, err = fault.DecisionPlans(ctx, u, "pending", "", 20)
	fault.Close()
	if err == nil || !tracer.fired.Load() {
		t.Fatal("方案读取故障被冒充为空目录", err)
	}
	changed := u
	changed.CredentialRevision++
	if _, err := f.Runtime.DecisionAutomation(ctx, changed); !errors.Is(err, decision.ErrPermission) {
		t.Fatal("过期凭据仍可读取设置", err)
	}
	if _, err := f.Runtime.DecisionPlans(ctx, changed, "pending", "", 20); !errors.Is(err, decision.ErrPermission) {
		t.Fatal("过期凭据仍可读取私有方案", err)
	}
	if _, err := f.Runtime.RejectDecisionPlan(ctx, changed, e.ID, decision.RejectPlan{PlanSHA256: pending.SHA256, Reason: "测试账号"}); !errors.Is(err, responseapi.ErrPermission) {
		t.Fatal("过期凭据仍可驳回方案", err)
	}
	if _, err := f.Runtime.DecisionPlans(ctx, u, "unknown", "/", 0); !errors.Is(err, decision.ErrInput) {
		t.Fatal("不受控的目录参数被接受", err)
	}
	if _, err := f.Runtime.RejectDecisionPlan(ctx, u, e.ID, decision.RejectPlan{}); !errors.Is(err, decision.ErrInput) {
		t.Fatal("空驳回申请被接受", err)
	}
	if _, err := f.Runtime.ChangeDecisionAutomation(ctx, u, &decision.AutomationChange{Ceiling: "unknown"}); !errors.Is(err, decision.ErrInput) {
		t.Fatal("无效设置被接受", err)
	}
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE decision_continuous_runs SET confirmation_deadline=confirmation_deadline-interval '1 second'
			WHERE tenant_id=$1 AND id=$2`, u.TenantID, pending.ID)
		return err
	}))
	if _, err := f.Runtime.DecisionPlans(ctx, u, "pending", "", 20); !errors.Is(err, decision.ErrSource) {
		t.Fatal("不一致的确认时限仍可展示", err)
	}
	if _, err := f.Runtime.CreateDecisionResponse(ctx, u, e.ID, "automation_corrupt_deadline",
		boundDecisionRequest(pending), job.Evidence, signer); !errors.Is(err, decision.ErrSource) {
		t.Fatal("不一致的确认时限仍可签发任务", err)
	}
	assertResponseProtectionCounts(t, ctx, f, u.TenantID, 0, 0)
}
