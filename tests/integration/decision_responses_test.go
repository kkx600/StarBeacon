//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/triage"
)

func decisionResponseFixture(t *testing.T, ctx context.Context) (*isolatedDatabase, model.Principal, ed25519.PrivateKey, decision.Evaluation, decision.ResponseRequest, triage.Evidence, string) {
	t.Helper()
	f, u, signer, input, password := responseTaskFixture(t, ctx)
	_, request := decisionArchiveFixture(t, ctx, f, u)
	evaluation, err := f.Runtime.CreateDecisionEvaluation(ctx, u, "response_archive", request)
	require(t, err)
	job, err := f.Runtime.AlertTriage(ctx, u, request.TriageID)
	require(t, err)
	return f, u, signer, evaluation, decision.ResponseRequest{EvaluationSHA256: evaluation.SHA256, SensorID: "sensor_response", RegistrationID: "registration_response", ConnectorID: input.ConnectorID, ConfigSHA256: input.ConfigSHA256, TTLSeconds: 300, Reason: "管理员核对原告警后确认", Confirmed: true}, job.Evidence, password
}

func TestDecisionResponseAtomicConsentIdempotencyOwnershipAndRetention(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, signer, evaluation, request, evidence, password := decisionResponseFixture(t, ctx)
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE retention_policies SET days=7 WHERE tenant_id=$1 AND category='operations'`, u.TenantID)
		return e
	}))
	var wg sync.WaitGroup
	results := make(chan decision.ResponseRecord, 2)
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := f.Runtime.CreateDecisionResponse(ctx, u, evaluation.ID, "consent_original", request, evidence, signer)
			results <- r
			errs <- e
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		require(t, e)
	}
	var first decision.ResponseRecord
	for r := range results {
		if first.ID != "" && first.ID != r.ID {
			t.Fatal("并发确认产生多个授权")
		}
		first = r
	}
	sealed, err := first.Seal()
	require(t, err)
	if sealed.SHA256 != first.SHA256 || first.ExpiresAt.Sub(first.CreatedAt) != 7*24*time.Hour || first.TargetIP != evaluation.Result.TargetIP || first.EvaluationSHA256 != evaluation.SHA256 {
		t.Fatal("授权失去原材料绑定或自定义保留期")
	}
	tasks, err := f.Runtime.Tasks(ctx, u.TenantID, request.SensorID)
	require(t, err)
	if len(tasks) != 1 || tasks[0].ID != first.TaskID || tasks[0].ResponseAction == nil || tasks[0].ResponseAction.TargetIP != first.TargetIP || tasks[0].ResponseAction.OwnerSHA256 != responseapi.Owner(u.TenantID, request.SensorID, request.RegistrationID, first.TaskID) {
		t.Fatal("原授权与签名任务不一致")
	}
	var audits int
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND (action='decision.response.confirm' OR action='sensor.task.response.block')`, u.TenantID).Scan(&audits)
	}))
	if audits != 2 {
		t.Fatal("任务与授权审计不完整", audits)
	}
	if _, err = f.Runtime.CreateDecisionResponse(ctx, u, evaluation.ID, "consent_other_key", request, evidence, signer); !errors.Is(err, store.ErrConflict) {
		t.Fatal("换键重复授权", err)
	}
	changed := request
	changed.TTLSeconds++
	if _, err = f.Runtime.ExistingDecisionResponse(ctx, u, evaluation.ID, "consent_original", changed); !errors.Is(err, store.ErrConflict) {
		t.Fatal("换期限复用请求键", err)
	}
	on := true
	other, err := f.Runtime.CreateUser(ctx, u, "consent_other_user", accounts.Create{Username: "consent_other", Password: password, Role: "admin", Active: &on})
	require(t, err)
	otherPrincipal, _, err := f.Runtime.Password(ctx, other.Username)
	require(t, err)
	if r, err := f.Runtime.DecisionResponse(ctx, otherPrincipal, evaluation.ID); err != nil || r != nil {
		t.Fatal("授权档案跨账号泄露", err)
	}
	if _, err := f.Runtime.CreateDecisionResponse(ctx, otherPrincipal, evaluation.ID, "consent_foreign_record", request, evidence, signer); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("他人评估暴露已有授权或允许创建任务", err)
	}
	viewer := u
	viewer.Role = "viewer"
	if _, err = f.Runtime.CreateDecisionResponse(ctx, viewer, evaluation.ID, "consent_viewer_key", request, evidence, signer); !errors.Is(err, responseapi.ErrPermission) {
		t.Fatal("只读账号获得授权", err)
	}
	// 运行角色不能修改历史授权，也不能删除尚未到期的授权。
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var update bool
		if e := tx.QueryRow(ctx, `SELECT has_table_privilege(current_user,'decision_responses','UPDATE')`).Scan(&update); e != nil {
			return e
		}
		if update {
			t.Fatal("运行角色可以更新历史授权")
		}
		tag, e := tx.Exec(ctx, `DELETE FROM decision_responses WHERE tenant_id=$1`, u.TenantID)
		if e == nil && tag.RowsAffected() != 0 {
			t.Fatal("未到期授权可被删除")
		}
		return e
	}))
	require(t, f.Runtime.TenantTx(ctx, "tenant_foreign", func(tx pgx.Tx) error {
		var count int
		e := tx.QueryRow(ctx, `SELECT count(*) FROM decision_responses`).Scan(&count)
		if e == nil && count != 0 {
			t.Fatal("RLS 跨租户读取授权")
		}
		return e
	}))
	// 来源和设备按自己的生命周期回收后，原键确认只读取原档案，不补发任务。
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		for _, query := range []string{`DELETE FROM decision_evaluations WHERE tenant_id=$1`, `DELETE FROM alert_triage_jobs WHERE tenant_id=$1`, `UPDATE sensors SET active=false WHERE tenant_id=$1`} {
			if _, e := tx.Exec(ctx, query, u.TenantID); e != nil {
				return e
			}
		}
		return nil
	}))
	again, err := f.Runtime.CreateDecisionResponse(ctx, u, evaluation.ID, "consent_original", request, triage.Evidence{}, nil)
	require(t, err)
	if again.SHA256 != first.SHA256 || again.TaskID != first.TaskID {
		t.Fatal("原确认改写授权或补发任务")
	}
	r, err := f.Runtime.DecisionResponse(ctx, u, evaluation.ID)
	require(t, err)
	if r == nil || r.SHA256 != first.SHA256 {
		t.Fatal("来源回收删除独立授权")
	}
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE decision_responses SET created_at=now()-interval '8 days',expires_at=now()-interval '1 hour' WHERE tenant_id=$1`, u.TenantID)
		return e
	}))
	r, err = f.Runtime.DecisionResponse(ctx, u, evaluation.ID)
	require(t, err)
	if r != nil {
		t.Fatal("到期授权仍可读")
	}
	_, err = f.Runtime.SweepHistory(ctx)
	require(t, err)
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var n int
		e := tx.QueryRow(ctx, `SELECT count(*) FROM decision_responses WHERE tenant_id=$1`, u.TenantID).Scan(&n)
		if e == nil && n != 0 {
			t.Fatal("到期授权未物理回收")
		}
		return e
	}))
}

func TestDecisionResponseRequalificationRollbackAndCorruptArchive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	f, u, signer, evaluation, request, evidence, _ := decisionResponseFixture(t, ctx)
	for _, change := range []func(*decision.ResponseRequest){func(r *decision.ResponseRequest) { r.Confirmed = false }, func(r *decision.ResponseRequest) { r.RegistrationID = "registration_replaced" }, func(r *decision.ResponseRequest) { r.ConfigSHA256 = control.Digest([]byte("replaced-config")) }} {
		input := request
		change(&input)
		if _, e := f.Runtime.CreateDecisionResponse(ctx, u, evaluation.ID, store.RandomID("consent_invalid_"), input, evidence, signer); e == nil {
			t.Fatal("无效授权来源被接受")
		}
	}
	changed := evidence
	changed.ObservedAt = changed.ObservedAt.Add(time.Second)
	changed, err := triage.Seal(changed)
	require(t, err)
	if _, err = f.Runtime.CreateDecisionResponse(ctx, u, evaluation.ID, "consent_changed_material", request, changed, signer); !errors.Is(err, decision.ErrSource) {
		t.Fatal("告警材料改变仍授权", err)
	}
	for _, cut := range []string{"SELECT input_hash FROM decision_responses", "SELECT registration_id FROM sensors", "INSERT INTO sensor_tasks", "INSERT INTO decision_responses", "INSERT INTO operation_audits"} {
		broken, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, cut)
		_, err = broken.CreateDecisionResponse(ctx, u, evaluation.ID, store.RandomID("consent_fault_"), request, evidence, signer)
		broken.Close()
		if err == nil || !tracer.fired.Load() {
			t.Fatal("事务故障没有触发", cut)
		}
		rows, e := f.Runtime.Tasks(ctx, u.TenantID, request.SensorID)
		require(t, e)
		if len(rows) != 0 {
			t.Fatal("回滚后仍有可投递任务")
		}
	}
	// 在任务及任务审计已经写入后，独立授权审计失败也必须整体回滚。
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `CREATE FUNCTION reject_response_consent() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'consent audit unavailable'; END $$; CREATE TRIGGER reject_response_consent BEFORE INSERT ON operation_audits FOR EACH ROW WHEN (NEW.action='decision.response.confirm') EXECUTE FUNCTION reject_response_consent()`)
		return e
	}))
	if _, err = f.Runtime.CreateDecisionResponse(ctx, u, evaluation.ID, "consent_audit_fault", request, evidence, signer); err == nil {
		t.Fatal("审计失败仍提交授权")
	}
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `DROP TRIGGER reject_response_consent ON operation_audits; DROP FUNCTION reject_response_consent()`)
		return e
	}))
	rows, err := f.Runtime.Tasks(ctx, u.TenantID, request.SensorID)
	require(t, err)
	if len(rows) != 0 {
		t.Fatal("独立审计失败留下任务")
	}
	first, err := f.Runtime.CreateDecisionResponse(ctx, u, evaluation.ID, "consent_integrity", request, evidence, signer)
	require(t, err)
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE decision_responses SET record=jsonb_set(record,'{target_ip}','"198.51.100.99"') WHERE tenant_id=$1 AND id=$2`, u.TenantID, first.ID)
		return e
	}))
	if _, err = f.Runtime.DecisionResponse(ctx, u, evaluation.ID); !errors.Is(err, decision.ErrSource) {
		t.Fatal("损坏授权仍可读", err)
	}
	if _, err = f.Runtime.ExistingDecisionResponse(ctx, u, evaluation.ID, "consent_integrity", request); !errors.Is(err, decision.ErrSource) {
		t.Fatal("损坏授权仍可确认", err)
	}
}

func TestDecisionResponseCannotAttachPreviouslyAuthorizedManualTask(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f, u, signer, evaluation, request, evidence, _ := decisionResponseFixture(t, ctx)
	key := "consent_namespace_original"
	manual := responseapi.Request{Kind: "response.block", Intent: responseapi.Intent{ConnectorID: request.ConnectorID, ConfigSHA256: request.ConfigSHA256, TargetIP: evaluation.Result.TargetIP, TTLSeconds: request.TTLSeconds, Reason: request.Reason}}
	id, err := f.Runtime.CreateResponseTask(ctx, u, request.SensorID, "decision_response_"+store.Hash(key)[:40], manual, signer)
	require(t, err)
	if _, err := f.Runtime.CreateDecisionResponse(ctx, u, evaluation.ID, key, request, evidence, signer); !errors.Is(err, store.ErrConflict) {
		t.Fatal("既有手工任务被追认为原评估授权", err)
	}
	r, err := f.Runtime.DecisionResponse(ctx, u, evaluation.ID)
	require(t, err)
	if r != nil {
		t.Fatal("拒绝绑定后仍留下授权档案")
	}
	rows, err := f.Runtime.Tasks(ctx, u.TenantID, request.SensorID)
	require(t, err)
	if len(rows) != 1 || rows[0].ID != id {
		t.Fatal("冲突改变原手工任务")
	}
}

func TestDecisionResponseCurrentPolicyAndAccountRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f, u, signer, evaluation, request, evidence, _ := decisionResponseFixture(t, ctx)
	edit := decisionPolicyEdit(evaluation.Policy)
	off := false
	edit.Active = &off
	_, err := f.Runtime.SaveDecisionPolicy(ctx, u, "consent_disable_policy", edit)
	require(t, err)
	if _, err = f.Runtime.CreateDecisionResponse(ctx, u, evaluation.ID, "consent_after_disable", request, evidence, signer); !errors.Is(err, decision.ErrSource) {
		t.Fatal("策略停用或修订变化后仍按历史结果授权", err)
	}
	rows, err := f.Runtime.Tasks(ctx, u.TenantID, request.SensorID)
	require(t, err)
	if len(rows) != 0 {
		t.Fatal("过期策略留下执行任务")
	}
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET active=false,revision=revision+1 WHERE tenant_id=$1 AND id=$2`, u.TenantID, u.ID)
		return err
	}))
	if _, err = f.Runtime.CreateDecisionResponse(ctx, u, evaluation.ID, "consent_disabled_actor", request, evidence, signer); !errors.Is(err, responseapi.ErrPermission) {
		t.Fatal("停用账号仍可确认处置", err)
	}
	if _, err = f.Runtime.DecisionResponse(ctx, u, evaluation.ID); !errors.Is(err, decision.ErrPermission) {
		t.Fatal("停用账号仍可读取授权", err)
	}
	if _, err = f.Runtime.ExistingDecisionResponse(ctx, u, evaluation.ID, "consent_disabled_actor", request); !errors.Is(err, decision.ErrPermission) {
		t.Fatal("停用账号仍可核对原提交", err)
	}
}

func TestDecisionResponseAuthenticatedHTTPUsesActualAlertAndOriginalConfirmation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, signer, evaluation, input, evidence, password := decisionResponseFixture(t, ctx)
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, err)
	index, err := contract.IndexName(u.TenantID, "alerts", time.Now().UTC().Format("2006-01-02"))
	require(t, err)
	require(t, es.EnsureIndex(ctx, index, time.Now().UTC().Format("2006-01-02")))
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		r, e := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(clean))
		require(t, e)
		r.Body.Close()
		if r.IsError() {
			t.Error("专属处置索引未回收")
		}
	})
	var eventTime time.Time
	for _, fact := range evidence.Facts {
		if fact.ID == "event.time" {
			eventTime, err = time.Parse(time.RFC3339Nano, fact.Value)
			require(t, err)
		}
	}
	alert := model.Alert{SchemaVersion: "alert.v1", TenantID: u.TenantID, EventID: evidence.EventID, RawSHA256: evidence.RawSHA256, SensorID: "sensor_owned", RegistrationID: "registration_owned", Timestamp: eventTime, ObservedAt: evidence.ObservedAt, ReceivedAt: evidence.ObservedAt, Source: model.Endpoint{IP: "192.0.2.10"}}
	alert.Event.Kind = "alert"
	alert.Rule.ID = "1000001"
	for _, e := range es.Bulk(ctx, index, []model.Alert{alert}) {
		require(t, e)
	}
	r, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
	require(t, err)
	r.Body.Close()
	if r.IsError() {
		t.Fatal("实际索引刷新失败")
	}
	api := &platform.API{DB: f.Runtime, ES: es, Signer: signer}
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, api, u.Username, password)
	path := "/decision-evaluations/" + evaluation.ID + "/response"
	var empty struct {
		Item *decision.ResponseRecord `json:"item"`
	}
	client.request("GET", path, "", nil, &empty, 200)
	if empty.Item != nil {
		t.Fatal("不存在授权却返回记录")
	}
	without := *client
	without.csrf = ""
	without.request("POST", path, "consent_no_csrf", input, nil, 403)
	var first, again decision.ResponseRecord
	client.request("POST", path, "consent_http_original", input, &first, 202)
	if first.TargetIP != alert.Source.IP || first.ExpiresAt.Sub(first.CreatedAt) != 180*24*time.Hour {
		t.Fatal("真实告警来源或默认保留期错误")
	}
	client.request("GET", path, "", nil, &empty, 200)
	if empty.Item == nil || empty.Item.SHA256 != first.SHA256 {
		t.Fatal("HTTP 原授权不可追溯")
	}
	client.request("POST", path, "consent_http_duplicate", input, nil, 409)
	// 关闭材料与签名服务后，原键确认仍有确定结果，不能产生第二个任务。
	api.ES = nil
	api.Signer = nil
	client.request("POST", path, "consent_http_original", input, &again, 200)
	if again.SHA256 != first.SHA256 || again.TaskID != first.TaskID {
		t.Fatal("服务不可用时改写原授权")
	}
	var original decision.Evaluation
	client.request("GET", "/decision-evaluations/"+evaluation.ID, "", nil, &original, 200)
	if original.SHA256 != evaluation.SHA256 || original.Result.ExecutionAuthorized {
		t.Fatal("人工确认改写影子结果")
	}
}

func verifyNativeDecisionResponse(t *testing.T, ctx context.Context, client *liveHTTP, job triage.Job, sensor string, device *genericHTTPDevice) {
	t.Helper()
	change := decisionPolicyInput("policy_native_consent")
	change.Definition.MaxAgeSeconds = 86400
	var policy decision.Record
	client.request("POST", "/decision-policies", "native_consent_policy", change, &policy, 200)
	var evaluation decision.Evaluation
	client.request("POST", "/decision-evaluations", "native_consent_evaluation", decision.EvaluationRequest{PolicyID: policy.ID, ExpectedRevision: policy.Revision, TriageID: job.ID}, &evaluation, 200)
	if evaluation.Result.Status != "matched" || evaluation.Result.TargetIP == "" || evaluation.Result.ExecutionAuthorized {
		t.Fatal("原生研判没有合法处置候选")
	}
	var sensors struct {
		Items []model.Sensor `json:"items"`
	}
	client.request("GET", "/sensors", "", nil, &sensors, 200)
	registration := ""
	for _, s := range sensors.Items {
		if s.ID == sensor {
			registration = s.RegistrationID
		}
	}
	input := decision.ResponseRequest{EvaluationSHA256: evaluation.SHA256, SensorID: sensor, RegistrationID: registration, ConnectorID: device.config.ID, ConfigSHA256: device.config.SHA256(), TTLSeconds: 300, Reason: "管理员确认原生告警的限时处置", Confirmed: true}
	path := "/decision-evaluations/" + evaluation.ID + "/response"
	var first, again decision.ResponseRecord
	client.request("POST", path, "native_consent_original", input, &first, 202)
	client.request("POST", path, "native_consent_original", input, &again, 200)
	if first.TaskID != again.TaskID || first.SHA256 != again.SHA256 {
		t.Fatal("原生处置重复签发")
	}
	wait := func(id, kind string) store.SensorTask {
		var result store.SensorTask
		eventually(t, ctx, "原生研判处置获得设备回执", func() bool {
			client.request("GET", "/tasks/"+id, "", nil, &result, 200)
			return result.State == "succeeded"
		})
		if result.Kind != kind || result.ResponseAction == nil || !result.RetainUntil.After(time.Now()) {
			t.Fatal("原生处置任务缺少冻结授权")
		}
		var receipt control.Receipt
		require(t, json.Unmarshal(result.Receipt, &receipt))
		var value responseapi.Result
		require(t, json.Unmarshal(receipt.Result, &value))
		require(t, value.Validate(*result.ResponseAction, kind, receipt.FinishedAt.UTC()))
		return result
	}
	original := wait(first.TaskID, "response.block")
	if original.ResponseAction.TargetIP != evaluation.Result.TargetIP {
		t.Fatal("设备动作更换告警来源")
	}
	for _, kind := range []string{"response.read", "response.revoke", "response.read"} {
		var accepted map[string]string
		client.request("POST", "/sensors/"+sensor+"/response-tasks", store.RandomID("native_consent_verify_"), responseapi.Request{Kind: kind, Intent: responseapi.Intent{ConnectorID: device.config.ID, ConfigSHA256: device.config.SHA256(), OriginalTaskID: first.TaskID, Reason: "核对本人原租约"}}, &accepted, 202)
		current := wait(accepted["id"], kind)
		if !current.ResponseAction.ExpiresAt.Equal(original.ResponseAction.ExpiresAt) {
			t.Fatal("原生回读延长租约")
		}
	}
	client.request("POST", path, "native_consent_other_key", input, nil, 409)
	var saved decision.Evaluation
	client.request("GET", "/decision-evaluations/"+evaluation.ID, "", nil, &saved, 200)
	if saved.SHA256 != evaluation.SHA256 || saved.Result.ExecutionAuthorized {
		t.Fatal("处置完成改写原生影子判断")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	if device.writes != 2 || device.deletes != 2 {
		t.Fatal("独立人工处置重复执行", device.writes, device.deletes)
	}
}
