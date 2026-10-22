//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
	"github.com/kkx600/StarBeacon/internal/watchlist"
)

func responseProtectionList(id, target string) watchlist.Change {
	c := watchlistInput(id)
	c.Definition.Values = []string{target}
	c.Definition.Sensors = []watchlist.Sensor{{SensorID: "sensor_response", RegistrationID: "registration_response"}}
	return c
}

func assertResponseProtectionCounts(t *testing.T, ctx context.Context, f *isolatedDatabase, tenant string, tasks, proofs int) {
	t.Helper()
	var actualTasks, actualProofs int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM sensor_tasks WHERE tenant_id=$1),(SELECT count(*) FROM response_watchlist_checks WHERE tenant_id=$1)`, tenant).Scan(&actualTasks, &actualProofs))
	if actualTasks != tasks || actualProofs != proofs {
		t.Fatal("授权任务与保护证明数量不一致", actualTasks, actualProofs, tasks, proofs)
	}
}

func assertFrozenResponseProtection(t *testing.T, ctx context.Context, f *isolatedDatabase, tenant, id string) store.SensorTask {
	t.Helper()
	task, err := f.Runtime.Task(ctx, tenant, id)
	require(t, err)
	if task.Kind != "response.block" || task.ResponseAction == nil || task.ResponseProtection == nil {
		t.Fatal("新封禁缺少冻结保护证明", task)
	}
	proof := task.ResponseProtection
	check, err := json.Marshal(proof.Check)
	require(t, err)
	var commandSHA, proofSHA string
	var retained, proofRetained time.Time
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT t.command_sha256,t.retain_until,p.command_sha256,p.expires_at FROM sensor_tasks t JOIN response_watchlist_checks p ON p.tenant_id=t.tenant_id AND p.task_id=t.id WHERE t.tenant_id=$1 AND t.id=$2`, tenant, id).Scan(&commandSHA, &retained, &proofSHA, &proofRetained))
	if proof.SchemaVersion != "response.protection.v1" || proof.CommandSHA256 != commandSHA || proofSHA != commandSHA || proof.CheckSHA256 != control.Digest(check) || proof.Check.SchemaVersion != watchlist.ResponseSchema || proof.Check.Matches == nil || len(proof.Check.Matches) != 0 || proof.Check.CheckedAt.Before(task.ResponseAction.RequestedAt.Add(-30*time.Second)) || proof.Check.CheckedAt.After(task.ResponseAction.RequestedAt.Add(30*time.Second)) || !proof.Check.CheckedAt.Before(task.ResponseAction.ExpiresAt) || !retained.Equal(proofRetained) || retained.Sub(task.CreatedAt) != 180*24*time.Hour {
		t.Fatal("保护证明未绑定命令、实际核对时间或原留存期限", proof, task)
	}
	return task
}

// 实际执行签名命令及受控 HTTPS 租约协议；不把该端点视为真实网络阻断设备。
func executeProtectionProtocolTask(t *testing.T, ctx context.Context, f *isolatedDatabase, identity transport.SensorIdentity, signer ed25519.PrivateKey, client *responseapi.Client, id, kind string) store.SensorTask {
	t.Helper()
	delivery, err := f.Runtime.NextTask(ctx, identity)
	require(t, err)
	if delivery == nil || delivery.ID != id || !ed25519.Verify(signer.Public().(ed25519.PublicKey), control.SignedBytes(delivery.Command), delivery.Signature) {
		t.Fatal("投递未绑定实际签名任务", delivery)
	}
	var command control.Command
	require(t, json.Unmarshal(delivery.Command, &command))
	require(t, control.Validate(command))
	if command.Kind != kind || command.RegistrationID != identity.RegistrationID || command.TenantID != identity.TenantID || command.SensorID != identity.SensorID {
		t.Fatal("命令注册或调用范围不一致", command)
	}
	action, err := responseapi.ReadAction(command.Payload)
	require(t, err)
	started := time.Now().UTC()
	result, err := client.Execute(ctx, kind, action)
	require(t, err)
	finished := time.Now().UTC()
	if !result.Verified || result.Effect != "not_observed" {
		t.Fatal("协议夹具冒充流量效果证明", result)
	}
	raw, err := json.Marshal(result)
	require(t, err)
	require(t, f.Runtime.SaveReceipt(ctx, identity, control.Receipt{CommandID: id, CommandSHA256: control.Digest(delivery.Command), State: "succeeded", StartedAt: started, FinishedAt: &finished, Result: raw}))
	task, err := f.Runtime.Task(ctx, identity.TenantID, id)
	require(t, err)
	if task.State != "succeeded" || task.ResponseAction == nil {
		t.Fatal("协议回执没有完成独立任务", task)
	}
	return task
}

func TestResponseProtectionOriginalConfirmationAndDeliveredLeaseOperations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	f, u, signer, input, password := responseTaskFixture(t, ctx)
	device := newGenericHTTPDevice(t, t.TempDir())
	input.ConnectorID, input.ConfigSHA256, input.TTLSeconds = device.config.ID, device.config.SHA256(), 300
	health := model.HostHealth{ObservedAt: time.Now().UTC(), CommandSignerSHA256: control.Digest(signer.Public().(ed25519.PublicKey)), TaskCapabilities: []string{"response.block", "response.read", "response.revoke"}, ResponseConnectors: []responseapi.Health{{ConnectorID: device.config.ID, DeviceID: device.config.DeviceID, Version: device.config.DeviceVersion, ConfigSHA256: device.config.SHA256(), Status: "ready", ObservedAt: time.Now().UTC(), MaxTTLSeconds: device.config.MaxTTLSeconds}}}
	rawHealth, err := json.Marshal(health)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE sensors SET health=$2,last_seen=clock_timestamp() WHERE tenant_id=$1 AND id='sensor_response'`, u.TenantID, rawHealth)
	require(t, err)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Signer: signer}, u.Username, password)
	path := "/sensors/sensor_response/response-tasks"
	var original, confirmed map[string]string
	a.request("POST", path, "protection_original", input, &original, 202)
	before := assertFrozenResponseProtection(t, ctx, f, u.TenantID, original["id"])
	if before.ResponseProtection.Check.StateSHA256 != watchlist.Digest([]watchlist.Reference{}) {
		t.Fatal("空名单状态没有明确冻结")
	}
	identity := transport.SensorIdentity{TenantID: u.TenantID, SensorID: "sensor_response", RegistrationID: "registration_response"}
	foreign := identity
	foreign.RegistrationID = "registration_foreign"
	if delivery, err := f.Runtime.NextTask(ctx, foreign); err != nil || delivery != nil {
		t.Fatal("另一注册代次取得原封禁任务", delivery, err)
	}
	deviceClient, err := responseapi.NewClient(device.config)
	require(t, err)
	defer deviceClient.Close()
	done := executeProtectionProtocolTask(t, ctx, f, identity, signer, deviceClient, original["id"], "response.block")
	initialReceipt := string(done.Receipt)
	var receipt control.Receipt
	require(t, json.Unmarshal(done.Receipt, &receipt))
	if err := f.Runtime.SaveReceipt(ctx, foreign, receipt); !errors.Is(err, store.ErrConflict) {
		t.Fatal("另一注册代次确认原封禁回执", err)
	}
	other, _, err := f.Runtime.Password(ctx, "users_owned_b")
	require(t, err)
	if _, err := f.Runtime.Task(ctx, other.TenantID, original["id"]); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("另一租户取得原封禁或保护证明", err)
	}
	require(t, f.Runtime.TenantTx(ctx, other.TenantID, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM response_watchlist_checks WHERE tenant_id=$1 AND task_id=$2`, u.TenantID, original["id"]).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatal("行级权限泄露另一租户的保护证明")
		}
		return nil
	}))
	_, err = f.Runtime.SaveWatchlist(ctx, u, "protection_enable", responseProtectionList("protect_original", input.TargetIP))
	require(t, err)
	a.request("POST", path, "protection_original", input, &confirmed, 202)
	if confirmed["id"] != original["id"] {
		t.Fatal("名单变化使原提交重发")
	}
	a.request("POST", path, "protection_denied", input, nil, 409)
	assertResponseProtectionCounts(t, ctx, f, u.TenantID, 1, 1)
	after := assertFrozenResponseProtection(t, ctx, f, u.TenantID, original["id"])
	if after.ResponseProtection.CheckSHA256 != before.ResponseProtection.CheckSHA256 {
		t.Fatal("原请求确认重新计算当前名单")
	}
	for index, kind := range []string{"response.read", "response.revoke"} {
		request := responseapi.Request{Kind: kind, Intent: responseapi.Intent{ConnectorID: input.ConnectorID, ConfigSHA256: input.ConfigSHA256, OriginalTaskID: original["id"], Reason: "名单变化后仍核对并解除原租约"}}
		key := "protection_read_original"
		if index == 1 {
			key = "protection_revoke_original"
		}
		var accepted map[string]string
		a.request("POST", path, key, request, &accepted, 202)
		current := executeProtectionProtocolTask(t, ctx, f, identity, signer, deviceClient, accepted["id"], kind)
		if current.ResponseProtection != nil || current.ResponseAction.LeaseID != original["id"] || !current.ResponseAction.ExpiresAt.Equal(done.ResponseAction.ExpiresAt) {
			t.Fatal("回读或解除重算名单、租约或期限", current)
		}
	}
	a.request("POST", path, "protection_new_block", input, nil, 409)
	assertResponseProtectionCounts(t, ctx, f, u.TenantID, 3, 1)
	after = assertFrozenResponseProtection(t, ctx, f, u.TenantID, original["id"])
	if string(after.Receipt) != initialReceipt || after.ResponseProtection.CheckSHA256 != before.ResponseProtection.CheckSHA256 {
		t.Fatal("独立回读和解除改写原任务历史")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	if device.writes != 1 || device.deletes != 1 {
		t.Fatal("重复请求或受保护新任务触发设备写入", device.writes, device.deletes)
	}
}

func TestResponseProtectionScopeTimeSourceAndCurrentPermission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	f, u, signer, input, _ := responseTaskFixture(t, ctx)
	c := responseProtectionList("protect_scope", input.TargetIP)
	off := false
	c.Active = &off
	record, err := f.Runtime.SaveWatchlist(ctx, u, "protect_scope_draft", c)
	require(t, err)
	for _, mode := range []string{"inactive", "observe", "future", "other_registration", "expired"} {
		active := true
		c.ExpectedRevision, c.Active = record.Revision, &active
		c.Definition.Kind = "protect"
		c.Definition.Sensors[0].RegistrationID = "registration_response"
		c.Definition.ValidFrom = time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
		c.Definition.ValidUntil = c.Definition.ValidFrom.Add(180 * 24 * time.Hour)
		switch mode {
		case "inactive":
			// 初始草稿本身用于本次核对，不创建无实质变更的修订。
			c.Active = &off
		case "observe":
			c.Definition.Kind = "observe"
		case "future":
			c.Definition.ValidFrom = time.Now().UTC().Truncate(time.Second).Add(time.Hour)
			c.Definition.ValidUntil = c.Definition.ValidFrom.Add(time.Hour)
		case "other_registration":
			// 冻结旧范围，再在没有历史任务引用的独立探针上验证注册差异由底层门禁处理。
			c.Definition.Sensors[0] = watchlist.Sensor{SensorID: "protection_other_probe", RegistrationID: "registration_other"}
			_, err := f.Owner.Pool.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id,active) VALUES($1,'protection_other_probe','另一采集点','registration_other',true)`, u.TenantID)
			require(t, err)
		case "expired":
			c.Definition.Sensors[0] = watchlist.Sensor{SensorID: "sensor_response", RegistrationID: "registration_response"}
			c.Definition.ValidUntil = time.Now().UTC().Truncate(time.Second).Add(3 * time.Second)
		}
		if mode != "inactive" {
			record, err = f.Runtime.SaveWatchlist(ctx, u, "protect_scope_"+mode, c)
			require(t, err)
		}
		if mode == "expired" {
			timer := time.NewTimer(time.Until(c.Definition.ValidUntil) + 25*time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				t.Fatal(ctx.Err())
			case <-timer.C:
			}
		}
		id, err := f.Runtime.CreateResponseTask(ctx, u, "sensor_response", "protect_allowed_"+mode, input, signer)
		require(t, err)
		assertFrozenResponseProtection(t, ctx, f, u.TenantID, id)
		// 未投递夹具只取消待办，用于后续范围核对，不构造设备执行成功。
		_, err = f.Owner.Pool.Exec(ctx, `UPDATE sensor_tasks SET state='cancelled' WHERE tenant_id=$1 AND id=$2 AND state='queued' AND delivery_count=0`, u.TenantID, id)
		require(t, err)
	}
	foreign, _, err := f.Runtime.Password(ctx, "users_owned_b")
	require(t, err)
	if _, err = f.Runtime.CreateResponseTask(ctx, foreign, "sensor_response", "protect_foreign_denied", input, signer); err == nil {
		t.Fatal("另一租户授权本租户封禁")
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE watchlist_revisions SET definition_sha256=$3 WHERE tenant_id=$1 AND list_id=$2 AND revision=$4`, u.TenantID, record.ID, store.Hash("corrupt-definition"), record.Revision)
	require(t, err)
	if _, err = f.Runtime.CreateResponseTask(ctx, u, "sensor_response", "protect_corrupt_denied", input, signer); !errors.Is(err, watchlist.ErrSource) || !errors.Is(err, responseapi.ErrUnavailable) {
		t.Fatal("损坏名单被当作空名单继续授权", err)
	}
	assertResponseProtectionCounts(t, ctx, f, u.TenantID, 5, 5)
	confirmed, err := f.Runtime.CreateResponseTask(ctx, u, "sensor_response", "protect_allowed_inactive", input, signer)
	require(t, err)
	if confirmed == "" {
		t.Fatal("原键确认受当前损坏名单影响")
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE users SET role='viewer',revision=revision+1 WHERE tenant_id=$1 AND id=$2`, u.TenantID, u.ID)
	require(t, err)
	for _, key := range []string{"protect_allowed_inactive", "protect_revoked_new"} {
		if _, err = f.Runtime.CreateResponseTask(ctx, u, "sensor_response", key, input, signer); !errors.Is(err, responseapi.ErrPermission) {
			t.Fatal("当前权限撤回后仍确认或创建授权", key, err)
		}
	}
	assertResponseProtectionCounts(t, ctx, f, u.TenantID, 5, 5)
}

func TestResponseProtectionRollbackImmutabilitySourceAndRetention(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	f, u, signer, input, _ := responseTaskFixture(t, ctx)
	for _, cut := range []string{"INSERT INTO response_watchlist_checks", "INSERT INTO operation_audits"} {
		broken, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, cut)
		_, err := broken.CreateResponseTask(ctx, u, "sensor_response", store.RandomID("protection_cut_"), input, signer)
		broken.Close()
		if err == nil || !tracer.fired.Load() {
			t.Fatal("保护证明事务故障未到达预期写入", cut, err)
		}
		assertResponseProtectionCounts(t, ctx, f, u.TenantID, 0, 0)
	}
	id, err := f.Runtime.CreateResponseTask(ctx, u, "sensor_response", "protection_retained", input, signer)
	require(t, err)
	task := assertFrozenResponseProtection(t, ctx, f, u.TenantID, id)
	err = f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE response_watchlist_checks SET check_sha256=$3 WHERE tenant_id=$1 AND task_id=$2`, u.TenantID, id, store.Hash("changed"))
		return err
	})
	var permission *pgconn.PgError
	if !errors.As(err, &permission) || permission.Code != "42501" {
		t.Fatal("运行角色能改写已授权证明", err)
	}
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM response_watchlist_checks WHERE tenant_id=$1 AND task_id=$2`, u.TenantID, id)
		if tag.RowsAffected() != 0 {
			t.Fatal("未到期证明可删除")
		}
		return err
	}))
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE response_watchlist_checks SET command_sha256=$3 WHERE tenant_id=$1 AND task_id=$2`, u.TenantID, id, store.Hash("other-command"))
	require(t, err)
	if _, err := f.Runtime.Task(ctx, u.TenantID, id); !errors.Is(err, watchlist.ErrSource) {
		t.Fatal("错误命令摘要的保护证明仍可读", err)
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE response_watchlist_checks SET command_sha256=$3 WHERE tenant_id=$1 AND task_id=$2`, u.TenantID, id, task.ResponseProtection.CommandSHA256)
	require(t, err)
	// 留存测试只改变专属数据库的日期与责任状态，不表示设备曾执行任何动作。
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE sensor_tasks SET retain_until=now()-interval '1 hour',state='running',delivery_count=1 WHERE tenant_id=$1 AND id=$2`, u.TenantID, id); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE response_watchlist_checks SET expires_at=now()-interval '1 hour' WHERE tenant_id=$1 AND task_id=$2`, u.TenantID, id)
		return err
	}))
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM response_watchlist_checks WHERE tenant_id=$1 AND task_id=$2`, u.TenantID, id)
		if tag.RowsAffected() != 0 {
			t.Fatal("未决执行责任的证明被删除")
		}
		return err
	}))
	_, err = f.Runtime.SweepHistory(ctx)
	require(t, err)
	assertResponseProtectionCounts(t, ctx, f, u.TenantID, 1, 1)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE sensor_tasks SET state='failed' WHERE tenant_id=$1 AND id=$2`, u.TenantID, id)
	require(t, err)
	first, err := f.Runtime.SweepHistory(ctx)
	require(t, err)
	if first.ByTable["response_watchlist_checks"] != 1 || first.ByTable["sensor_tasks"] != 0 {
		t.Fatal("子证明必须先于父任务回收", first)
	}
	assertResponseProtectionCounts(t, ctx, f, u.TenantID, 1, 0)
	second, err := f.Runtime.SweepHistory(ctx)
	require(t, err)
	if second.ByTable["sensor_tasks"] != 1 {
		t.Fatal("证明回收后终态父任务仍不能删除", second)
	}
	assertResponseProtectionCounts(t, ctx, f, u.TenantID, 0, 0)
}

func TestResponseProtectionContinuousDecisionIsSkippedWithoutAuthorization(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	f, candidate, signer, job, _ := continuousFixture(t, ctx, "automatic")
	u := candidate.Principal
	c := responseProtectionList("protect_continuous", "192.0.2.10")
	_, err := f.Runtime.SaveWatchlist(ctx, u, "protect_continuous_enable", c)
	require(t, err)
	evaluation, record := completeContinuous(t, ctx, f, candidate, job, signer)
	if record.State != "skipped" || record.Code != "target_protected" || record.TaskID != "" {
		t.Fatal("保护命中仍生成持续自动封禁", record)
	}
	assertResponseProtectionCounts(t, ctx, f, u.TenantID, 0, 0)
	stored, err := f.Runtime.ContinuousDecision(ctx, u, evaluation.ID)
	require(t, err)
	if stored == nil || stored.SHA256 != record.SHA256 {
		t.Fatal("保护拒绝未保留不可变运行依据", stored)
	}
	off := false
	c.ExpectedRevision, c.Active = 1, &off
	_, err = f.Runtime.SaveWatchlist(ctx, u, "protect_continuous_disable", c)
	require(t, err)
	repeated, err := f.Runtime.CompleteContinuousDecision(ctx, candidate, evaluation.ID, job.Evidence, signer)
	require(t, err)
	if repeated.SHA256 != record.SHA256 || repeated.TaskID != "" {
		t.Fatal("名单变化使原运行重新授权", repeated)
	}
	assertResponseProtectionCounts(t, ctx, f, u.TenantID, 0, 0)
	// 数据库研判夹具只验证授权事务，不作为真实模型质量或设备流量效果证据。
	job = insertContinuousTriage(t, ctx, f, u, job, "triage_protection_new", "event_protection_new", "192.0.2.11")
	_, allowed := completeContinuous(t, ctx, f, candidate, job, signer)
	if allowed.State != "queued" || allowed.TaskID == "" {
		t.Fatal("无保护命中新研判未获得独立授权", allowed)
	}
	assertFrozenResponseProtection(t, ctx, f, u.TenantID, allowed.TaskID)
	assertResponseProtectionCounts(t, ctx, f, u.TenantID, 1, 1)
	if _, err := f.Runtime.CompleteContinuousDecision(ctx, store.DecisionCandidate{Principal: u, Policy: candidate.Policy, TriageID: "triage_missing"}, evaluation.ID, job.Evidence, signer); !errors.Is(err, decision.ErrSource) && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("不同研判身份复用了原评估", err)
	}
}
