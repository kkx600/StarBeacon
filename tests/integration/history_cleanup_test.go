//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/store"
)

// 使用专属实际 PG 数据库验证删除后的权威记录和引用关系，不以返回的统计数量代替验证。
func TestHistoryCleanupExpiryReferencesRuntimeIsolationAndRecovery(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
	defer stop()
	f := newIsolatedDatabase(t, ctx)
	for _, tenant := range []string{"history_a", "history_b"} {
		require(t, admin.Bootstrap(ctx, f.Owner, tenant, "生命周期验收", tenant, store.Token(), "admin"))
	}
	exec := func(query string, args ...any) {
		t.Helper()
		_, err := f.Owner.Pool.Exec(ctx, query, args...)
		require(t, err)
	}
	assertCount := func(query string, expected int) {
		t.Helper()
		var count int
		require(t, f.Owner.Pool.QueryRow(ctx, query).Scan(&count))
		if count != expected {
			t.Fatalf("生命周期结果与权威存储不一致：%s；%d / %d", query, count, expected)
		}
	}
	exec(`INSERT INTO operation_audits(tenant_id,user_id,action,object_id,request_id,expires_at) VALUES('history_a','owner','test','expired','test',now()-interval '1 minute'),('history_a','owner','test','live','test',now()+interval '1 day'),('history_b','owner','test','other_live','test',now()+interval '1 day')`)
	exec(`INSERT INTO login_audits(tenant_id,username,success,expires_at) VALUES('history_a','expired',true,now()-interval '1 minute'),('history_a','live',true,now()+interval '1 day'),(NULL,'anonymous_expired',false,now()-interval '1 minute'),(NULL,'anonymous_live',false,now()+interval '1 day')`)
	exec(`INSERT INTO inventory_objects(tenant_id,kind,id,name,revision,active,data) VALUES('history_a','assets','asset','当前资产',2,true,'{}')`)
	exec(`INSERT INTO inventory_history(tenant_id,kind,id,revision,name,active,data,valid_from,expires_at) VALUES('history_a','assets','asset',1,'历史资产',true,'{}',now()-interval '200 days',now()-interval '1 minute'),('history_a','assets','asset',2,'当前资产',true,'{}',now(),now()+interval '1 day')`)
	exec(`INSERT INTO retention_previews(tenant_id,id,created_by,candidate,current_days,expires_at) VALUES('history_a','expired_preview','owner','{}',180,now()-interval '1 minute'),('history_a','live_preview','owner','{}',180,now()+interval '1 day')`)
	exec(`INSERT INTO retention_changes(tenant_id,id,created_by,category,days,revision,request_hash,idempotency_key_hash,expires_at) VALUES('history_a','expired_change','owner','operations',180,2,'old','old',now()-interval '1 minute'),('history_a','live_change','owner','operations',180,3,'live','live',now()+interval '1 day')`)

	exec(`INSERT INTO notification_channels(tenant_id,id,revision,name,kind,enabled,severities,target) VALUES('history_a','channel',3,'通知渠道','webhook',true,'["high"]','https://example.invalid')`)
	exec(`INSERT INTO notification_channel_versions(tenant_id,channel_id,revision,ciphertext,expires_at) SELECT 'history_a','channel',n,'encrypted',CASE WHEN n=4 THEN now()+interval '1 day' ELSE now()-interval '1 minute' END FROM generate_series(1,4) n`)
	exec(`INSERT INTO notification_batches(tenant_id,id,upstream_batch_id,channel_id,channel_revision,message,expires_at) VALUES('history_a','expired_batch','expired','channel',2,'{}',now()-interval '1 minute'),('history_a','running_batch','running','channel',2,'{}',now()-interval '1 minute'),('history_a','live_batch','live','channel',2,'{}',now()-interval '1 minute')`)
	exec(`INSERT INTO notification_deliveries(tenant_id,id,batch_id,recipient,state,lease_until,expires_at) VALUES('history_a','expired_delivery','expired_batch','recipient','accepted',NULL,now()-interval '1 minute'),('history_a','running_delivery','running_batch','recipient','running',now()+interval '1 day',now()-interval '1 minute'),('history_a','live_delivery','live_batch','recipient','accepted',NULL,now()+interval '1 day')`)

	exec(`INSERT INTO model_providers(tenant_id,id,revision,public) VALUES('history_a','provider',3,'{}')`)
	exec(`INSERT INTO model_provider_versions(tenant_id,provider_id,revision,ciphertext,expires_at) SELECT 'history_a','provider',n,'encrypted',CASE WHEN n=4 THEN now()+interval '1 day' ELSE now()-interval '1 minute' END FROM generate_series(1,4) n`)
	exec(`INSERT INTO model_capability_checks(tenant_id,id,provider_id,provider_revision,created_by,idempotency_key_hash,state,deadline,expires_at) VALUES('history_a','expired_check','provider',2,'owner','expired','succeeded',now()-interval '1 minute',now()-interval '1 minute'),('history_a','running_check','provider',2,'owner','running','running',now()+interval '1 day',now()-interval '1 minute'),('history_a','live_check','provider',4,'owner','live','succeeded',now()+interval '1 day',now()+interval '1 day')`)
	exec(`INSERT INTO analysis_threads(tenant_id,id,created_by,title,expires_at) VALUES('history_a','expired_empty','owner','到期空会话',now()-interval '1 minute'),('history_a','expired_active','owner','活动会话',now()-interval '1 minute'),('history_a','expired_terminal','owner','结束会话',now()-interval '1 minute'),('history_a','live_empty','owner','有效会话',now()+interval '1 day')`)
	var riverID int64
	require(t, f.Owner.Pool.QueryRow(ctx, `INSERT INTO starbeacon_jobs.river_job(kind,args,queue,max_attempts) VALUES('sb_analysis_v1','{}','default',1) RETURNING id`).Scan(&riverID))
	for _, job := range []struct {
		id, state, kind, thread string
		river                   any
	}{
		{"expired_job", "succeeded", "chat", "expired_terminal", nil},
		{"running_job", "running", "chat", "expired_active", nil},
		{"queued_job", "queued", "daily", "", nil},
		{"river_pending_job", "succeeded", "daily", "", riverID},
	} {
		var thread any
		if job.thread != "" {
			thread = job.thread
		}
		exec(`INSERT INTO analysis_jobs(tenant_id,id,created_by,kind,thread_id,provider_id,provider_revision,revision,period_start,period_end,request,request_hash,idempotency_key_hash,template,evidence,prompt_hash,state,river_job_id,expires_at) VALUES('history_a',$1,'owner',$2,$3,'provider',2,1,now()-interval '1 day'+($4::int*interval '1 second'),now(),'{}',$1,$1,'test','{}','test',$5,$6,now()-interval '1 minute')`, job.id, job.kind, thread, len(job.id), job.state, job.river)
	}

	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	for _, item := range []struct {
		id, kind, state string
		deliveries      int
		live            bool
	}{
		{"done", "diagnostics", "succeeded", 1, false},
		{"unknown", "diagnostics", "unknown", 1, false},
		{"unknown_apply", "rules.apply", "unknown", 1, false},
		{"running", "diagnostics", "running", 1, false},
		{"queued_unused", "diagnostics", "queued", 0, false},
		{"queued_delivered", "diagnostics", "queued", 1, false},
		{"live", "diagnostics", "succeeded", 1, true},
	} {
		identity := "probe_" + item.id
		exec(`INSERT INTO sensors(tenant_id,id,name,registration_id) VALUES('history_a',$1,$1,$1)`, identity)
		payload := json.RawMessage(`{}`)
		if item.kind == "rules.apply" {
			text := `alert tcp any any -> any any (msg:"验收"; sid:1000001; rev:1;)`
			var err error
			// 此用例仅检查历史保护，资格摘要是签名契约夹具，不作为原生发布验收证据。
			digest := control.Digest([]byte("history fixture"))
			grant := &control.RuleAuthorization{ValidationTaskID: "check_fixture", PositiveReplayTaskID: "positive_fixture", NegativeReplayTaskID: "negative_fixture", ExpectedRulesSHA256: digest, ConfigSHA256: digest, ProfileSHA256: digest, ValidationReceiptSHA256: digest, PositiveReceiptSHA256: digest, NegativeReceiptSHA256: digest}
			payload, err = control.RulePayload(control.RulePackage{PackageID: "rules", Revision: 1, EngineVersion: "8.0.7", Text: text, SHA256: control.Digest([]byte(text)), Authorization: grant})
			require(t, err)
		}
		command := control.Command{ID: item.id, TenantID: "history_a", SensorID: identity, RegistrationID: identity, Kind: item.kind, IssuedAt: time.Now().Add(-200 * 24 * time.Hour), ExpiresAt: time.Now().Add(-200*24*time.Hour + time.Hour), Payload: payload}
		raw, signature, err := control.Encode(command, private)
		require(t, err)
		retained := time.Now().Add(-time.Minute)
		if item.live {
			retained = time.Now().Add(24 * time.Hour)
		}
		exec(`INSERT INTO sensor_tasks(tenant_id,id,sensor_id,registration_id,kind,state,idempotency_key,request_sha256,command,signature,command_sha256,created_by,expires_at,delivery_count,retain_until) VALUES('history_a',$1,$2,$2,$3,$4,$1,$5,$6,$7,$5,'owner',$8,$9,$10)`, item.id, identity, item.kind, item.state, control.Digest(raw), raw, signature, command.ExpiresAt, item.deliveries, retained)
	}
	exec(`INSERT INTO routes(token,tenant_id,sensor_id,registration_id,stream_id,partition_day,expires_at) VALUES('expired_route','history_a','probe_done','probe_done','alerts',current_date-200,now()-interval '1 minute'),('live_route','history_a','probe_done','probe_done','alerts',current_date,now()+interval '1 day')`)
	exec(`INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at) SELECT 'expired_session',id,'csrf',now()-interval '1 minute' FROM users WHERE tenant_id='history_a'`)
	exec(`INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at) SELECT 'live_session',id,'csrf',now()+interval '1 day' FROM users WHERE tenant_id='history_a'`)

	// 删除权限自身受时间和状态约束；租户请求不能读取或回收匿名登录与他人记录。
	require(t, f.Runtime.TenantTx(ctx, "history_a", func(tx pgx.Tx) error {
		var anonymous, other int
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE tenant_id IS NULL),count(*) FILTER(WHERE tenant_id='history_b') FROM login_audits`).Scan(&anonymous, &other); err != nil {
			return err
		}
		if anonymous != 0 || other != 0 {
			t.Fatal("业务租户读取了维护或其他租户的审计")
		}
		for _, query := range []string{`DELETE FROM operation_audits WHERE object_id='live'`, `DELETE FROM sensor_tasks WHERE id='unknown_apply'`, `DELETE FROM notification_deliveries WHERE id='running_delivery'`, `DELETE FROM model_provider_versions WHERE revision=3`, `DELETE FROM notification_channel_versions WHERE revision=3`, `DELETE FROM analysis_jobs WHERE id='river_pending_job'`} {
			tag, err := tx.Exec(ctx, query)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 0 {
				t.Fatal("运行角色删除了受保护的事实", query)
			}
		}
		return nil
	}))
	var canRewrite bool
	require(t, f.Runtime.Pool.QueryRow(ctx, `SELECT has_table_privilege(current_user,'operation_audits','UPDATE') OR has_table_privilege(current_user,'inventory_history','UPDATE') OR has_table_privilege(current_user,'model_provider_versions','UPDATE')`).Scan(&canRewrite))
	if canRewrite {
		t.Fatal("清理授予了不可变历史的改写权限")
	}
	for range 3 {
		report, err := f.Runtime.SweepHistory(ctx)
		require(t, err)
		if report.Deleted > 4096 || report.Tenants > 32 {
			t.Fatal("清理超出单轮上限", report)
		}
	}
	for _, check := range []struct {
		query string
		count int
	}{
		{`SELECT count(*) FROM operation_audits`, 2}, {`SELECT count(*) FROM login_audits`, 2},
		{`SELECT count(*) FROM inventory_history`, 1}, {`SELECT count(*) FROM inventory_objects`, 1},
		{`SELECT count(*) FROM retention_previews`, 1}, {`SELECT count(*) FROM retention_changes`, 1},
		{`SELECT count(*) FROM notification_deliveries`, 2}, {`SELECT count(*) FROM notification_batches`, 2},
		{`SELECT count(*) FROM notification_channel_versions`, 3}, {`SELECT count(*) FROM notification_channels`, 1},
		{`SELECT count(*) FROM model_capability_checks`, 2}, {`SELECT count(*) FROM model_provider_versions`, 3},
		{`SELECT count(*) FROM model_providers`, 1}, {`SELECT count(*) FROM analysis_jobs`, 3},
		{`SELECT count(*) FROM analysis_threads`, 2}, {`SELECT count(*) FROM sensor_tasks`, 4},
		{`SELECT count(*) FROM sessions`, 1}, {`SELECT count(*) FROM routes`, 1},
	} {
		assertCount(check.query, check.count)
	}
	// 引用终止之后才允许按既有期限回收，不把引用消失当作新的留存起点。
	exec(`UPDATE model_capability_checks SET state='uncertain' WHERE id='running_check'`)
	exec(`UPDATE notification_deliveries SET state='uncertain',lease_until=NULL WHERE id='running_delivery'`)
	exec(`UPDATE analysis_jobs SET state='uncertain' WHERE id IN('running_job','queued_job')`)
	exec(`UPDATE starbeacon_jobs.river_job SET state='completed',finalized_at=now() WHERE id=$1`, riverID)
	for range 3 {
		_, err := f.Runtime.SweepHistory(ctx)
		require(t, err)
	}
	assertCount(`SELECT count(*) FROM analysis_jobs`, 0)
	assertCount(`SELECT count(*) FROM analysis_threads`, 1)
	assertCount(`SELECT count(*) FROM model_provider_versions`, 2)
	assertCount(`SELECT count(*) FROM notification_batches`, 1)
	assertCount(`SELECT count(*) FROM notification_channel_versions`, 3)
	assertCount(`SELECT count(*) FROM notification_deliveries`, 1)
	assertCount(`SELECT count(*) FROM operation_audits`, 2)
	assertCount(`SELECT count(*) FROM sensor_tasks WHERE id='unknown_apply'`, 1)

	// 表级权限故障必须撤销同租户之前的删除和进度。
	exec(`INSERT INTO operation_audits(tenant_id,user_id,action,object_id,request_id,expires_at) VALUES('history_a','owner','test','rollback','test',now()-interval '1 minute'),('history_b','owner','test','continue','test',now()-interval '1 minute')`)
	exec(`UPDATE retention_maintenance SET next_category=0 WHERE tenant_id IN('history_a','history_b')`)
	exec(`REVOKE DELETE ON inventory_history FROM starbeacon_app`)
	report, err := f.Runtime.SweepHistory(ctx)
	exec(`GRANT DELETE ON inventory_history TO starbeacon_app`)
	if err == nil || report.Deleted != 0 {
		// 两个租户都到达同一权限故障；任何已统计删除都必须是成功提交的记录。
		t.Fatal("清理权限故障没有返回事务回滚", report, err)
	}
	assertCount(`SELECT count(*) FROM operation_audits WHERE object_id IN('rollback','continue')`, 2)
	var next int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT next_category FROM retention_maintenance WHERE tenant_id='history_a'`).Scan(&next))
	if next != 0 {
		t.Fatal("失败批次提前提交了分类进度", next)
	}
	_, err = f.Runtime.SweepHistory(ctx)
	require(t, err)
	assertCount(`SELECT count(*) FROM operation_audits WHERE object_id IN('rollback','continue')`, 0)
	// 租户局部故障不能中止其他租户；所有注入对象都位于本用例专属数据库。
	exec(`INSERT INTO operation_audits(tenant_id,user_id,action,object_id,request_id,expires_at) VALUES('history_a','owner','test','rollback','test',now()-interval '1 minute'),('history_b','owner','test','continue','test',now()-interval '1 minute')`)
	exec(`INSERT INTO inventory_history(tenant_id,kind,id,revision,name,active,data,valid_from,expires_at) VALUES('history_a','assets','asset',1,'历史资产',true,'{}',now()-interval '200 days',now()-interval '1 minute')`)
	exec(`UPDATE retention_maintenance SET next_category=0 WHERE tenant_id IN('history_a','history_b')`)
	exec(`CREATE FUNCTION history_test_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.tenant_id='history_a' THEN RAISE EXCEPTION '专属验收故障'; END IF; RETURN OLD; END; $$`)
	exec(`CREATE TRIGGER history_test_failure BEFORE DELETE ON inventory_history FOR EACH ROW EXECUTE FUNCTION history_test_failure()`)
	report, err = f.Runtime.SweepHistory(ctx)
	exec(`DROP TRIGGER history_test_failure ON inventory_history`)
	exec(`DROP FUNCTION history_test_failure()`)
	if err == nil || report.Deleted != 1 {
		t.Fatal("租户局部故障阻止了其他租户提交", report, err)
	}
	assertCount(`SELECT count(*) FROM operation_audits WHERE object_id='rollback'`, 1)
	assertCount(`SELECT count(*) FROM operation_audits WHERE object_id='continue'`, 0)
	_, err = f.Runtime.SweepHistory(ctx)
	require(t, err)
	assertCount(`SELECT count(*) FROM operation_audits WHERE object_id='rollback'`, 0)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.Runtime.SweepHistory(cancelled); err == nil {
		t.Fatal("已取消清理仍然执行")
	}
}

func TestHistoryCleanupBoundsDurableCategoryCursorTenantFairnessAndLocks(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
	defer stop()
	f := newIsolatedDatabase(t, ctx)
	_, err := f.Owner.Pool.Exec(ctx, `INSERT INTO tenants(id,name) SELECT 'tenant_'||lpad(n::text,2,'0'),'清理预算验收' FROM generate_series(0,33) n`)
	require(t, err)
	for _, query := range []string{
		`INSERT INTO operation_audits(tenant_id,user_id,action,object_id,request_id,expires_at) SELECT id,'owner','test','expired','test',now()-interval '1 minute' FROM tenants WHERE id<>'tenant_00'`,
		`INSERT INTO operation_audits(tenant_id,user_id,action,object_id,request_id,expires_at) SELECT 'tenant_00','owner','test',n::text,'test',now()-interval '1 minute' FROM generate_series(1,600) n`,
		`INSERT INTO login_audits(tenant_id,username,success,expires_at) SELECT 'tenant_00',n::text,true,now()-interval '1 minute' FROM generate_series(1,600) n`,
		`INSERT INTO retention_previews(tenant_id,id,created_by,candidate,current_days,expires_at) SELECT 'tenant_00','preview_'||n,'owner','{}',180,now()-interval '1 minute' FROM generate_series(1,600) n`,
		`INSERT INTO retention_changes(tenant_id,id,created_by,category,days,revision,request_hash,idempotency_key_hash,expires_at) SELECT 'tenant_00','change_'||n,'owner','operations',180,2,n::text,n::text,now()-interval '1 minute' FROM generate_series(1,600) n`,
	} {
		_, err := f.Owner.Pool.Exec(ctx, query)
		require(t, err)
	}
	report, err := f.Runtime.SweepHistory(ctx)
	require(t, err)
	if report.Tenants != 32 || report.Deleted != 1055 || report.ByTable["operation_audits"] != 287 || report.ByTable["login_audits"] != 256 {
		t.Fatal("高用量租户挤占其他租户或违反分类预算", report)
	}
	var remaining, next int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id>'tenant_31'`).Scan(&remaining))
	if remaining != 2 {
		t.Fatal("租户扫描上限失效", remaining)
	}
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT next_category FROM retention_maintenance WHERE tenant_id='tenant_00'`).Scan(&next))
	if next != 6 {
		t.Fatal("分类续点未与删除共同固化", next)
	}
	// 独立 Store 实例没有内存分类游标，仍从已提交进度开始；下一轮原实例继续后续租户。
	restarted, err := store.Open(ctx, f.RuntimeDSN)
	require(t, err)
	defer restarted.Close()
	_, err = restarted.SweepHistory(ctx)
	require(t, err)
	report, err = f.Runtime.SweepHistory(ctx)
	require(t, err)
	if report.Tenants != 2 {
		t.Fatal("后续租户没有轮转机会", report)
	}
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id>'tenant_31'`).Scan(&remaining))
	if remaining != 0 {
		t.Fatal("后续租户到期记录未删除")
	}
	lock, err := f.Owner.Pool.Begin(ctx)
	require(t, err)
	defer lock.Rollback(context.Background())
	_, err = lock.Exec(ctx, `SELECT tenant_id FROM retention_maintenance WHERE tenant_id='tenant_00' FOR UPDATE`)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO operation_audits(tenant_id,user_id,action,object_id,request_id,expires_at) VALUES('tenant_01','owner','test','other_during_lock','test',now()-interval '1 day')`)
	require(t, err)
	classificationStore, err := store.Open(ctx, f.RuntimeDSN)
	require(t, err)
	defer classificationStore.Close()
	started := time.Now()
	type sweepOutcome struct {
		report  store.HistorySweep
		err     error
		elapsed time.Duration
	}
	completed := make(chan sweepOutcome, 1)
	sweepCtx, cancelSweep := context.WithCancel(ctx)
	defer cancelSweep()
	go func() {
		result, sweepErr := classificationStore.SweepHistory(sweepCtx)
		completed <- sweepOutcome{result, sweepErr, time.Since(started)}
	}()
	// 验证邻租户在持锁期间实际提交，不能把随后其他 30 个租户的扫描耗时算作锁等待。
	// 进展期限保持 3 秒，整轮仍受 SweepHistory 的原 20 秒预算约束。
	progressCtx, cancelProgress := context.WithTimeout(ctx, 3*time.Second)
	var progressed time.Duration
	var progressErr error
	for progressCtx.Err() == nil {
		var pending int
		progressErr = f.Owner.Pool.QueryRow(progressCtx, `SELECT count(*) FROM operation_audits WHERE tenant_id='tenant_01' AND object_id='other_during_lock'`).Scan(&pending)
		if progressErr != nil {
			break
		}
		if pending == 0 {
			progressed = time.Since(started)
			break
		}
		select {
		case <-progressCtx.Done():
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancelProgress()
	if progressed == 0 || progressed > 3*time.Second {
		cancelSweep()
	}
	result := <-completed
	cancelSweep()
	if progressed == 0 || progressed > 3*time.Second {
		t.Fatal("分类锁持有期间邻租户未在原期限内提交清理", progressed, progressErr, result.err)
	}
	require(t, result.err)
	report = result.report
	if report.Deleted != 1 {
		t.Fatal("分类锁期间清理数量不一致", report)
	}
	t.Log("分类锁持有期间邻租户实际提交清理", progressed, "整轮扫描", result.elapsed)
	_, err = lock.Exec(ctx, `UPDATE retention_maintenance SET next_category=0 WHERE tenant_id='tenant_00'`)
	require(t, err)
	require(t, lock.Commit(ctx))
	for range 8 {
		_, err := classificationStore.SweepHistory(ctx)
		require(t, err)
	}
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits`).Scan(&remaining))
	if remaining != 0 {
		t.Fatal("分类锁释放后的到期记录没有恢复回收", remaining)
	}
	var progress int64
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT total_deleted FROM retention_maintenance WHERE tenant_id='tenant_00'`).Scan(&progress))
	if progress != 2400 {
		t.Fatal(fmt.Sprintf("已提交的清理进度计数不一致：%d", progress))
	}
	// 匿名审计与多个高用量租户共享全局预算，部分分类从已提交续点继续。
	for _, query := range []string{
		`INSERT INTO operation_audits(tenant_id,user_id,action,object_id,request_id,expires_at) SELECT t.id,'owner','test',n::text,'test',now()-interval '1 minute' FROM tenants t CROSS JOIN generate_series(1,256) n WHERE t.id<='tenant_04'`,
		`INSERT INTO login_audits(tenant_id,username,success,expires_at) SELECT t.id,n::text,true,now()-interval '1 minute' FROM tenants t CROSS JOIN generate_series(1,256) n WHERE t.id<='tenant_04'`,
		`INSERT INTO retention_previews(tenant_id,id,created_by,candidate,current_days,expires_at) SELECT t.id,'bulk_'||n,'owner','{}',180,now()-interval '1 minute' FROM tenants t CROSS JOIN generate_series(1,256) n WHERE t.id<='tenant_04'`,
		`INSERT INTO retention_changes(tenant_id,id,created_by,category,days,revision,request_hash,idempotency_key_hash,expires_at) SELECT t.id,'bulk_'||n,'owner','operations',180,2,n::text,'bulk_'||n,now()-interval '1 minute' FROM tenants t CROSS JOIN generate_series(1,256) n WHERE t.id<='tenant_04'`,
		`INSERT INTO login_audits(tenant_id,username,success,expires_at) SELECT NULL,'anonymous_'||n,false,now()-interval '1 minute' FROM generate_series(1,256) n`,
		`UPDATE retention_maintenance SET next_category=0 WHERE tenant_id<='tenant_04'`,
	} {
		_, err := f.Owner.Pool.Exec(ctx, query)
		require(t, err)
	}
	budgetStore, err := store.Open(ctx, f.RuntimeDSN)
	require(t, err)
	defer budgetStore.Close()
	report, err = budgetStore.SweepHistory(ctx)
	require(t, err)
	if report.Deleted != 4096 || report.Tenants != 4 {
		t.Fatal("多个高用量租户越过全局回收预算", report)
	}
	for range 3 {
		_, err := budgetStore.SweepHistory(ctx)
		require(t, err)
	}
	for _, table := range []string{"operation_audits", "login_audits", "retention_previews", "retention_changes"} {
		require(t, f.Owner.Pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&remaining))
		if remaining != 0 {
			t.Fatal("达到回收预算后没有从续点恢复", table, remaining)
		}
	}
}

// 独立数据库排除其他租户扫描时间，实际验证业务行锁的超时、回滚与解除后恢复。
func TestHistoryCleanupLockedBusinessRowTimesOutAndRecovers(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
	defer stop()
	f := newIsolatedDatabase(t, ctx)
	_, err := f.Owner.Pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('history_locked','业务行锁验收')`)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO operation_audits(tenant_id,user_id,action,object_id,request_id,expires_at) VALUES('history_locked','owner','test','locked_row','test',now()-interval '1 day')`)
	require(t, err)
	lock, err := f.Owner.Pool.Begin(ctx)
	require(t, err)
	defer lock.Rollback(context.Background())
	_, err = lock.Exec(ctx, `SELECT id FROM operation_audits WHERE tenant_id='history_locked' FOR UPDATE`)
	require(t, err)
	lockedStore, err := store.Open(ctx, f.RuntimeDSN)
	require(t, err)
	defer lockedStore.Close()
	started := time.Now()
	_, err = lockedStore.SweepHistory(ctx)
	if err == nil || !strings.Contains(err.Error(), "lock timeout") || time.Since(started) > 3*time.Second {
		t.Fatal("业务锁没有触发原期限内的回滚", err, time.Since(started))
	}
	var remaining int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id='history_locked'`).Scan(&remaining))
	if remaining != 1 {
		t.Fatal("锁失败后到期记录没有完整保留", remaining)
	}
	require(t, lock.Rollback(ctx))
	for range 8 {
		_, err := lockedStore.SweepHistory(ctx)
		require(t, err)
	}
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id='history_locked'`).Scan(&remaining))
	if remaining != 0 {
		t.Fatal("业务锁释放后到期记录没有恢复回收", remaining)
	}
	var progress int64
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT total_deleted FROM retention_maintenance WHERE tenant_id='history_locked'`).Scan(&progress))
	if progress != 1 {
		t.Fatal("回滚或重试造成清理账目不一致", progress)
	}
}
