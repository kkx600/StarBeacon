//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/assistant"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/inventory"
	"github.com/kkx600/StarBeacon/internal/jobs"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/mcpaccess"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/retention"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
)

// 只断开用例专属连接；服务端实际回滚事务，不更改共享账号、宿主或其他数据库。
type disconnectQuery struct {
	prefix string
	fired  atomic.Bool
}

func (d *disconnectQuery) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(strings.TrimSpace(data.SQL), d.prefix) && d.fired.CompareAndSwap(false, true) {
		_ = conn.PgConn().Close(ctx)
	}
	return ctx
}
func (*disconnectQuery) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func disconnectedStore(t *testing.T, ctx context.Context, dsn, prefix string) (*store.Postgres, *disconnectQuery) {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	require(t, err)
	tracer := &disconnectQuery{prefix: prefix}
	cfg.ConnConfig.Tracer = tracer
	cfg.MinConns, cfg.MaxConns = 0, 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require(t, err)
	t.Cleanup(pool.Close)
	return &store.Postgres{Pool: pool}, tracer
}

func ownedBusinessSnapshot(t *testing.T, ctx context.Context, db *store.Postgres, tenant string) string {
	t.Helper()
	state := map[string]json.RawMessage{}
	require(t, db.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		for _, table := range []string{"inventory_objects", "inventory_history", "model_providers", "model_provider_versions", "model_capability_checks", "notification_channels", "notification_channel_versions", "notification_batches", "notification_deliveries", "retention_policies", "retention_previews", "retention_changes", "sensors", "sensor_groups", "sensor_management_requests", "saved_searches", "saved_search_changes", "sensor_tasks", "replay_samples", "analysis_jobs", "analysis_threads", "mcp_bindings", "mcp_auth_routes", "operation_audits"} {
			var raw []byte
			if err := tx.QueryRow(ctx, "SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY to_jsonb(v)::text),'[]'::jsonb) FROM (SELECT * FROM "+pgx.Identifier{table}.Sanitize()+" WHERE tenant_id=$1) v", tenant).Scan(&raw); err != nil {
				return err
			}
			state[table] = raw
		}
		return nil
	}))
	raw, err := json.Marshal(state)
	require(t, err)
	return string(raw)
}

func TestPostgresDisconnectRollsBackConfigurationTasksAndAudit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant, password := store.RandomID("it_fault_"), store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "事务中断验收", tenant, password, "admin"))
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	vault, err := secrets.New(store.Token())
	require(t, err)
	policy := outbound.Policy{}
	modelConfig := llm.Config{Name: "受控提供方", Kind: "openai_responses", BaseURL: "https://models.example.com/v1", Model: "owned-model", APIKey: "owned-key", Enabled: true, MaxOutputTokens: 256, TimeoutSeconds: 5, DailyRequests: 1000}
	_, err = f.Runtime.SaveModelProvider(ctx, u, store.ModelChange{ID: "provider_seed", Config: modelConfig, ReplaceKey: true}, vault, policy, "seed_model")
	require(t, err)
	enabled := true
	noticeConfig := notify.Config{Name: "受控通知", Kind: "webhook", Endpoint: "https://notice.example.com/ingest", Enabled: true, Severities: []string{"high"}}
	channelChange := store.ChannelChange{ID: "channel_seed", Name: noticeConfig.Name, Kind: noticeConfig.Kind, Enabled: &enabled, Severities: noticeConfig.Severities, Connection: &noticeConfig}
	_, err = f.Runtime.SaveNotificationChannel(ctx, u, channelChange, vault, policy, "seed_channel")
	require(t, err)
	_, err = f.Runtime.SaveInventory(ctx, u, "groups", "group_seed", 0, json.RawMessage(`{"name":"生产资产","active":true}`), "seed_group")
	require(t, err)
	asset, err := json.Marshal(inventory.Asset{Name: "业务主机", GroupID: "group_seed", Active: true, Criticality: "high", NetworkDomain: "office", Interfaces: []inventory.Interface{{Name: "eth0", IPs: []string{"192.0.2.5"}}}})
	require(t, err)
	_, err = f.Runtime.SaveInventory(ctx, u, "assets", "asset_seed", 0, asset, "seed_asset")
	require(t, err)
	candidate := retention.Candidate{Category: "alerts", Days: 90, ExpectedRevision: 1, ApplyMode: "future"}
	preview, err := f.Runtime.PreviewRetention(ctx, u, candidate)
	require(t, err)
	identity := transport.SensorIdentity{TenantID: tenant, SensorID: "sensor_seed", RegistrationID: "registration_seed"}
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id) VALUES($1,$2,'受控探针',$3)`, tenant, identity.SensorID, identity.RegistrationID)
		if err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id) VALUES($1,'sensor_create_fault','受控任务探针','registration_create_fault')`, tenant)
		}
		return err
	}))
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	payload := json.RawMessage(`{}`)
	taskID, err := f.Runtime.CreateTask(ctx, u, identity.SensorID, "diagnostics", "seed_task", payload, signer)
	require(t, err)
	var commandHash string
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT command_sha256 FROM sensor_tasks WHERE tenant_id=$1 AND id=$2", tenant, taskID).Scan(&commandHash)
	}))
	receipt := control.Receipt{CommandID: taskID, CommandSHA256: commandHash, State: "running", StartedAt: time.Now().UTC(), Result: json.RawMessage(`{}`)}
	sample := replay.Sample{ID: "sample_fault", Name: "规则验证.pcap", Size: 1024}
	uploading := sample
	uploading.ID = "sample_uploading"
	require(t, f.Runtime.ReserveSample(ctx, u, uploading, 1<<20))
	ready := sample
	ready.ID = "sample_ready"
	require(t, f.Runtime.ReserveSample(ctx, u, ready, 1<<20))
	require(t, f.Runtime.CompleteSample(ctx, u, ready.ID, control.Digest([]byte("sample")), "pcap", "seed_sample"))
	binding := mcpaccess.Change{ID: "binding_fault", Name: "分析服务", Subject: "subject_owned", OAuthClientID: "client_owned", Scopes: []string{"alerts:read"}, Enabled: true, RequestsPerMinute: 60, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	seedBinding := binding
	seedBinding.ID = "binding_seed"
	seedBinding.Subject = "subject_seed"
	_, err = f.Runtime.SaveMCPBinding(ctx, u, "https://issuer.example.com", seedBinding, "seed_binding")
	require(t, err)
	alert := notify.Summary{ID: "event_seed", SensorID: identity.SensorID, Timestamp: time.Now().UTC(), Severity: "high", RuleID: "1000001", RuleName: "规则验证"}
	require(t, f.Runtime.EnqueueNotifications(ctx, tenant, "batch_seed", []notify.Summary{alert}, vault, ""))
	analysisInput, err := (assistant.Request{Kind: "daily", Period: time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02"), Timezone: "UTC"}).Normalize(time.Now().UTC())
	require(t, err)
	analysisJob, err := f.Runtime.CreateAnalysis(ctx, u, analysisInput, "analysis_seed", assistant.Evidence{}, "统计范围", nil, vault, "seed_analysis")
	require(t, err)
	type operation struct {
		name     string
		prefixes []string
		run      func(*store.Postgres) error
	}
	lock := "SELECT pg_advisory_xact_lock"
	audit := "INSERT INTO operation_audits"
	ops := []operation{
		{"tenant_transaction", []string{"begin", "SELECT set_config"}, func(db *store.Postgres) error { _, e := db.RetentionPolicies(ctx, tenant); return e }},
		{"asset_save", []string{lock, "SELECT revision FROM inventory_objects", "SELECT active FROM inventory_objects", "INSERT INTO inventory_objects", "INSERT INTO inventory_history", audit}, func(db *store.Postgres) error {
			_, e := db.SaveInventory(ctx, u, "assets", "asset_seed", 1, asset, "asset_save")
			return e
		}},
		{"group_protection", []string{"SELECT EXISTS(SELECT 1 FROM inventory_objects"}, func(db *store.Postgres) error {
			_, e := db.SaveInventory(ctx, u, "groups", "group_seed", 1, json.RawMessage(`{"name":"生产资产","active":false}`), "group_save")
			return e
		}},
		{"model_create", []string{lock, "SELECT revision FROM model_providers", "SELECT count(*) FROM model_providers", "INSERT INTO model_providers", "INSERT INTO model_provider_versions", audit}, func(db *store.Postgres) error {
			_, e := db.SaveModelProvider(ctx, u, store.ModelChange{ID: "provider_fault", ReplaceKey: true, Config: modelConfig}, vault, policy, "model_save")
			return e
		}},
		{"model_keep_credentials", []string{"SELECT ciphertext FROM model_provider_versions"}, func(db *store.Postgres) error {
			c := modelConfig
			c.APIKey = ""
			_, e := db.SaveModelProvider(ctx, u, store.ModelChange{ID: "provider_seed", ExpectedRevision: 1, Config: c}, vault, policy, "model_keep")
			return e
		}},
		{"model_check", []string{lock, "SELECT revision FROM model_providers", "UPDATE model_capability_checks", "SELECT jsonb_build_object", "SELECT ciphertext", "UPDATE analysis_jobs SET state='failed'", "UPDATE analysis_jobs SET state='uncertain'", "SELECT count(*) FILTER", "INSERT INTO model_capability_checks", audit}, func(db *store.Postgres) error {
			_, e := db.StartModelCheck(ctx, u, "provider_seed", "check_fault", 1, vault, "model_check")
			return e
		}},
		{"channel_create", []string{lock, "SELECT revision,kind", "SELECT count(*) FROM notification_channels", "INSERT INTO notification_channels", "INSERT INTO notification_channel_versions", audit}, func(db *store.Postgres) error {
			c := channelChange
			c.ID = "channel_fault"
			_, e := db.SaveNotificationChannel(ctx, u, c, vault, policy, "channel_save")
			return e
		}},
		{"channel_keep_credentials", []string{"SELECT ciphertext FROM notification_channel_versions"}, func(db *store.Postgres) error {
			c := channelChange
			c.ExpectedRevision = 1
			c.Connection = nil
			_, e := db.SaveNotificationChannel(ctx, u, c, vault, policy, "channel_keep")
			return e
		}},
		{"notification_enqueue", []string{"SELECT id,revision,enabled", "SELECT ciphertext", "INSERT INTO notification_batches", "INSERT INTO notification_deliveries"}, func(db *store.Postgres) error {
			return db.EnqueueNotifications(ctx, tenant, "batch_fault", []notify.Summary{alert}, vault, "")
		}},
		{"notification_test", []string{audit}, func(db *store.Postgres) error {
			return db.TestNotification(ctx, u, "channel_seed", "notice_fault", vault, "notice_test")
		}},
		{"notification_lease", []string{"UPDATE notification_deliveries SET state='uncertain'", "SELECT d.id,b.channel_id", "SELECT revision,enabled", "SELECT ciphertext", "UPDATE notification_channels", "UPDATE notification_deliveries SET state='running'"}, func(db *store.Postgres) error { _, e := db.LeaseNotification(ctx, tenant, vault); return e }},
		{"retention_preview", []string{lock, "SELECT days,revision", "DELETE FROM retention_previews", "INSERT INTO retention_previews"}, func(db *store.Postgres) error { _, e := db.PreviewRetention(ctx, u, candidate); return e }},
		{"retention_commit", []string{lock, "SELECT category,days,revision", "SELECT candidate", "UPDATE retention_policies", "INSERT INTO retention_changes", "DELETE FROM retention_previews", audit}, func(db *store.Postgres) error {
			_, _, e := db.SaveRetention(ctx, u, retention.Change{PreviewID: preview.ID, Candidate: candidate}, "retention_fault")
			return e
		}},
		{"task_create", []string{lock, "SELECT id,request_sha256", "SELECT registration_id", "UPDATE sensor_tasks", "INSERT INTO sensor_tasks", audit}, func(db *store.Postgres) error {
			_, e := db.CreateTask(ctx, u, "sensor_create_fault", "diagnostics", "task_fault", payload, signer)
			return e
		}},
		{"task_receipt", []string{"SELECT state,command_sha256", "UPDATE sensor_tasks"}, func(db *store.Postgres) error { return db.SaveReceipt(ctx, identity, receipt) }},
		{"task_cancel", []string{"UPDATE sensor_tasks", audit}, func(db *store.Postgres) error { return db.CancelTask(ctx, u, taskID, "task_cancel") }},
		{"sample_reserve", []string{lock, "SELECT COALESCE(sum(size)", "INSERT INTO replay_samples"}, func(db *store.Postgres) error { return db.ReserveSample(ctx, u, sample, 1<<20) }},
		{"sample_complete", []string{"UPDATE replay_samples", audit}, func(db *store.Postgres) error {
			return db.CompleteSample(ctx, u, uploading.ID, control.Digest([]byte("sample")), "pcap", "sample_complete")
		}},
		{"mcp_create", []string{lock, "SELECT count(*) FROM mcp_bindings", "INSERT INTO mcp_bindings", "INSERT INTO mcp_auth_routes", "SELECT id,name,issuer", audit}, func(db *store.Postgres) error {
			_, e := db.SaveMCPBinding(ctx, u, "https://issuer.example.com", binding, "mcp_save")
			return e
		}},
		{"mcp_update", []string{"UPDATE mcp_bindings"}, func(db *store.Postgres) error {
			c := seedBinding
			c.ExpectedRevision = 1
			_, e := db.SaveMCPBinding(ctx, u, "https://issuer.example.com", c, "mcp_update")
			return e
		}},
		{"mcp_delete", []string{"DELETE FROM mcp_bindings", audit}, func(db *store.Postgres) error { return db.DeleteMCPBinding(ctx, u, seedBinding.ID, 1, "mcp_delete") }},
		{"analysis_create", []string{lock, "UPDATE analysis_jobs SET state='failed'", "UPDATE analysis_jobs SET state='uncertain'", "SELECT request_hash FROM analysis_jobs", "SELECT count(*) FROM analysis_jobs", "SELECT COALESCE(max(revision)", "INSERT INTO analysis_jobs", audit}, func(db *store.Postgres) error {
			_, e := db.CreateAnalysis(ctx, u, analysisInput, "analysis_fault", assistant.Evidence{}, "统计范围", nil, vault, "analysis_create")
			return e
		}},
		{"analysis_model_create", []string{"SELECT revision FROM model_providers", "SELECT ciphertext", "UPDATE model_capability_checks", "SELECT count(*) FILTER", "INSERT INTO analysis_threads", "UPDATE analysis_jobs SET river_job_id"}, func(db *store.Postgres) error {
			queue, e := jobs.NewAnalysis(db, vault, policy)
			if e != nil {
				return e
			}
			c := analysisInput
			c.Kind, c.ProviderID, c.ProviderRevision, c.Question, c.Period, c.Timezone, c.AllowContext = "chat", "provider_seed", 1, "分析告警", "", "", true
			_, e = db.CreateAnalysis(ctx, u, c, "analysis_model_fault", assistant.Evidence{}, "受控上下文", queue, vault, "analysis_model_create")
			return e
		}},
	}
	// 列表读取与依赖异常也必须返回错误，不能把服务不可用显示成业务空状态。
	reads := []operation{
		{"inventory_list", []string{"SELECT id,kind,revision"}, func(db *store.Postgres) error { _, e := db.Inventory(ctx, tenant, "assets", "", "", 20); return e }},
		{"inventory_history", []string{"SELECT id,kind,revision"}, func(db *store.Postgres) error {
			_, e := db.InventoryHistory(ctx, tenant, "assets", "asset_seed", time.Now())
			return e
		}},
		{"models_list", []string{"UPDATE model_capability_checks", "SELECT p.id"}, func(db *store.Postgres) error { _, e := db.ModelProviders(ctx, tenant); return e }},
		{"channels_list", []string{"SELECT id,revision,name"}, func(db *store.Postgres) error { _, e := db.NotificationChannels(ctx, tenant); return e }},
		{"deliveries_list", []string{"SELECT d.id,b.channel_id"}, func(db *store.Postgres) error { _, _, e := db.NotificationDeliveries(ctx, tenant, "", ""); return e }},
		{"retention_list", []string{"SELECT category,days"}, func(db *store.Postgres) error { _, e := db.RetentionPolicies(ctx, tenant); return e }},
		{"tasks_list", []string{"UPDATE sensor_tasks", "SELECT id,sensor_id"}, func(db *store.Postgres) error { _, e := db.Tasks(ctx, tenant, ""); return e }},
		{"samples_list", []string{"SELECT id,name,size"}, func(db *store.Postgres) error { _, e := db.Samples(ctx, tenant); return e }},
		{"mcp_list", []string{"SELECT id,name,issuer"}, func(db *store.Postgres) error { _, e := db.MCPBindings(ctx, tenant); return e }},
		{"mcp_identity", []string{"SELECT tenant_id,binding_id", "SELECT id,name,issuer", "SELECT u.id,u.tenant_id"}, func(db *store.Postgres) error {
			_, e := db.MCPIdentity(ctx, "https://issuer.example.com", "subject_seed", "client_owned")
			return e
		}},
		{"analysis_job", []string{"UPDATE analysis_jobs SET state='failed'", "UPDATE analysis_jobs SET state='uncertain'", "SELECT jsonb_build_object"}, func(db *store.Postgres) error { _, e := db.AnalysisJob(ctx, u, analysisJob.ID); return e }},
		{"analysis_list", []string{"SELECT id,kind,COALESCE"}, func(db *store.Postgres) error { _, e := db.AnalysisJobs(ctx, u, "reports", "", 20); return e }},
	}
	for _, op := range append(ops, reads...) {
		for i, prefix := range op.prefixes {
			t.Run(fmt.Sprintf("%s/%02d", op.name, i), func(t *testing.T) {
				before := ownedBusinessSnapshot(t, ctx, f.Owner, tenant)
				db, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
				if err := op.run(db); err == nil {
					t.Fatal("数据库连接中断被误报为成功")
				}
				if !tracer.fired.Load() {
					t.Fatalf("没有执行所需的故障边界：%s", prefix)
				}
				if after := ownedBusinessSnapshot(t, ctx, f.Owner, tenant); before != after {
					t.Fatal("中断后的业务数据、修订或审计没有完全回滚")
				}
			})
		}
	}
	// 全部中断后仍能在原修订上提交，并且只形成一份对应历史与审计。
	updated, err := f.Runtime.SaveInventory(ctx, u, "assets", "asset_seed", 1, asset, "healthy_retry")
	require(t, err)
	if updated.Revision != 2 {
		t.Fatal("失败事务破坏了后续修订提交")
	}
	history, err := f.Runtime.InventoryHistory(ctx, tenant, "assets", "asset_seed", time.Now().Add(time.Second))
	require(t, err)
	if len(history) != 2 {
		t.Fatal("失败提交遗留了历史或正常重试未持久化")
	}
	t.Log("专属 PostgreSQL 连接中断、事务回滚、凭据版本、任务、持久队列、审计与后续重试通过")
}
