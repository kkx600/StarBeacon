//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestTaskHTTPRejectsMixedEvidenceAndMissingReplaySources(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant, password := store.RandomID("it_task_inputs_"), store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "任务准入验收", tenant, password, "admin"))
	dir := t.TempDir()
	ca := filepath.Join(dir, "pki")
	require(t, admin.DevPKI(ca))
	identity, err := admin.Provision(ctx, f.Owner, tenant, "sensor_owned", "任务准入探针", ca, filepath.Join(dir, "sensor"))
	require(t, err)
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	api := &platform.API{DB: f.Runtime, Signer: signer}
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, api, tenant, password)
	health := model.HostHealth{ObservedAt: time.Now().UTC(), CommandSignerSHA256: control.Digest(pub), TaskCapabilities: []string{"diagnostics", "rules.replay", "rules.validate", "rules.reconcile"}, RegisteredRulesAvailable: true}
	setHealth := func() { require(t, f.Runtime.Heartbeat(ctx, identity, health)) }
	setHealth()
	path := "/sensors/sensor_owned/tasks"
	for _, body := range []any{
		map[string]any{"kind": "diagnostics", "validation_task_id": "validation_owned"},
		map[string]any{"kind": "rules.replay", "expected_rules_sha256": control.Digest([]byte("rules"))},
		map[string]any{"kind": "rules.validate", "unknown_task_id": "task_owned"},
		map[string]any{"kind": "diagnostics", "package_id": "package_owned"},
		map[string]any{"kind": "rules.reconcile", "unknown_task_id": "bad/id"},
		map[string]any{"kind": "rules.reconcile", "unknown_task_id": "task_owned", "package_id": "package_owned"},
	} {
		client.request("POST", path, "invalid_owned_key", body, nil, 400)
	}
	client.request("POST", path, "missing_rules_key", map[string]any{"kind": "rules.validate", "package_id": "package_missing", "revision": 1}, nil, 404)
	client.request("POST", path, "missing_storage_key", map[string]any{"kind": "rules.replay", "sample_id": "sample_owned", "rule_mode": "registered"}, nil, 503)
	health.RegisteredRulesAvailable = false
	setHealth()
	client.request("POST", path, "missing_snapshot_key", map[string]any{"kind": "rules.replay", "sample_id": "sample_owned", "rule_mode": "registered"}, nil, 409)
	health.RegisteredRulesAvailable = true
	setHealth()
	objects, err := replay.NewLocal(filepath.Join(t.TempDir(), "objects"), 1<<30)
	require(t, err)
	api.Samples = objects
	client.request("POST", path, "missing_sample_key", map[string]any{"kind": "rules.replay", "sample_id": "sample_missing", "rule_mode": "package", "package_id": "package_missing", "revision": 1}, nil, 404)
	sample := replay.Sample{ID: "sample_owned", Name: "bounded.pcap", SHA256: control.Digest([]byte("sample")), Size: 24, Format: "pcap", CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}
	var user model.Principal
	client.request("GET", "/auth/me", "", nil, &user, 200)
	require(t, f.Runtime.ReserveSample(ctx, user, sample, 1<<20))
	require(t, f.Runtime.CompleteSample(ctx, user, sample.ID, sample.SHA256, sample.Format, "sample_seed"))
	client.request("POST", path, "missing_package_key", map[string]any{"kind": "rules.replay", "sample_id": sample.ID, "rule_mode": "package", "package_id": "package_missing", "revision": 1}, nil, 404)
	for _, body := range []any{map[string]any{"kind": "rules.replay", "sample_id": sample.ID, "rule_mode": "wrong"}, map[string]any{"kind": "rules.replay", "sample_id": sample.ID, "rule_mode": "registered", "package_id": "package_owned"}} {
		client.request("POST", path, "mixed_replay_key", body, nil, 400)
	}
	for _, body := range []any{
		map[string]any{"name": "规则", "text": "alert tcp any any -> any any (sid:1000001;)", "unknown": true},
		map[string]any{"id": "invalid/id", "name": "规则", "text": "alert tcp any any -> any any (sid:1000001;)"},
		map[string]any{"id": "rules_owned", "name": "", "text": "alert tcp any any -> any any (sid:1000001;)"},
		map[string]any{"id": "rules_owned", "name": "规则", "text": "invalid"},
		map[string]any{"id": "rules_owned", "name": "规则", "text": "alert tcp any any -> any any (sid:1000001;)", "expected_revision": -1},
	} {
		client.request("POST", "/rule-packages", "", body, nil, 400)
	}
	var rulePackage store.RulePackage
	client.request("POST", "/rule-packages", "", map[string]any{"name": "正常检测规则", "text": "alert tcp any any -> any any (sid:1000001;)"}, &rulePackage, 201)
	if !contract.ValidID(rulePackage.ID) {
		t.Fatal("规则包未获得合法服务端身份")
	}
	var tasks, audits int
	require(t, f.Runtime.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM sensor_tasks WHERE tenant_id=$1),(SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action LIKE 'task.%')`, tenant).Scan(&tasks, &audits)
	}))
	if tasks != 0 || audits != 0 {
		t.Fatal("失败任务留下了可执行记录或成功审计", tasks, audits)
	}
}
