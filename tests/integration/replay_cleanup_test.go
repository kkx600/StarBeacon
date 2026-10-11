//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/testpcap"
)

type cleanupStorage struct {
	replay.Storage
	remove func(context.Context, string) error
}

func (s cleanupStorage) Remove(ctx context.Context, key string) error { return s.remove(ctx, key) }

func TestReplayCleanupReleasesConnectionRecoversAndProtectsActiveTask(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	fixture := newIsolatedDatabase(t, ctx)
	sweeper := oneConnectionStore(t, ctx, fixture.RuntimeDSN, nil)
	tenant := "gc_main"
	require(t, admin.Bootstrap(ctx, fixture.Owner, tenant, "样本清理验收", tenant, store.Token(), "admin"))
	user, _, err := fixture.Owner.Password(ctx, tenant)
	require(t, err)
	objects, err := replay.NewLocal(filepath.Join(t.TempDir(), "samples"), 128<<20)
	require(t, err)
	capture, err := testpcap.HTTP(false)
	require(t, err)
	seed := func(id string, ready bool) replay.Sample {
		t.Helper()
		v := replay.Sample{ID: id, Name: id + ".pcap", Size: int64(len(capture))}
		require(t, fixture.Runtime.ReserveSample(ctx, user, v, 32<<20))
		sha, format, err := objects.Put(ctx, replay.Key(tenant, id), bytes.NewReader(capture), v.Size)
		require(t, err)
		v.SHA256, v.Format = sha, format
		if ready {
			require(t, fixture.Runtime.CompleteSample(ctx, user, id, sha, format, store.RandomID("req_")))
		}
		return v
	}
	setTimes := func(id, state string, created, expires time.Time) {
		t.Helper()
		require(t, fixture.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "UPDATE replay_samples SET state=$3,created_at=$4,expires_at=$5 WHERE tenant_id=$1 AND id=$2", tenant, id, state, created, expires)
			return err
		}))
	}
	state := func(id string) string {
		t.Helper()
		var v string
		err := fixture.Owner.Pool.QueryRow(ctx, "SELECT state FROM replay_samples WHERE tenant_id=$1 AND id=$2", tenant, id).Scan(&v)
		if errors.Is(err, pgx.ErrNoRows) {
			return "absent"
		}
		require(t, err)
		return v
	}
	now := time.Now().UTC()
	seed("live", true)
	seed("expired", true)
	setTimes("expired", "ready", now.Add(-time.Hour), now.Add(-10*time.Minute))
	seed("grace", true)
	setTimes("grace", "ready", now.Add(-time.Hour), now.Add(-time.Minute))
	seed("upload_recent", false)
	seed("upload_stale", false)
	setTimes("upload_stale", "uploading", now.Add(-2*time.Hour), now.Add(180*24*time.Hour))
	seed("failed_stale", false)
	setTimes("failed_stale", "failed", now.Add(-2*time.Hour), now.Add(180*24*time.Hour))
	leased := seed("leased", true)
	_, err = fixture.Owner.Pool.Exec(ctx, "INSERT INTO sensors(tenant_id,id,name,registration_id) VALUES($1,'gc_sensor','清理租约验收',$2)", tenant, store.RandomID("reg_"))
	require(t, err)
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	payload, err := control.ReplayPayload(control.Replay{SampleID: leased.ID, SampleSize: leased.Size, SampleSHA256: leased.SHA256, RuleMode: "registered"})
	require(t, err)
	task, err := fixture.Runtime.CreateTask(ctx, user, "gc_sensor", "rules.replay", store.RandomID("key_"), payload, signer)
	require(t, err)
	setTimes("leased", "ready", now.Add(-time.Hour), now.Add(-10*time.Minute))
	entered, release := make(chan struct{}), make(chan struct{})
	var unlock sync.Once
	unblock := func() { unlock.Do(func() { close(release) }) }
	defer unblock()
	blocked := cleanupStorage{Storage: objects, remove: func(ctx context.Context, key string) error {
		if key == replay.Key(tenant, "expired") {
			close(entered)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
			}
		}
		return objects.Remove(ctx, key)
	}}
	done := make(chan error, 1)
	go func() { done <- sweeper.SweepSamples(ctx, blocked) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("清理未进入对象删除阶段")
	}
	if state("expired") != "deleting" || sweeper.Pool.Stat().AcquiredConns() != 0 {
		t.Fatal("对象删除前未提交标记或仍占用数据库连接")
	}
	query, stop := context.WithTimeout(ctx, 2*time.Second)
	_, err = sweeper.Sample(query, tenant, "live")
	stop()
	require(t, err)
	if err := sweeper.SweepSamples(ctx, objects); err == nil {
		t.Fatal("同一清理器接受了重叠轮次")
	}
	unblock()
	require(t, <-done)
	for _, id := range []string{"expired", "upload_stale", "failed_stale"} {
		if state(id) != "absent" {
			t.Fatal("可清理的样本没有移除", id)
		}
		if f, err := objects.Open(ctx, replay.Key(tenant, id)); !errors.Is(err, os.ErrNotExist) {
			if f != nil {
				f.Close()
			}
			t.Fatal("元数据删除后仍遗留样本对象", id)
		}
	}
	for id, expected := range map[string]string{"live": "ready", "grace": "ready", "upload_recent": "uploading", "leased": "ready"} {
		if state(id) != expected {
			t.Fatal("清理越过保护期或活动任务租约", id)
		}
	}
	require(t, fixture.Runtime.CancelTask(ctx, user, task, store.RandomID("req_")))
	require(t, sweeper.SweepSamples(ctx, objects))
	if state("leased") != "absent" {
		t.Fatal("已取消的任务仍阻止过期样本清理")
	}
	seed("retry", true)
	setTimes("retry", "ready", now.Add(-time.Hour), now.Add(-10*time.Minute))
	storageFailure := errors.New("对象存储暂不可用")
	failing := cleanupStorage{Storage: objects, remove: func(context.Context, string) error { return storageFailure }}
	if err := sweeper.SweepSamples(ctx, failing); !errors.Is(err, storageFailure) || state("retry") != "deleting" {
		t.Fatal("删除失败没有保留可恢复的清理标记")
	}
	if _, err := fixture.Runtime.Sample(ctx, tenant, "retry"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("待删除样本仍可查询并创建任务")
	}
	var used int64
	require(t, fixture.Owner.Pool.QueryRow(ctx, "SELECT sum(size) FROM replay_samples WHERE tenant_id=$1", tenant).Scan(&used))
	if err := fixture.Runtime.ReserveSample(ctx, user, replay.Sample{ID: "quota_check", Name: "quota.pcap", Size: int64(len(capture))}, used); !errors.Is(err, replay.ErrQuota) {
		t.Fatal("待删除对象提前释放了存储额度")
	}
	require(t, sweeper.SweepSamples(ctx, objects))
	if state("retry") != "absent" {
		t.Fatal("对象存储恢复后未完成清理")
	}
	seed("commit_retry", true)
	setTimes("commit_retry", "ready", now.Add(-time.Hour), now.Add(-10*time.Minute))
	interruptCtx, interrupt := context.WithCancel(ctx)
	interrupting := cleanupStorage{Storage: objects, remove: func(ctx context.Context, key string) error {
		if err := objects.Remove(ctx, key); err != nil {
			return err
		}
		interrupt()
		return nil
	}}
	if err := sweeper.SweepSamples(interruptCtx, interrupting); !errors.Is(err, context.Canceled) || state("commit_retry") != "deleting" {
		t.Fatal("对象已删除但元数据提交中断时没有留下恢复标记")
	}
	require(t, sweeper.SweepSamples(ctx, objects))
	if state("commit_retry") != "absent" {
		t.Fatal("对象缺失的删除重试不幂等")
	}
	if err := sweeper.SweepSamples(ctx, nil); err == nil {
		t.Fatal("未配置对象存储时清理成功")
	}
}

func TestReplayCleanupBoundsAndTenantRoundRobin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	fixture := newIsolatedDatabase(t, ctx)
	db := fixture.Runtime
	objects, err := replay.NewLocal(filepath.Join(t.TempDir(), "samples"), 128<<20)
	require(t, err)
	// 没有对象的墓碑模拟上轮已删除对象但提交中断，不构造虚假的可重放文件。
	_, err = fixture.Owner.Pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('a_busy','积压租户');
INSERT INTO replay_samples(tenant_id,id,name,size,state,created_by,expires_at)
 SELECT 'a_busy','sample_'||i,'恢复样本.pcap',24,'deleting','cleanup',now()-interval '10 minutes' FROM generate_series(1,205) i;
INSERT INTO tenants(id,name) SELECT 'b_'||lpad(i::text,3,'0'),'后续租户' FROM generate_series(1,33) i;
INSERT INTO replay_samples(tenant_id,id,name,size,state,created_by,expires_at)
 SELECT id,'sample_one','恢复样本.pcap',24,'deleting','cleanup',now()-interval '10 minutes' FROM tenants WHERE id LIKE 'b_%'`)
	require(t, err)
	count := func(prefix string) int {
		t.Helper()
		var n int
		require(t, fixture.Owner.Pool.QueryRow(ctx, "SELECT count(*) FROM replay_samples WHERE tenant_id LIKE $1", prefix+"%").Scan(&n))
		return n
	}
	require(t, db.SweepSamples(ctx, objects))
	if count("a_") != 105 || count("b_") != 33 {
		t.Fatal("单轮样本上限没有生效")
	}
	require(t, db.SweepSamples(ctx, objects))
	if count("a_") != 105 || count("b_") != 1 {
		t.Fatal("租户扫描上限或轮转公平性没有生效")
	}
	require(t, db.SweepSamples(ctx, objects))
	if count("a_") != 105 || count("b_") != 0 {
		t.Fatal("游标没有继续扫描剩余租户")
	}
	require(t, db.SweepSamples(ctx, objects))
	if count("a_") != 5 {
		t.Fatal("游标没有在末尾回绕")
	}
	for round := 0; round < 4; round++ {
		require(t, db.SweepSamples(ctx, objects))
	}
	if count("") != 0 {
		t.Fatal("积压没有在有界轮转中完成")
	}
	_, err = fixture.Owner.Pool.Exec(ctx, `INSERT INTO replay_samples(tenant_id,id,name,size,state,created_by)
 VALUES('a_busy','fail_one','恢复样本.pcap',24,'deleting','cleanup'),('a_busy','good_one','恢复样本.pcap',24,'deleting','cleanup')`)
	require(t, err)
	failure := errors.New("单个对象删除失败")
	partial := cleanupStorage{Storage: objects, remove: func(ctx context.Context, key string) error {
		if key == replay.Key("a_busy", "fail_one") {
			return failure
		}
		return objects.Remove(ctx, key)
	}}
	// 新实例从首个租户扫描；单个对象失败不阻塞同一批次的后续对象。
	fresh := oneConnectionStore(t, ctx, fixture.RuntimeDSN, nil)
	if err := fresh.SweepSamples(ctx, partial); !errors.Is(err, failure) || count("") != 1 {
		t.Fatal("单个对象失败中止了其他样本清理")
	}
	stopped, stop := context.WithCancel(ctx)
	stop()
	if err := fresh.SweepSamples(stopped, objects); !errors.Is(err, context.Canceled) {
		t.Fatal("已取消的清理仍继续执行")
	}
}
