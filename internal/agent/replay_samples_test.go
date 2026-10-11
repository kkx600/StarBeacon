package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/testpcap"
	bolt "go.etcd.io/bbolt"
)

func TestLocalReplaySampleQuantityAndFailedImportRecovery(t *testing.T) {
	dir := t.TempDir()
	wal, err := OpenWAL(filepath.Join(dir, "wal.db"), "tenant_samples", "sensor_samples", "reg_samples", 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer wal.Close()
	storage, err := replay.NewLocal(filepath.Join(dir, "samples"), 100*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := NewLocalIdentity(wal, "sample-test-password")
	if err != nil {
		t.Fatal(err)
	}
	u, _, err := identity.Password(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	token, csrf, err := identity.CreateSession(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewServer(httpapi.Middleware(mux))
	defer server.Close()
	auth := httpapi.NewAuth(identity, nil, server.URL, "sample_session", false)
	service := &ReplayService{WAL: wal, Storage: storage, Engine: &Engine{Config: config.Config{}}, RetentionDays: 180}
	service.Register(mux, auth)
	packet, err := testpcap.HTTP(false)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err = wal.DB.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("replay_samples"))
		if err != nil {
			return err
		}
		for i := range replay.MaxSamples {
			sample := replay.Sample{ID: fmt.Sprintf("sample_fixture_%05d", i), Name: "capture.pcap", Size: int64(len(packet)), SHA256: control.Digest(packet), Format: "pcap", CreatedAt: now, ExpiresAt: now.AddDate(0, 0, 180)}
			raw, err := json.Marshal(sample)
			if err != nil {
				return err
			}
			if err = b.Put([]byte(sample.ID), raw); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	post := func(data []byte, status int) []byte {
		t.Helper()
		r, err := http.NewRequest("POST", server.URL+"/api/local/v1/replay/samples", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/octet-stream")
		r.Header.Set("X-Filename", "capture.pcap")
		r.Header.Set("Origin", server.URL)
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(&http.Cookie{Name: "sample_session", Value: token})
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != status {
			t.Fatalf("导入样本状态 %d，期望 %d；%s", response.StatusCode, status, raw)
		}
		return raw
	}
	post(packet, 409)
	removeFixture := func(i int) {
		t.Helper()
		if err := wal.DB.Update(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte("replay_samples")).Delete([]byte(fmt.Sprintf("sample_fixture_%05d", i)))
		}); err != nil {
			t.Fatal(err)
		}
	}
	removeFixture(0)
	var sample replay.Sample
	if err = json.Unmarshal(post(packet, 201), &sample); err != nil {
		t.Fatal(err)
	}
	if sample.SHA256 != control.Digest(packet) || sample.ExpiresAt.Sub(sample.CreatedAt) < 179*24*time.Hour {
		t.Fatal("实际样本摘要或默认期限不正确")
	}
	reader, err := storage.Open(context.Background(), replay.Key(wal.TenantID, sample.ID))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || !bytes.Equal(stored, packet) {
		t.Fatal("实际 PCAP 对象没有完整持久化", err)
	}
	post(packet, 409)
	removeFixture(1)
	post(bytes.Repeat([]byte{0}, len(packet)), 422)
	count := func() int {
		t.Helper()
		n := 0
		if err := wal.DB.View(func(tx *bolt.Tx) error { n = tx.Bucket([]byte("replay_samples")).Stats().KeyN; return nil }); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count() != replay.MaxSamples-1 {
		t.Fatal("格式失败仍占用样本名额")
	}
	if err = wal.DB.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists([]byte("local_audits"))
		if e != nil {
			return e
		}
		return b.Put(key(0), []byte(`{"broken":`))
	}); err != nil {
		t.Fatal(err)
	}
	post(packet, 503)
	if count() != replay.MaxSamples-1 {
		t.Fatal("审计失败仍保留未发布样本")
	}
}

func sampleFixture(t *testing.T) (*ReplayService, []byte) {
	t.Helper()
	dir := t.TempDir()
	wal, err := OpenWAL(filepath.Join(dir, "wal.db"), "tenant_gc", "sensor_gc", "reg_gc", 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { wal.Close() })
	storage, err := replay.NewLocal(filepath.Join(dir, "objects"), 100*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := testpcap.HTTP(false)
	if err != nil {
		t.Fatal(err)
	}
	return &ReplayService{WAL: wal, Storage: storage, RetentionDays: 180}, packet
}

func TestLocalSampleFinalSlotIsAtomicAcrossConcurrentImports(t *testing.T) {
	s, _ := sampleFixture(t)
	now := time.Now().UTC()
	if err := s.WAL.DB.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("replay_samples"))
		if err != nil {
			return err
		}
		for i := range replay.MaxSamples - 1 {
			id := fmt.Sprintf("reserved_fixture_%05d", i)
			raw, err := json.Marshal(localSample{Sample: replay.Sample{ID: id, CreatedAt: now, ExpiresAt: now.AddDate(0, 0, 180)}, State: "uploading"})
			if err != nil {
				return err
			}
			if err := b.Put([]byte(id), raw); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		id  string
		err error
	}
	start := make(chan struct{})
	results := make(chan outcome, 32)
	for i := range 32 {
		go func() {
			<-start
			id := fmt.Sprintf("concurrent_%02d", i)
			err := s.reserveSample(context.Background(), replay.Sample{ID: id, CreatedAt: now, ExpiresAt: now.AddDate(0, 0, 180)})
			results <- outcome{id: id, err: err}
		}()
	}
	close(start)
	winner := ""
	rejected := 0
	for range 32 {
		result := <-results
		if result.err == nil {
			if winner != "" {
				t.Fatal("多个并发导入占用同一个剩余名额")
			}
			winner = result.id
		} else if errors.Is(result.err, replay.ErrQuota) {
			rejected++
		} else {
			t.Fatal(result.err)
		}
	}
	if winner == "" || rejected != 31 {
		t.Fatal("最后一个名额未得到唯一分配", winner, rejected)
	}
	if err := s.removePendingSample(winner); err != nil {
		t.Fatal(err)
	}
	if err := s.reserveSample(context.Background(), replay.Sample{ID: "replacement", CreatedAt: now, ExpiresAt: now.AddDate(0, 0, 180)}); err != nil {
		t.Fatal("失败导入回收后不能再次使用名额", err)
	}
}

func recordSample(t *testing.T, s *ReplayService, sample localSample) {
	t.Helper()
	raw, err := json.Marshal(sample)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.WAL.DB.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists([]byte("replay_samples"))
		if e != nil {
			return e
		}
		return b.Put([]byte(sample.ID), raw)
	}); err != nil {
		t.Fatal(err)
	}
}

func objectPath(s *ReplayService, id string) string {
	return filepath.Join(s.Storage.Dir, control.Digest([]byte(replay.Key(s.WAL.TenantID, id)))+".pcap")
}

func TestLocalReplaySweepBoundsGraceReservationsAndOrphans(t *testing.T) {
	s, packet := sampleFixture(t)
	ctx := context.Background()
	if err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	put := func(id string, expiry time.Time, state string, age time.Duration) {
		t.Helper()
		sha, kind, err := s.Storage.Put(ctx, replay.Key(s.WAL.TenantID, id), bytes.NewReader(packet), int64(len(packet)))
		if err != nil {
			t.Fatal(err)
		}
		recordSample(t, s, localSample{Sample: replay.Sample{ID: id, Name: "capture.pcap", Size: int64(len(packet)), SHA256: sha, Format: kind, CreatedAt: now.Add(-age), ExpiresAt: expiry}, State: state})
		old := now.Add(-2 * time.Hour)
		if err = os.Chtimes(objectPath(s, id), old, old); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 101 {
		put(fmt.Sprintf("expired_%03d", i), now.Add(-10*time.Minute), "", 181*24*time.Hour)
	}
	put("grace", now.Add(-time.Minute), "", 180*24*time.Hour)
	put("live", now.AddDate(0, 0, 180), "", 0)
	put("pending_recent", now.AddDate(0, 0, 180), "uploading", time.Minute)
	put("pending_stale", now.AddDate(0, 0, 180), "uploading", 2*time.Hour)
	if _, err := s.Sample("pending_recent"); err == nil {
		t.Fatal("导入预留作为已发布样本读取")
	}
	if _, err := s.Sample("expired_000"); err == nil {
		t.Fatal("过期样本仍可查询")
	}
	if _, err := s.Sample("missing"); err == nil {
		t.Fatal("缺失样本未拒绝")
	}
	if _, _, err := s.Storage.Put(ctx, replay.Key(s.WAL.TenantID, "orphan"), bytes.NewReader(packet), int64(len(packet))); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-2 * time.Hour)
	if err := os.Chtimes(objectPath(s, "orphan"), old, old); err != nil {
		t.Fatal(err)
	}
	if err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Storage.Open(ctx, replay.Key(s.WAL.TenantID, "expired_000")); err == nil {
		t.Fatal("已回收对象仍然存在")
	}
	for _, id := range []string{"expired_100", "grace", "live", "pending_recent", "pending_stale"} {
		reader, err := s.Storage.Open(ctx, replay.Key(s.WAL.TenantID, id))
		if err != nil {
			t.Fatal("有界清理或孤儿清理错误删除保留对象", id, err)
		}
		reader.Close()
	}
	if _, err := os.Stat(objectPath(s, "orphan")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("未索引旧对象未回收", err)
	}
	if err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"expired_100", "pending_stale"} {
		if _, err := os.Stat(objectPath(s, id)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("后续批次没有回收过期或中断导入对象", id, err)
		}
	}
	if _, err := s.Sample("live"); err != nil {
		t.Fatal("回收影响有效样本", err)
	}
	if err := s.reserveSample(ctx, replay.Sample{ID: "pending_index", CreatedAt: now, ExpiresAt: now.AddDate(0, 0, 180)}); err != nil {
		t.Fatal(err)
	}
	if err := s.removePendingSample("pending_index"); err != nil {
		t.Fatal(err)
	}
	if err := s.removePendingSample("live"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sample("live"); err != nil {
		t.Fatal("失败导入回收错误删除已发布对象", err)
	}
	if err := s.removePendingSample("missing"); err != nil {
		t.Fatal(err)
	}
}

type delayedSampleReader struct {
	once             sync.Once
	entered, release chan struct{}
	reader           io.Reader
}

func (r *delayedSampleReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered); <-r.release })
	return r.reader.Read(p)
}

func TestLocalSampleGCDoesNotBlockEventWALDuringDiskWait(t *testing.T) {
	s, packet := sampleFixture(t)
	now := time.Now().UTC()
	recordSample(t, s, localSample{Sample: replay.Sample{ID: "expired", Name: "capture.pcap", SHA256: control.Digest(packet), Size: int64(len(packet)), Format: "pcap", CreatedAt: now.AddDate(0, 0, -181), ExpiresAt: now.Add(-10 * time.Minute)}})
	blocked := &delayedSampleReader{entered: make(chan struct{}), release: make(chan struct{}), reader: bytes.NewReader(packet)}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(blocked.release) }) }
	defer release()
	upload := make(chan error, 1)
	go func() {
		_, _, err := s.Storage.Put(context.Background(), replay.Key(s.WAL.TenantID, "slow_upload"), blocked, int64(len(packet)))
		upload <- err
	}()
	select {
	case <-blocked.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("受控磁盘等待没有进入")
	}
	sweep := make(chan error, 1)
	go func() { sweep <- s.Sweep(context.Background()) }()
	deadline := time.Now().Add(3 * time.Second)
	marked := false
	for time.Now().Before(deadline) {
		if err := s.WAL.DB.View(func(tx *bolt.Tx) error {
			var sample localSample
			if err := json.Unmarshal(tx.Bucket([]byte("replay_samples")).Get([]byte("expired")), &sample); err != nil {
				return err
			}
			marked = sample.State == "deleting"
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if marked {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !marked {
		t.Fatal("回收未在磁盘等待前提交标记")
	}
	written := make(chan error, 1)
	go func() {
		written <- s.WAL.SaveLocalConfig([]byte(`{"interfaces":[],"status":"not_applied"}`), "admin", "request_gc")
	}()
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("等待对象存储时阻塞了 WAL 写事务")
	}
	release()
	if err := <-upload; err != nil {
		t.Fatal(err)
	}
	if err := <-sweep; err != nil {
		t.Fatal(err)
	}
}

func TestLocalSampleDeletionRecoveryCancellationAndCorruption(t *testing.T) {
	s, packet := sampleFixture(t)
	now := time.Now().UTC()
	recordSample(t, s, localSample{Sample: replay.Sample{ID: "recover", Name: "capture.pcap", Size: int64(len(packet)), SHA256: control.Digest(packet), Format: "pcap", CreatedAt: now.AddDate(0, 0, -181), ExpiresAt: now.Add(-time.Hour)}})
	path := objectPath(s, "recover")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "block"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Sweep(context.Background()); err == nil {
		t.Fatal("对象删除失败仍报告回收成功")
	}
	if err := s.WAL.DB.View(func(tx *bolt.Tx) error {
		var sample localSample
		if err := json.Unmarshal(tx.Bucket([]byte("replay_samples")).Get([]byte("recover")), &sample); err != nil {
			return err
		}
		if sample.State != "deleting" {
			t.Error("失败删除没有持久回收标记")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sample("recover"); err == nil {
		t.Fatal("回收中的样本仍可读取")
	}
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Storage.Put(context.Background(), replay.Key(s.WAL.TenantID, "recover"), bytes.NewReader(packet), int64(len(packet))); err != nil {
		t.Fatal(err)
	}
	if err := s.Sweep(context.Background()); err != nil {
		t.Fatal("可恢复删除未完成", err)
	}
	recordSample(t, s, localSample{Sample: replay.Sample{ID: "live", SHA256: control.Digest(packet), CreatedAt: now, ExpiresAt: now.AddDate(0, 0, 180)}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Sweep(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("取消的回收仍继续执行", err)
	}
	if err := s.reserveSample(ctx, replay.Sample{ID: "cancelled"}); !errors.Is(err, context.Canceled) {
		t.Fatal("取消的请求仍预留样本", err)
	}
	if err := s.WAL.DB.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("replay_samples")).Put([]byte("broken"), []byte(`{"bad":`))
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Sweep(context.Background()); err == nil {
		t.Fatal("损坏索引未停止回收")
	}
	if err := s.removePendingSample("broken"); err == nil {
		t.Fatal("未解析的索引被直接删除")
	}
	if err := s.WAL.DB.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("replay_samples")).Delete([]byte("broken")) }); err != nil {
		t.Fatal(err)
	}
	if err := s.reserveSample(context.Background(), replay.Sample{ID: "live"}); err == nil {
		t.Fatal("预留覆盖了已存在样本")
	}
	if err := s.WAL.DB.Update(func(tx *bolt.Tx) error {
		raw, _ := json.Marshal(localSample{Sample: replay.Sample{ID: "different"}})
		return tx.Bucket([]byte("replay_samples")).Put([]byte("live"), raw)
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Sweep(context.Background()); err == nil {
		t.Fatal("索引身份不一致仍进行对象删除")
	}
}
