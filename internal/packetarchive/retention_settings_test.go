package packetarchive

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/packetpolicy"
	bolt "go.etcd.io/bbolt"
)

func TestRetentionSingleRevisionAndPersistentSeal(t *testing.T) {
	s, db := retentionSpool(t)
	if _, err := s.RetentionObservation(); !errors.Is(err, ErrRetentionUnavailable) {
		t.Fatal("缺少引导文件时应报告未知", err)
	}
	installRetention(t, s, `{"network_domain":"test_domain","revision":1}`)
	base, err := s.RetentionObservation()
	if err != nil || !base.Valid() || base.Origin != "file" {
		t.Fatal("引导配置回读无效", err)
	}
	next := base.Policy
	next.Revision++
	next.Mode = RetentionAlertOnly
	change := packetpolicy.Change{ExpectedRevision: base.Policy.Revision, ExpectedSHA256: base.SHA256, Policy: next}
	brokenAudit := errors.New("审计写入失败模拟")
	if _, err := s.UpdateRetention(change, "local", "", func(*bolt.Tx) error { return brokenAudit }); !errors.Is(err, brokenAudit) {
		t.Fatal("审计失败未回滚配置", err)
	}
	var audits atomic.Int64
	audit := func(*bolt.Tx) error { audits.Add(1); return nil }
	result := make(chan error, 2)
	var running sync.WaitGroup
	for _, origin := range []string{"platform", "local"} {
		running.Go(func() {
			task := ""
			if origin == "platform" {
				task = "retention_task"
			}
			_, err := s.UpdateRetention(change, origin, task, audit)
			result <- err
		})
	}
	running.Wait()
	close(result)
	var rejected int
	for err := range result {
		if errors.Is(err, ErrRetentionConflict) {
			rejected++
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if rejected != 1 || audits.Load() != 1 {
		t.Fatal("双端并发同一基线只能变更一次")
	}
	active, err := s.RetentionObservation()
	if err != nil || !next.Equal(active.Policy) || !active.Valid() {
		t.Fatal("回读未确认获胜的修订", err)
	}
	if active.Origin == "platform" {
		replay, err := s.UpdateRetention(change, "platform", active.TaskID, audit)
		if err != nil || replay.SHA256 != active.SHA256 || audits.Load() != 1 {
			t.Fatal("重复平台命令重复写入", err)
		}
	}
	reopened, err := NewSpool(db, s.Dir, s.TenantID, s.SensorID, s.RegistrationID, s.Quota, s.SegmentBytes)
	if err != nil {
		t.Fatal(err)
	}
	reopened.RetentionFile = s.RetentionFile
	installRetention(t, reopened, `{"network_domain":"another_domain","revision":7}`)
	got, err := reopened.RetentionObservation()
	if err != nil || got.SHA256 != active.SHA256 {
		t.Fatal("重开后不同网络域的引导文件覆盖了经审计的配置", err)
	}
	frames := sessionFrames(t)
	at := frames[0].info.Timestamp.Add(-time.Second)
	pending := hotRetention(t, reopened, "managed_seal", at, frames)
	sealRetention(t, pending, frames[len(frames)-1].info.Timestamp.Add(time.Second))
	installRetention(t, reopened, `{"network_domain":"test_domain","revision":3,"mode":"full"}`)
	row, _ := retainedRecord(t, reopened, pending.ID)
	if row.Capture.Retention.PolicyRevision != 2 || row.Capture.Retention.Mode != RetentionAlertOnly || row.Capture.Packets != 0 {
		t.Fatal("后续配置变化改写了已冻结窗口", row.Capture.Retention)
	}
	got, err = reopened.RetentionObservation()
	if err != nil || got.Policy.Revision != 3 || got.Origin != "file" {
		t.Fatal("本地文件的同域更高修订未同步", err)
	}
	// 内部状态损坏应触发原样保护，而非继续按不可信配置裁剪。
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket(retentionSettings).Put(activeRetentionKey, []byte("{}")) }); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.RetentionObservation(); !errors.Is(err, ErrIntegrity) {
		t.Fatal("已损坏持久化状态被标为正常", err)
	}
}
