package collectorupdate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func expireMaintenance(m *Manager) {
	m.Now = func() time.Time { return fixedTime.AddDate(0, 0, 181) }
}

func applyCurrentTime(t *testing.T, m *Manager, generation, revision int64, sign func(Proof) (Envelope, error), archive string, proof Envelope) State {
	t.Helper()
	proof.Proof.IssuedAt, proof.Proof.ExpiresAt = m.now().Add(-time.Hour), m.now().Add(time.Hour)
	proof, err := sign(proof.Proof)
	if err != nil {
		t.Fatal(err)
	}
	state, err := m.Apply(context.Background(), archive, proof, fmt.Sprintf("timed_%d", generation), revision)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func releaseExists(t *testing.T, m *Manager, r *Release) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(m.Root, "releases", r.Directory))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

func TestCollectorMaintenanceCleanupPreviewsAndRetainsRollback(t *testing.T) {
	m, runtime, key := managerFixture(t)
	first := applyFixture(t, m, key, 1, 0)
	applyFixture(t, m, key, 2, 1)
	last := applyFixture(t, m, key, 3, 2)
	before, _ := os.ReadFile(filepath.Join(m.Root, "state.json"))
	calls := len(runtime.calls)
	expireMaintenance(m)
	preview, err := m.Cleanup(context.Background(), false)
	if err != nil || len(preview.ReleaseCandidates) != 1 || len(preview.ReceiptCandidates) != 2 || preview.ReleasesRemoved != 0 || preview.Executed || !releaseExists(t, m, first.Current) {
		t.Fatal(preview, err)
	}
	result, err := m.Cleanup(context.Background(), true)
	if err != nil || result.ReleasesRemoved != 1 || result.ReceiptsRemoved != 2 || result.LogicalBytesRemoved <= 0 || releaseExists(t, m, first.Current) || !releaseExists(t, m, last.Current) || !releaseExists(t, m, last.Previous) {
		t.Fatal(result, err)
	}
	after, _ := os.ReadFile(filepath.Join(m.Root, "state.json"))
	if !bytes.Equal(before, after) || len(runtime.calls) != calls || BootGuard(m.Root) != nil {
		t.Fatal("回收修改了运行状态或调用了服务管理")
	}
	if again, err := m.Cleanup(context.Background(), true); err != nil || again.ReleasesRemoved != 0 || again.ReceiptsRemoved != 0 {
		t.Fatal(again, err)
	}
	rolled, err := m.Rollback(context.Background(), "rollback_after_cleanup", last.Revision)
	if err != nil || rolled.Current.Proof.Generation != 2 || rolled.MaxGeneration != 3 {
		t.Fatal("回收破坏了前版本回退或发布代次", rolled, err)
	}
}

func TestCollectorCleanupFreezesRetentionAndProtectsUnexpiredReferences(t *testing.T) {
	m, _, key := managerFixture(t)
	first := applyFixture(t, m, key, 1, 0)
	m.Now = func() time.Time { return fixedTime.AddDate(0, 0, 10) }
	archive, proof := writeZIP(t, key, 2, items(2))
	applyCurrentTime(t, m, 2, 1, func(p Proof) (Envelope, error) { return Sign(p, key) }, archive, proof)
	m.Now = func() time.Time { return fixedTime.AddDate(0, 0, 20) }
	archive, proof = writeZIP(t, key, 3, items(3))
	applyCurrentTime(t, m, 3, 2, func(p Proof) (Envelope, error) { return Sign(p, key) }, archive, proof)
	expireMaintenance(m)
	m.RetentionDays = 1
	result, err := m.Cleanup(context.Background(), true)
	if err != nil || result.ReleasesRemoved != 0 || !slices.Contains(result.ProtectedReleases, first.Current.Directory) || !releaseExists(t, m, first.Current) {
		t.Fatal("旧记录被当前配置重算，或忽略有效回执引用", result, err)
	}
	m.Now = func() time.Time { return fixedTime.AddDate(0, 0, 200) }
	result, err = m.Cleanup(context.Background(), true)
	if err != nil || result.ReleasesRemoved != 1 || releaseExists(t, m, first.Current) {
		t.Fatal("到期边界未实际回收", result, err)
	}
}

func TestCollectorCleanupReclaimsStagedOrphanAndConfiguredExpiry(t *testing.T) {
	m, _, key := managerFixture(t)
	if err := m.initialize(); err != nil {
		t.Fatal(err)
	}
	archive, proof := writeZIP(t, key, 1, items(1))
	if _, err := stage(context.Background(), m.Root, archive, proof, m.Key, fixedTime, 0); err == nil {
		t.Fatal("接受无效制品期限")
	}
	release, err := stage(context.Background(), m.Root, archive, proof, m.Key, fixedTime, 7)
	if err != nil {
		t.Fatal(err)
	}
	m.Now = func() time.Time { return fixedTime.AddDate(0, 0, 6) }
	if result, err := m.Cleanup(context.Background(), true); err != nil || result.ReleasesRemoved != 0 {
		t.Fatal(result, err)
	}
	m.Now = func() time.Time { return fixedTime.AddDate(0, 0, 7) }
	if result, err := m.Cleanup(context.Background(), true); err != nil || result.ReleasesRemoved != 1 || releaseExists(t, m, &release) {
		t.Fatal(result, err)
	}
}

func TestCollectorCleanupResumesInterruptedRecursiveDeletion(t *testing.T) {
	m, _, key := managerFixture(t)
	first := applyFixture(t, m, key, 1, 0)
	applyFixture(t, m, key, 2, 1)
	applyFixture(t, m, key, 3, 2)
	expireMaintenance(m)
	garbage := filepath.Join(m.Root, "reclaim")
	if err := os.Mkdir(garbage, 0700); err != nil {
		t.Fatal(err)
	}
	record := reclaimRecord{SchemaVersion: 1, Instance: m.Instance, BindingSHA256: m.BindingSHA256, Release: *first.Current}
	if err := atomicJSON(filepath.Join(garbage, first.Current.Directory+".json"), record); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(m.Root, "releases", first.Current.Directory), filepath.Join(garbage, first.Current.Directory)); err != nil {
		t.Fatal(err)
	}
	// 模拟元数据已被删掉后进程退出；独立回收凭据必须仍能识别剩余文件。
	if err := os.Remove(filepath.Join(garbage, first.Current.Directory, releaseRetentionFile)); err != nil {
		t.Fatal(err)
	}
	result, err := m.Cleanup(context.Background(), true)
	if err != nil || result.ReleasesRemoved != 1 || result.ReceiptsRemoved != 2 {
		t.Fatal(result, err)
	}
	if files, err := os.ReadDir(garbage); err != nil || len(files) != 0 {
		t.Fatal("中断回收未清理独立凭据", err)
	}
	// 目录已删而凭据尚未提交的边界不会重复计算删除体积。
	if err := atomicJSON(filepath.Join(garbage, first.Current.Directory+".json"), record); err != nil {
		t.Fatal(err)
	}
	result, err = m.Cleanup(context.Background(), true)
	if err != nil || result.ReleasesRemoved != 0 || result.LogicalBytesRemoved != 0 {
		t.Fatal(result, err)
	}
}

func TestCollectorCleanupResumesBeforeRenameAndBlocksRestaging(t *testing.T) {
	m, _, key := managerFixture(t)
	m.initialize()
	archive, proof := writeZIP(t, key, 1, items(1))
	release, err := stage(context.Background(), m.Root, archive, proof, m.Key, fixedTime, 1)
	if err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(m.Root, "reclaim")
	os.Mkdir(garbage, 0700)
	record := reclaimRecord{SchemaVersion: 1, Instance: m.Instance, BindingSHA256: m.BindingSHA256, Release: release}
	atomicJSON(filepath.Join(garbage, release.Directory+".json"), record)
	m.Now = func() time.Time { return fixedTime.AddDate(0, 0, 2) }
	result, err := m.Cleanup(context.Background(), true)
	if err != nil || result.ReleasesRemoved != 1 || len(result.ReleaseCandidates) != 1 || releaseExists(t, m, &release) {
		t.Fatal("移动前中断的回收不能继续", result, err)
	}
	atomicJSON(filepath.Join(garbage, release.Directory+".json"), record)
	if _, err := Stage(context.Background(), m.Root, archive, proof, m.Key, fixedTime); err == nil {
		t.Fatal("未完成回收的同名制品被重新暂存")
	}
	result, err = m.Cleanup(context.Background(), true)
	if err != nil || len(result.ReleaseCandidates) != 0 || result.ReleasesRemoved != 0 {
		t.Fatal("只剩回收凭据时错误计量了制品", result, err)
	}
}

func TestCollectorCleanupRejectsForeignReclaimProofAndOversizedTree(t *testing.T) {
	for _, kind := range []string{"foreign", "malformed", "link", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			m, _, key := managerFixture(t)
			first := applyFixture(t, m, key, 1, 0)
			applyFixture(t, m, key, 2, 1)
			applyFixture(t, m, key, 3, 2)
			expireMaintenance(m)
			garbage := filepath.Join(m.Root, "reclaim")
			os.Mkdir(garbage, 0700)
			switch kind {
			case "foreign":
				atomicJSON(filepath.Join(garbage, first.Current.Directory+".json"), reclaimRecord{SchemaVersion: 1, Instance: "other", BindingSHA256: m.BindingSHA256, Release: *first.Current})
			case "malformed":
				os.WriteFile(filepath.Join(garbage, "broken.json"), []byte("{"), 0600)
			case "link":
				os.Symlink(t.TempDir(), filepath.Join(garbage, "external"))
			case "oversized":
				f, err := os.Create(filepath.Join(m.Root, "releases", first.Current.Directory, "oversized"))
				if err != nil {
					t.Fatal(err)
				}
				err = f.Truncate(MaxExpandedBytes + (3 << 20))
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			result, err := m.Cleanup(context.Background(), true)
			if err == nil || result.ReleasesRemoved != 0 || result.ReceiptsRemoved != 0 || !releaseExists(t, m, first.Current) {
				t.Fatal("回收未在删除前拒绝异常来源或超限材料", result, err)
			}
		})
	}
}

func TestCollectorCleanupRetainsUnknownLegacyAndClearsKnownLegacy(t *testing.T) {
	m, _, key := managerFixture(t)
	for i := int64(1); i <= 9; i++ {
		state := applyFixture(t, m, key, i, i-1)
		if err := os.Remove(filepath.Join(m.Root, "releases", state.Current.Directory, releaseRetentionFile)); err != nil {
			t.Fatal(err)
		}
	}
	unknown := filepath.Join(m.Root, "releases", "unmanaged")
	if err := os.Mkdir(unknown, 0755); err != nil {
		t.Fatal(err)
	}
	expireMaintenance(m)
	first, err := m.Cleanup(context.Background(), true)
	if err != nil || first.ReleasesRemoved != 5 || !first.MoreEligible || first.UnmanagedReleases != 1 {
		t.Fatal(first, err)
	}
	second, err := m.Cleanup(context.Background(), true)
	if err != nil || second.ReleasesRemoved != 2 || second.MoreEligible || second.UnmanagedReleases != 1 {
		t.Fatal(second, err)
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Fatal("没有来源依据的目录被删除", err)
	}
}

func TestCollectorCleanupRejectsRecoveryConflictSelectionAndCancellation(t *testing.T) {
	m, _, key := managerFixture(t)
	state := applyFixture(t, m, key, 1, 0)
	expireMaintenance(m)
	lock, err := m.lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Cleanup(context.Background(), true); !errors.Is(err, ErrConflict) {
		t.Fatal("维护并发未被拒绝", err)
	}
	lock.Close()
	state.Operation.Phase, state.Operation.FinishedAt = "unknown", nil
	if err := m.save(state); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Cleanup(context.Background(), true); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatal("未知维护仍执行回收", err)
	}
	finished := fixedTime
	state.Operation.Phase, state.Operation.FinishedAt = "committed", &finished
	m.save(state)
	os.Remove(filepath.Join(m.Root, "current"))
	os.Symlink("releases/other", filepath.Join(m.Root, "current"))
	if _, err := m.Cleanup(context.Background(), true); err == nil {
		t.Fatal("程序选择异常仍执行回收")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Cleanup(ctx, true); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestCollectorCleanupPreflightRejectsTamperingBeforeAnyDeletion(t *testing.T) {
	for _, kind := range []string{"receipt_owner", "receipt_phase", "receipt_target", "receipt_unknown", "release_owner", "release_deadline", "release_target", "release_symlink", "release_writable", "extra_operation"} {
		t.Run(kind, func(t *testing.T) {
			m, _, key := managerFixture(t)
			first := applyFixture(t, m, key, 1, 0)
			applyFixture(t, m, key, 2, 1)
			applyFixture(t, m, key, 3, 2)
			expireMaintenance(m)
			path := filepath.Join(m.Root, "releases", first.Current.Directory, releaseRetentionFile)
			var record releaseRetention
			readJSON(path, &record)
			switch kind {
			case "receipt_owner":
				first.Instance = "other"
			case "receipt_phase":
				first.Operation.Phase = "unknown"
			case "receipt_target":
				first.Operation.Target.Directory = "../other"
			case "receipt_unknown":
				os.WriteFile(m.receiptPath(first.Operation.ID), []byte(`{"unknown":true}`), 0600)
			case "release_owner":
				record.Release.Directory = "elsewhere"
			case "release_deadline":
				record.RetainUntil = record.StagedAt
			case "release_target":
				record.Release.BinarySHA256 = strings.Repeat("c", 64)
			case "release_symlink":
				outside := filepath.Join(t.TempDir(), "keep")
				os.WriteFile(outside, []byte("do not remove"), 0600)
				os.Symlink(outside, filepath.Join(m.Root, "releases", first.Current.Directory, "outside"))
			case "release_writable":
				os.Chmod(filepath.Join(m.Root, "releases", first.Current.Directory, "www/index.html"), 0666)
			case "extra_operation":
				os.Mkdir(filepath.Join(m.Root, "operations", "unknown"), 0755)
			}
			if slices.Contains([]string{"receipt_owner", "receipt_phase", "receipt_target"}, kind) {
				atomicJSON(m.receiptPath(first.Operation.ID), first)
			}
			if strings.HasPrefix(kind, "release_") && !slices.Contains([]string{"release_symlink", "release_writable"}, kind) {
				atomicJSON(path, record)
			}
			result, err := m.Cleanup(context.Background(), true)
			if err == nil || result.ReleasesRemoved != 0 || result.ReceiptsRemoved != 0 || !releaseExists(t, m, first.Current) {
				t.Fatal("异常材料没有在回收前被拒绝", result, err)
			}
		})
	}
}

func TestCollectorCleanupDirectoryAndReceiptBudgets(t *testing.T) {
	m, _, key := managerFixture(t)
	first := applyFixture(t, m, key, 1, 0)
	last := applyFixture(t, m, key, 2, 1)
	expireMaintenance(m)
	for i := 0; i < cleanupReceiptBatch+1; i++ {
		copy := first
		op := *first.Operation
		op.ID = fmt.Sprintf("copy_%03d", i)
		copy.Operation = &op
		if err := atomicJSON(m.receiptPath(op.ID), copy); err != nil {
			t.Fatal(err)
		}
	}
	result, err := m.Cleanup(context.Background(), true)
	if err != nil || result.ReceiptsRemoved != cleanupReceiptBatch || !result.MoreEligible || !releaseExists(t, m, last.Current) || !releaseExists(t, m, last.Previous) {
		t.Fatal(result, err)
	}
	result, err = m.Cleanup(context.Background(), true)
	if err != nil || result.ReceiptsRemoved != 2 || result.MoreEligible {
		t.Fatal(result, err)
	}
	for _, directory := range []string{"operations", "releases"} {
		t.Run(directory, func(t *testing.T) {
			m, _, _ := managerFixture(t)
			m.initialize()
			limit := maxCleanupReceipts
			if directory == "releases" {
				limit = maxCleanupReleases
			}
			for i := 0; i <= limit; i++ {
				file, err := os.Create(filepath.Join(m.Root, directory, fmt.Sprintf("entry_%04d", i)))
				if err != nil {
					t.Fatal(err)
				}
				file.Close()
			}
			if result, err := m.Cleanup(context.Background(), true); err == nil || result.ReleasesRemoved != 0 || result.ReceiptsRemoved != 0 {
				t.Fatal(result, err)
			}
		})
	}
}

func TestCollectorCleanupCLIOutputAndReclaimOwnership(t *testing.T) {
	m, _, _ := managerFixture(t)
	var output bytes.Buffer
	if err := executeCleanup(context.Background(), m, false, &output); err != nil || !strings.Contains(output.String(), `"executed":false`) {
		t.Fatal(output.String(), err)
	}
	if executeCleanup(context.Background(), m, false, failingOutput{}) == nil {
		t.Fatal("回收结果输出失败未返回错误")
	}
	if err := os.Mkdir(filepath.Join(m.Root, "reclaim"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Cleanup(context.Background(), true); err == nil {
		t.Fatal("信任了共享回收目录")
	}
	os.Chmod(filepath.Join(m.Root, "reclaim"), 0700)
	os.Mkdir(filepath.Join(m.Root, "reclaim", "unknown"), 0700)
	if _, err := m.Cleanup(context.Background(), true); err == nil {
		t.Fatal("回收了没有来源凭据的目录")
	}
}
