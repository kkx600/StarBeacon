package collectorupdate

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

const releaseRetentionFile = ".maintenance-retention.json"

// 维护目录属于低频控制面；拒绝超额目录，避免回收无限扫描或占住维护锁。
const maxCleanupReceipts = 4096
const maxCleanupReleases = 1024
const cleanupReceiptBatch = 100
const cleanupReleaseBatch = 5

type releaseRetention struct {
	SchemaVersion int       `json:"schema_version"`
	Release       Release   `json:"release"`
	StagedAt      time.Time `json:"staged_at"`
	RetainUntil   time.Time `json:"retain_until"`
}

type CleanupReport struct {
	SchemaVersion       int       `json:"schema_version"`
	Instance            string    `json:"instance"`
	EvaluatedAt         time.Time `json:"evaluated_at"`
	Executed            bool      `json:"executed"`
	ReceiptsScanned     int       `json:"receipts_scanned"`
	ReleasesScanned     int       `json:"releases_scanned"`
	ReceiptCandidates   []string  `json:"receipt_candidates"`
	ReleaseCandidates   []string  `json:"release_candidates"`
	ProtectedReleases   []string  `json:"protected_releases"`
	UnmanagedReleases   int       `json:"unmanaged_releases"`
	ReceiptsRemoved     int       `json:"receipts_removed"`
	ReleasesRemoved     int       `json:"releases_removed"`
	LogicalBytesRemoved int64     `json:"logical_bytes_removed"`
	MoreEligible        bool      `json:"more_eligible"`
}

type cleanupReceipt struct {
	name     string
	releases []string
	size     int64
}

type cleanupRelease struct {
	name    string
	bytes   int64
	release Release
	pending bool
	present bool
}

type reclaimRecord struct {
	SchemaVersion int     `json:"schema_version"`
	Instance      string  `json:"instance"`
	BindingSHA256 string  `json:"binding_sha256"`
	Release       Release `json:"release"`
}

// Cleanup 不调用服务管理、WAL 或设备接口；与程序切换共享排他维护锁。
// 先核对完整有界目录及全部回收候选，再删除；失败不会删除尚有未知引用的材料。
func (m *Manager) Cleanup(ctx context.Context, execute bool) (CleanupReport, error) {
	report := CleanupReport{SchemaVersion: 1, Instance: m.Instance, EvaluatedAt: m.now(), Executed: execute, ReceiptCandidates: []string{}, ReleaseCandidates: []string{}, ProtectedReleases: []string{}}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	lock, err := m.lock()
	if err != nil {
		return report, err
	}
	defer lock.Close()
	s, err := m.readState()
	if err != nil {
		return report, err
	}
	if s.Operation != nil && s.Operation.FinishedAt == nil {
		return report, ErrRecoveryRequired
	}
	root, err := os.OpenRoot(m.Root)
	if err != nil {
		return report, err
	}
	defer root.Close()
	rootInfo, err := root.Stat(".")
	if err != nil {
		return report, err
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return report, errors.New("无法核对维护文件系统身份")
	}
	device := uint64(rootStat.Dev)
	protected := map[string]bool{}
	for _, r := range []*Release{s.Current, s.Previous} {
		if r != nil {
			protected[r.Directory] = true
		}
	}
	selected, err := root.Readlink("current")
	if s.Current != nil && (err != nil || selected != filepath.Join("releases", s.Current.Directory)) || s.Current == nil && !errors.Is(err, os.ErrNotExist) {
		return report, errors.New("维护状态与当前程序选择不一致，禁止回收")
	}
	operations, err := cleanupEntries(root, "operations", maxCleanupReceipts)
	if err != nil {
		return report, err
	}
	known := map[string]Release{}
	deadline := map[string]time.Time{}
	var receipts []cleanupReceipt
	for _, item := range operations {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		name := item.Name()
		id := strings.TrimSuffix(name, ".json")
		if !strings.HasSuffix(name, ".json") || !contract.ValidID(id) || item.Type() != 0 {
			return report, errors.New("维护回执目录含有无法核对的对象，禁止回收")
		}
		var previous State
		if err := readJSON(filepath.Join(m.Root, "operations", name), &previous); err != nil {
			return report, err
		}
		op := previous.Operation
		if previous.SchemaVersion != 1 || previous.Instance != m.Instance || previous.Mode != m.Mode || previous.BindingSHA256 != m.BindingSHA256 || op == nil || op.ID != id || op.Kind != "apply" && op.Kind != "rollback" || op.FinishedAt == nil || op.Phase != "committed" && op.Phase != "restored" || op.StartedAt.IsZero() || op.FinishedAt.Before(op.StartedAt) || !op.RetainUntil.After(op.StartedAt) {
			return report, errors.New("维护回执归属、完成状态或冻结期限无效")
		}
		info, err := item.Info()
		if err != nil {
			return report, err
		}
		receipt := cleanupReceipt{name: name, size: info.Size()}
		for _, r := range []*Release{&op.Target, op.Original, previous.Current, previous.Previous} {
			if r == nil {
				continue
			}
			if err := r.validate(); err != nil {
				return report, err
			}
			if old, ok := known[r.Directory]; ok && old != *r {
				return report, errors.New("同名历史制品存在不同身份")
			}
			known[r.Directory] = *r
			if deadline[r.Directory].Before(op.RetainUntil) {
				deadline[r.Directory] = op.RetainUntil
			}
			receipt.releases = append(receipt.releases, r.Directory)
			if op.RetainUntil.After(report.EvaluatedAt) {
				protected[r.Directory] = true
			}
		}
		report.ReceiptsScanned++
		if !op.RetainUntil.After(report.EvaluatedAt) && (s.Operation == nil || s.Operation.ID != id) {
			receipts = append(receipts, receipt)
		}
	}
	releases, err := cleanupEntries(root, "releases", maxCleanupReleases)
	if err != nil {
		return report, err
	}
	pending, err := m.pendingReclaims(root)
	if err != nil {
		return report, err
	}
	var candidates []cleanupRelease
	for _, candidate := range pending {
		if candidate.present && protected[candidate.name] {
			return report, errors.New("待回收材料仍受有效部署或未到期回执保护")
		}
		if len(candidates) >= cleanupReleaseBatch {
			report.MoreEligible = true
			continue
		}
		if candidate.present {
			candidate.bytes, err = cleanupTree(ctx, filepath.Join(m.Root, "reclaim", candidate.name), device)
			if err != nil {
				return report, err
			}
		}
		candidates = append(candidates, candidate)
		if candidate.present {
			report.ReleaseCandidates = append(report.ReleaseCandidates, candidate.name)
		}
	}
	legacy := map[string]bool{}
	for _, item := range releases {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		name := item.Name()
		report.ReleasesScanned++
		if !item.IsDir() || item.Type()&os.ModeSymlink != 0 {
			return report, errors.New("历史制品目录含有无法核对的对象，禁止回收")
		}
		var record releaseRetention
		var identity Release
		err := readJSON(filepath.Join(m.Root, "releases", name, releaseRetentionFile), &record)
		if errors.Is(err, os.ErrNotExist) {
			legacy[name] = true
			if _, ok := known[name]; !ok {
				report.UnmanagedReleases++
				continue
			}
			identity = known[name]
		} else if err != nil {
			return report, err
		} else {
			if record.SchemaVersion != 1 || record.Release.validate() != nil || record.Release.Directory != name || record.StagedAt.IsZero() || !record.RetainUntil.After(record.StagedAt) {
				return report, errors.New("历史制品身份或冻结期限无效")
			}
			if old, ok := known[name]; ok && old != record.Release {
				return report, errors.New("历史制品与维护回执不一致")
			}
			if deadline[name].Before(record.RetainUntil) {
				deadline[name] = record.RetainUntil
			}
			identity = record.Release
		}
		if protected[name] || deadline[name].After(report.EvaluatedAt) {
			protected[name] = true
			continue
		}
		if len(candidates) >= cleanupReleaseBatch {
			report.MoreEligible = true
			continue
		}
		bytes, err := cleanupTree(ctx, filepath.Join(m.Root, "releases", name), device)
		if err != nil {
			return report, err
		}
		candidates = append(candidates, cleanupRelease{name: name, bytes: bytes, release: identity, present: true})
		if !slices.Contains(report.ReleaseCandidates, name) {
			report.ReleaseCandidates = append(report.ReleaseCandidates, name)
		}
	}
	for name := range protected {
		report.ProtectedReleases = append(report.ProtectedReleases, name)
	}
	slices.Sort(report.ProtectedReleases)
	removed := map[string]bool{}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if execute {
			if err := m.reclaim(root, candidate); err != nil {
				return report, err
			}
			if candidate.present {
				report.ReleasesRemoved++
			}
			report.LogicalBytesRemoved += candidate.bytes
		}
		removed[candidate.name] = true
	}
	if execute && len(candidates) != 0 {
		if err := syncDirectory(filepath.Join(m.Root, "releases")); err != nil {
			return report, err
		}
	}
	for _, receipt := range receipts {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		// 旧目录没有独立期限时，最后一份来源回执必须留到该目录真正回收。
		blocked := false
		for _, name := range receipt.releases {
			if legacy[name] && !removed[name] {
				blocked = true
			}
		}
		if blocked {
			continue
		}
		if len(report.ReceiptCandidates) >= cleanupReceiptBatch {
			report.MoreEligible = true
			break
		}
		report.ReceiptCandidates = append(report.ReceiptCandidates, strings.TrimSuffix(receipt.name, ".json"))
		if execute {
			if err := root.Remove(filepath.Join("operations", receipt.name)); err != nil {
				return report, err
			}
			report.ReceiptsRemoved++
			report.LogicalBytesRemoved += receipt.size
		}
	}
	if execute && report.ReceiptsRemoved != 0 {
		err = syncDirectory(filepath.Join(m.Root, "operations"))
	}
	return report, err
}

func (m *Manager) pendingReclaims(root *os.Root) ([]cleanupRelease, error) {
	info, err := root.Lstat("reclaim")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm()&0077 != 0 || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("维护回收目录必须由当前部署管理员独占")
	}
	entries, err := cleanupEntries(root, "reclaim", maxCleanupReleases*2)
	if err != nil {
		return nil, err
	}
	var result []cleanupRelease
	directories := map[string]bool{}
	records := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() {
			directories[entry.Name()] = true
			continue
		}
		if entry.Type() != 0 || !strings.HasSuffix(entry.Name(), ".json") {
			return nil, errors.New("维护回收目录含有未知对象")
		}
		var record reclaimRecord
		if err := readJSON(filepath.Join(m.Root, "reclaim", entry.Name()), &record); err != nil {
			return nil, err
		}
		if record.SchemaVersion != 1 || record.Instance != m.Instance || record.BindingSHA256 != m.BindingSHA256 || record.Release.validate() != nil || entry.Name() != record.Release.Directory+".json" {
			return nil, errors.New("维护回收凭据的归属或制品身份无效")
		}
		records[record.Release.Directory] = true
		result = append(result, cleanupRelease{name: record.Release.Directory, release: record.Release, pending: true})
	}
	for name := range directories {
		if !records[name] {
			return nil, errors.New("待回收目录缺少独立来源凭据")
		}
	}
	for i := range result {
		result[i].present = directories[result[i].name]
	}
	return result, nil
}

func (m *Manager) reclaim(root *os.Root, candidate cleanupRelease) error {
	if err := root.Mkdir("reclaim", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if !candidate.pending {
		// 凭据和待删除目录分开保存；进程在递归删除任意位置退出后仍能核对剩余材料。
		path := filepath.Join(m.Root, "reclaim", candidate.name+".json")
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("同名回收凭据已存在，须先完成原回收")
		}
		record := reclaimRecord{SchemaVersion: 1, Instance: m.Instance, BindingSHA256: m.BindingSHA256, Release: candidate.release}
		if err := atomicJSON(path, record); err != nil {
			return err
		}
		if _, err := root.Lstat(filepath.Join("reclaim", candidate.name)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("同名回收目录已存在，禁止覆盖")
		}
		if err := root.Rename(filepath.Join("releases", candidate.name), filepath.Join("reclaim", candidate.name)); err != nil {
			return err
		}
		if err := errors.Join(syncDirectory(filepath.Join(m.Root, "releases")), syncDirectory(filepath.Join(m.Root, "reclaim"))); err != nil {
			return err
		}
	}
	if err := root.RemoveAll(filepath.Join("reclaim", candidate.name)); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Join(m.Root, "reclaim")); err != nil {
		return err
	}
	if err := root.Remove(filepath.Join("reclaim", candidate.name+".json")); err != nil {
		return err
	}
	return syncDirectory(filepath.Join(m.Root, "reclaim"))
}

func cleanupEntries(root *os.Root, directory string, limit int) ([]os.DirEntry, error) {
	f, err := root.Open(directory)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > limit {
		return nil, errors.New("维护回收目录超过核对预算，请先核对目录容量")
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, nil
}

func cleanupTree(ctx context.Context, directory string, device uint64) (int64, error) {
	info, err := os.Lstat(directory)
	if err != nil {
		return 0, err
	}
	base, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(base.Dev) != device || !info.IsDir() || info.Mode().Perm()&0022 != 0 || base.Uid != uint32(os.Geteuid()) {
		return 0, errors.New("历史制品目录权限或归属无效")
	}
	var size int64
	files := 0
	tree, err := os.OpenRoot(directory)
	if err != nil {
		return 0, err
	}
	defer tree.Close()
	var visit func(string) error
	visit = func(name string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		files++
		if files > maxFiles*2+10 {
			return errors.New("历史制品文件数量超过核对预算")
		}
		info, err := tree.Lstat(name)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Dev != base.Dev || stat.Uid != base.Uid || info.Mode().Perm()&0022 != 0 || !info.IsDir() && !info.Mode().IsRegular() {
			return errors.New("历史制品包含链接、额外挂载或权限异常对象")
		}
		if info.Mode().IsRegular() {
			size += info.Size()
			if size > MaxExpandedBytes+(2<<20) {
				return errors.New("历史制品体积超过核对预算")
			}
			return nil
		}
		f, err := tree.Open(name)
		if err != nil {
			return err
		}
		defer f.Close()
		for {
			entries, err := f.ReadDir(64)
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			for _, entry := range entries {
				if err := visit(filepath.Join(name, entry.Name())); err != nil {
					return err
				}
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
		}
	}
	err = visit(".")
	return size, err
}
