package packetarchive

import (
	"path/filepath"
	"testing"
)

func TestSharedPoolFloorReclaimAndAdmission(t *testing.T) {
	const gib = int64(1) << 30
	total := uint64(1000 * gib)
	percent := Pool{FreePercent: 5}
	if percent.Floor(total) != uint64(50*gib) {
		t.Fatal("百分比阈值错误", percent.Floor(total))
	}
	if mixed := (Pool{FreeBytes: 80 * gib, FreePercent: 5}); mixed.Floor(total) != uint64(80*gib) {
		t.Fatal("绝对阈值与百分比应取较大值")
	}
	if (Pool{FreeBytes: 2000 * gib}).Floor(total) != total {
		t.Fatal("阈值不能超过总容量")
	}
	low := Usage{Measured: true, Free: uint64(30 * gib), Total: total}
	if got := percent.Reclaim(low, 900*gib, 0); got != 20*gib {
		t.Fatal("剩余空间缺口计算错误", got)
	}
	if got := percent.Reclaim(low, 900*gib, 15*gib); got != 5*gib {
		t.Fatal("待删除原包未计入即将释放的空间", got)
	}
	if got := percent.Reclaim(Usage{Measured: true, Free: uint64(60 * gib), Total: total}, 900*gib, 0); got != 0 {
		t.Fatal("空间充足时不应回收", got)
	}
	limited := Pool{LimitBytes: 500 * gib}
	if got := limited.Reclaim(Usage{}, 520*gib, 5*gib); got != 15*gib {
		t.Fatal("目录总量上限计算错误", got)
	}
	if got := (Pool{}).Reclaim(low, 900*gib, 0); got != 0 {
		t.Fatal("关闭空间回收后仍按容量删除", got)
	}
	if !percent.Admit(Usage{}, 16<<20) || !percent.Admit(Usage{Measured: true, Free: uint64(26 * gib), Total: total}, 16<<20) || percent.Admit(Usage{Measured: true, Free: uint64(25 * gib), Total: total}, 16<<20) {
		t.Fatal("准入保留空间错误")
	}
}

func TestLocalObjectsReportFilesystemUsage(t *testing.T) {
	objects, err := NewLocalObjects(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	usage, err := objects.Usage()
	if err != nil || !usage.Measured || usage.Total == 0 || usage.Free > usage.Total {
		t.Fatalf("文件系统容量读取错误：%+v %v", usage, err)
	}
	var _ Measurer = objects
}
