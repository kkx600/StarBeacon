package packetarchive

import (
	"errors"

	"golang.org/x/sys/unix"
)

// ErrStorageFull 表示平台共享原包存储暂时没有可用空间；采集器保留本地原件，回收后继续上传。
var ErrStorageFull = errors.New("平台原包存储空间不足；空间回收后采集器继续上传本地原件")

// Pool 描述全部租户共享的平台原包存储。容量取决于部署存储：剩余空间低于阈值或目录总量超过上限时，
// 按全局最早优先回收已归档原包；保留期仍是每个原包的最长期限。
type Pool struct {
	// FreeBytes 与 FreePercent 取较大值作为文件系统需要保持的剩余空间；均为 0 时只按保留期删除。
	FreeBytes   int64
	FreePercent int
	// LimitBytes 限制目录登记的存储字节总量，0 表示不限；对象存储无法探测剩余空间时使用。
	LimitBytes int64
}

// Usage 是原包存储所在文件系统的剩余与总容量；对象存储无法测量时 Measured 为 false。
type Usage struct {
	Measured    bool
	Free, Total uint64
}

// Measurer 由能够读取所在文件系统容量的对象存储实现。
type Measurer interface {
	Usage() (Usage, error)
}

// Usage 读取对象目录所在文件系统对非特权进程可用的空间。
func (s *LocalObjects) Usage() (Usage, error) {
	var disk unix.Statfs_t
	if err := unix.Statfs(s.Dir, &disk); err != nil {
		return Usage{}, err
	}
	return Usage{Measured: true, Free: disk.Bavail * uint64(disk.Bsize), Total: disk.Blocks * uint64(disk.Bsize)}, nil
}

// Floor 返回需要保持的剩余空间。
func (p Pool) Floor(total uint64) uint64 {
	floor := uint64(max(p.FreeBytes, 0))
	if p.FreePercent > 0 {
		floor = max(floor, total/100*uint64(p.FreePercent))
	}
	return min(floor, total)
}

// Reclaim 返回本轮需要回收的存储字节数。pending 是已到期、尚未删除但仍占用空间的原包字节，
// 计入即将释放的空间，避免同一缺口被重复回收。
func (p Pool) Reclaim(u Usage, cataloged, pending int64) int64 {
	need := int64(0)
	if u.Measured {
		floor, free := p.Floor(u.Total), u.Free+uint64(max(pending, 0))
		if free < floor {
			need = int64(floor - free)
		}
	}
	if live := cataloged - max(pending, 0); p.LimitBytes > 0 && live > p.LimitBytes {
		need = max(need, live-p.LimitBytes)
	}
	return need
}

// Admit 判断平台能否接收一个新原包：至少保留一半剩余空间阈值，避免在下一轮回收前写满磁盘。
// 未测量文件系统时不按空间拒绝，目录总量上限由回收在事后执行。
func (p Pool) Admit(u Usage, stored int64) bool {
	if !u.Measured {
		return true
	}
	return u.Free >= p.Floor(u.Total)/2+uint64(max(stored, 0))
}
