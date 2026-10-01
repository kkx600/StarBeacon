// Package hosthealth 读取宿主机与服务进程观测，不将宿主指标当作数据存储容量。
package hosthealth

import (
	"context"
	"runtime"
	"strconv"
	"time"

	"github.com/kkx600/StarBeacon/internal/buildinfo"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
)

type Snapshot struct {
	Version       string    `json:"version"`
	Commit        string    `json:"commit"`
	ObservedAt    time.Time `json:"observed_at"`
	CPUPercent    *float64  `json:"cpu_percent"`
	MemoryPercent *float64  `json:"memory_percent"`
	DiskPercent   *float64  `json:"disk_percent"`
	HeapBytes     string    `json:"heap_bytes"`
	Goroutines    int       `json:"goroutines"`
	Errors        []string  `json:"errors"`
}

func Read(ctx context.Context) Snapshot {
	out := Snapshot{Version: buildinfo.Version, Commit: buildinfo.Commit, Errors: []string{}, ObservedAt: time.Now().UTC()}
	if v, e := cpu.PercentWithContext(ctx, 0, false); e == nil && len(v) > 0 {
		out.CPUPercent = &v[0]
	} else {
		out.Errors = append(out.Errors, "cpu_unavailable")
	}
	if v, e := mem.VirtualMemoryWithContext(ctx); e == nil {
		out.MemoryPercent = &v.UsedPercent
	} else {
		out.Errors = append(out.Errors, "memory_unavailable")
	}
	if v, e := disk.UsageWithContext(ctx, "."); e == nil {
		out.DiskPercent = &v.UsedPercent
	} else {
		out.Errors = append(out.Errors, "disk_unavailable")
	}
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	out.HeapBytes = strconv.FormatUint(stats.HeapAlloc, 10)
	out.Goroutines = runtime.NumGoroutine()
	return out
}
