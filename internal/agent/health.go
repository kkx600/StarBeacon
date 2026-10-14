package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/kkx600/StarBeacon/internal/buildinfo"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/telemetry"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	psnet "github.com/shirou/gopsutil/v4/net"
)

func (w *WAL) Health(ctx context.Context, path string) model.HostHealth {
	h := model.HostHealth{Version: buildinfo.Version, ObservedAt: time.Now().UTC(), Errors: []string{}, CaptureStatus: "eve_reader_only"}
	h.Hostname, _ = os.Hostname()
	if v, e := cpu.PercentWithContext(ctx, 0, false); e == nil && len(v) > 0 {
		h.CPUPercent = &v[0]
	} else {
		h.Errors = append(h.Errors, "cpu_unavailable")
	}
	if v, e := mem.VirtualMemoryWithContext(ctx); e == nil {
		h.MemoryPercent = &v.UsedPercent
	} else {
		h.Errors = append(h.Errors, "memory_unavailable")
	}
	if v, e := disk.UsageWithContext(ctx, filepath.Dir(path)); e == nil {
		h.DiskPercent = &v.UsedPercent
	} else {
		h.Errors = append(h.Errors, "disk_unavailable")
	}
	var rx, tx uint64
	if v, e := psnet.IOCountersWithContext(ctx, true); e == nil {
		for _, i := range v {
			rx += i.BytesRecv
			tx += i.BytesSent
		}
	} else {
		h.Errors = append(h.Errors, "network_unavailable")
	}
	h.RXBytes = strconv.FormatUint(rx, 10)
	h.TXBytes = strconv.FormatUint(tx, 10)
	if interfaces, err := Interfaces(); err == nil {
		encoded, err := json.Marshal(interfaces)
		if err == nil && len(interfaces) <= 128 && len(encoded) <= 24*1024 {
			h.NetworkInterfaces = interfaces
		} else {
			h.Errors = append(h.Errors, "network_inventory_unavailable")
		}
	} else {
		h.Errors = append(h.Errors, "network_inventory_unavailable")
	}
	n, b, e := w.Stats()
	if e == nil {
		h.WALPending = n
		h.WALBytes = int64(b)
		telemetry.WALPending.Set(float64(n))
		telemetry.WALBytes.Set(float64(b))
	} else {
		h.Errors = append(h.Errors, "wal_unavailable")
	}
	w.mu.RLock()
	h.TaskCapabilities = append([]string(nil), w.taskCapabilities...)
	h.CommandSignerSHA256 = w.commandSignerSHA256
	h.RegisteredRulesAvailable = w.registeredRulesAvailable
	rulesPath := w.registeredRulesPath
	captureSnapshot, capabilities := w.captureSnapshot, w.capabilities
	for code, active := range w.failures {
		if active {
			h.Errors = append(h.Errors, code)
		}
	}
	w.mu.RUnlock()
	if captureSnapshot != nil {
		state := captureSnapshot()
		h.CaptureStatus = state.Status
		h.Capture, _ = json.Marshal(state)
		if state.ErrorCode != "" {
			h.Errors = append(h.Errors, state.ErrorCode)
		}
	}
	if w.packetArchives != nil {
		h.PacketArchive = w.packetArchives.JSON()
	}
	if capabilities != nil {
		h.TaskCapabilities = capabilities()
	}
	if w.protocolSnapshot != nil {
		h.ProtocolCapabilities = w.protocolSnapshot(ctx)
	}
	if w.responseHealth != nil {
		h.ResponseConnectors = w.responseHealth()
	}
	if w.applicationState != nil {
		h.ApplicationRules = w.applicationState()
	}
	if rulesPath != "" {
		if hash, err := ruleFileDigest(rulesPath, 64*1024*1024); err == nil {
			h.RegisteredRulesSHA256 = hash
		} else {
			h.RegisteredRulesAvailable = false
			h.Errors = append(h.Errors, "registered_rules_unavailable")
		}
	}
	return h
}
