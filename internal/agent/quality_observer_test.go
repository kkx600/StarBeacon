package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQualityObservationRequiresDurableEVECommit(t *testing.T) {
	for _, full := range []bool{false, true} {
		dir := t.TempDir()
		budget := uint64(1 << 20)
		if full {
			budget = 1
		}
		w, err := OpenWAL(filepath.Join(dir, "wal.db"), "tenant_quality", "sensor_quality", "reg_quality", budget)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		at := time.Now().UTC()
		path := filepath.Join(dir, "eve.json")
		data := []byte(`{"event_type":"stats","timestamp":"` + at.Format(time.RFC3339Nano) + `","stats":{"detect":{"alert_queue_overflow":1}}}` + "\n")
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		s := &CaptureSupervisor{state: CaptureState{Status: "running"}, active: &captureProcess{}}
		s.quality.Start("engine_test", "hash", at.Add(-time.Second))
		calls := 0
		r := &EVEReader{WAL: w, Path: path, Route: func(context.Context, string) (string, error) { return "route", nil }, ObserveStats: func(raw []byte, observed time.Time) { calls++; s.ObserveStats(raw, observed) }}
		defer r.Close()
		err = r.Poll(context.Background())
		state := s.Snapshot()
		if full {
			if err != ErrWALFull || calls != 0 || state.Quality.State != "unavailable" {
				t.Fatal("未持久化统计刷新了健康状态", err, calls, state.Quality)
			}
		} else {
			if err != nil || calls != 1 || state.Quality.State != "baseline" || state.Quality.ConfigSHA256 != "hash" {
				t.Fatal(err, calls, state.Quality)
			}
			if err = r.Poll(context.Background()); err != nil || calls != 1 {
				t.Fatal("重复读取产生新观察", err, calls)
			}
		}
		s.state.Status = "stopped"
		s.ObserveStats(data[:len(data)-1], at.Add(time.Second))
		if s.Snapshot().Quality.State != "stopped" {
			t.Fatal("停止引擎仍显示当前观测")
		}
	}
}
