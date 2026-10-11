package store

import (
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/analytics"
)

func TestAnalysisWindowBoundsPreserveCalendarAndChatLimits(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, kind string
		window     analytics.Window
		valid      bool
	}{
		{"未提供范围", "chat", analytics.Window{}, false},
		{"未提供结束", "daily", analytics.Window{Start: start}, false},
		{"未提供开始", "monthly", analytics.Window{End: start}, false},
		{"零长度", "chat", analytics.Window{Start: start, End: start}, false},
		{"反向范围", "weekly", analytics.Window{Start: start, End: start.Add(-time.Second)}, false},
		{"对话上限", "chat", analytics.Window{Start: start, End: start.Add(31 * 24 * time.Hour)}, true},
		{"对话超限", "chat", analytics.Window{Start: start, End: start.Add(31*24*time.Hour + time.Nanosecond)}, false},
		{"日历月含夏令时", "monthly", analytics.Window{Start: start, End: start.Add(31*24*time.Hour + time.Hour)}, true},
		{"周期范围超限", "monthly", analytics.Window{Start: start, End: start.Add(32*24*time.Hour + time.Nanosecond)}, false},
		{"未知作业类型", "unknown", analytics.Window{Start: start, End: start.Add(time.Hour)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if validAnalysisWindow(tc.window, tc.kind) != tc.valid {
				t.Fatal("统计窗口的可用性与业务范围不一致")
			}
		})
	}
}
