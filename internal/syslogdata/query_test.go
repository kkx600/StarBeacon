package syslogdata

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestSearchQueryBindsTenantFiltersAndCursor(t *testing.T) {
	q := SearchQuery{Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), Limit: 20}
	if q.Validate("tenant") != nil {
		t.Fatal("基础查询无效")
	}
	if _, id, err := q.Position("tenant"); err != nil || id != "" {
		t.Fatal("首屏位置不正确")
	}
	seq := 0
	q.Severity = &seq
	q.PeerIP = "192.0.2.1"
	q.SensorID = "sensor"
	q.SourceID = "source"
	q.NetworkDomain = "dmz"
	q.Hostname = "host"
	q.Application = "app"
	q.Keyword = "中文关键字"
	q.State = "parsed"
	next := q
	next.Cursor = q.Next("tenant", q.Start.Add(time.Hour), strings.Repeat("a", 64))
	if next.Validate("tenant") != nil {
		t.Fatal("同查询游标无效")
	}
	if next.Validate("other") == nil {
		t.Fatal("跨租户游标被接受")
	}
	for _, change := range []func(*SearchQuery){func(q *SearchQuery) { q.Start = time.Time{} }, func(q *SearchQuery) { q.Start = q.End }, func(q *SearchQuery) { q.Start = q.End.Add(-32 * 24 * time.Hour) }, func(q *SearchQuery) { q.Limit = 101 }, func(q *SearchQuery) { q.SensorID = "UPPER" }, func(q *SearchQuery) { q.SourceID = "bad/id" }, func(q *SearchQuery) { q.NetworkDomain = "bad" + strings.Repeat("x", 64) }, func(q *SearchQuery) { q.PeerIP = "localhost" }, func(q *SearchQuery) { q.PeerIP = "::ffff:192.0.2.1" }, func(q *SearchQuery) { q.Hostname = "bad\nhost" }, func(q *SearchQuery) { q.Application = strings.Repeat("x", 257) }, func(q *SearchQuery) { q.State = "success" }, func(q *SearchQuery) { n := 8; q.Severity = &n }, func(q *SearchQuery) { q.Keyword = "different" }, func(q *SearchQuery) { q.Limit = 10 }} {
		v := next
		change(&v)
		if v.Validate("tenant") == nil {
			t.Fatal("约束或游标筛选漂移未拒绝")
		}
	}
	for _, cursor := range []string{"not-json", "a!", strings.Repeat("a", 513), base64.RawURLEncoding.EncodeToString([]byte(`{"time":"2026-01-01T01:00:00Z","id":"a","query":"b"}`)), q.Next("tenant", q.Start.Add(-time.Second), strings.Repeat("a", 64)), q.Next("tenant", q.End, strings.Repeat("a", 64))} {
		v := q
		v.Cursor = cursor
		if v.Validate("tenant") == nil {
			t.Fatal("损坏游标未拒绝")
		}
	}
}
func TestSourceQueryPagingAndHealth(t *testing.T) {
	q := SourceQuery{Limit: 20}
	if q.Validate() != nil {
		t.Fatal("来源查询无效")
	}
	q.Cursor = q.Next("sensor_a", "source_a")
	sensor, source, err := q.Position()
	if err != nil || sensor != "sensor_a" || source != "source_a" {
		t.Fatal("续页无效")
	}
	for _, change := range []func(*SourceQuery){func(q *SourceQuery) { q.Limit = 0 }, func(q *SourceQuery) { q.SensorID = "other" }, func(q *SourceQuery) { q.SourceID = "UPPER" }, func(q *SourceQuery) { q.Cursor = "bad" }, func(q *SourceQuery) { q.Cursor = strings.Repeat("a", 513) }} {
		v := q
		change(&v)
		if v.Validate() == nil {
			t.Fatal("来源游标漂移未拒绝")
		}
	}
	now := time.Now().UTC()
	h := Health{ReceiverBinding: testSource().Binding(), State: "listening", ObservedAt: now, StartedAt: now.Add(-time.Second), Received: "1", Persisted: "1", Dropped: "0", Rejected: "0", FramingErrors: "0", LastPersistedAt: &now, MaxMessageBytes: 4096, IdentityQuality: "network_allowlist", UpstreamLoss: "unknown"}
	if !h.Valid() {
		t.Fatal("健康观测无效")
	}
	for _, pair := range []struct{ state, reason string }{{"starting", "listener_not_ready"}, {"degraded", "durable_queue_unavailable"}, {"unavailable", "listener_unavailable"}, {"stopped", "listener_stopped"}} {
		v := h
		v.State = pair.state
		v.Reason = pair.reason
		if !v.Valid() {
			t.Fatal("有效状态被拒绝")
		}
		v.Reason = "wrong"
		if v.Valid() {
			t.Fatal("原因状态不匹配被接受")
		}
	}
	for _, change := range []func(*Health){func(h *Health) { h.SourceID = "" }, func(h *Health) { h.State = "unknown" }, func(h *Health) { h.Reason = "wrong" }, func(h *Health) { h.Received = "01" }, func(h *Health) { h.StartedAt = h.ObservedAt.Add(time.Hour) }, func(h *Health) { h.StartedAt = time.Time{} }, func(h *Health) { h.MaxMessageBytes = 1 }, func(h *Health) { at := h.StartedAt.Add(-time.Second); h.LastPersistedAt = &at }, func(h *Health) { h.IdentityQuality = "certificate" }, func(h *Health) { h.UpstreamLoss = "zero" }} {
		v := h
		change(&v)
		if v.Valid() {
			t.Fatal("损坏来源状态被接受")
		}
	}
	h.Transport = "udp"
	h.UpstreamLoss = "unmeasurable"
	if !h.Valid() {
		t.Fatal("UDP 状态无效")
	}
	h.Transport = "tls"
	h.IdentityQuality = "certificate"
	h.UpstreamLoss = "unknown"
	if !h.Valid() {
		t.Fatal("证书来源状态无效")
	}
}
