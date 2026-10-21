package syslogdata

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testSource() Source {
	return Source{ID: "edge", Name: "边界设备", NetworkDomain: "dmz", Listen: "127.0.0.1:16514", Transport: "tcp", Format: "rfc5424", AllowedPeers: []string{"127.0.0.1/32"}, AcceptUnauthenticated: true, MaxMessageBytes: 4096, MaxConnections: 4, MaxEventsPerSecond: 100}
}
func testRecord(raw []byte) Record {
	return Record{SchemaVersion: Schema, Binding: testSource().Binding(), SourceEpoch: "wal_epoch", SourceSequence: "1", ObservedAt: time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC), Peer: Peer{IP: "127.0.0.1", Port: 25200}, RawBase64: base64.StdEncoding.EncodeToString(raw), RawSHA256: Hash(raw)}
}
func recordBytes(v Record) []byte { raw, _ := json.Marshal(v); return raw }
func TestStrictSourceConfiguration(t *testing.T) {
	valid := testSource()
	if valid.Validate() != nil || !valid.Binding().Valid() {
		t.Fatal("固定来源无效")
	}
	if !valid.Allows(netip.MustParseAddr("::ffff:127.0.0.1")) || valid.Allows(netip.MustParseAddr("192.0.2.1")) || valid.Allows(netip.Addr{}) || valid.Allows(netip.MustParseAddr("0.0.0.0")) || valid.Allows(netip.MustParseAddr("224.0.0.1")) {
		t.Fatal("地址允许范围不正确")
	}
	invalid := []func(*Source){func(s *Source) { s.ID = "UPPER" }, func(s *Source) { s.Name = "包含\n换行" }, func(s *Source) { s.Name = " leading" }, func(s *Source) { s.Name = string([]byte{255}) }, func(s *Source) { s.NetworkDomain = "" }, func(s *Source) { s.Listen = "localhost:16514" }, func(s *Source) { s.Listen = "127.0.0.1:514" }, func(s *Source) { s.Listen = "224.0.0.1:16514" }, func(s *Source) { s.MaxMessageBytes = 255 }, func(s *Source) { s.MaxConnections = 33 }, func(s *Source) { s.MaxEventsPerSecond = 0 }, func(s *Source) { s.AllowedPeers = nil }, func(s *Source) { s.AllowedPeers = []string{"192.0.2.1/24"} }, func(s *Source) { s.AllowedPeers = []string{"::ffff:192.0.2.0/120"} }, func(s *Source) { s.AllowedPeers = []string{"127.0.0.1/32", "127.0.0.1/32"} }, func(s *Source) { s.Format = "auto" }, func(s *Source) { s.Timezone = "UTC" }, func(s *Source) { s.Format = "rfc3164" }, func(s *Source) { s.Format = "rfc3164"; s.Timezone = "bad/zone" }, func(s *Source) { s.Format = "rfc3164"; s.Timezone = "UTC"; s.YearPolicy = "now" }, func(s *Source) { s.Transport = "udp" }, func(s *Source) { s.Transport = "tls" }, func(s *Source) { s.Transport = "http" }, func(s *Source) { s.AcceptUnauthenticated = false }, func(s *Source) { s.AcceptDatagramLoss = true }, func(s *Source) { s.TLS.CertificateFile = "/private/cert" }}
	for i, change := range invalid {
		v := testSource()
		change(&v)
		if v.Validate() == nil {
			t.Errorf("错误配置 %d 未拒绝", i)
		}
	}
	legacy := testSource()
	legacy.Format = "rfc3164"
	legacy.Timezone = "Asia/Shanghai"
	legacy.YearPolicy = "nearest_received_year"
	if legacy.Validate() != nil || !legacy.Binding().Valid() {
		t.Fatal("显式旧协议策略无效")
	}
	udp := testSource()
	udp.Transport = "udp"
	udp.AcceptDatagramLoss = true
	if udp.Validate() != nil {
		t.Fatal("显式 UDP 确认无效")
	}
	secure := testSource()
	secure.Transport = "tls"
	secure.AcceptUnauthenticated = false
	secure.TLS = TLSFiles{CertificateFile: "/private/cert", PrivateKeyFile: "/private/key", ClientCAFile: "/private/ca", ClientFingerprints: []string{Hash([]byte("cert"))}}
	if secure.Validate() != nil || !secure.Binding().Valid() {
		t.Fatal("TLS 来源无效")
	}
	for _, change := range []func(*Source){func(s *Source) { s.AcceptUnauthenticated = true }, func(s *Source) { s.AcceptDatagramLoss = true }, func(s *Source) { s.TLS.PrivateKeyFile = "relative" }, func(s *Source) { s.TLS.ClientFingerprints = []string{"bad"} }, func(s *Source) {
		s.TLS.ClientFingerprints = append(s.TLS.ClientFingerprints, s.TLS.ClientFingerprints[0])
	}} {
		v := secure
		change(&v)
		if v.Validate() == nil {
			t.Fatal("TLS 认证约束被绕过")
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "sources.json")
	save := func(raw []byte) {
		t.Helper()
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("写配置失败")
		}
	}
	f := File{SchemaVersion: "syslog.sources.v1", Sources: []Source{valid}}
	raw, _ := json.Marshal(f)
	save(raw)
	loaded, err := LoadFile(path)
	if err != nil || len(loaded.Sources) != 1 {
		t.Fatal("来源文件无法读取", err)
	}
	for _, v := range []string{`{}`, `{"schema_version":"syslog.sources.v1","sources":[],"extra":true}`, `{"schema_version":"syslog.sources.v1","schema_version":"syslog.sources.v1","sources":[]}`, `{"SCHEMA_VERSION":"syslog.sources.v1","sources":[]}`, `{"schema_version":"syslog.sources.v1","sources":[]} {}`} {
		save([]byte(v))
		if _, err := LoadFile(path); err == nil {
			t.Fatal("非严格配置被接受")
		}
	}
	for _, sources := range [][]Source{{valid, valid}, append([]Source{valid}, func() Source { v := valid; v.ID = "second"; return v }()), make([]Source, 17)} {
		f.Sources = sources
		raw, _ := json.Marshal(f)
		save(raw)
		if _, err := LoadFile(path); err == nil {
			t.Fatal("重复或超限来源未拒绝")
		}
	}
	if _, err := LoadFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("缺失文件被接受")
	}
	save([]byte(`{"schema_version":"syslog.sources.v1","sources":[]}`))
	os.Chmod(path, 0644)
	if _, err := LoadFile(path); err == nil {
		t.Fatal("公开配置文件被接受")
	}
	os.Remove(path)
	os.Symlink("missing", path)
	if _, err := LoadFile(path); err == nil {
		t.Fatal("符号链接被接受")
	}
}

func TestOriginalBytesAndReceiverIdentity(t *testing.T) {
	original := []byte("<13>1 2026-01-01T00:00:00Z device app 1 id - 中文\n" + string([]byte{255}))
	record := testRecord(original)
	v, raw, err := DecodeRecord(recordBytes(record))
	if err != nil || !bytes.Equal(raw, original) || v.Binding.SourceID != "edge" {
		t.Fatal("原始字节没有完整保留", err)
	}
	mutations := []func(*Record){func(v *Record) { v.SchemaVersion = "other" }, func(v *Record) { v.Binding.SourceID = "" }, func(v *Record) { v.Binding.ConfigSHA256 = "a" }, func(v *Record) { v.Binding.Format = "auto" }, func(v *Record) { v.Binding.Transport = "http" }, func(v *Record) { v.Binding.Format = "rfc3164"; v.Binding.Timezone = "bad" }, func(v *Record) { v.SourceEpoch = "" }, func(v *Record) { v.SourceSequence = "0" }, func(v *Record) { v.SourceSequence = "01" }, func(v *Record) { v.SourceSequence = "18446744073709551615" }, func(v *Record) { v.ObservedAt = time.Time{} }, func(v *Record) { v.ObservedAt = time.Date(2500, 1, 1, 0, 0, 0, 0, time.UTC) }, func(v *Record) { v.Peer.IP = "::ffff:127.0.0.1" }, func(v *Record) { v.Peer.IP = "0.0.0.0" }, func(v *Record) { v.Peer.IP = "224.0.0.1" }, func(v *Record) { v.Peer.Port = 0 }, func(v *Record) { v.Peer.CertificateSHA256 = Hash([]byte("cert")) }, func(v *Record) { v.Binding.Transport = "tls" }, func(v *Record) { v.RawSHA256 = Hash([]byte("different")) }, func(v *Record) { v.RawBase64 = "@@@@" }, func(v *Record) { v.RawBase64 = "" }, func(v *Record) { v.RawSHA256 = "BAD" }}
	for i, mutate := range mutations {
		v := record
		mutate(&v)
		if _, _, err := DecodeRecord(recordBytes(v)); err == nil {
			t.Errorf("原始记录约束 %d 未执行", i)
		}
	}
	if _, _, err := DecodeRecord(append([]byte(" "), recordBytes(record)...)); err == nil {
		t.Fatal("非规范传输载荷被接受")
	}
	v = record
	v.Binding.Transport = "tls"
	v.Peer.CertificateSHA256 = Hash([]byte("cert"))
	if _, _, err := DecodeRecord(recordBytes(v)); err != nil {
		t.Fatal("TLS 接收身份无效")
	}
}

func TestStrictParsingAndTimeUncertainty(t *testing.T) {
	cases := []struct{ raw, format, zone, observed, state, quality, message string }{
		{"<13>1 2026-01-01T00:00:00Z fake-host app 7 id [audit@32473 key=\"value\"] 中文消息", "rfc5424", "", "2026-01-01T00:01:00Z", "parsed", "source_timezone", "中文消息"},
		{"<13>1 - - - - - - no clock", "rfc5424", "", "2026-01-01T00:01:00Z", "parsed", "missing_source_time", "no clock"},
		{"<13>1 2026-01-02T00:00:00Z host app 7 id - future", "rfc5424", "", "2026-01-01T00:01:00Z", "parsed", "future_source_time", "future"},
		{"<13>1 1990-01-01T00:00:00Z host app 7 id - old", "rfc5424", "", "2026-01-01T00:01:00Z", "parsed", "source_time_out_of_range", "old"},
		{"<13>2 2026-01-01T00:00:00Z host app 7 id - unsupported", "rfc5424", "", "2026-01-01T00:01:00Z", "quarantined", "unavailable", ""},
		{"<13>1 2026-01-01T00:00:00.123456789Z host app 7 id - invalid fraction", "rfc5424", "", "2026-01-01T00:01:00Z", "quarantined", "unavailable", ""},
		{"broken\x00data", "rfc5424", "", "2026-01-01T00:01:00Z", "quarantined", "unavailable", ""},
		{"<13>Dec 31 23:59:59 host app[7]: year boundary", "rfc3164", "UTC", "2026-01-01T00:01:00Z", "parsed", "inferred_year_timezone", "year boundary"},
		{"<13>Nov  1 01:30:00 host app: fold", "rfc3164", "America/New_York", "2026-11-01T07:00:00Z", "parsed", "ambiguous_local_time", "fold"},
		{"<13>Mar  8 02:30:00 host app: gap", "rfc3164", "America/New_York", "2026-03-08T08:00:00Z", "parsed", "ambiguous_local_time", "gap"},
		{"<13>Jan  1 00:00:00 host app: line one\nline two", "rfc3164", "Asia/Shanghai", "2026-01-01T00:01:00Z", "parsed", "inferred_year_timezone", "line one\nline two"},
		{"<13>Jan  1 00:00:00 host app: wrong zone", "rfc3164", "missing/zone", "2026-01-01T00:01:00Z", "quarantined", "unavailable", ""},
		{"whatever", "auto", "", "2026-01-01T00:01:00Z", "quarantined", "unavailable", ""},
	}
	for i, test := range cases {
		t.Run(strconvTest(i), func(t *testing.T) {
			record := testRecord([]byte(test.raw))
			record.Binding.Format = test.format
			record.Binding.Timezone = test.zone
			if test.format == "rfc3164" {
				record.Binding.YearPolicy = "nearest_received_year"
			}
			record.ObservedAt, _ = time.Parse(time.RFC3339, test.observed)
			out := Parse(record, []byte(test.raw))
			if out.State != test.state || out.TimeQuality != test.quality || out.Message != test.message {
				t.Fatalf("解析质量不一致: %+v", out)
			}
			if out.State == "parsed" && (out.Priority == nil || *out.Priority != 13 || out.Facility == nil || *out.Facility != 1 || out.Severity == nil || *out.Severity != 5) {
				t.Fatal("PRI 拆分不正确")
			}
			if test.quality == "ambiguous_local_time" && out.SourceTime != nil {
				t.Fatal("不确定时间被当作确定时间")
			}
			if strings.Contains(test.raw, "year boundary") && (out.SourceTime == nil || out.SourceTime.Year() != 2025) {
				t.Fatal("跨年没有绑定接收时刻")
			}
		})
	}
}
func strconvTest(i int) string { return time.Unix(int64(i), 0).Format("05") }
