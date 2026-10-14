package protocolcap

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

const fixture = `%YAML 1.1
---
flow:
  memcap: 32mb
stream:
  memcap: 33554432
  reassembly:
    memcap: 64mb
    depth: 0
defrag:
  memcap: 16mb
app-layer:
  protocols:
    http:
      enabled: yes
      libhtp:
        default-config:
          request-body-limit: 4mb
          response-body-limit: 8mb
    tls:
      enabled: true
    imap:
      enabled: detection-only
    pgsql:
      enabled: no
    dns:
      tcp:
        enabled: no
      udp:
        enabled: yes
outputs:
  - eve-log:
      enabled: yes
      types:
        - http:
            extended: yes
        - tls
`

func base() Report {
	return Report{ObservedAt: time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC), Source: "managed_configuration", CaptureActive: true, EngineVersion: "8.0.7", EngineSHA256: strings.Repeat("a", 64), ConfigSHA256: strings.Repeat("b", 64)}
}

func sample(t *testing.T) Report {
	t.Helper()
	config, err := Configuration([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	return Build(base(), []string{"http", "tls", "imap", "dns", "ssh", "native-extension"}, config, true)
}

func row(t *testing.T, report Report, id string) Entry {
	t.Helper()
	for _, item := range report.Protocols {
		if item.Protocol == id {
			return item
		}
	}
	t.Fatal("协议记录缺失", id)
	return Entry{}
}

func TestProtocolCatalogKeepsNativeConfigurationAndEffectsSeparate(t *testing.T) {
	report := sample(t)
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ id, recognition, transactions string }{
		{"http", "configured", "configured"}, {"tls", "configured", "configured"},
		{"imap", "detection_only", "disabled"}, {"pgsql", "disabled", "disabled"},
		{"dns", "partial", "partial"}, {"ssh", "native_listed", "unknown"},
		{"modbus", "unlisted", "unknown"}, {"native-extension", "native_listed", "unknown"},
	} {
		v := row(t, report, tc.id)
		if v.Recognition != tc.recognition || v.Transactions != tc.transactions || v.Qualification != "not_qualified" || v.FileExtraction != "not_implemented" || v.ExternalLogs != "not_implemented" {
			t.Fatal("原生列出、配置、日志或效果混淆", tc.id, v)
		}
	}
	if row(t, report, "ethernet").PacketForensics != "packet_headers_only" || row(t, report, "http").PacketForensics != "not_implemented" || report.Limits[3].Value != "0" || report.Limits[1].Value != "33554432" {
		t.Fatal("原包头部能力或显式限额丢失", report.Limits)
	}
	if value := row(t, report, "dns").Bindings; len(value) != 2 || value[0].Transport != "tcp" || value[0].Mode != "no" || value[1].Mode != "yes" {
		t.Fatal("传输层差异丢失", value)
	}
	if row(t, report, "http").OnlineRules != "requires_validation" || row(t, report, "imap").OnlineRules != "disabled" {
		t.Fatal("目录为规则效果授予了资格")
	}
}

func TestProtocolCatalogRequiresExplicitParserAndLoggerConfiguration(t *testing.T) {
	for _, tc := range []struct{ enabled, logger, expected string }{
		{"yes", "yes", "configured"}, {"true", "no", "not_configured"},
		{"false", "yes", "disabled"}, {"detection-only", "yes", "disabled"},
		{"auto", "yes", "unknown"}, {"42", "yes", "unknown"},
	} {
		raw := fmt.Sprintf("app-layer:\n  protocols:\n    http:\n      enabled: %s\noutputs:\n  - eve-log:\n      enabled: yes\n      types:\n        - http:\n            enabled: %s\n", tc.enabled, tc.logger)
		config, err := Configuration([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		report := Build(base(), []string{"http"}, config, false)
		if v := row(t, report, "http"); v.Transactions != tc.expected || row(t, report, "tcp").PacketForensics != "not_implemented" {
			t.Fatal("未显式启用被补为完整能力", tc, v)
		}
	}
	config, _ := Configuration([]byte("app-layer:\n  protocols:\n    http:\n      enabled: yes\noutputs:\n  - eve-log:\n      enabled: no\n      types: [http]\nstream:\n  reassembly:\n    depth: \"SECRET-NOT-A-SIZE\"\n"))
	report := Build(base(), []string{"http"}, config, false)
	encoded, _ := json.Marshal(report)
	if row(t, report, "http").Transactions != "not_configured" || strings.Contains(string(encoded), "SECRET") {
		t.Fatal("禁用日志或非限额文本泄漏到目录")
	}
}

func TestNativeProtocolListRejectsPartialOrMalformedOutput(t *testing.T) {
	const head = "=========Supported App Layer Protocols=========\n"
	names, err := ListProtocols([]byte("Warning: log file unavailable\n" + head + "http\r\ndns\n\n"))
	if err != nil || strings.Join(names, ",") != "dns,http" {
		t.Fatal("原生目录未识别", names, err)
	}
	for _, raw := range []string{"", "http\ndns", head, head + "http\nhttp", head + "http\n" + head, head + "tls\nerror: failed", head + "HTTP", head + "bad\x00name", strings.Repeat("a", 32769)} {
		if _, err := ListProtocols([]byte(raw)); err == nil {
			t.Fatal("不完整目录被接受", raw[:min(len(raw), 100)])
		}
	}
	raw := head
	for i := 0; i < 129; i++ {
		raw += fmt.Sprintf("protocol-%d\n", i)
	}
	if _, err = ListProtocols([]byte(raw)); err == nil {
		t.Fatal("目录数量超限未拒绝")
	}
}

func TestProtocolConfigurationRejectsUnexpandedReferencesAndMultipleDocuments(t *testing.T) {
	for _, raw := range []string{"", "[]", "a: 1\na: 2", "a: 1\n---\nb: 2", "include: secret.yaml", "includes: [other.yaml]", "plugins: [/tmp/plugin.so]", strings.Repeat(" ", 1024*1024+1)} {
		if _, err := Configuration([]byte(raw)); err == nil {
			t.Fatal("未知有效配置被接受", raw[:min(len(raw), 80)])
		}
	}
	if _, err := Configuration([]byte("plugins: []\ninclude: null\nincludes: []\n")); err != nil {
		t.Fatal("显式空引用未接受", err)
	}
}

func TestProtocolReportRejectsUnboundedOrSelfQualifiedFacts(t *testing.T) {
	clone := func() Report { raw, _ := json.Marshal(sample(t)); var r Report; _ = json.Unmarshal(raw, &r); return r }
	for _, mutate := range []func(*Report){
		func(r *Report) { r.SchemaVersion = 2 }, func(r *Report) { r.ObservedAt = time.Time{} },
		func(r *Report) { r.Protocols = append(r.Protocols, r.Protocols[0]) },
		func(r *Report) { r.Protocols = make([]Entry, 161) }, func(r *Report) { r.Limits = make([]Limit, 8) },
		func(r *Report) { r.State = "accepted" }, func(r *Report) { r.EngineVersion = "8.0.70" },
		func(r *Report) { r.EngineSHA256 = "bad" }, func(r *Report) { r.ConfigSHA256 = "bad" },
		func(r *Report) { r.Source = "external_claim" }, func(r *Report) { r.Source = "offline_template" },
		func(r *Report) { r.ErrorCode = "secret" }, func(r *Report) { r.Protocols = nil },
		func(r *Report) { r.Protocols[0].Protocol = "BAD" }, func(r *Report) { r.Protocols[0].Name = "" },
		func(r *Report) { r.Protocols[0].Name = "x\nsecret" }, func(r *Report) { r.Protocols[0].Name = strings.Repeat("x", 65) },
		func(r *Report) { r.Protocols[0].Bindings = make([]Binding, 3) },
		func(r *Report) { r.Protocols[0].FileExtraction = "configured" },
		func(r *Report) { r.Protocols[0].ExternalLogs = "configured" },
		func(r *Report) { r.Protocols[0].Qualification = "passed" },
		func(r *Report) { r.Protocols[0].Recognition = "passed" }, func(r *Report) { r.Protocols[0].Transactions = "passed" },
		func(r *Report) { r.Protocols[0].OnlineRules = "passed" }, func(r *Report) { r.Protocols[0].PacketForensics = "passed" },
		func(r *Report) { r.Protocols[0].Bindings = []Binding{{"tcp", "yes"}, {"tcp", "no"}} },
		func(r *Report) { r.Protocols[0].Bindings = []Binding{{"secret", "yes"}} },
		func(r *Report) { r.Protocols[0].Bindings = []Binding{{"tcp", "secret"}} },
		func(r *Report) { r.Limits[0].Key = "secret.key" }, func(r *Report) { r.Limits[0] = r.Limits[1] },
		func(r *Report) { r.Limits[0].Value = "secret" }, func(r *Report) { r.Limits = nil },
	} {
		r := clone()
		mutate(&r)
		if r.Validate() == nil {
			t.Fatal("无效能力或效果资格未拒绝", r)
		}
	}
	r := clone()
	r.Source, r.CaptureActive = "offline_template", false
	if r.Validate() != nil {
		t.Fatal("离线模板观测未接受")
	}
	for _, state := range []string{"pending", "unavailable"} {
		r = Report{SchemaVersion: SchemaVersion, State: state, Source: "unavailable", ObservedAt: time.Now(), ErrorCode: "inspection_pending"}
		if r.Validate() != nil {
			t.Fatal("明确未知状态被拒绝")
		}
		r.ErrorCode = "arbitrary-secret"
		if r.Validate() == nil {
			t.Fatal("错误正文不应进入观测")
		}
		r.ErrorCode, r.EngineVersion = "engine_not_configured", "8.0.7"
		if r.Validate() == nil {
			t.Fatal("未知状态携带能力声明")
		}
	}
}
