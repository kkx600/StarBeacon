package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
)

func TestProtocolObservationFailureDoesNotClaimDetectionCapability(t *testing.T) {
	ctx := context.Background()
	p := &ProtocolInspector{}
	if r := p.Observe(ctx); r.ErrorCode != "engine_not_configured" || r.Validate() != nil {
		t.Fatal("缺配置不应出现能力", r)
	}
	e := captureFixture(t)
	p.Engine = e
	e.Config.SuricataBinary = "/missing/engine"
	if r := p.Observe(ctx); r.ErrorCode != "native_protocol_inventory_unavailable" || r.Validate() != nil {
		t.Fatal("缺引擎状态错误", r)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if p.Observe(cancelled).ErrorCode != "protocol_inspection_cancelled" {
		t.Fatal("取消后继续查询")
	}
	e.Config.SuricataConfig = filepath.Join(t.TempDir(), "absent.yaml")
	if p.Observe(ctx).ErrorCode != "protocol_configuration_unavailable" {
		t.Fatal("缺配置文件未明确报告")
	}
	p.mu.Lock()
	if r := p.Observe(ctx); r.State != "pending" || r.Validate() != nil {
		t.Fatal("并发观测未有界返回", r)
	}
	p.mu.Unlock()
	for _, code := range []string{"engine_not_configured", "engine_isolation_unavailable", "engine_version_mismatch", "native_protocol_inventory_unavailable", "protocol_configuration_unavailable", "protocol_configuration_unsupported", "protocol_observation_changed", "protocol_inspection_cancelled"} {
		if r := protocolFailure(code); r.Validate() != nil || r.CaptureActive || len(r.Protocols) != 0 {
			t.Fatal("失败观测不符合契约", code, r)
		}
	}
}

func TestProtocolSnapshotDoesNotWaitForNativeInspection(t *testing.T) {
	p := &ProtocolInspector{}
	if p.Snapshot(context.Background()).State != "pending" {
		t.Fatal("未执行观测时不能声明协议能力")
	}
	p.record.Store(protocolFailure("engine_not_configured"))
	p.mu.Lock()
	done := make(chan struct{})
	go func() { p.Snapshot(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		p.mu.Unlock()
		t.Fatal("健康读取被原生命令锁阻塞")
	}
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	p.Run(ctx)
	if r := p.Snapshot(context.Background()); r.ErrorCode != "engine_not_configured" || p.Snapshot(ctx).ErrorCode != "protocol_inspection_cancelled" {
		t.Fatal("后台观测或取消未按实际状态呈现", r)
	}
}

func TestNativeProtocolObservationUsesFrozenConfigurationAndInvalidatesCache(t *testing.T) {
	binary, template := os.Getenv("SB_TEST_SURICATA_BINARY"), os.Getenv("SB_TEST_SURICATA_CONFIG")
	if binary == "" || template == "" {
		t.Skip("原生协议能力检查需 Suricata 8.0.7 和隔离环境")
	}
	raw, err := os.ReadFile(template)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.yaml")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	p := &ProtocolInspector{Engine: &Engine{Config: config.Config{Mode: "development", SuricataBinary: binary, SuricataConfig: path}}}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	r := p.Observe(ctx)
	if r.Validate() != nil || r.State != "observed" || r.EngineVersion != "8.0.7" || r.ConfigSHA256 != control.Digest(raw) || r.EngineSHA256 == "" || r.Source != "offline_template" || r.CaptureActive || len(r.Protocols) < 35 {
		t.Fatal("真实协议目录或来源未核验", r)
	}
	if p.Observe(ctx) != r || p.Snapshot(ctx) != r {
		t.Fatal("同一事实重复运行原生命令")
	}
	updated := []byte("%YAML 1.1\n---\napp-layer:\n  protocols:\n    http:\n      enabled: yes\n    imap:\n      enabled: detection-only\noutputs: []\n")
	if err = os.WriteFile(path, updated, 0600); err != nil {
		t.Fatal(err)
	}
	r = p.Observe(ctx)
	if r.State != "observed" || r.ConfigSHA256 != control.Digest(updated) || r.CaptureActive {
		t.Fatal("配置变更后错误复用旧观测", r)
	}
	for _, row := range r.Protocols {
		if row.Protocol == "http" && row.Transactions != "not_configured" || row.Protocol == "imap" && row.Transactions != "disabled" {
			t.Fatal("实际模板解析与日志状态混淆", row)
		}
	}
	if err = os.WriteFile(path, []byte("include: /private/credential.yaml\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if r = p.Observe(ctx); r.ErrorCode != "protocol_configuration_unsupported" || len(r.Protocols) != 0 {
		t.Fatal("未展开引用被当作实际配置", r)
	}
}

func TestNativeProtocolCommandErrorsDoNotClaimVersionMismatch(t *testing.T) {
	if os.Getenv("SB_TEST_SURICATA_BINARY") == "" {
		t.Skip("原生命令错误验证需独立隔离环境")
	}
	path := filepath.Join(t.TempDir(), "profile.yaml")
	if err := os.WriteFile(path, []byte("app-layer: {protocols: {http: {enabled: yes}}}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ binary, code string }{
		{"/usr/bin/false", "native_protocol_inventory_unavailable"},
		{"/usr/bin/true", "engine_version_mismatch"},
	} {
		t.Run(filepath.Base(tc.binary), func(t *testing.T) {
			p := &ProtocolInspector{Engine: &Engine{Config: config.Config{Mode: "development", SuricataBinary: tc.binary, SuricataConfig: path}}}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			r := p.Observe(ctx)
			if r.Validate() != nil || r.State != "unavailable" || r.ErrorCode != tc.code || len(r.Protocols) != 0 || r.CaptureActive {
				t.Fatal("原生命令执行错误与实际版本不匹配必须分别呈现", r)
			}
		})
	}
}
