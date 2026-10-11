package control

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func captureInput() CaptureConfiguration {
	revision, promiscuous := uint64(2), false
	s := CaptureSettings{Interfaces: []string{"eth0"}, Threads: 2, BPFFilter: "tcp port 8088", Promiscuous: &promiscuous}
	return CaptureConfiguration{ExpectedRevision: &revision, ExpectedConfigSHA256: strings.Repeat("a", 64), ExpectedSettingsSHA256: CaptureSettingsDigest(s), Settings: s}
}

func TestCaptureConfigurationRejectsAmbiguousAndUnboundedInputs(t *testing.T) {
	for name, change := range map[string]func(*CaptureConfiguration){
		"revision_missing":      func(p *CaptureConfiguration) { p.ExpectedRevision = nil },
		"revision_limit":        func(p *CaptureConfiguration) { v := uint64(9007199254740991); p.ExpectedRevision = &v },
		"settings_digest":       func(p *CaptureConfiguration) { p.ExpectedSettingsSHA256 = "bad" },
		"uppercase_digest":      func(p *CaptureConfiguration) { p.ExpectedConfigSHA256 = strings.Repeat("A", 64) },
		"interfaces_missing":    func(p *CaptureConfiguration) { p.Settings.Interfaces = nil },
		"interfaces_excessive":  func(p *CaptureConfiguration) { p.Settings.Interfaces = make([]string, 17) },
		"interfaces_repeated":   func(p *CaptureConfiguration) { p.Settings.Interfaces = []string{"eth0", "eth0"} },
		"interfaces_empty_name": func(p *CaptureConfiguration) { p.Settings.Interfaces = []string{""} },
		"interfaces_path":       func(p *CaptureConfiguration) { p.Settings.Interfaces = []string{"../eth0"} },
		"interfaces_multiline":  func(p *CaptureConfiguration) { p.Settings.Interfaces = []string{"eth0\neth1"} },
		"threads_missing":       func(p *CaptureConfiguration) { p.Settings.Threads = 0 },
		"threads_excessive":     func(p *CaptureConfiguration) { p.Settings.Threads = 65 },
		"threads_total": func(p *CaptureConfiguration) {
			p.Settings.Interfaces = []string{"eth0", "eth1", "eth2"}
			p.Settings.Threads = 64
		},
		"promiscuous_missing": func(p *CaptureConfiguration) { p.Settings.Promiscuous = nil },
		"filter_excessive":    func(p *CaptureConfiguration) { p.Settings.BPFFilter = strings.Repeat("测", 700) },
		"filter_multiline":    func(p *CaptureConfiguration) { p.Settings.BPFFilter = "tcp\nport 80" },
		"filter_utf8":         func(p *CaptureConfiguration) { p.Settings.BPFFilter = string([]byte{255}) },
		"filter_untrimmed":    func(p *CaptureConfiguration) { p.Settings.BPFFilter = " tcp " },
	} {
		t.Run(name, func(t *testing.T) {
			p := captureInput()
			change(&p)
			if p.Validate() == nil {
				t.Fatal("不可信采集参数被接受")
			}
		})
	}
	p := captureInput()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(p)
	if _, err := ReadCaptureConfiguration(raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{`, string(raw) + ` {}`, strings.Replace(string(raw), `"settings":{`, `"settings":{"shell":"id",`, 1), strings.Replace(string(raw), `"expected_revision":2`, `"expected_revision":2,"unknown":true`, 1)} {
		if _, err := ReadCaptureConfiguration([]byte(bad)); err == nil {
			t.Fatal("额外 JSON 或字段被接受")
		}
	}
	p.Settings.Interfaces = []string{}
	p.ExpectedConfigSHA256 = ""
	if p.Validate() != nil {
		t.Fatal("停止采集或初始观测不能提交")
	}
}

func TestCaptureReceiptRequiresNativeAppliedState(t *testing.T) {
	p := captureInput()
	makeResult := func() map[string]any {
		return map[string]any{"interfaces": p.Settings.Interfaces, "threads": 2, "bpf_filter": "tcp port 8088", "promiscuous": false, "managed": true, "revision": 3, "applied_revision": 3, "applied_settings": p.Settings, "status": "running", "config_sha256": strings.Repeat("b", 64), "pid": 1234, "observed_at": time.Now().UTC()}
	}
	for name, change := range map[string]func(map[string]any){
		"pending":                func(r map[string]any) { r["status"] = "pending" },
		"no_applied_settings":    func(r map[string]any) { delete(r, "applied_settings") },
		"wrong_applied_settings": func(r map[string]any) { s := p.Settings; s.BPFFilter = "udp"; r["applied_settings"] = s },
		"desired_only":           func(r map[string]any) { r["applied_revision"] = 2 },
		"other_revision":         func(r map[string]any) { r["revision"] = 9; r["applied_revision"] = 9 },
		"external":               func(r map[string]any) { r["managed"] = false },
		"no_pid":                 func(r map[string]any) { delete(r, "pid") },
		"no_digest":              func(r map[string]any) { delete(r, "config_sha256") },
		"no_time":                func(r map[string]any) { delete(r, "observed_at") },
		"wrong_nic":              func(r map[string]any) { r["interfaces"] = []string{"eth1"} },
		"wrong_filter":           func(r map[string]any) { r["bpf_filter"] = "udp port 53" },
	} {
		t.Run(name, func(t *testing.T) {
			r := makeResult()
			change(r)
			raw, _ := json.Marshal(r)
			if ValidateCaptureResult(p, raw) == nil {
				t.Fatal("未生效或不匹配的回读被接受")
			}
		})
	}
	r := makeResult()
	raw, _ := json.Marshal(r)
	if err := ValidateCaptureResult(p, raw); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCaptureResult(p, []byte(`{`)); err == nil {
		t.Fatal("损坏回读被接受")
	}
	p.Settings.Interfaces = []string{}
	r["applied_settings"] = p.Settings
	r["interfaces"] = []string{}
	r["status"] = "stopped"
	r["pid"] = 0
	raw, _ = json.Marshal(r)
	if err := ValidateCaptureResult(p, raw); err != nil {
		t.Fatal(err)
	}
	r["pid"] = 1234
	raw, _ = json.Marshal(r)
	if ValidateCaptureResult(p, raw) == nil {
		t.Fatal("仍运行的检测进程被当作已停止")
	}
}
