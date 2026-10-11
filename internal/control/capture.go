package control

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

type CaptureSettings struct {
	Interfaces  []string `json:"interfaces"`
	Threads     int      `json:"threads"`
	BPFFilter   string   `json:"bpf_filter"`
	Promiscuous *bool    `json:"promiscuous"`
}

// 远程任务绑定上次观测的期望配置和实际引擎配置，设备在配置事务内再次比较。
type CaptureConfiguration struct {
	ExpectedRevision       *uint64         `json:"expected_revision"`
	ExpectedConfigSHA256   string          `json:"expected_config_sha256"`
	ExpectedSettingsSHA256 string          `json:"expected_settings_sha256"`
	Settings               CaptureSettings `json:"settings"`
}

func captureDigest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}

func (s CaptureSettings) Validate() error {
	if s.Interfaces == nil || len(s.Interfaces) > 16 || s.Threads < 1 || s.Threads > 64 || len(s.Interfaces)*s.Threads > 128 || s.Promiscuous == nil || len(s.BPFFilter) > 2048 || !utf8.ValidString(s.BPFFilter) || strings.ContainsAny(s.BPFFilter, "\x00\r\n") || strings.TrimSpace(s.BPFFilter) != s.BPFFilter {
		return errors.New("采集网卡、过滤器或线程参数无效")
	}
	seen := map[string]bool{}
	for _, name := range s.Interfaces {
		if name == "" || len(name) > 64 || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n\t /\\") || seen[name] {
			return errors.New("采集接口名称无效或重复")
		}
		seen[name] = true
	}
	return nil
}

func (p CaptureConfiguration) Validate() error {
	if p.ExpectedRevision == nil || *p.ExpectedRevision >= 9007199254740991 || !captureDigest(p.ExpectedSettingsSHA256) || (p.ExpectedConfigSHA256 != "" && !captureDigest(p.ExpectedConfigSHA256)) {
		return errors.New("采集配置缺少可信的期望修订或摘要")
	}
	return p.Settings.Validate()
}

func ReadCaptureConfiguration(raw json.RawMessage) (CaptureConfiguration, error) {
	var p CaptureConfiguration
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
		return p, errors.New("采集配置参数无效")
	}
	return p, p.Validate()
}

func CaptureSettingsDigest(settings CaptureSettings) string {
	raw, _ := json.Marshal(settings)
	return Digest(raw)
}

// 只接受与任务目标一致的生效回读；期望保存或进程尚未就绪不能成为成功回执。
func ValidateCaptureResult(p CaptureConfiguration, raw json.RawMessage) error {
	var result struct {
		CaptureSettings
		Managed         bool             `json:"managed"`
		Revision        uint64           `json:"revision"`
		AppliedRevision uint64           `json:"applied_revision"`
		AppliedSettings *CaptureSettings `json:"applied_settings"`
		Status          string           `json:"status"`
		ConfigSHA256    string           `json:"config_sha256"`
		PID             int              `json:"pid"`
		ObservedAt      time.Time        `json:"observed_at"`
	}
	if p.Validate() != nil || json.Unmarshal(raw, &result) != nil || !result.Managed || result.ObservedAt.IsZero() || result.AppliedSettings == nil || result.AppliedSettings.Validate() != nil || CaptureSettingsDigest(*result.AppliedSettings) != CaptureSettingsDigest(p.Settings) || result.Revision != result.AppliedRevision || (result.Revision != *p.ExpectedRevision && result.Revision != *p.ExpectedRevision+1) || result.CaptureSettings.Validate() != nil || CaptureSettingsDigest(result.CaptureSettings) != CaptureSettingsDigest(p.Settings) {
		return errors.New("采集回读与任务目标不一致")
	}
	if len(p.Settings.Interfaces) == 0 {
		if result.Status != "stopped" || result.PID != 0 {
			return errors.New("采集停止未得到实际回读")
		}
	} else if result.Status != "running" || result.PID < 1 || !captureDigest(result.ConfigSHA256) {
		return errors.New("检测进程或生效配置尚未核实")
	}
	return nil
}
