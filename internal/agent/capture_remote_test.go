package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"runtime"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
)

func remoteCaptureInput(s *CaptureSupervisor, settings CaptureSettings) control.CaptureConfiguration {
	current := s.Snapshot()
	return control.CaptureConfiguration{ExpectedRevision: &current.Revision, ExpectedConfigSHA256: current.ConfigSHA256, ExpectedSettingsSHA256: current.SettingsSHA256, Settings: control.CaptureSettings(settings)}
}

func TestRemoteCaptureConfigurationFencesLocalChanges(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	}
	e := captureFixture(t)
	s, err := NewCaptureSupervisor(e)
	if err != nil {
		t.Fatal(err)
	}
	promiscuous := false
	settings := CaptureSettings{Interfaces: []string{}, Threads: 1, Promiscuous: &promiscuous}
	input := remoteCaptureInput(s, settings)
	state, code, err := s.ConfigureRemote(context.Background(), input, "task_remote_stop")
	if err != nil || code != "" || state.Status != "stopped" || state.Revision != 1 || state.AppliedRevision != 1 {
		t.Fatal("远程停止配置未得到实际应用", state, code, err)
	}
	input = remoteCaptureInput(s, settings)
	state, code, err = s.ConfigureRemote(context.Background(), input, "task_same")
	if err != nil || state.Revision != 1 {
		t.Fatal("相同配置不应产生新修订", state, code, err)
	}
	settings.Threads = 2
	if _, err = s.Configure(context.Background(), settings, "admin", "local_change"); err != nil {
		t.Fatal(err)
	}
	before, _ := e.WAL.LocalConfig()
	state, code, err = s.ConfigureRemote(context.Background(), input, "task_stale")
	after, _ := e.WAL.LocalConfig()
	if err == nil || code != "capture_configuration_changed" || state.Revision != 2 || !bytes.Equal(before, after) {
		t.Fatal("旧平台观测覆盖了本机配置", state, code, err)
	}
	s.op.Lock()
	_, code, err = s.ConfigureRemote(context.Background(), remoteCaptureInput(s, settings), "task_busy")
	s.op.Unlock()
	if err == nil || code != "capture_operation_in_progress" {
		t.Fatal("并发采集事务未拒绝", code, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, code, err = s.ConfigureRemote(cancelled, remoteCaptureInput(s, settings), "task_cancelled")
	if err == nil || code != "command_cancelled" {
		t.Fatal("已取消的配置仍被执行", code, err)
	}
	bad := remoteCaptureInput(s, settings)
	bad.Settings.Interfaces = []string{"no-such-interface"}
	_, code, err = s.ConfigureRemote(context.Background(), bad, "task_bad_nic")
	if err == nil || code != "invalid_capture_configuration" {
		t.Fatal("不存在的网卡被接受", code, err)
	}
	input = remoteCaptureInput(s, settings)
	input.ExpectedConfigSHA256 = control.Digest([]byte("other"))
	if _, code, err = s.ConfigureRemote(context.Background(), input, "task_bad_actual"); err == nil || code != "capture_configuration_changed" {
		t.Fatal("其他生效配置观测被接受")
	}
}

func TestRemoteCaptureEngineRequiresManagedConfiguration(t *testing.T) {
	e := captureFixture(t)
	if _, code, err := e.Execute(context.Background(), control.Command{ID: "task_external", Kind: "capture.configure", Payload: json.RawMessage(`{}`)}); err == nil || code != "capture_not_managed" {
		t.Fatal("非托管设备接受采集配置")
	}
	if runtime.GOOS != "linux" {
		return
	}
	s, err := NewCaptureSupervisor(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, code, err := e.Execute(context.Background(), control.Command{ID: "task_bad", Kind: "capture.configure", Payload: json.RawMessage(`{}`)}); err == nil || code != "invalid_capture_configuration" {
		t.Fatal("缺失的配置参数被执行")
	}
	value := false
	p := remoteCaptureInput(s, CaptureSettings{Interfaces: []string{}, Threads: 1, Promiscuous: &value})
	raw, _ := json.Marshal(p)
	result, code, err := e.Execute(context.Background(), control.Command{ID: "task_stop", Kind: "capture.configure", Payload: raw})
	if err != nil || code != "" || control.ValidateCaptureResult(p, result) != nil {
		t.Fatal("采集任务没有返回有效生效回读", code, err)
	}
}

func TestInterruptedCaptureTaskPreservesUnknownReceipt(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	}
	e := captureFixture(t)
	s, err := NewCaptureSupervisor(e)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m, err := NewTaskManager(e.WAL, pub, e)
	if err != nil {
		t.Fatal(err)
	}
	value := false
	settings := CaptureSettings{Interfaces: []string{}, Threads: 2, Promiscuous: &value}
	p := remoteCaptureInput(s, settings)
	payload, _ := json.Marshal(p)
	now := time.Now().UTC()
	c := control.Command{ID: "task_interrupted_capture", TenantID: e.WAL.TenantID, SensorID: e.WAL.SensorID, RegistrationID: e.WAL.RegistrationID, Kind: "capture.configure", Payload: payload, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	raw, sig, err := control.Encode(c, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Accept(raw, sig); err != nil {
		t.Fatal(err)
	}
	// 模拟期望配置已经落盘、任务最终回执尚未提交的进程中断。
	saved, _ := json.Marshal(CaptureState{CaptureSettings: settings, Revision: 1, Managed: true, Status: "pending"})
	if err = e.WAL.SaveLocalConfig(saved, "platform", c.ID); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewTaskManager(e.WAL, pub, e)
	if err != nil {
		t.Fatal(err)
	}
	if err = recovered.Accept(raw, sig); err != nil {
		t.Fatal(err)
	}
	rows, err := recovered.List()
	if err != nil || len(rows) != 1 || rows[0].State != "unknown" || rows[0].Receipt.Code != "execution_interrupted" || len(recovered.queue) != 0 {
		t.Fatal("中断的采集命令被盲目重放或改写成功", rows, err)
	}
	pending, err := recovered.Pending()
	if err != nil || len(pending) != 1 {
		t.Fatal("未知结果未进入持久回执", err)
	}
	actual, err := e.WAL.LocalConfig()
	if err != nil || !bytes.Equal(actual, saved) {
		t.Fatal("恢复任务改写了独立期望配置", err)
	}
}
