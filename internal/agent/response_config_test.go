package agent

import (
	"encoding/json"
	"github.com/kkx600/StarBeacon/internal/response"
	"os"
	"testing"
)

func TestResponseConfigurationCheckDoesNotApplyFilesOrReadCredentials(t *testing.T) {
	var absent *ResponseService
	if absent.CheckConfiguration().State != "not_configured" {
		t.Fatal("未配置状态不正确")
	}
	s, path, writes, mu := responseServiceFixture(t)
	if v := s.CheckConfiguration(); v.State != "current" || v.RunningCount != 1 || v.FileCount != 1 || v.CheckedAt.IsZero() {
		t.Fatal(v)
	}
	file, err := response.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// 凭据内容不参与结构核对；状态不能被解释为认证成功。
	if err = os.Remove(file.Connectors[0].TokenFile); err != nil {
		t.Fatal(err)
	}
	if s.CheckConfiguration().State != "current" {
		t.Fatal("结构核对访问了凭据")
	}
	file.RetentionDays++
	raw, _ := json.Marshal(file)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if s.CheckConfiguration().State != "restart_required" || s.retention == file.RetentionDays {
		t.Fatal("文件变化未保持运行绑定")
	}
	for _, value := range []string{`{}`, `{"schema_version":"response.connectors.v1","connectors":[]}`} {
		if err = os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if s.CheckConfiguration().State != "invalid" {
			t.Fatal("损坏文件未明确显示")
		}
	}
	if err = os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if s.CheckConfiguration().State != "invalid" {
		t.Fatal("不安全权限未拒绝")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if s.CheckConfiguration().State != "invalid" {
		t.Fatal("文件缺失伪装正常")
	}
	mu.Lock()
	defer mu.Unlock()
	if *writes != 0 {
		t.Fatal("配置核对触发了设备写入")
	}
}
