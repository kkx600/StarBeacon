package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/control"
)

func TestRuleDigestRejectsForeignFilesAndReportsActualFileChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "managed.rules")
	text := strings.Repeat("# evidence\n", 8192)
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	hash, err := ruleFileDigest(path, int64(len(text)))
	if err != nil || hash != control.Digest([]byte(text)) {
		t.Fatal("流式规则摘要与原文不一致", err)
	}
	for _, name := range []string{dir, filepath.Join(dir, "missing"), path} {
		if _, err := ruleFileDigest(name, 1); err == nil {
			t.Fatal("特殊路径或超限规则没有拒绝", name)
		}
	}
	link := filepath.Join(dir, "linked.rules")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ruleFileDigest(link, 1<<20); err == nil {
		t.Fatal("规则摘要跟随了未登记的链接")
	}
	w, err := OpenWAL(filepath.Join(dir, "state.db"), "tenant_digest", "sensor_digest", "reg_digest", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.registeredRulesPath = path
	w.registeredRulesAvailable = true
	if v := w.Health(context.Background(), w.DB.Path()); v.RegisteredRulesSHA256 != hash {
		t.Fatal("心跳没有携带登记文件摘要")
	}
	if err := os.WriteFile(path, []byte("# external replacement\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if v := w.Health(context.Background(), w.DB.Path()); v.RegisteredRulesSHA256 == hash || v.RegisteredRulesSHA256 == "" {
		t.Fatal("心跳继续提供旧的文件摘要")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	v := w.Health(context.Background(), w.DB.Path())
	if v.RegisteredRulesAvailable || v.RegisteredRulesSHA256 != "" {
		t.Fatal("缺失文件仍被标记可用")
	}
}
