package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/control"
)

func TestInspectionEvidenceIsStableAcrossWorkspacesAndBindsAuxiliaryContent(t *testing.T) {
	source := filepath.Join(t.TempDir(), "suricata.yaml")
	if err := os.WriteFile(source, []byte("%YAML 1.1\n---\n{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	firstInput, secondInput := t.TempDir(), t.TempDir()
	firstBase, firstProfile, err := offlineConfig(source, firstInput)
	if err != nil {
		t.Fatal(err)
	}
	secondBase, secondProfile, err := offlineConfig(source, secondInput)
	if err != nil {
		t.Fatal(err)
	}
	if firstBase != secondBase || control.Digest([]byte(firstProfile)) != control.Digest([]byte(secondProfile)) {
		t.Fatal("临时工作目录影响了相同检测配置的发布资格")
	}
	for _, input := range []string{firstInput, secondInput} {
		yaml, err := os.ReadFile(filepath.Join(input, "replay.yaml"))
		if err != nil || !strings.Contains(string(yaml), input) {
			t.Fatal("原生执行配置没有使用实际工作目录", err)
		}
	}
	for _, name := range []string{"classification.config", "reference.config", "threshold.config"} {
		if err := os.WriteFile(filepath.Join(filepath.Dir(source), name), []byte("# trusted "+name+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		base, profile, err := offlineConfig(source, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if base != firstBase || profile == firstProfile {
			t.Fatal("辅助配置变化没有使先前证据失效", name)
		}
		firstProfile = profile
	}
	if err := os.WriteFile(source, []byte("%YAML 1.1\n---\nstream: {reassembly: {depth: 1mb}}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	changed, _, err := offlineConfig(source, t.TempDir())
	if err != nil || changed == firstBase {
		t.Fatal("检测主配置变化未更新摘要", err)
	}
}
