package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretFilesWithoutEnvironmentMutation(t *testing.T) {
	development(t)
	t.Setenv("SB_DATABASE_URL", "")
	path := filepath.Join(t.TempDir(), "database.secret")
	if err := os.WriteFile(path, []byte("postgres://app@127.0.0.1/db?sslmode=disable\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SB_DATABASE_URL_FILE", path)
	c, err := Load("platform")
	if err != nil {
		t.Fatal(err)
	}
	if c.DatabaseURL != "postgres://app@127.0.0.1/db?sslmode=disable" || os.Getenv("SB_DATABASE_URL") != "" {
		t.Fatal("Secret 被改写或配置未读取")
	}
	t.Setenv("SB_DATABASE_URL", "postgres://conflicting/db")
	if _, err := Load("platform"); err == nil {
		t.Fatal("允许两种凭据来源发生冲突")
	}
}
func TestInvalidSecretFilesDoNotExposeContents(t *testing.T) {
	for _, value := range []string{"", "secret\nsecond", "secret\x00value", strings.Repeat("s", 65537)} {
		t.Run(stringLength(value), func(t *testing.T) {
			development(t)
			t.Setenv("SB_LOCAL_PASSWORD", "")
			path := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(path, []byte(value), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SB_LOCAL_PASSWORD_FILE", path)
			_, err := Load("platform")
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatal("接受非法 Secret 或错误包含内容", err)
			}
		})
	}
	for _, path := range []string{filepath.Join(t.TempDir(), "missing"), t.TempDir()} {
		development(t)
		t.Setenv("SB_LOCAL_PASSWORD_FILE", path)
		if _, err := Load("platform"); err == nil {
			t.Fatal("接受不存在或非普通 Secret 文件")
		}
	}
	if _, err := Load("invalid"); err == nil {
		t.Fatal("接受未声明角色")
	}
}
func stringLength(value string) string {
	if value == "" {
		return "empty"
	}
	if len(value) > 65536 {
		return "oversized"
	}
	return "control_character"
}

func TestSecretPipeIsRejectedWithoutWaiting(t *testing.T) {
	development(t)
	path := filepath.Join(t.TempDir(), "configuration-pipe")
	if e := exec.Command("mkfifo", path).Run(); e != nil {
		t.Fatal(e)
	}
	t.Setenv("SB_LOCAL_PASSWORD_FILE", path)
	if _, e := Load("platform"); e == nil {
		t.Fatal("配置管道未被拒绝")
	}
}
