//go:build integration

package integration

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/config"
)

// 诊断只导出受控角色的结构化退出原因，不复制环境或业务正文。
func logRoleFailure(t *testing.T, role, path string, c config.Config) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Logf("角色 %s 的启动诊断不可读取", role)
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, 32*1024))
	for found := 0; scanner.Scan() && found < 4; {
		var line struct {
			Level  string `json:"level"`
			Reason string `json:"reason"`
		}
		if json.Unmarshal(scanner.Bytes(), &line) != nil || line.Level != "ERROR" || line.Reason == "" {
			continue
		}
		found++
		t.Logf("角色 %s 退出原因：%s", role, redactRoleReason(line.Reason, c))
	}
}

func redactRoleReason(reason string, c config.Config) string {
	values := []string{}
	for _, entry := range roleEnvironment(c) {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || !strings.HasPrefix(name, "SB_") || len(value) < 8 {
			continue
		}
		values = append(values, value)
		if parsed, err := url.Parse(value); err == nil && parsed.User != nil {
			if password, exists := parsed.User.Password(); exists && password != "" {
				values = append(values, password, url.QueryEscape(password), url.PathEscape(password))
			}
		}
	}
	// 完整连接串先于其中的凭据替换，防止短值替换后留下完整地址的其他部分。
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	for _, value := range values {
		reason = strings.ReplaceAll(reason, value, "[已隐藏]")
	}
	return reason
}

func TestRoleDiagnosticRedactsCredentials(t *testing.T) {
	password := "test-secret-p@ss/word"
	c := config.Config{LocalPassword: password, CredentialKey: "test-master-secret", DatabaseURL: "postgres://owner:" + url.PathEscape(password) + "@postgres:5432/starbeacon"}
	reason := "failed " + c.DatabaseURL + "; password " + password + "; encoded " + url.QueryEscape(password) + "; key " + c.CredentialKey + "; bind: address already in use"
	result := redactRoleReason(reason, c)
	for _, value := range []string{password, c.DatabaseURL, c.CredentialKey, url.QueryEscape(password)} {
		if strings.Contains(result, value) {
			t.Fatal("启动诊断包含凭据")
		}
	}
	if !strings.Contains(result, "address already in use") {
		t.Fatal("诊断未保留不含凭据的故障原因")
	}
}

func TestRoleAddressesAreDistinctAndReleased(t *testing.T) {
	addresses := availableAddresses(t, 16)
	seen := map[string]bool{}
	for _, address := range addresses {
		if seen[address] {
			t.Fatal("为多个角色重复分配端口")
		}
		seen[address] = true
		listener, err := net.Listen("tcp", address)
		require(t, err)
		require(t, listener.Close())
	}
}
