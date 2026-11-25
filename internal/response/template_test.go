package response

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

func ownedTemplate(t *testing.T) (Template, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/owned_acl_template.json")
	if err != nil {
		t.Fatal(err)
	}
	var definition Template
	if err := json.Unmarshal(raw, &definition); err != nil {
		t.Fatal(err)
	}
	return definition, raw
}

func TestResponseTemplateRestrictsMethodsPathsOwnershipAndScalars(t *testing.T) {
	_, raw := ownedTemplate(t)
	for _, mutation := range []struct{ old, next string }{
		{`"response.template.v1"`, `"response.template.v2"`},
		{`"/session/new"`, `"https://example.test/new"`},
		{`"password_field": "pass"`, `"password_field": "user"`},
		{`"ttl_seconds": 60`, `"ttl_seconds": 301`},
		{`"/v1/status"`, `"/v1/%2e%2e/status"`},
		{`"/v1/status"`, `"//other.example.test/status"`},
		{`"/v1/status"`, `"/v1/status?redirect=1"`},
		{`"method": "GET"`, `"method": "HEAD"`},
		{`"{{task_id}}"`, `"{{secret.password}}"`},
		{`"{{expires_at}}"`, `"constant"`},
		{`"/v1/acl/by-task/{{task_id}}"`, `"/v1/acl/by-task/fixed"`},
		{`"/v1/acl/rules/{{lease.rule_id}}"`, `"/v1/acl/rules/{{lease.rule_id}}/{{lease.rule_id}}"`},
		{`"name": "version"`, `"name": "device_id"`},
		{`"name": "address"`, `"name": "comment"`},
		{`"name": "address"`, `"name": "$illegal"`},
		{`"name": "address"`, `"name": "address", "name": "third"`},
		{`"name": "address"`, `"name": "address", "secret": "unexpected"`},
		{`"status": [201]`, `"status": []`},
		{`"status": [201]`, `"status": [201, 201]`},
		{`"status": [201]`, `"status": [404]`},
		{`"status": [404], "field": "code", "equals": "unassigned"`, `"status": [404]`},
		{`"equals": 0`, `"equals": 0.0`},
		{`"equals": 0`, `"equals": null`},
		{`"field": "code", "equals": 0`, `"equals": 0`},
		{`"field": "code", "equals": 0`, `"field": "code", "equals": ` + strconv.Quote(strings.Repeat("x", 257))},
	} {
		changed := strings.Replace(string(raw), mutation.old, mutation.next, 1)
		var invalid Template
		if changed == string(raw) || json.Unmarshal([]byte(changed), &invalid) == nil {
			t.Fatalf("无效模板未被拒绝：%s", mutation.old)
		}
	}
	for _, bad := range []string{`null`, `[]`, `{"code":0,"code":1}`, `{"bad.key":0}`, `{"code":[[[[[[[[[0]]]]]]]]]}`} {
		if _, err := readTemplateReply([]byte(bad)); !errors.Is(err, ErrUnknown) {
			t.Fatal("无效设备回执未标为未知", err)
		}
	}
}

func TestResponseTemplateBindsDefinitionAndRequiresVerifiedDevice(t *testing.T) {
	definition, raw := ownedTemplate(t)
	legacy, _ := clientFixture(t)
	if _, err := NewTemplateClient(Configuration{}, definition); !errors.Is(err, ErrInput) {
		t.Fatal("空设备绑定被接受", err)
	}
	bad := definition
	bad.Block.Accept.Equals = json.RawMessage(`{"bad"}`)
	if _, err := NewTemplateClient(legacy.Config, bad); !errors.Is(err, ErrInput) {
		t.Fatal("无法序列化的模板被接受", err)
	}
	bad = definition
	bad.Health.Path = "/invalid/../path"
	if _, err := NewTemplateClient(legacy.Config, bad); !errors.Is(err, ErrInput) {
		t.Fatal("不受控模板被接受", err)
	}
	badConfig := legacy.Config
	badConfig.CAFile = "/nonexistent/owned-certificate.pem"
	if _, err := NewTemplateClient(badConfig, definition); !errors.Is(err, ErrUnavailable) {
		t.Fatal("缺少设备证书仍可配置", err)
	}
	client, err := NewTemplateClient(legacy.Config, definition)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Describe(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("普通令牌文件被当成登录凭据", err)
	}
	definition.Login = nil
	definition.Health.Path = "/starbeacon/v1/device"
	definition.Health.Accept.Field, definition.Health.Accept.Equals = "", nil
	for index, field := range definition.Health.Values {
		definition.Health.Values[index].Value = field.Name
	}
	staticClient, err := NewTemplateClient(legacy.Config, definition)
	if err != nil {
		t.Fatal(err)
	}
	defer staticClient.Close()
	if _, err := staticClient.Describe(context.Background()); err != nil || client.BindingSHA256() == staticClient.BindingSHA256() || staticClient.BindingSHA256() == legacy.BindingSHA256() {
		t.Fatal("固定令牌验证或模板摘要绑定失败", err)
	}
	if err := json.Unmarshal(raw, &bad); err != nil || bad.SHA256() == definition.SHA256() {
		t.Fatal("不同定义摘要相同", err)
	}
}
