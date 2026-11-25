package plugingen

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/response"
)

const fixtureDoc = "GET /health 返回 JSON，healthy 为布尔值。"

func inputFor(entries ...string) Request {
	return Request{ProviderID: "provider_fixture", ProviderRevision: 7, DeviceType: "firewall", Abilities: entries,
		Documentation: fixtureDoc, AllowContext: true}
}

func TestPluginPromptBoundaryAndDocumentDigest(t *testing.T) {
	r := inputFor("block", "pull_alerts", "isolate")
	r.Documentation += "\n凭据使用占位符，Authorization: Bearer <TOKEN>"
	prompt, err := r.Prompt()
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(prompt), &fields) != nil || len(fields) != 3 ||
		fields["device_type"] == nil || fields["required_entries"] == nil || fields["documentation"] == nil ||
		strings.Contains(prompt, r.ProviderID) || strings.Contains(prompt, "provider_revision") {
		t.Fatal("冻结材料含输入许可和接口文档之外的非必要字段")
	}
	var entries []string
	if err = json.Unmarshal(fields["required_entries"], &entries); err != nil ||
		!slices.Equal(entries, []string{"pull_alerts", "block", "isolate", "health", "verify", "unblock", "release"}) {
		t.Fatal("入口与选择的能力不一致", entries, err)
	}
	if got := DocumentSHA256(r.Documentation); len(got) != 64 || got == DocumentSHA256(fixtureDoc) {
		t.Fatal("文档摘要未绑定实际字节")
	}
	for _, bad := range []func(*Request){
		func(v *Request) { v.AllowContext = false },
		func(v *Request) { v.ProviderID = "path/invalid" },
		func(v *Request) { v.ProviderRevision = 0 },
		func(v *Request) { v.DeviceType = "unknown" },
		func(v *Request) { v.Abilities = nil },
		func(v *Request) { v.Abilities = []string{"health", "health"} },
		func(v *Request) { v.Abilities = []string{"release"} },
		func(v *Request) { v.Documentation = "  " },
		func(v *Request) { v.Documentation += "\x00" },
		func(v *Request) { v.Documentation += string([]byte{0xff}) },
		func(v *Request) { v.Documentation = strings.Repeat("文", MaxDocumentationBytes) },
		func(v *Request) { v.Documentation = strings.Repeat("\t", MaxDocumentationBytes-50) + fixtureDoc },
	} {
		input := inputFor("health")
		bad(&input)
		if _, err := input.Prompt(); !errors.Is(err, ErrInput) {
			t.Fatal("非法输入进入模型材料", err)
		}
	}
	for _, secret := range []string{
		"Authorization: Bearer SYNTHETIC_TEST_TOKEN",
		`{"password":"notarealpassword"}`, "api_key=SYNTHETIC_TEST_TOKEN",
		"-----BEGIN PRIVATE KEY-----", "https://fixture:samplepassword@device.example",
	} {
		next := inputFor("health")
		next.Documentation += "\n" + secret
		if _, err := next.Prompt(); !errors.Is(err, ErrCredentials) {
			t.Fatal("凭据格式未被过滤", err)
		}
	}
}

func TestPluginOutputUsesExistingDraftContractAndRejectsExtraAbilities(t *testing.T) {
	replace := func(text, before, after string) string { return strings.Replace(text, before, after, 1) }
	const definition = `{"schema_version":"response.template.v1","health":{"method":"GET","path":"/health","accept":{"status":[200],"field":"healthy","equals":true}}}`
	sample := response.PluginExample{Method: "GET", Path: "/health", Status: 200, Response: `{"healthy":true}`}
	template := output{Format: "template", Name: "设备检查草稿", Definition: definition, Entries: []string{}, Examples: []response.PluginExample{sample}}
	encode := func(v output) string { raw, _ := json.Marshal(v); return string(raw) }
	health := inputFor("health")
	candidate, err := DecodeOutput(encode(template), health)
	if err != nil || candidate.Device != "防火墙" || candidate.Template.SchemaVersion != response.TemplateSchema || len(candidate.Examples) != 1 {
		t.Fatal("合格模板未被解析为待审草稿", candidate, err)
	}
	bad := template
	bad.Format = "active"
	empty := template
	empty.Examples = []response.PluginExample{}
	invalidExample := template
	invalidExample.Examples = []response.PluginExample{{Method: "GET", Path: "https://device.example", Status: 200}}
	for _, raw := range []string{
		`{}`, encode(bad), encode(empty), encode(invalidExample),
		replace(encode(template), `"format":"template"`, `"format":"template","format":"script"`),
		replace(encode(template), `"name":`, `"activate":true,"name":`),
		replace(encode(template), `"entries":[]`, `"entries":["health"]`),
		replace(encode(template), `"examples":[`, `"extra":{"name":true},"examples":[`),
		encode(output{Format: "template", Name: "错配", Definition: "null", Entries: []string{}, Examples: template.Examples}),
		encode(output{Format: "insufficient", Name: "有额外内容", Entries: []string{}, Examples: []response.PluginExample{}}),
	} {
		if draft, err := DecodeOutput(raw, health); draft != nil || !errors.Is(err, ErrOutput) {
			t.Fatal("异常输出被采纳", err)
		}
	}
	if _, err := DecodeOutput(encode(template), inputFor("isolate")); !errors.Is(err, ErrOutput) {
		t.Fatal("模板替代了终端能力", err)
	}
	insufficient := output{Format: "insufficient", Entries: []string{}, Examples: []response.PluginExample{}}
	if _, err := DecodeOutput(encode(insufficient), health); !errors.Is(err, ErrInsufficient) {
		t.Fatal("资料不足被标记为成功", err)
	}
	script := output{Format: "script", Name: "脚本设备检查", Definition: "def health(ctx):\n    return http.get('/health').status == 200\n",
		Entries: []string{"health"}, Examples: template.Examples}
	if c, err := DecodeOutput(encode(script), health); err != nil || c.Script == nil {
		t.Fatal("合格脚本未形成受限草稿", err)
	}
	for _, source := range []string{
		"def health",
		"def other(ctx): return True",
		"load('other.star', 'check')\n" + script.Definition,
	} {
		bad := script
		bad.Definition = source
		if _, err := DecodeOutput(encode(bad), health); !errors.Is(err, ErrOutput) {
			t.Fatal("脚本声明或语法未核对", err)
		}
	}
	if schema := OutputSchema(); schema["additionalProperties"] != false || schema["type"] != "object" {
		t.Fatal("模型请求不是严格结构化输出")
	}
}
