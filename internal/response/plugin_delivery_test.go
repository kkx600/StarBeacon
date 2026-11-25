package response

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func draftVersion(t *testing.T, entries ...string) PluginVersion {
	t.Helper()
	script := &PluginScript{Source: "def health(ctx): return True", Entries: entries}
	v := PluginVersion{ID: "plugin", Version: 1, Name: "联动", Device: "测试夹具", CreatedBy: "operator", CreatedAt: time.Now(),
		Kind: "script", State: "draft", Script: script, ScriptSHA256: script.SHA256(),
		Examples: []PluginExample{{Method: "GET", Path: "/health", Status: 200, Response: `{"value":true}`}}}
	if v.Validate() != nil {
		t.Fatal("版本夹具无效")
	}
	return v
}

func TestPluginDraftFreezeRejectsAmbiguousSamplesAndCapabilities(t *testing.T) {
	valid := draftVersion(t, "health").draft()
	raw, _ := json.Marshal(valid)
	var decoded PluginDraft
	if json.Unmarshal(raw, &decoded) != nil || decoded.SHA256() != valid.SHA256() {
		t.Fatal("草稿摘要不稳定")
	}
	profiles := [][]string{nil, {"health", "health"}, {"block"}, {"health", "release"}, {"isolate", "release"}, {"unknown"}}
	for _, entries := range profiles {
		if (&PluginScript{Source: valid.Script.Source, Entries: entries}).Validate() == nil {
			t.Fatalf("错误的入口组合未拒绝 %v", entries)
		}
	}
	for _, sample := range []PluginExample{
		{Method: "PATCH", Path: "/health", Status: 201},
		{Method: "GET", Path: "https://device.example/status", Status: 200},
		{Method: "GET", Path: "/escape/../status", Status: 200},
		{Method: "GET", Path: "/health", Status: 302},
		{Method: "GET", Path: "/health", Status: 200, Query: "x=%xx"},
		{Method: "GET", Path: "/health", Status: 200, Query: "x=2&a=1"},
		{Method: "GET", Path: "/health", Status: 200, Response: "not JSON"},
	} {
		if sample.valid() {
			t.Fatalf("无效的设备样例仍可进入草稿 %v", sample)
		}
	}
	for _, input := range []string{
		strings.Replace(string(raw), `"expected_version":0,`, "", 1),
		strings.Replace(string(raw), `"name":"联动"`, `"name":"联动","name":"重复"`, 1),
		strings.Replace(string(raw), `"source":`, `"not_known":`, 1),
		strings.Replace(string(raw), `"device":`, `"kind":"active","device":`, 1),
	} {
		if json.Unmarshal([]byte(input), &decoded) == nil {
			t.Fatalf("无效草稿解码为可运行配置 %s", input[:min(len(input), 64)])
		}
	}
	for _, update := range []func(*PluginDraft){
		func(v *PluginDraft) { v.ID = "../plugin" },
		func(v *PluginDraft) { v.ExpectedVersion = 33 },
		func(v *PluginDraft) { v.Name = " " },
		func(v *PluginDraft) { v.Template.SchemaVersion = TemplateSchema },
		func(v *PluginDraft) { v.Examples = make([]PluginExample, 49) },
		func(v *PluginDraft) { v.Examples[0].Path = "/bad/../path" },
	} {
		draft := draftVersion(t, "health").draft()
		update(&draft)
		if draft.Validate() == nil {
			t.Fatal("无效草稿通过直接调用校验")
		}
	}
}

func ownedPluginBinding() PluginBinding {
	return PluginBinding{PluginID: "plugin", DeviceID: "device", BindingSHA256: strings.Repeat("b", 64)}
}

func TestPluginTrialProofModesAndScope(t *testing.T) {
	for _, tc := range []struct {
		entries []string
		mode    string
		checks  int
	}{{[]string{"health", "pull_alerts"}, "read_only", 1}, {[]string{"block", "verify", "unblock"}, "block", 4},
		{[]string{"isolate", "verify", "release"}, "isolate", 4}, {[]string{"block", "unblock", "isolate", "release", "verify"}, "block_and_isolate", 8}} {
		v := draftVersion(t, tc.entries...)
		for _, stage := range PluginStages {
			in := PluginTrial{Version: v, Stage: stage, Binding: ownedPluginBinding()}
			raw, _ := json.Marshal(in)
			trial, err := ReadPluginTrial(raw)
			if err != nil || trial.Version.DefinitionSHA256() != v.DefinitionSHA256() || v.TrialMode() != tc.mode {
				t.Fatal("三档请求未绑定插件定义", err)
			}
			r := in.Result()
			r.Checks = in.Checks()
			if stage == PluginCapability && len(r.Checks) != tc.checks {
				t.Fatalf("%s 验收步骤错误", tc.mode)
			}
			for _, step := range r.Checks {
				var requests []PluginTrialRequest
				ctx := WithPluginTrialRequests(t.Context(), &requests)
				if step != "writes_denied" {
					RecordPluginTrialRequest(ctx, http.MethodGet, &http.Response{StatusCode: http.StatusOK})
				}
				r.Events = append(r.Events, PluginTrialEvent{Entry: step, Code: "ok", DurationMS: 31, Requests: requests})
			}
			data, _ := json.Marshal(r)
			if got, err := ReadPluginTrialResult(data, in); err != nil || got.SHA256() != r.SHA256() {
				t.Fatal("合格回执未能读取", err)
			}
			for _, change := range []func(*PluginTrialResult){
				func(v *PluginTrialResult) { v.Stage = "publish" },
				func(v *PluginTrialResult) { v.Binding.PluginID = "other_plugin" },
				func(v *PluginTrialResult) { v.DefinitionSHA256 = strings.Repeat("0", 64) },
				func(v *PluginTrialResult) { v.Checks = v.Checks[1:] },
				func(v *PluginTrialResult) { v.Events[0].Code = "failed" },
				func(v *PluginTrialResult) { v.Events[0].Requests = []PluginTrialRequest{{Method: "TRACE"}} },
				func(v *PluginTrialResult) { v.Events[0].Requests = []PluginTrialRequest{{Method: "GET", Status: 601}} },
				func(v *PluginTrialResult) {
					v.Events[0].Requests = make([]PluginTrialRequest, maxPluginTrialRequests+1)
				},
			} {
				bad := r
				bad.Events = append([]PluginTrialEvent(nil), r.Events...)
				change(&bad)
				raw, _ := json.Marshal(bad)
				if _, err := ReadPluginTrialResult(raw, in); err == nil {
					t.Fatal("错配或失败回执通过资格检查")
				}
			}
		}
	}
	in := PluginTrial{Version: draftVersion(t, "health"), Stage: PluginSimulate, Binding: ownedPluginBinding()}
	in.Version.Examples = nil
	raw, _ := json.Marshal(in)
	if _, err := ReadPluginTrial(raw); err == nil {
		t.Fatal("没有样例的模拟通过预检")
	}
}

func TestPluginTrialRequestTraceBoundsAndSanitization(t *testing.T) {
	var requests []PluginTrialRequest
	RecordPluginTrialRequest(t.Context(), http.MethodGet, nil)
	ctx := WithPluginTrialRequests(t.Context(), &requests)
	RecordPluginTrialRequest(ctx, http.MethodPost, nil)
	for range maxPluginTrialRequests {
		RecordPluginTrialRequest(ctx, http.MethodGet, &http.Response{
			StatusCode: http.StatusNotFound, Request: &http.Request{Header: http.Header{"Authorization": {"私有凭据"}}},
		})
	}
	if len(requests) != maxPluginTrialRequests || requests[0] != (PluginTrialRequest{Method: "POST"}) ||
		requests[1] != (PluginTrialRequest{Method: "GET", Status: 404}) {
		t.Fatal("请求摘要未按有界方法和状态记录")
	}
	raw, _ := json.Marshal(requests)
	if strings.Contains(string(raw), "私有凭据") {
		t.Fatal("私有请求数据进入回执")
	}
}

func TestPluginTemplatePullValidatesPageAndPreservesLargeVendorRecord(t *testing.T) {
	template := Template{SchemaVersion: TemplateSchema, Pull: &TemplatePull{
		Path: "/alerts", CursorParam: "cursor", ItemsField: "list", CursorField: "next",
		Fields: []TemplateField{{Name: "id", Value: "uid"}, {Name: "name", Value: "label"},
			{Name: "severity", Value: "priority"}, {Name: "time", Value: "when"}},
	}}
	cfg := Configuration{ID: "connector", DeviceID: "device", DeviceVersion: "fixture/1",
		Origin: "https://127.0.0.1", CAFile: "/private/test.ca", TokenFile: "/private/token", MaxTTLSeconds: 60}
	payload := strings.Repeat("<", 12*1024)
	raw := `{"list":[{"uid":"a1","label":"设备事件","priority":"严重","when":"2026-11-24T00:01:00Z","vendor":{"native":"` + payload + `"}}],"next":"page_2"}`
	responses := []PluginExample{
		{Method: "GET", Path: "/alerts", Query: "cursor=initial", Status: 200, Response: raw},
		{Method: "GET", Path: "/alerts", Query: "cursor=page_2", Status: 200, Response: `{"list":[true],"next":"page_3"}`},
		{Method: "GET", Path: "/alerts", Query: "cursor=page_2", Status: 200, Response: `{"list":[{"uid":"a1"}],"next":"page_3"}`},
		{Method: "GET", Path: "/alerts", Query: "cursor=page_2", Status: 200, Response: `{"list":[],"next":null}`},
	}
	replay := NewPluginReplay(responses, nil)
	client, err := NewTemplateSimulation(cfg, template, replay)
	if err != nil {
		t.Fatal("只读设备告警模板无法绑定", err)
	}
	defer client.Close()
	if _, err := client.PullAlerts(t.Context(), " invalid"); err != ErrInput {
		t.Fatal("无效游标透传到设备", err)
	}
	page, err := client.PullAlerts(t.Context(), "initial")
	if err != nil || len(page.Items) != 1 || page.Cursor != "page_2" || page.Items[0].Severity != "critical" ||
		!strings.Contains(string(page.Items[0].Raw), payload) {
		t.Fatal("大体积厂商记录未保留原文和当前游标", err)
	}
	for _, want := range []error{ErrInput, ErrInput, ErrUnavailable} {
		if _, err := client.PullAlerts(t.Context(), "page_2"); err != want {
			t.Fatal("无效厂商页未稳定拒绝", err)
		}
	}
	if !replay.Complete() {
		t.Fatal("未完全核对匹配的厂商分页")
	}
}

func pluginTestGrant(v PluginVersion) PluginGrant {
	return PluginGrant{TenantID: "tenant", SensorID: "sensor", RegistrationID: "registration", Version: v.Version,
		Binding: ownedPluginBinding(), DefinitionSHA256: v.DefinitionSHA256(),
		TrialSHA256: [3]string{strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64)}}
}

func TestImmutablePluginSignatureAndAssignmentTransitions(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v1 := draftVersion(t, "health")
	artifact := func(v PluginVersion) *PluginArtifact {
		release, err := SignPlugin(pluginTestGrant(v), key)
		if err != nil {
			t.Fatal(err)
		}
		return &PluginArtifact{Version: v, Release: release}
	}
	a1 := artifact(v1)
	if a1.Validate() != nil || a1.Release.Verify(pub, "tenant", "sensor", "registration") != nil ||
		a1.Release.Verify(pub, "tenant", "other_sensor", "registration") == nil ||
		a1.Release.Verify(nil, "tenant", "sensor", "registration") == nil {
		t.Fatal("签名身份边界未生效")
	}
	mutated := *a1
	mutated.Version.Name = "修改源码后的内容"
	if mutated.Validate() == nil {
		t.Fatal("签名可用于另一个版本内容")
	}
	grant := a1.Release.Grant
	grant.TrialSHA256[2] = grant.TrialSHA256[0]
	if _, err := SignPlugin(grant, key); err == nil {
		t.Fatal("重复的试运行证明被签名")
	}

	a := PluginActivation{PluginID: v1.ID, Action: PluginPublish, Artifact: a1}
	raw, _ := json.Marshal(a)
	if _, err := ReadPluginActivation(raw); err != nil {
		t.Fatal(err)
	}
	receipt, _ := json.Marshal(a.Result())
	if ReadPluginActivationResult(receipt, a) != nil || ReadPluginActivationResult([]byte(`{}`), a) == nil {
		t.Fatal("启用回执不能被替换")
	}
	next, err := a.Apply(PluginAssignment{})
	if err != nil || next.Current != a1 || next.Generation != 1 {
		t.Fatal("初次启用有误", err)
	}
	if _, err = a.Apply(next); err == nil {
		t.Fatal("过期代次能覆盖当前发布")
	}
	a.ExpectedGeneration = 1
	if _, err = a.Apply(next); err == nil {
		t.Fatal("重复启用创建新代次")
	}
	v2 := v1
	v2.Version = 2
	a.Artifact = artifact(v2)
	next, err = a.Apply(next)
	if err != nil || next.Previous != a1 || next.Generation != 2 {
		t.Fatal("未保留上次发布", err)
	}
	a = PluginActivation{PluginID: v1.ID, Action: PluginRollback, Artifact: a1, ExpectedGeneration: 2}
	next, err = a.Apply(next)
	if err != nil || next.Current != a1 || next.Previous.Version.Version != 2 || next.Generation != 3 {
		t.Fatal("回退未绑定上一份签名", err)
	}
	a = PluginActivation{PluginID: v1.ID, Action: PluginDisable, ExpectedGeneration: 3}
	next, err = a.Apply(next)
	if err != nil || next.Current != nil || next.Previous != a1 || next.Generation != 4 {
		t.Fatal("停用破坏之前的签名发布", err)
	}
	a = PluginActivation{PluginID: v1.ID, Action: PluginRollback, Artifact: a1, ExpectedGeneration: 4}
	if restored, err := a.Apply(next); err != nil || restored.Current != a1 || restored.Generation != 5 {
		t.Fatal("已停用版本不能使用原签名重新启用", err)
	}
	for _, invalid := range []PluginActivation{
		{PluginID: v1.ID, Action: "publish"},
		{PluginID: "foreign", Action: "publish", Artifact: a1},
		{PluginID: v1.ID, Action: "disable", Artifact: a1, ExpectedGeneration: 1},
		{PluginID: v1.ID, Action: "disable"},
		{PluginID: v1.ID, Action: "other"},
	} {
		raw, _ := json.Marshal(invalid)
		if _, err := ReadPluginActivation(raw); err == nil {
			t.Fatal("无效发布可下发", invalid.Action)
		}
	}
}

func TestPluginReplayChecksSequenceAndFrozenJSON(t *testing.T) {
	examples := []PluginExample{{Method: "POST", Path: "/session", Request: `{"a":"{{host_id}}","b":1}`, Status: 201, Response: `{"id":"{{host_id}}"}`},
		{Method: "GET", Path: "/alerts", Query: "after=begin", Status: 200, Response: `{"items":[]}`}}
	replay := NewPluginReplay(examples, map[string]string{"host_id": "sample_host"})
	client := &http.Client{Transport: replay}
	do := func(method, path, body string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(context.Background(), method, "https://192.0.2.2"+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		return client.Do(req)
	}
	res, err := do("POST", "/session", `{"b":1, "a":"sample_host"}`)
	if err != nil || res.StatusCode != 201 || replay.Complete() {
		t.Fatal("模拟设备未使用冻结样例", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != `{"id":"sample_host"}` {
		t.Fatal("样例未使用测试替换值")
	}
	res, err = do("GET", "/alerts?after=begin", "")
	if err != nil || !replay.Complete() {
		t.Fatal("完整样例未消费", err)
	}
	res.Body.Close()
	if _, err = do("GET", "/alerts?after=begin", ""); err == nil || replay.Complete() {
		t.Fatal("未登记请求仍被回放")
	}
	for _, bad := range []struct{ method, path, data string }{
		{"GET", "/session", `{"a":"sample_host","b":1}`}, {"POST", "/session?offset=1", `{"a":"sample_host","b":1}`},
		{"POST", "/other", `{"a":"sample_host","b":1}`}, {"POST", "/session", `{"a":"other","b":1}`},
		{"POST", "/session", "bad JSON"}, {"POST", "/session", strings.Repeat("a", 17000)},
	} {
		replay = NewPluginReplay(examples, map[string]string{"host_id": "sample_host"})
		client.Transport = replay
		if _, err = do(bad.method, bad.path, bad.data); err == nil || replay.Complete() {
			t.Fatal("模拟接受了不同的网络请求", bad.method, bad.path)
		}
	}
}
