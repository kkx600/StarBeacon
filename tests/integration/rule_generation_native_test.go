//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kkx600/StarBeacon/internal/agent"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/rulegen"
	"github.com/kkx600/StarBeacon/internal/store"
)

// 受控 TLS 提供方只证明请求契约与队列链路；不代表商业模型的生成质量或费用。
func newGenerationProvider(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var request struct {
			Model string `json:"model"`
			Input string `json:"input"`
			Store *bool  `json:"store"`
			Text  struct {
				Format struct {
					Type   string `json:"type"`
					Name   string `json:"name"`
					Strict bool   `json:"strict"`
				} `json:"format"`
			} `json:"text"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 65537)).Decode(&request) != nil || r.Header.Get("Authorization") != "Bearer owned-rule-generation-key" || request.Store == nil || *request.Store || request.Text.Format.Type != "json_schema" || !request.Text.Format.Strict || request.Text.Format.Name != "starbeacon_rule_candidates" || request.Model != "owned-rule-model" {
			w.WriteHeader(400)
			return
		}
		var prompt struct {
			Description string           `json:"description"`
			SIDs        []uint32         `json:"assigned_sids"`
			Material    rulegen.Evidence `json:"material"`
		}
		if json.Unmarshal([]byte(request.Input), &prompt) != nil || len(prompt.SIDs) < 1 || len(prompt.SIDs) > 3 {
			w.WriteHeader(400)
			return
		}
		candidates := []map[string]any{}
		for _, sid := range prompt.SIDs {
			refs := []int64{}
			if len(prompt.Material.Packets) > 0 {
				refs = append(refs, prompt.Material.Packets[0].Packet)
			}
			rule := fmt.Sprintf(`alert http any any -> any any (msg:"StarBeacon generated rule"; flow:established,to_server; http.uri; content:"/starbeacon/ai-validation"; sid:%d; rev:1;)`, sid)
			if strings.Contains(prompt.Description, "[invalid_output]") {
				rule = strings.Replace(rule, "alert ", "drop ", 1)
			}
			candidates = append(candidates, map[string]any{"sid": sid, "engine_version": "8.0.7", "title": "请求路径检测", "rule": rule, "explanation": "依据本次有界材料起草，仍需目标引擎和正反样本验证。", "risks": []string{"合法业务可能使用相同路径"}, "references": refs})
		}
		text, _ := json.Marshal(map[string]any{"candidates": candidates})
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(prompt.Description, "[cancel_after_send]") {
			<-r.Context().Done()
			return
		}
		if strings.Contains(prompt.Description, "[uncertain]") {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"error":{"message":"controlled failure","type":"server_error"}}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "owned-rule-response", "object": "response", "model": "owned-rule-model", "status": "completed", "output": []any{map[string]any{"id": "owned-rule-message", "type": "message", "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": string(text), "annotations": []any{}}}}}, "usage": map[string]any{"input_tokens": 3, "output_tokens": 4, "total_tokens": 7}})
	}))
	return server, calls
}

func verifyNativeRuleGeneration(t *testing.T, ctx context.Context, platformHTTP, collectorHTTP *liveHTTP, providerURL string, calls *atomic.Int32) {
	t.Helper()
	var provider llm.Provider
	config := llm.Config{Name: "规则生成协议验收", Kind: "openai_responses", BaseURL: providerURL + "/v1", Model: "owned-rule-model", Enabled: true, APIKey: "owned-rule-generation-key", MaxOutputTokens: 1024, TimeoutSeconds: 5, DailyRequests: 1}
	platformHTTP.request("POST", "/models/providers", "", store.ModelChange{ID: "provider_rule_live", ReplaceKey: true, Config: config}, &provider, 200)
	positive := []byte("GET /starbeacon/ai-validation HTTP/1.1\r\nHost: replay.example\r\nConnection: close\r\n\r\n")
	negative := []byte("GET /starbeacon/allowed HTTP/1.1\r\nHost: replay.example\r\nConnection: close\r\n\r\n")
	var sample, other replay.Sample
	platformHTTP.request("POST", "/replay/samples/http", "", positive, &sample, 201)
	platformHTTP.request("POST", "/replay/samples/http", "", negative, &other, 201)
	if sample.Origin == nil || !sample.Origin.Valid() || sample.Origin.RawSHA256 != control.Digest(positive) || sample.Origin.RawBytes != int64(len(positive)) || sample.Format != "pcap" {
		t.Fatal("实际二进制入口没有保留准确的合成来源")
	}
	input := rulegen.Request{Description: "依据请求路径起草旁路检测规则，并说明匹配范围与误报风险。", Source: "http_raw", SampleID: sample.ID, SampleSHA256: sample.SHA256, ProviderID: provider.ID, ProviderRevision: provider.Revision, CandidateCount: 1, AllowContext: true}
	var job rulegen.Job
	platformHTTP.request("POST", "/rule-generation/jobs", "live_generation_owned", input, &job, 202)
	id := job.ID
	eventually(t, ctx, "规则候选经持久队列与 TLS 生成协议返回", func() bool {
		platformHTTP.request("GET", "/rule-generation/jobs/"+id, "", nil, &job, 200)
		if job.State != "queued" && job.State != "running" && job.State != "succeeded" {
			t.Fatal("规则生成未完成", job.State, job.Result.Code)
		}
		return job.State == "succeeded"
	})
	if len(job.Candidates) != 1 || job.Evidence.Sample == nil || !replay.SameOrigin(sample.Origin, job.Evidence.Sample.Origin) || len(job.Candidates[0].References) != 1 || job.Candidates[0].References[0] != 4 || job.Result.Usage == nil || calls.Load() != 1 {
		t.Fatal("生成出处、真实包引用或请求次数不准确")
	}
	var repeated rulegen.Job
	platformHTTP.request("POST", "/rule-generation/jobs", "live_generation_owned", input, &repeated, 200)
	if repeated.ID != id || calls.Load() != 1 {
		t.Fatal("相同请求重复调用模型")
	}
	changed := input
	changed.Description += "不同输入"
	platformHTTP.request("POST", "/rule-generation/jobs", "live_generation_owned", changed, nil, 409)
	platformHTTP.request("POST", "/models/providers/"+provider.ID+"/test", "live_generation_budget", map[string]any{"expected_revision": provider.Revision}, nil, 429)
	var pkg store.RulePackage
	platformHTTP.request("POST", "/rule-generation/jobs/"+id+"/adopt", "", map[string]any{"sid": job.Candidates[0].SID}, &pkg, 200)
	if pkg.SHA256 != job.Candidates[0].SHA256 || pkg.GenerationID == nil || *pkg.GenerationID != id || pkg.GenerationSID == nil || *pkg.GenerationSID != job.Candidates[0].SID {
		t.Fatal("候选保存失去冻结出处")
	}
	var replayed store.RulePackage
	platformHTTP.request("POST", "/rule-generation/jobs/"+id+"/adopt", "", map[string]any{"sid": job.Candidates[0].SID}, &replayed, 200)
	if replayed.ID != pkg.ID || replayed.Revision != 1 || !replayed.CreatedAt.Equal(pkg.CreatedAt) {
		t.Fatal("候选保存重试产生了不同修订")
	}
	var accepted struct {
		ID string `json:"id"`
	}
	waitTask := func(id string) control.Receipt {
		var result control.Receipt
		eventually(t, ctx, "指定探针回传候选规则原生验证", func() bool {
			var tasks struct {
				Items []store.SensorTask `json:"items"`
			}
			platformHTTP.request("GET", "/tasks", "", nil, &tasks, 200)
			for _, task := range tasks.Items {
				if task.ID != id {
					continue
				}
				if task.State == "failed" || task.State == "unknown" || task.State == "expired" {
					t.Fatal("候选原生验证未通过", task.State)
				}
				if task.State == "succeeded" {
					require(t, json.Unmarshal(task.Receipt, &result))
					return true
				}
			}
			return false
		})
		return result
	}
	platformHTTP.request("POST", "/sensors/sensor_live/tasks", "live_generated_validation", map[string]any{"kind": "rules.validate", "package_id": pkg.ID, "revision": pkg.Revision}, &accepted, 202)
	validation := waitTask(accepted.ID)
	if !bytes.Contains(validation.Result, []byte(`"syntax":"passed"`)) {
		t.Fatal("候选没有通过真实 Suricata 装载")
	}
	for i, s := range []replay.Sample{sample, other} {
		platformHTTP.request("POST", "/sensors/sensor_live/tasks", fmt.Sprintf("live_generated_replay_%d", i), map[string]any{"kind": "rules.replay", "sample_id": s.ID, "rule_mode": "package", "package_id": pkg.ID, "revision": pkg.Revision}, &accepted, 202)
		receipt := waitTask(accepted.ID)
		var report struct {
			Count     int64           `json:"alert_count"`
			Origin    *replay.Origin  `json:"sample_origin"`
			SampleSHA string          `json:"sample_sha256"`
			Metadata  replay.Metadata `json:"sample_metadata"`
			RulesSHA  string          `json:"rules_sha256"`
		}
		require(t, json.Unmarshal(receipt.Result, &report))
		if report.Count != int64(1-i) || !replay.SameOrigin(report.Origin, s.Origin) || report.SampleSHA != s.SHA256 || report.RulesSHA != pkg.SHA256 || report.Metadata.TCPHandshake.CompleteHandshakes != 1 {
			t.Fatal("真实正反样本回放或合成标记不准确", i, report.Count)
		}
	}
	var local replay.Sample
	collectorHTTP.request("POST", "/replay/samples/http", "", positive, &local, 201)
	collectorHTTP.request("POST", "/replay/tasks", "live_generated_local", map[string]any{"sample_id": local.ID, "rule_mode": "package", "rules": pkg.Text}, &accepted, 202)
	eventually(t, ctx, "采集器本地合成样本检测并保留来源", func() bool {
		var task agent.LocalTaskSummary
		collectorHTTP.request("GET", "/tasks/"+accepted.ID, "", nil, &task, 200)
		if task.ID != accepted.ID || task.Origin != "local" {
			t.Fatal("采集器本地合成样本详情未绑定任务来源", task)
		}
		if task.State != "succeeded" {
			return false
		}
		var report struct {
			Count  int64          `json:"alert_count"`
			Origin *replay.Origin `json:"sample_origin"`
		}
		require(t, json.Unmarshal(task.Receipt.Result, &report))
		return report.Count == 1 && replay.SameOrigin(local.Origin, report.Origin)
	})
	if calls.Load() != 1 {
		t.Fatal("本地验证或额度检查意外重复模型调用")
	}
	t.Log("规则生成协议、不可变出处、共享额度、HTTP Raw 原始摘要、目标探针原生装载、正反样本与本地重放通过；合成握手不代表真实捕获。")
}
