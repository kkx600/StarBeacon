//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/model"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/triage"
)

// 实际离线 PCAP 告警经 HTTPS 模型协议、持续判断、签名控制面和采集器获得独立租约回读。
// 协议端点不丢弃真实流量；模型返回受控结构化结论，不授予领域质量资格。
func verifyNativeContinuousDecision(t *testing.T, ctx context.Context, client *liveHTTP, alert model.Alert, sensor string, device *genericHTTPDevice, url string) {
	t.Helper()
	// 必须先观察到真实连接器就绪；策略启用不替代设备资格，拒绝档案也不会自动补发。
	waitNativeResponseReady(t, ctx, client, sensor, device)
	device.mu.Lock()
	writes, deletes := device.writes, device.deletes
	device.mu.Unlock()
	var provider llm.Provider
	config := llm.Config{Name: "持续决策协议验证", Kind: "openai_responses", BaseURL: url + "/v1", Model: "owned-triage-model", Enabled: true, APIKey: "owned-triage-key", MaxOutputTokens: 512, TimeoutSeconds: 5, DailyRequests: 2}
	client.request("POST", "/models/providers", "", store.ModelChange{ID: "provider_continuous_native", ReplaceKey: true, Config: config}, &provider, 200)
	change := decisionPolicyInput("policy_continuous_native")
	change.Definition.Mode = "automatic"
	change.Definition.MaxAgeSeconds = 86400
	change.Definition.Continuous = &decision.ContinuousConfig{ProviderID: provider.ID, ProviderRevision: provider.Revision, Automatic: &decision.AutomaticConfig{SensorID: sensor, RegistrationID: alert.RegistrationID, ConnectorID: device.config.ID, ConfigSHA256: device.config.SHA256(), TTLSeconds: 60, CooldownSeconds: 3600, MaxHourlyActions: 2, AcceptUncalibratedScore: true}}
	var policy decision.Record
	client.request("POST", "/decision-policies", "native_continuous_policy", change, &policy, 200)
	request := triage.Request{EventID: alert.EventID, RawSHA256: alert.RawSHA256, ProviderID: provider.ID, ProviderRevision: provider.Revision, Note: "[automatic_response] 受控协议测试，根据实际源 IP 和规则引用判断", AllowContext: true}
	create := func(key string) triage.Job {
		var j triage.Job
		client.request("POST", "/alerts/"+alert.EventID+"/triage", key, request, &j, 202)
		return j
	}
	read := func(job triage.Job) decision.ContinuousRecord {
		var result decision.ContinuousRecord
		eventually(t, ctx, "持续决策保存本人评估与独立授权", func() bool {
			var page decision.EvaluationPage
			client.request("GET", "/decision-evaluations?policy_id="+policy.ID+"&triage_id="+job.ID, "", nil, &page, 200)
			if len(page.Items) == 0 {
				return false
			}
			if len(page.Items) != 1 || page.Items[0].Result.ExecutionAuthorized {
				t.Fatal("重复判断或判断结果冒充授权")
			}
			var response struct {
				Item *decision.ContinuousRecord `json:"item"`
			}
			client.request("GET", "/decision-evaluations/"+page.Items[0].ID+"/continuous", "", nil, &response, 200)
			if response.Item == nil {
				return false
			}
			result = *response.Item
			sealed, err := result.Seal()
			require(t, err)
			if sealed.SHA256 != result.SHA256 || result.EvaluationSHA256 != page.Items[0].SHA256 {
				t.Fatal("授权摘要或来源失配")
			}
			return true
		})
		return result
	}
	first := read(create("native_continuous_triage"))
	if first.State != "queued" || first.TargetIP != alert.Source.IP || first.TaskID == "" {
		t.Fatal("持续研判未授权原目标", first.State, first.Code)
	}
	manual := decision.ResponseRequest{EvaluationSHA256: first.EvaluationSHA256, SensorID: sensor, RegistrationID: alert.RegistrationID, ConnectorID: device.config.ID, ConfigSHA256: device.config.SHA256(), TTLSeconds: 60, Reason: "核验自动策略不能再次人工授权", Confirmed: true}
	client.request("POST", "/decision-evaluations/"+first.EvaluationID+"/response", "native_continuous_manual_denied", manual, nil, 403)
	var original store.SensorTask
	eventually(t, ctx, "采集器执行自动授权并完成设备独立回读", func() bool {
		client.request("GET", "/tasks/"+first.TaskID, "", nil, &original, 200)
		return original.State == "succeeded"
	})
	var receipt control.Receipt
	require(t, json.Unmarshal(original.Receipt, &receipt))
	var actual responseapi.Result
	require(t, json.Unmarshal(receipt.Result, &actual))
	require(t, actual.Validate(*original.ResponseAction, "response.block", receipt.FinishedAt.UTC()))
	duplicate := read(create("native_continuous_duplicate"))
	if duplicate.State != "skipped" || duplicate.Code != "event_already_authorized" || duplicate.TaskID != "" {
		t.Fatal("同一告警重复研判创建封禁", duplicate.State, duplicate.Code)
	}
	for _, kind := range []string{"response.read", "response.revoke", "response.read"} {
		var accepted map[string]string
		client.request("POST", "/sensors/"+sensor+"/response-tasks", store.RandomID("continuous_verify_"), responseapi.Request{Kind: kind, Intent: responseapi.Intent{ConnectorID: device.config.ID, ConfigSHA256: device.config.SHA256(), OriginalTaskID: first.TaskID, Reason: "核对自动授权的原租约"}}, &accepted, 202)
		var task store.SensorTask
		eventually(t, ctx, "原租约回读与条件解封", func() bool {
			client.request("GET", "/tasks/"+accepted["id"], "", nil, &task, 200)
			return task.State == "succeeded"
		})
		if task.ResponseAction == nil || !task.ResponseAction.ExpiresAt.Equal(original.ResponseAction.ExpiresAt) {
			t.Fatal("读回或解封改变原期限")
		}
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	if device.writes != writes+1 || device.deletes != deletes+1 {
		t.Fatal("自动授权重复写入或解封", device.writes-writes, device.deletes-deletes)
	}
}
