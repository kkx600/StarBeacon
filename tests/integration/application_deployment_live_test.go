//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kkx600/StarBeacon/internal/application"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
)

// 该链路使用实际平台和采集器进程、签名控制 RPC、原生 Suricata、WAL、NATS 与 ES。
// 受控域名样本只验证可见协议规则，不授予互联网产品识别率或字节计量资格。
func prepareNativeApplicationDeployment(t *testing.T, ctx context.Context, platformHTTP *liveHTTP, sensor model.Sensor) string {
	t.Helper()
	active := true
	change := applicationRuleInput("application_live")
	change.Name = "业务请求应用识别"
	change.Active = &active
	change.Definition.Protocols = []string{"http"}
	change.Definition.Any = []application.Condition{{Field: "http.host", Op: "eq", Value: "replay.example"}}
	change.Definition.All = []application.Condition{{Field: "http.method", Op: "eq", Value: "GET"}, {Field: "http.path", Op: "prefix", Value: "/starbeacon/"}}
	var record application.Record
	platformHTTP.request("POST", "/application-rules", "application_live_create", change, &record, 200)
	var snapshot application.Snapshot
	platformHTTP.request("GET", "/application-rules/snapshot", "", nil, &snapshot, 200)
	if len(snapshot.Versions) != 1 || snapshot.RulesSHA256 != application.Digest(snapshot.Versions) {
		t.Fatal("完整应用目录快照错误")
	}
	var health model.HostHealth
	var state application.State
	require(t, json.Unmarshal(sensor.Health, &health))
	require(t, json.Unmarshal(health.ApplicationRules, &state))
	if state.Validate() != nil {
		t.Fatal("采集器未提供应用状态观测")
	}
	input := application.DeploymentInput{ExpectedRegistrationID: sensor.RegistrationID, ExpectedStateSHA256: state.StateSHA256, RulesSHA256: snapshot.RulesSHA256}
	var accepted struct {
		ID string `json:"id"`
	}
	platformHTTP.request("POST", "/sensors/"+sensor.ID+"/application-rules", "application_live_deploy", input, &accepted, 202)
	var task store.SensorTask
	eventually(t, ctx, "应用规则经签名控制 RPC 完成持久安装", func() bool {
		platformHTTP.request("GET", "/tasks/"+accepted.ID, "", nil, &task, 200)
		if task.State == "failed" || task.State == "unknown" || task.State == "expired" {
			t.Fatal("应用安装未取得成功回执", task.State, string(task.Receipt))
		}
		return task.State == "succeeded"
	})
	var repeated struct {
		ID string `json:"id"`
	}
	platformHTTP.request("POST", "/sensors/"+sensor.ID+"/application-rules", "application_live_deploy", input, &repeated, 202)
	if repeated.ID != accepted.ID {
		t.Fatal("原部署重复产生任务")
	}
	return accepted.ID
}

func verifyNativeApplicationAttribution(t *testing.T, record model.Alert, deployment string) {
	t.Helper()
	a := record.Application
	if a == nil || a.DeploymentID != deployment || a.RawSHA256 != record.RawSHA256 || a.Result.Origin != "suricata_visible_metadata" || a.Result.Status != "candidate" || a.ProductID != "owned_files" || a.Result.MatchedRuleCount != 1 || len(a.Result.Matches) != 1 || a.Result.Matches[0].RuleID != "application_live" || !a.Result.EvaluatedAt.Equal(record.ObservedAt) {
		t.Fatal("原生 HTTP 分类没有完成冻结来源、复算与可见性核对")
	}
}
