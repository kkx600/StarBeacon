//go:build integration

package integration

import (
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/correlation"
	"github.com/kkx600/StarBeacon/internal/model"
)

// 使用实际捕获链路已经索引的告警，不能把注入的合成记录作为原生捕获证明。
func verifyNativeCorrelation(t *testing.T, api *liveHTTP, fact model.Alert) {
	input := correlationInput("correlation_native")
	input.Definition.Filter = "rule.id == " + fact.Rule.ID
	input.Definition.WindowSeconds = 15
	var rule correlation.Record
	api.request("POST", "/correlation-rules", "correlation_native_create", input, &rule, 200)
	start := fact.Timestamp.UTC().Truncate(15 * time.Second)
	end := start.Add(15 * time.Second)
	if now := time.Now().UTC().Truncate(time.Second); end.After(now) {
		end = now
	}
	if !end.After(fact.Timestamp) {
		t.Fatal("真实告警时间尚未形成可查询区间")
	}
	query := correlation.Request{ExpectedRevision: rule.Revision, Start: start, End: end}
	var result, repeated correlation.Result
	api.request("POST", "/correlation-rules/"+rule.ID+"/backtest", "", query, &result, 200)
	api.request("POST", "/correlation-rules/"+rule.ID+"/backtest", "", query, &repeated, 200)
	if result.UniqueEvents != 1 || len(result.Windows) != 1 || result.ThresholdWindows != 0 || result.ExecutionAuthorized || result.SourceCoverage != "not_attested" || result.SnapshotSHA256 != repeated.SnapshotSHA256 {
		t.Fatal("原生告警窗口回测范围或重复读取身份不一致", result)
	}
	w := result.Windows[0]
	if w.SensorID != fact.SensorID || w.RegistrationID != fact.RegistrationID || w.Count != 1 || w.MetricValue != 1 || len(w.Evidence) != 1 || w.Evidence[0].EventID != fact.EventID || w.Evidence[0].RawSHA256 != fact.RawSHA256 || w.DetectionID != repeated.Windows[0].DetectionID {
		t.Fatal("回测证据与原生告警不能对应", w)
	}
	t.Logf("原生告警 → 固定 PIT 快照 → 15 秒窗口回测 → 相同事件与原文摘要回读通过；唯一告警=1，阈值窗口=0，覆盖未经证明，未生成处置")
}
