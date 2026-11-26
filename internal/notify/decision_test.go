package notify

import (
	"strings"
	"testing"
	"time"
)

func TestDecisionTimeoutNoticeUsesOnlyOperationalSummary(t *testing.T) {
	config := Config{Kind: "webhook", Streams: []string{"quality"}}
	message := Message{TenantID: "tenant_owned", BatchID: "continuous_owned", ID: "delivery_owned",
		DecisionTimeout: &DecisionTimeout{PlanID: "continuous_owned", ExpiredAt: time.Now().UTC()}}
	if !validDecisionTimeout(config, message) || !strings.Contains(message.Text(), "已超过确认时限") {
		t.Fatal("值班摘要未通过验证")
	}
	alertsOnly := config
	alertsOnly.Streams = []string{"alerts"}
	if validDecisionTimeout(alertsOnly, message) {
		t.Fatal("超时消息误入普通告警通知")
	}
	message.BatchID = "different"
	if validDecisionTimeout(config, message) {
		t.Fatal("未绑定原方案")
	}
	message.DecisionTimeout = nil
	if !validDecisionTimeout(config, message) {
		t.Fatal("旧通知类型受影响")
	}
}
