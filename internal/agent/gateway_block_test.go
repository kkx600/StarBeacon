package agent

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/gatewayblock"
)

func TestGatewayBlockTaskHistoryKeepsFollowingSignedTasksAvailable(t *testing.T) {
	engine := &Engine{}
	m, signer := taskFixture(t, engine)
	issued := time.Now().UTC()
	digest := strings.Repeat("a", 64)
	action := gatewayblock.Action{RequestID: "gateway_request", EventID: digest, ConfigSHA256: digest,
		PolicyID: "gateway_policy", Revision: 1, Trigger: gatewayblock.Rule, LeaseUntil: issued.Add(8 * time.Second),
		Flow: gatewayblock.Flow{SourceIP: netip.MustParseAddr("10.203.35.3"), SourcePort: 1234,
			DestinationIP: netip.MustParseAddr("10.203.36.3"), DestinationPort: 8080, Transport: "tcp"}}
	payload, err := json.Marshal(action)
	if err != nil {
		t.Fatal(err)
	}
	c := control.Command{ID: "task_gateway_history", TenantID: m.WAL.TenantID, SensorID: m.WAL.SensorID,
		RegistrationID: m.WAL.RegistrationID, Kind: gatewayblock.CommandKind, IssuedAt: issued,
		ExpiresAt: issued.Add(gatewayblock.DispatchWindow), Payload: payload}
	if result, code, err := engine.Execute(t.Context(), c); err == nil || code != "gateway_unavailable" || len(result) != 0 {
		t.Fatal("未开启本地网关仍可执行任务", result, code, err)
	}
	malformed := c
	malformed.Payload = json.RawMessage(`{}`)
	if _, code, err := engine.Execute(t.Context(), malformed); err == nil || code != "invalid_gateway_block" {
		t.Fatal("执行入口接受未绑定连接的任务", code, err)
	}
	raw, sig, err := control.Encode(c, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Accept(raw, sig); err != nil {
		t.Fatal(err)
	}
	// 接收后允许从档案查证，并允许清理游标跨过该任务。
	if task, err := m.Task(c.ID); err != nil || task.Kind != c.Kind || task.Origin != "platform" {
		t.Fatal("已接收的网关任务无法从档案核对", task, err)
	}
	if err = m.Sweep(t.Context()); err != nil {
		t.Fatal("历史扫描拒绝已接收的网关任务", err)
	}
	select {
	case <-m.queue:
	default:
		t.Fatal("已签名的网关任务没有进入执行队列")
	}
	next, nextSig := signedFixtureCommand(t, m, signer, "task_gateway_followup", time.Now().UTC())
	if err = m.Accept(next, nextSig); err != nil {
		t.Fatal("网关历史阻塞后续合法任务", err)
	}
}
