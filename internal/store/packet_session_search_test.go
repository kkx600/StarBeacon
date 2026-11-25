package store

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/traffic"
)

func TestPacketSessionEndpointScopeAndRetentionFilter(t *testing.T) {
	q := model.TrafficSearchRequest{EventKind: traffic.PacketSessionKind, EndpointA: "192.0.2.18/24", EndpointB: "[2001:db8::1]:443", Retention: "policy_truncated"}
	if err := validatePacketSessionSearch(&q); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(packetSessionSearchFilters(q, nil))
	for _, term := range []string{`"source.ip":"192.0.2.0/24"`, `"destination.ip":"2001:db8::1"`, `"destination.port":443`, `"packet_session_retention":"policy_truncated"`} {
		if !strings.Contains(string(encoded), term) {
			t.Fatal("缺少正确的会话条件", term)
		}
	}
	for _, bad := range []model.TrafficSearchRequest{
		{EventKind: "http", EndpointA: "192.0.2.1"}, {EventKind: traffic.PacketSessionKind, EndpointA: "bad"},
		{EventKind: traffic.PacketSessionKind, Retention: "all"}, {EventKind: traffic.PacketSessionKind, EndpointB: "fe80::1%eth0"},
		{EventKind: traffic.PacketSessionKind, EndpointA: strings.Repeat("x", 81)},
	} {
		if validatePacketSessionSearch(&bad) == nil {
			t.Fatal("接受了超出会话字段范围的条件", bad)
		}
	}
	if value, port := packetEndpoint("::ffff:192.0.2.5"); value != "192.0.2.5" || port != nil {
		t.Fatal("普通 IPv4 地址未规范化", value, port)
	}
}
