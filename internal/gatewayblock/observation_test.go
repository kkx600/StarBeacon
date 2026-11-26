package gatewayblock

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGatewayObservationPacketProofRequiresSameServiceAndKnownHeader(t *testing.T) {
	flow := testFlow("10.203.35.3", "10.203.36.3", "tcp")
	tcp := func(size int, port uint16, flags byte) []byte {
		packet := make([]byte, size)
		packet[0], packet[9] = 0x45, 6
		binary.BigEndian.PutUint16(packet[2:4], uint16(size))
		source, dest := flow.SourceIP.As4(), flow.DestinationIP.As4()
		copy(packet[12:16], source[:])
		copy(packet[16:20], dest[:])
		binary.BigEndian.PutUint16(packet[20:22], port)
		binary.BigEndian.PutUint16(packet[22:24], flow.DestinationPort)
		packet[32], packet[33] = 0x50, flags
		return packet
	}
	zeroPort := tcp(40, 0, 0x02)
	badHeader := tcp(40, flow.SourcePort, 0x02)
	badHeader[32] = 0x10
	fragment := tcp(45, flow.SourcePort, 0x10)
	fragment[6] = 0x20
	unrelated := tcp(45, flow.SourcePort+1, 0x02)
	unrelated[22] = 1
	neighbor := tcp(41, flow.SourcePort+1, 0x10)
	otherIP := tcp(45, flow.SourcePort+1, 0x02)
	otherIP[15] = 4
	shortTCP := tcp(40, flow.SourcePort, 0x02)
	protocol := tcp(40, flow.SourcePort, 0x02)
	protocol[9] = 17
	for _, tc := range []struct {
		name string
		raw  []byte
		size int
		ok   bool
		data bool
		syn  bool
	}{
		{"原连接数据", tcp(41, flow.SourcePort, 0x10), 41, true, true, false},
		{"原端口新握手", tcp(40, flow.SourcePort, 0x02), 40, true, true, false},
		{"新源端口握手", tcp(40, flow.SourcePort+1, 0x02), 40, true, false, true},
		{"分流已有连接", neighbor, 41, true, false, false},
		{"其他传输协议", protocol, 40, true, false, false},
		{"其他端口", unrelated, 45, true, false, false},
		{"其他源地址", otherIP, 45, true, false, false},
		{"报头无数据", tcp(40, flow.SourcePort, 0x10), 40, true, false, false},
		{"只捕获头部", tcp(1500, flow.SourcePort, 0x10)[:128], 1500, true, true, false},
		{"分片", fragment, 45, false, false, false},
		{"无效 TCP 长度", badHeader, 40, false, false, false},
		{"无效端口", zeroPort, 40, false, false, false},
		{"截断 IP", []byte{0x45}, 50, false, false, false},
		{"截断 TCP", shortTCP[:29], 40, false, false, false},
		{"未知版本", []byte{0x75}, 51, false, false, false},
		{"空样本", nil, 40, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var o Observation
			if got := o.countPacket(tc.raw, tc.size, flow); got != tc.ok || (o.OriginalPackets > 0) != tc.data ||
				(o.Reconnect != nil) != tc.syn || tc.syn && o.Reconnect.SourcePort != flow.SourcePort+1 {
				t.Fatal("出侧采样身份或数据判定不一致", got, o)
			}
		})
	}

	udp := testFlow("fd12:35::3", "fd12:36::3", "udp")
	datagram := func(port, payload, datagramLength uint16, protocol byte) []byte {
		packet := make([]byte, 48+payload)
		packet[0], packet[6] = 0x60, protocol
		source, dest := udp.SourceIP.As16(), udp.DestinationIP.As16()
		copy(packet[8:24], source[:])
		copy(packet[24:40], dest[:])
		binary.BigEndian.PutUint16(packet[4:6], 8+payload)
		binary.BigEndian.PutUint16(packet[40:42], port)
		binary.BigEndian.PutUint16(packet[42:44], udp.DestinationPort)
		binary.BigEndian.PutUint16(packet[44:46], datagramLength)
		return packet
	}
	for _, tc := range []struct {
		raw           []byte
		ok, data, new bool
	}{
		{datagram(udp.SourcePort, 1, 9, 17), true, true, false},
		{datagram(udp.SourcePort+1, 1, 9, 17), true, false, true},
		{datagram(udp.SourcePort+1, 0, 8, 17), true, false, false},
		{datagram(udp.SourcePort, 0, 20, 17), false, false, false},
		{datagram(udp.SourcePort, 1, 9, 44), false, false, false},
		{[]byte{0x60}, false, false, false},
	} {
		var o Observation
		if got := o.countPacket(tc.raw, len(tc.raw), udp); got != tc.ok || (o.OriginalPackets > 0) != tc.data ||
			(o.Reconnect != nil) != tc.new {
			t.Fatal("IPv6 UDP 采样身份或数据判定不一致", got, o)
		}
	}
}

func TestGatewayObservationReceiptSeparatesReadbackWindowAndFollowUp(t *testing.T) {
	now := time.Now().UTC()
	flow := testFlow("10.203.35.3", "10.203.36.3", "tcp")
	local := testLocal()
	prior := local.Binding()
	local.ObserveInterface = "test-egress.3"
	if !local.Binding().Observation || prior.Observation || prior.ConfigSHA256 == local.Binding().ConfigSHA256 {
		t.Fatal("增加观察口后没有独立记录配置绑定")
	}
	a := Action{RequestID: "gateway_observed", ConfigSHA256: local.Binding().ConfigSHA256, Flow: flow,
		LeaseUntil: now.Add(12 * time.Second), Observe: true, FollowUp: true}
	verified := now.Add(time.Second)
	observation := Observation{State: FlowPaused, Interface: local.ObserveInterface, StartedAt: verified,
		FinishedAt: verified.Add(ObserveWindow), EgressPackets: 3}
	result := Result{RequestID: a.RequestID, ConfigSHA256: a.ConfigSHA256, Flow: flow, LeaseUntil: a.LeaseUntil, VerifiedAt: verified}
	check := func(o *Observation, valid bool) {
		t.Helper()
		result.Observation = o
		body, _ := json.Marshal(result)
		got, err := ReadResult(body, a, now, now.Add(DispatchWindow), verified.Add(ObserveWindow+time.Second))
		if valid && (err != nil || got.Observation == nil || got.Observation.State != o.State) ||
			!valid && !errors.Is(err, ErrUnknown) {
			t.Fatal("观察回执不符合绑定时窗、方向或证据门槛", got, o, err)
		}
	}
	check(&observation, true)
	check(nil, false)
	for _, invalid := range []func(*Observation){
		func(o *Observation) { o.Interface = "坏路径" },
		func(o *Observation) { o.State = "unrecognized" },
		func(o *Observation) { o.FinishedAt = o.StartedAt },
		func(o *Observation) { o.StartedAt = now },
		func(o *Observation) { o.OriginalPackets = 1 },
		func(o *Observation) { o.Code = "packet_loss" },
		func(o *Observation) { o.EgressPackets = 0 },
		func(o *Observation) { o.State, o.OriginalPackets = FlowContinued, 4 },
		func(o *Observation) { o.State = FlowContinued },
		func(o *Observation) { o.State = FlowContinued; o.Reconnect = &flow },
	} {
		changed := observation
		invalid(&changed)
		check(&changed, false)
	}
	next := flow
	next.SourcePort++
	continued := observation
	continued.State, continued.Reconnect = FlowContinued, &next
	check(&continued, true)
	unknown := observation
	unknown.State, unknown.Code, unknown.FinishedAt = FlowUnknown, "egress_idle", unknown.StartedAt
	check(&unknown, true)
	unknown.Code = "unrecognized"
	check(&unknown, false)

	device := FollowUpDevice{PluginID: "gateway_plugin", Generation: 3, ConnectorID: "connector_local",
		ConfigSHA256: strings.Repeat("c", 64), MaxTTLSeconds: 120}
	follow := FollowUp{PluginID: device.PluginID, Generation: device.Generation, ConnectorID: device.ConnectorID,
		ConfigSHA256: device.ConfigSHA256, TTLSeconds: 30, TargetSide: "source"}
	if !follow.Valid() || !follow.Matches(device) || follow.Target(flow) != flow.SourceIP.String() {
		t.Fatal("来源方向和插件绑定未固定", follow)
	}
	follow.TargetSide, follow.TTLSeconds = "destination", 121
	if !follow.Valid() || follow.Matches(device) || follow.Target(flow) != flow.DestinationIP.String() {
		t.Fatal("设备时长上限或目的方向未生效", follow)
	}
	follow.TargetSide = "any"
	if follow.Valid() {
		t.Fatal("接受未授权方向")
	}
}

func TestGatewayObservationRechecksFirewallAndPreservesReadback(t *testing.T) {
	config := testLocal()
	config.ObserveInterface = "sb-missing1"
	path := filepath.Join(t.TempDir(), "gateway.json")
	write := func() {
		t.Helper()
		raw, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	flow := testFlow("10.203.35.3", "10.203.36.3", "tcp")
	chain, element := chainFixture(flow), elementFixture(flow, "task_gateway", 3)
	s := &Service{path: path, nft: func(_ context.Context, args ...string) ([]byte, error) {
		switch args[3] {
		case "chain":
			return chain, nil
		case "set":
			return element, nil
		default:
			return nil, nil
		}
	}}
	a := Action{RequestID: "gateway_observe", Flow: flow, ConfigSHA256: config.Binding().ConfigSHA256,
		LeaseUntil: time.Now().Add(14 * time.Second), Observe: true}
	got, _, err := s.Apply(t.Context(), "task_gateway", a, time.Now().Add(DispatchWindow))
	if err != nil || got.Observation == nil || got.Observation.Code != "observer_unavailable" || got.VerifiedAt.IsZero() {
		t.Fatal("观察失败丢失独立防火墙回读", got, err)
	}
	if !s.observationBindingCurrent(t.Context(), "task_gateway", a) ||
		s.observationBindingCurrent(t.Context(), "different_owner", a) {
		t.Fatal("观察结束后没有重新核对限时条目归属")
	}
	chain = nil
	if s.observationBindingCurrent(t.Context(), "task_gateway", a) {
		t.Fatal("转发链被移除后仍认可观察")
	}
	config.ObserveInterface = "../eth0"
	write()
	if s.Health(t.Context()) != nil || s.observationBindingCurrent(t.Context(), "task_gateway", a) {
		t.Fatal("变化的观察配置未被收回")
	}
}
