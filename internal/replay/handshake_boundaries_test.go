package replay

import (
	"encoding/binary"
	"slices"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// 握手观测不进行 IP 重组；片段、隧道和无法解码的帧必须保留质量限制。
func TestHandshakeFragmentTunnelAndVLANDepthRemainUnassessed(t *testing.T) {
	_, ipv4 := handshakePacket(t, handshakeFrame{seq: 100, syn: true})
	_, ipv6 := handshakePacket(t, handshakeFrame{seq: 100, syn: true, ipv6: true})
	fragment4 := append([]byte(nil), ipv4...)
	binary.BigEndian.PutUint16(fragment4[20:22], 0x2000)
	fragment6 := append(append(append([]byte(nil), ipv6[:54]...), 6, 0, 0, 1, 0, 0, 0, 1), ipv6[54:]...)
	fragment6[20] = 44
	binary.BigEndian.PutUint16(fragment6[18:20], uint16(len(fragment6)-54))
	tunnel := append(append(append([]byte(nil), ipv4[:34]...), ipv4[14:34]...), ipv4[34:]...)
	tunnel[23] = 4
	binary.BigEndian.PutUint16(tunnel[16:18], uint16(len(tunnel)-14))
	vlan := append([]byte(nil), ipv4[:12]...)
	vlan = append(vlan, 0x81, 0x00)
	for i := 0; i < 9; i++ {
		next := uint16(0x8100)
		if i == 8 {
			next = 0x0800
		}
		vlan = binary.BigEndian.AppendUint16(vlan, uint16(i+1))
		vlan = binary.BigEndian.AppendUint16(vlan, next)
	}
	vlan = append(vlan, ipv4[14:]...)
	for _, tc := range []struct {
		name, reason string
		data         []byte
	}{
		{"IPv4 片段", "ip_fragmentation", fragment4},
		{"IPv6 片段", "ip_fragmentation", fragment6},
		{"嵌套 IP 隧道", "unsupported_network_layer", tunnel},
		{"VLAN 深度超限", "vlan_depth", vlan},
		{"帧头损坏", "decode_error", ipv4[:9]},
		{"TCP 帧截断", "truncated_or_invalid_packet", ipv4[:45]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tracker := newHandshakeTracker()
			for i := 0; i < 2; i++ {
				packet := gopacket.NewPacket(tc.data, layers.LinkTypeEthernet, gopacket.Default)
				tracker.observe(packet, gopacket.CaptureInfo{CaptureLength: len(tc.data), Length: len(tc.data)})
			}
			out := tracker.result()
			if !out.Limited || out.SkippedPackets != 2 || out.AssessedFlows != 0 || out.CompleteHandshakes != 0 || len(out.LimitReasons) != 1 || !slices.Contains(out.LimitReasons, tc.reason) {
				t.Fatalf("不支持的帧形成了握手结论或重复限制：%+v", out)
			}
		})
	}
}
