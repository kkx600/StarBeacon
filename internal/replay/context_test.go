package replay

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func contextPacket(t *testing.T, kind string, payload []byte) []byte {
	t.Helper()
	ether := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ipv4 := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.ParseIP("192.0.2.10").To4(), DstIP: net.ParseIP("198.51.100.20").To4(), Protocol: layers.IPProtocolTCP}
	ipv6 := &layers.IPv6{Version: 6, HopLimit: 64, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"), NextHeader: layers.IPProtocolUDP}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: 80, Seq: 1001, Ack: 5001, ACK: true, DataOffset: 5, Window: 65535}
	udp := &layers.UDP{SrcPort: 53000, DstPort: 53}
	parts := []gopacket.SerializableLayer{ether, ipv4, tcp, gopacket.Payload(payload)}
	requireChecksum := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	requireChecksum(tcp.SetNetworkLayerForChecksum(ipv4))
	switch kind {
	case "udp":
		ipv4.Protocol = layers.IPProtocolUDP
		requireChecksum(udp.SetNetworkLayerForChecksum(ipv4))
		parts = []gopacket.SerializableLayer{ether, ipv4, udp, gopacket.Payload(payload)}
	case "ipv6":
		ether.EthernetType = layers.EthernetTypeIPv6
		requireChecksum(udp.SetNetworkLayerForChecksum(ipv6))
		parts = []gopacket.SerializableLayer{ether, ipv6, udp, gopacket.Payload(payload)}
	case "fragment4":
		ipv4.Flags = layers.IPv4MoreFragments
	case "fragment6":
		ether.EthernetType = layers.EthernetTypeIPv6
		ipv6.NextHeader = layers.IPProtocolIPv6Fragment
		parts = []gopacket.SerializableLayer{ether, ipv6, gopacket.Payload(append([]byte{6, 0, 0, 1, 0, 0, 0, 1}, bytes.Repeat([]byte{1}, 20)...))}
	case "ethernet":
		ether.EthernetType = 0x88b5
		parts = []gopacket.SerializableLayer{ether, gopacket.Payload(payload)}
	case "invalid":
		return []byte{1, 2, 3}
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, parts...); err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(buffer.Bytes())
}

func contextPCAP(t *testing.T, packets [][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "context.pcap")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriter(file)
	if err = writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for i, p := range packets {
		if err = writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, int64(i)), CaptureLength: len(p), Length: len(p)}, p); err != nil {
			t.Fatal(err)
		}
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestContextPreservesTCPUDPAndIPv6PayloadBytes(t *testing.T) {
	data := []byte{0, 255, '\r', '\n'}
	path := contextPCAP(t, [][]byte{contextPacket(t, "tcp", nil), contextPacket(t, "tcp", data), contextPacket(t, "udp", data), contextPacket(t, "ipv6", data)})
	metadata, snippets, limited, err := InspectContext(context.Background(), path)
	if err != nil || metadata.Packets != 4 || limited || len(snippets) != 3 {
		t.Fatal("正常有界载荷不完整", metadata.Packets, len(snippets), limited, err)
	}
	for i, row := range snippets {
		if row.Packet != int64(i+2) || row.PayloadHex != hex.EncodeToString(data) || row.PayloadLimited {
			t.Fatal("原始帧编号或字节发生变化", row)
		}
	}
	if snippets[0].Protocol != "tcp" || snippets[0].SourcePort != 40000 || snippets[0].DestinationPort != 80 || snippets[1].Protocol != "udp" || snippets[2].SourceIP != "2001:db8::1" || snippets[2].DestinationIP != "2001:db8::2" {
		t.Fatal("实际网络方向或协议不准确")
	}
}

func TestContextReportsFragmentAndUndecodableMaterial(t *testing.T) {
	for _, kind := range []string{"fragment4", "fragment6", "ethernet", "invalid"} {
		t.Run(kind, func(t *testing.T) {
			path := contextPCAP(t, [][]byte{contextPacket(t, kind, []byte("material"))})
			metadata, snippets, limited, err := InspectContext(context.Background(), path)
			if err != nil || metadata.Packets != 1 || len(snippets) != 0 || !limited {
				t.Fatal("不完整材料被当作可用明文载荷", len(snippets), limited, err)
			}
		})
	}
}

func TestContextBoundsFramesSnippetsAndBytesWithoutChangingFile(t *testing.T) {
	payload := bytes.Repeat([]byte{255}, 257)
	packets := [][]byte{}
	for i := 0; i < 10; i++ {
		packets = append(packets, contextPacket(t, "udp", payload))
	}
	path := contextPCAP(t, packets)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	metadata, snippets, limited, err := InspectContext(context.Background(), path)
	if err != nil || metadata.Packets != 10 || !limited || len(snippets) != 8 {
		t.Fatal("载荷数量限制未生效", len(snippets), limited, err)
	}
	for i, row := range snippets {
		if row.Packet != int64(i+1) || !row.PayloadLimited || row.PayloadHex != hex.EncodeToString(payload[:256]) {
			t.Fatal("载荷字节限制或原始序号不准确")
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("模型材料提取改写原文件")
	}
	packets = nil
	for i := 0; i < 127; i++ {
		packets = append(packets, contextPacket(t, "tcp", nil))
	}
	packets = append(packets, contextPacket(t, "tcp", []byte("frame128")), contextPacket(t, "tcp", []byte("frame129")))
	metadata, snippets, limited, err = InspectContext(context.Background(), contextPCAP(t, packets))
	if err != nil || metadata.Packets != 129 || len(snippets) != 1 || snippets[0].Packet != 128 || !limited {
		t.Fatal("帧扫描限制未生效", len(snippets), limited, err)
	}
}

func TestContextUnavailableAndCancelledFile(t *testing.T) {
	if _, _, _, err := InspectContext(context.Background(), filepath.Join(t.TempDir(), "missing.pcap")); err == nil {
		t.Fatal("不存在的原始对象仍通过")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := InspectContext(ctx, contextPCAP(t, [][]byte{contextPacket(t, "tcp", []byte("raw"))})); err == nil {
		t.Fatal("取消后仍提取模型材料")
	}
}

func TestSameOriginDoesNotInventProvenance(t *testing.T) {
	origin := Origin{Kind: "http_raw", Synthetic: true, RawBytes: 1, RawSHA256: string(bytes.Repeat([]byte{'a'}, 64)), Encoder: HTTPEncoder, SegmentBytes: 1460}
	if !SameOrigin(nil, nil) || SameOrigin(nil, &origin) || SameOrigin(&origin, nil) || !SameOrigin(&origin, &origin) {
		t.Fatal("缺失来源与合成来源混淆")
	}
	other := origin
	other.RawBytes++
	if SameOrigin(&origin, &other) {
		t.Fatal("不同原始字节来源被当作相同")
	}
}
