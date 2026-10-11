package replay

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/kkx600/StarBeacon/internal/testpcap"
)

type handshakeFrame struct {
	server            bool
	seq, ack          uint32
	syn, ackFlag, rst bool
	payload           string
	port              uint16
	vlan              uint16
	ipv6              bool
}

func handshakePacket(t testing.TB, frame handshakeFrame) (gopacket.Packet, []byte) {
	t.Helper()
	src, dst := net.ParseIP("192.0.2.10"), net.ParseIP("198.51.100.20")
	srcMAC, dstMAC := net.HardwareAddr{2, 0, 0, 0, 0, 1}, net.HardwareAddr{2, 0, 0, 0, 0, 2}
	if frame.ipv6 {
		src, dst = net.ParseIP("2001:db8::10"), net.ParseIP("2001:db8::20")
	}
	port := frame.port
	if port == 0 {
		port = 40000
	}
	srcPort, dstPort := layers.TCPPort(port), layers.TCPPort(80)
	if frame.server {
		src, dst = dst, src
		srcMAC, dstMAC = dstMAC, srcMAC
		srcPort, dstPort = dstPort, srcPort
	}
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip4 := &layers.IPv4{Version: 4, TTL: 64, SrcIP: src, DstIP: dst, Protocol: layers.IPProtocolTCP}
	ip6 := &layers.IPv6{Version: 6, HopLimit: 64, SrcIP: src, DstIP: dst, NextHeader: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: srcPort, DstPort: dstPort, Seq: frame.seq, Ack: frame.ack, SYN: frame.syn, ACK: frame.ackFlag, RST: frame.rst, Window: 65535}
	var network gopacket.SerializableLayer = ip4
	if frame.ipv6 {
		eth.EthernetType = layers.EthernetTypeIPv6
		network = ip6
		if err := tcp.SetNetworkLayerForChecksum(ip6); err != nil {
			t.Fatal(err)
		}
	} else if err := tcp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatal(err)
	}
	stack := []gopacket.SerializableLayer{eth}
	if frame.vlan != 0 {
		kind := eth.EthernetType
		eth.EthernetType = layers.EthernetTypeDot1Q
		stack = append(stack, &layers.Dot1Q{VLANIdentifier: frame.vlan, Type: kind})
	}
	stack = append(stack, network, tcp, gopacket.Payload([]byte(frame.payload)))
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, stack...); err != nil {
		t.Fatal(err)
	}
	data := append([]byte(nil), buffer.Bytes()...)
	return gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true}), data
}

func observeFrames(t *testing.T, frames []handshakeFrame) HandshakeObservation {
	t.Helper()
	tracker := newHandshakeTracker()
	for _, frame := range frames {
		packet, data := handshakePacket(t, frame)
		tracker.observe(packet, gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data)})
	}
	return tracker.result()
}

func TestHandshakeRequiresBothDirectionsAndMatchingSequence(t *testing.T) {
	syn := handshakeFrame{seq: 1000, syn: true}
	synAck := handshakeFrame{server: true, seq: 5000, ack: 1001, syn: true, ackFlag: true}
	ack := handshakeFrame{seq: 1001, ack: 5001, ackFlag: true}
	for _, tc := range []struct {
		name     string
		frames   []handshakeFrame
		complete int64
	}{
		{"完整握手", []handshakeFrame{syn, synAck, ack}, 1},
		{"SYN 重传只计一次", []handshakeFrame{syn, syn, synAck, synAck, ack, ack}, 1},
		{"未观察到 SYN", []handshakeFrame{synAck, ack}, 0},
		{"缺少第三次握手", []handshakeFrame{syn, synAck}, 0},
		{"ACK 方向错误", []handshakeFrame{syn, synAck, {server: true, seq: 1001, ack: 5001, ackFlag: true}}, 0},
		{"ACK 序号错误", []handshakeFrame{syn, synAck, {seq: 1002, ack: 5001, ackFlag: true}}, 0},
		{"ACK 确认号错误", []handshakeFrame{syn, synAck, {seq: 1001, ack: 6001, ackFlag: true}}, 0},
		{"SYNACK 未确认客户端 SYN", []handshakeFrame{syn, {server: true, seq: 5000, ack: 1000, syn: true, ackFlag: true}, ack}, 0},
		{"RST 后不补推握手", []handshakeFrame{syn, synAck, {server: true, seq: 5001, ack: 1001, ackFlag: true, rst: true}, ack}, 0},
		{"先前未知流的 RST 不阻止新的 SYN", []handshakeFrame{{rst: true}, syn, synAck, ack}, 1},
		{"第三次握手可携带数据", []handshakeFrame{syn, synAck, {seq: 1001, ack: 5001, ackFlag: true, payload: "GET / HTTP/1.1\r\n\r\n"}}, 1},
		{"序号回绕", []handshakeFrame{{seq: ^uint32(0), syn: true}, {server: true, seq: ^uint32(0), ack: 0, syn: true, ackFlag: true}, {seq: 0, ack: 0, ackFlag: true}}, 1},
		{"TCP Fast Open", []handshakeFrame{{seq: 1000, syn: true, payload: "GET"}, {server: true, seq: 5000, ack: 1004, syn: true, ackFlag: true, payload: "OK"}, {seq: 1004, ack: 5003, ackFlag: true}}, 1},
		{"TCP Fast Open 不能接受跨范围确认", []handshakeFrame{{seq: 1000, syn: true, payload: "GET"}, {server: true, seq: 5000, ack: 1005, syn: true, ackFlag: true}, ack}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := observeFrames(t, tc.frames)
			if out.CompleteHandshakes != tc.complete || out.AssessedFlows != 1 || out.ChecksumValidation != "not_checked" {
				t.Fatalf("握手观测=%+v", out)
			}
			if tc.complete == 0 && out.IncompleteFlows != 1 {
				t.Fatal("不完整握手丢失", out)
			}
		})
	}
	for _, frame := range []*handshakeFrame{&syn, &synAck, &ack} {
		frame.ipv6 = true
	}
	if out := observeFrames(t, []handshakeFrame{syn, synAck, ack}); out.CompleteHandshakes != 1 || out.AssessedFlows != 1 {
		t.Fatal("IPv6 握手未保留", out)
	}
}

func TestHandshakeDoesNotJoinVLANInterfaceOrCaptureSection(t *testing.T) {
	frames := []handshakeFrame{{seq: 1000, syn: true}, {server: true, seq: 5000, ack: 1001, syn: true, ackFlag: true}, {seq: 1001, ack: 5001, ackFlag: true}}
	for _, scope := range []string{"vlan", "interface", "section"} {
		t.Run(scope, func(t *testing.T) {
			tracker := newHandshakeTracker()
			for i, frame := range frames {
				ci := gopacket.CaptureInfo{}
				if scope == "vlan" {
					frame.vlan = 10
					if i == 1 {
						frame.vlan = 20
					}
				}
				if scope == "interface" && i == 1 {
					ci.InterfaceIndex = 1
				}
				if scope == "section" && i == 1 {
					tracker.section++
				}
				packet, data := handshakePacket(t, frame)
				ci.CaptureLength, ci.Length = len(data), len(data)
				tracker.observe(packet, ci)
			}
			out := tracker.result()
			if out.CompleteHandshakes != 0 || out.AssessedFlows != 2 || out.IncompleteFlows != 2 {
				t.Fatal("跨观测域拼接了握手", out)
			}
		})
	}
}

func TestHandshakeTruncationReuseAndBoundedState(t *testing.T) {
	tracker := newHandshakeTracker()
	packet, data := handshakePacket(t, handshakeFrame{seq: 1000, syn: true})
	tracker.observe(packet, gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data) + 10})
	if out := tracker.result(); !out.Limited || out.SkippedPackets != 1 || out.AssessedFlows != 0 {
		t.Fatal("截断帧被用来确认握手", out)
	}
	for _, frame := range []handshakeFrame{{seq: 1000, syn: true}, {server: true, seq: 5000, ack: 1001, syn: true, ackFlag: true}, {seq: 1001, ack: 5001, ackFlag: true}, {seq: 9000, syn: true}, {server: true, seq: 15000, ack: 9001, syn: true, ackFlag: true}, {seq: 9001, ack: 15001, ackFlag: true}} {
		packet, data := handshakePacket(t, frame)
		tracker.observe(packet, gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data)})
	}
	if out := tracker.result(); out.CompleteHandshakes != 2 || out.ReusedTuples != 1 || out.IncompleteFlows != 0 {
		t.Fatal("五元组复用未分开记录握手", out)
	}
	tracker = newHandshakeTracker()
	for i := 1; i <= maxHandshakeFlows+1; i++ {
		packet, data := handshakePacket(t, handshakeFrame{seq: 1000, syn: true, port: uint16(i)})
		tracker.observe(packet, gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data)})
	}
	out := tracker.result()
	again := tracker.result()
	if !out.Limited || out.AssessedFlows != maxHandshakeFlows || out.SkippedPackets != 1 || out.IncompleteFlows != again.IncompleteFlows {
		t.Fatal("流状态超出资源边界或结果重复计数", out, again)
	}
}

func TestInspectHandshakePCAPNGSectionsRemainIndependent(t *testing.T) {
	var output bytes.Buffer
	for section, frames := range [][]handshakeFrame{{{seq: 1000, syn: true}}, {{server: true, seq: 5000, ack: 1001, syn: true, ackFlag: true}, {seq: 1001, ack: 5001, ackFlag: true}}} {
		writer, err := pcapgo.NewNgWriter(&output, layers.LinkTypeEthernet)
		if err != nil {
			t.Fatal(err)
		}
		for i, frame := range frames {
			_, data := handshakePacket(t, frame)
			if err = writer.WritePacket(gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data), Timestamp: time.Date(2026, 10, 3, 0, section, i, 0, time.UTC)}, data); err != nil {
				t.Fatal(err)
			}
		}
		if err = writer.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "sections.pcapng")
	if err := os.WriteFile(path, output.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	meta, err := Inspect(context.Background(), path)
	if err != nil || meta.TCPHandshake.CompleteHandshakes != 0 || meta.TCPHandshake.AssessedFlows != 2 {
		t.Fatal("跨 PCAPNG 节形成错误握手", meta, err)
	}
	for _, ng := range []bool{false, true} {
		data, err := testpcap.HTTP(ng)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		meta, err = Inspect(context.Background(), path)
		if err != nil || meta.TCPHandshake.CompleteHandshakes != 1 || meta.TCPHandshake.IncompleteFlows != 0 {
			t.Fatal("完整 PCAP/PCAPNG HTTP 样本未识别握手", meta, err)
		}
	}
}

// 基准只测离线容器读取与元数据检查，不作为网卡捕获、检测或上报吞吐。
func BenchmarkInspectHTTP100K(b *testing.B) {
	fixture, err := testpcap.HTTP(false)
	if err != nil {
		b.Fatal(err)
	}
	reader, err := pcapgo.NewReader(bytes.NewReader(fixture))
	if err != nil {
		b.Fatal(err)
	}
	type frame struct {
		data []byte
		info gopacket.CaptureInfo
	}
	frames := []frame{}
	for {
		data, info, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			b.Fatal(err)
		}
		frames = append(frames, frame{data, info})
	}
	path := filepath.Join(b.TempDir(), "inspection-100k.pcap")
	file, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	writer := pcapgo.NewWriterNanos(file)
	if err = writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		b.Fatal(err)
	}
	const packets = 100008
	for i := 0; i < packets; i++ {
		f := frames[i%len(frames)]
		f.info.Timestamp = time.Date(2026, 10, 3, 0, 0, 0, i*1000, time.UTC)
		if err = writer.WritePacket(f.info, f.data); err != nil {
			b.Fatal(err)
		}
	}
	if err = file.Close(); err != nil {
		b.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(info.Size())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		meta, err := Inspect(context.Background(), path)
		if err != nil || meta.Packets != packets || meta.TCPHandshake.CompleteHandshakes != 1 {
			b.Fatal(meta, err)
		}
	}
}
