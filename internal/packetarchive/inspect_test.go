package packetarchive

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func inspectedField(v PacketInspection, key string) string {
	for _, layer := range v.Layers {
		for _, field := range layer.Fields {
			if field.Name == key {
				return field.Value
			}
		}
	}
	return ""
}

func inspectionSource(t *testing.T) (Manifest, []byte, []sessionFrame) {
	t.Helper()
	frames := sessionFrames(t)
	input := sessionArchive(t, "packet_inspect", frames, nil)
	raw, err := os.ReadFile(input.File.Name())
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	index, err := EncodeFrames(context.Background(), &encoded, bytes.NewReader(raw), "zstd", DefaultFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	input.Manifest.Encoding = index
	return input.Manifest, encoded.Bytes(), frames
}

func TestPacketInspectionPreservesActualFramesAndRejectsCorruptArchive(t *testing.T) {
	m, stored, frames := inspectionSource(t)
	dir := t.TempDir()
	for i, frame := range frames {
		v, err := InspectPacket(context.Background(), byteRanges(stored), m, dir, i+1)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(v.Packet)
		_, digest, _ := m.JSON()
		if err != nil || !bytes.Equal(raw, frame.raw) || v.PacketSHA256 != Digest(frame.raw) || v.ManifestSHA256 != digest || v.RawSHA256 != m.Encoding.RawSHA256 || v.Number != i+1 || v.Total != 9 || !v.CapturedAt.Equal(frame.info.Timestamp) || v.CapturedLength != len(frame.raw) || v.OriginalLength != frame.info.Length || v.Interface != "eth0" || v.Truncated || v.VLANOffload || v.DecodeStatus != "parsed" || v.ChecksumValidation != "not_checked" || v.PayloadVisibility != "not_decoded" {
			t.Fatalf("原字节与回执被改写：%+v %v", v, err)
		}
		if inspectedField(v, "eth.src") == "" || inspectedField(v, "eth.dst") == "" || inspectedField(v, "ip.src") == "" || inspectedField(v, "tcp.seq") == "" {
			t.Fatal("实际 L2/L3/L4 字段缺失")
		}
		for _, layer := range v.Layers {
			if layer.Offset == nil || *layer.Offset+layer.Length > len(raw) {
				t.Fatal("顺序协议层没有实际字节映射")
			}
		}
	}
	var vlanRaw, vlanStored bytes.Buffer
	header := m.Capture
	header.Packets, header.PacketBytes, header.TruncatedPackets, header.VLANOffloadPackets = 0, 0, 0, 0
	header.FirstPacketAt, header.LastPacketAt = nil, nil
	recorder, err := NewRecorder(&vlanRaw, header, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	vlanID := uint16(120)
	for _, frame := range frames {
		if err = recorder.Write(frame.info, frame.raw, &vlanID); err != nil {
			t.Fatal(err)
		}
	}
	drops := uint64(0)
	vlanCapture, err := recorder.Seal(m.Capture.EndedAt, "rotation", &drops)
	if err != nil {
		t.Fatal(err)
	}
	vlanIndex, err := EncodeFrames(context.Background(), &vlanStored, bytes.NewReader(vlanRaw.Bytes()), "zstd", DefaultFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	vlanView, err := InspectPacket(context.Background(), byteRanges(vlanStored.Bytes()), Manifest{Capture: vlanCapture, Encoding: vlanIndex}, dir, 1)
	if err != nil || !vlanView.VLANOffload || vlanView.PacketSHA256 != Digest(frames[0].raw) || inspectedField(vlanView, "vlan.id") != "" {
		t.Fatal("VLAN 卸载元数据改变了原字节或被作为捕获字段", vlanView, err)
	}
	corrupt := bytes.Clone(stored)
	corrupt[len(corrupt)/2] ^= 1
	if _, err := InspectPacket(context.Background(), byteRanges(corrupt), m, dir, 1); err == nil {
		t.Fatal("损坏的归档仍返回一个貌似正确的包")
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatal("核对暂存未回收", files, err)
	}
}

func TestPacketInspectionBoundariesCancellationAndUnavailableStaging(t *testing.T) {
	m, stored, _ := inspectionSource(t)
	for _, raw := range []string{"", "0", "-1", "+1", "01", "1.0", "1048577", "999999999999999999999"} {
		if _, err := InspectionNumber(raw, url.Values{}); !errors.Is(err, ErrPacketNumber) {
			t.Fatal("非规范包序号被接受", raw)
		}
	}
	if n, err := InspectionNumber("1048576", nil); err != nil || n != 1048576 {
		t.Fatal(n, err)
	}
	if _, err := InspectionNumber("1", url.Values{"unknown": {"1"}}); err == nil {
		t.Fatal("未知筛选参数被接受")
	}
	for _, number := range []int{0, -1, 1048577, 10} {
		if _, err := InspectPacket(context.Background(), byteRanges(stored), m, t.TempDir(), number); err == nil {
			t.Fatal("无效或不存在的序号仍读取原包")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := InspectPacket(ctx, byteRanges(stored), m, t.TempDir(), 1); !errors.Is(err, context.Canceled) {
		t.Fatal("取消后继续读取原包", err)
	}
	for _, test := range []struct {
		source   RangeSource
		manifest Manifest
		dir      string
	}{{nil, m, t.TempDir()}, {byteRanges(stored), Manifest{}, t.TempDir()}, {byteRanges(stored), m, ""}, {byteRanges(stored), m, t.TempDir() + "/absent"}, {func(context.Context, int64, int64) (io.ReadCloser, error) { return nil, io.ErrClosedPipe }, m, t.TempDir()}} {
		if _, err := InspectPacket(context.Background(), test.source, test.manifest, test.dir, 1); err == nil {
			t.Fatal("不可用来源或暂存仍返回原包")
		}
	}
}

func TestPacketInspectionProtocolFieldsTruncationAndDecodeBudget(t *testing.T) {
	ethernet := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ipv4 := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP("192.0.2.10"), DstIP: net.ParseIP("198.51.100.20"), Protocol: layers.IPProtocolUDP}
	ipv6 := &layers.IPv6{Version: 6, HopLimit: 63, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"), NextHeader: layers.IPProtocolUDP, FlowLabel: 17}
	udp := &layers.UDP{SrcPort: 40001, DstPort: 9000}
	serialize := func(items ...gopacket.SerializableLayer) []byte {
		t.Helper()
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, items...); err != nil {
			t.Fatal(err)
		}
		return bytes.Clone(buf.Bytes())
	}
	udp4 := serialize(ethernet, ipv4, udp, gopacket.Payload("raw"))
	eth6 := *ethernet
	eth6.EthernetType = layers.EthernetTypeIPv6
	udp6 := serialize(&eth6, ipv6, udp, gopacket.Payload("raw"))
	ethVLAN := *ethernet
	ethVLAN.EthernetType = layers.EthernetTypeDot1Q
	vlan := serialize(&ethVLAN, &layers.Dot1Q{VLANIdentifier: 120, Priority: 3, DropEligible: true, Type: layers.EthernetTypeIPv4}, ipv4, udp, gopacket.Payload("raw"))
	ethARP := *ethernet
	ethARP.EthernetType = layers.EthernetTypeARP
	arp := serialize(&ethARP, &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: 1, SourceHwAddress: ethernet.SrcMAC, DstHwAddress: ethernet.DstMAC, SourceProtAddress: []byte{192, 0, 2, 10}, DstProtAddress: []byte{198, 51, 100, 20}})
	icmpIP := *ipv4
	icmpIP.Protocol = layers.IPProtocolICMPv4
	icmp := serialize(ethernet, &icmpIP, &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0), Id: 17, Seq: 2})
	icmp6IP := *ipv6
	icmp6IP.NextHeader = layers.IPProtocolICMPv6
	icmp6 := serialize(&eth6, &icmp6IP, &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(128, 0)}, gopacket.Payload([]byte{0, 17, 0, 2}))
	fragmentIP := *ipv6
	fragmentIP.NextHeader = layers.IPProtocolIPv6Fragment
	fragment := serialize(&eth6, &fragmentIP, gopacket.Payload([]byte{17, 0, 0, 9, 0, 0, 0, 23, 1, 2, 3, 4}))
	stamp := time.Date(2026, 10, 9, 0, 0, 0, 123456789, time.UTC)
	for _, test := range []struct {
		raw          []byte
		field, value string
	}{{udp4, "udp.dstport", "9000"}, {udp6, "ipv6.src", "2001:db8::1"}, {vlan, "vlan.id", "120"}, {arp, "arp.src.proto_ipv4", "192.0.2.10"}, {icmp, "icmp.type", "8"}, {icmp6, "icmpv6.type", "128"}, {fragment, "ipv6.frag.id", "23"}, {fragment, "ipv6.frag.offset", "1"}, {fragment, "ipv6.frag.more", "true"}} {
		v := inspectFrame(test.raw, gopacket.CaptureInfo{Timestamp: stamp, CaptureLength: len(test.raw), Length: len(test.raw)})
		if inspectedField(v, test.field) != test.value || v.DecodeStatus != "parsed" || !v.CapturedAt.Equal(stamp) {
			t.Fatalf("协议字段未按实际字节解析：%s %+v", test.field, v)
		}
	}
	truncated := inspectFrame(udp4[:17], gopacket.CaptureInfo{Timestamp: stamp, CaptureLength: 17, Length: len(udp4)})
	if !truncated.Truncated || truncated.DecodeStatus != "partial" || truncated.CapturedLength != 17 || inspectedField(truncated, "ip.src") != "" {
		t.Fatal("截断包补造了网络字段", truncated)
	}
	var chain []gopacket.SerializableLayer
	chain = append(chain, ethernet)
	for range 18 {
		inner := *ipv4
		inner.Protocol = layers.IPProtocolIPv4
		chain = append(chain, &inner)
	}
	chain = append(chain, gopacket.Payload([]byte{0}))
	nested := serialize(chain...)
	v := inspectFrame(nested, gopacket.CaptureInfo{Timestamp: stamp, CaptureLength: len(nested), Length: len(nested)})
	if v.DecodeStatus != "limited" || len(v.Layers) > 16 {
		t.Fatal("层级预算未限制递归解析", v.DecodeStatus, len(v.Layers))
	}
	boundedBuilder{}.DumpPacketData()
}
