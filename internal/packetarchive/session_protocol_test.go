package packetarchive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func sessionNetworkFrame(t *testing.T, frame sessionFrame, ipv6 bool, vlans []uint16, change func(*layers.Ethernet, *layers.IPv4)) sessionFrame {
	t.Helper()
	packet := gopacket.NewPacket(frame.raw, layers.LayerTypeEthernet, gopacket.Default)
	ethernet := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if change != nil {
		change(ethernet, ip)
	}
	typeCode := layers.EthernetTypeIPv4
	var network gopacket.SerializableLayer = ip
	if ipv6 {
		typeCode = layers.EthernetTypeIPv6
		source, destination := net.ParseIP("2001:db8::10"), net.ParseIP("2001:db8::20")
		if tcp.SrcPort == 80 {
			source, destination = destination, source
		}
		value := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP, SrcIP: source, DstIP: destination}
		network = value
		if e := tcp.SetNetworkLayerForChecksum(value); e != nil {
			t.Fatal(e)
		}
	} else if e := tcp.SetNetworkLayerForChecksum(ip); e != nil {
		t.Fatal(e)
	}
	ethernet.EthernetType = typeCode
	serial := []gopacket.SerializableLayer{ethernet}
	if len(vlans) > 0 {
		ethernet.EthernetType = layers.EthernetTypeDot1Q
		for i, vlan := range vlans {
			next := typeCode
			if i+1 < len(vlans) {
				next = layers.EthernetTypeDot1Q
			}
			serial = append(serial, &layers.Dot1Q{VLANIdentifier: vlan, Type: next})
		}
	}
	serial = append(serial, network, tcp, gopacket.Payload(tcp.Payload))
	buffer := gopacket.NewSerializeBuffer()
	if e := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, serial...); e != nil {
		t.Fatal(e)
	}
	frame.raw = bytes.Clone(buffer.Bytes())
	frame.info.CaptureLength, frame.info.Length = len(frame.raw), len(frame.raw)
	return frame
}

func TestSessionIPv6AndVLANRequireExactNetworkAndLinkIdentity(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, vlans := range [][]uint16{{}, {101}, {101, 102}} {
			t.Run(fmt.Sprintf("IPv6=%t/VLANs=%d", ipv6, len(vlans)), func(t *testing.T) {
				frames := sessionFrames(t)
				for i := range frames {
					frames[i] = sessionNetworkFrame(t, frames[i], ipv6, vlans, nil)
				}
				input := sessionArchive(t, "packet_network", frames, nil)
				request := sessionRequest("packet_network")
				request.VLANs = slices.Clone(vlans)
				if ipv6 {
					request.ClientIP, request.ServerIP = "2001:db8::10", "2001:db8::20"
				}
				var out bytes.Buffer
				report, e := ExportSession(context.Background(), &out, request, []SessionInput{input})
				if e != nil || report.Completeness != "full_session" || report.Packets != 9 {
					t.Fatalf("链路身份匹配失败：%+v %v", report, e)
				}
				request.VLANs = append(request.VLANs, 333)
				out.Reset()
				report, e = ExportSession(context.Background(), &out, request, []SessionInput{input})
				if !errors.Is(e, ErrSessionIncomplete) || report.Packets != 0 || out.Len() != 0 {
					t.Fatal("合并了不同 VLAN 的原件", e)
				}
				request.VLANs = slices.Clone(vlans)
				request.ClientMAC = "02:00:00:00:00:03"
				if report, e = ExportSession(context.Background(), &out, request, []SessionInput{input}); !errors.Is(e, ErrSessionIncomplete) || report.Packets != 0 {
					t.Fatal("合并了不同链路端点", e)
				}
			})
		}
	}
}

func TestSessionFragmentCannotQualifyAsCompleteConnection(t *testing.T) {
	frames := sessionFrames(t)
	fragment := sessionNetworkFrame(t, frames[0], false, nil, func(_ *layers.Ethernet, ip *layers.IPv4) { ip.Flags |= layers.IPv4MoreFragments })
	frames = append(append([]sessionFrame{fragment}, frames...), sessionNetworkFrame(t, frames[0], false, nil, func(e *layers.Ethernet, _ *layers.IPv4) { e.SrcMAC = net.HardwareAddr{2, 0, 0, 0, 0, 8} }))
	input := sessionArchive(t, "packet_fragment", frames, nil)
	request := sessionRequest("packet_fragment")
	var out bytes.Buffer
	report, e := ExportSession(context.Background(), &out, request, []SessionInput{input})
	if !errors.Is(e, ErrSessionIncomplete) || !slices.Contains(report.Reasons, "fragment_or_tunnel_scope_unsupported") || out.Len() != 0 {
		t.Fatal("分片未核实却声明完整", e)
	}
	request.Mode = "snapshot"
	report, e = ExportSession(context.Background(), &out, request, []SessionInput{input})
	if e != nil || report.Packets != 9 || report.Completeness != "snapshot" {
		t.Fatal("快照混入无法匹配的分片或其他链路", e)
	}
}

type failedSessionDestination struct {
	err        error
	short      bool
	panicValue bool
}

func (w failedSessionDestination) Write(p []byte) (int, error) {
	if w.panicValue {
		panic("受控制品写入失败")
	}
	if w.short {
		return len(p) - 1, nil
	}
	return 0, w.err
}

func TestSessionSourceAndDestinationFailuresDoNotConfirmExport(t *testing.T) {
	input := sessionArchive(t, "packet_failure", sessionFrames(t), nil)
	request := sessionRequest("packet_failure")
	for _, value := range []failedSessionDestination{{err: io.ErrClosedPipe}, {short: true}, {panicValue: true}} {
		_, e := ExportSession(context.Background(), value, request, []SessionInput{input})
		want := io.ErrClosedPipe
		if value.short {
			want = io.ErrShortWrite
		}
		if value.panicValue {
			want = ErrIntegrity
		}
		if !errors.Is(e, want) {
			t.Fatal("失败制品写入被报告为成功", e)
		}
	}
	limited := &boundedSessionWriter{target: io.Discard, size: MaxSegmentBytes - 1}
	if n, e := limited.Write([]byte{1, 2}); n != 0 || !errors.Is(e, ErrLimit) {
		t.Fatal("制品超过输出预算仍写入", n, e)
	}
	wrong := input
	wrong.Manifest.Capture.SensorID = "sensor_foreign"
	first := sessionArchive(t, "packet_first_scope", sessionFrames(t), nil)
	if _, e := ExportSession(context.Background(), io.Discard, sessionRequest(first.Manifest.Capture.ID, input.Manifest.Capture.ID), []SessionInput{first, wrong}); !errors.Is(e, ErrIntegrity) {
		t.Fatal("跨探针原件被合并", e)
	}
	wrong = input
	wrong.File = nil
	if _, e := ExportSession(context.Background(), io.Discard, request, []SessionInput{wrong}); !errors.Is(e, ErrIntegrity) {
		t.Fatal("缺失原件被接受", e)
	}
	if e := input.File.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := ExportSession(context.Background(), io.Discard, request, []SessionInput{input}); !errors.Is(e, os.ErrClosed) {
		t.Fatal("关闭的原件仍能导出", e)
	}
}

func TestSessionJSONRejectsAmbiguousRequests(t *testing.T) {
	for _, raw := range []string{`{}`, `null`, `{"mode":"snapshot","mode":"full_session"}`, `{"mode":"snapshot","unknown":1}`, `{} {}`, `{"client_port":65536}`} {
		var request SessionRequest
		if e := request.UnmarshalJSON([]byte(raw)); e == nil {
			t.Fatal("歧义请求被接受", raw)
		}
	}
}
