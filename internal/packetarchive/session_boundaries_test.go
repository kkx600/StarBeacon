package packetarchive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// 对实际序列化报文逐项改变协议条件，核对严格导出不会把缺测或异常连接标为完整。
func TestSessionTCPQualificationBoundariesRequireExplicitSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		change       func([]sessionFrame) []sessionFrame
	}{
		{"反向 SYN 未携带 ACK", "syn_ack_unconfirmed", func(v []sessionFrame) []sessionFrame {
			v[1] = mutateSessionTCP(t, v[1], func(tcp *layers.TCP) { tcp.ACK = false })
			return v
		}},
		{"客户端同时打开", "tuple_reuse_or_simultaneous_open", func(v []sessionFrame) []sessionFrame {
			v[0] = mutateSessionTCP(t, v[0], func(tcp *layers.TCP) { tcp.ACK = true })
			return v
		}},
		{"重置后仍出现载荷", "payload_after_reset", func(v []sessionFrame) []sessionFrame {
			v[2] = mutateSessionTCP(t, v[2], func(tcp *layers.TCP) { tcp.RST = true })
			return v
		}},
		{"对端确认超出序号预算", "acknowledgement_space_unqualified", func(v []sessionFrame) []sessionFrame {
			v[4] = mutateSessionTCP(t, v[4], func(tcp *layers.TCP) { tcp.Ack += maxDirectionBytes + 2 })
			return v
		}},
		{"请求载荷存在序号缺口", "payload_sequence_gap", func(v []sessionFrame) []sessionFrame {
			v[3] = mutateSessionTCP(t, v[3], func(tcp *layers.TCP) { tcp.Seq++ })
			return v
		}},
		{"原包长度超过捕获长度", "selected_packet_truncated", func(v []sessionFrame) []sessionFrame {
			v[3].info.Length += 8
			return v
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frames := tc.change(sessionFrames(t))
			input := sessionArchive(t, "packet_boundary", frames, nil)
			request := sessionRequest(input.Manifest.Capture.ID)
			var output bytes.Buffer
			report, err := ExportSession(context.Background(), &output, request, []SessionInput{input})
			if !errors.Is(err, ErrSessionIncomplete) || output.Len() != 0 || !slices.Contains(report.Reasons, tc.reason) {
				t.Fatal("异常连接被当作完整原件或缺失原因", report, err)
			}
			request.Mode = "snapshot"
			report, err = ExportSession(context.Background(), &output, request, []SessionInput{input})
			if err != nil || report.Completeness != "snapshot" || report.Packets != uint64(len(frames)) || !slices.Contains(report.Reasons, tc.reason) {
				t.Fatal("显式快照改写了观察到的协议限制", report, err)
			}
		})
	}
}

func TestSessionSelectionDoesNotMixOtherNetworkProtocolsOrAddresses(t *testing.T) {
	frames := sessionFrames(t)
	otherIP := sessionNetworkFrame(t, frames[3], false, nil, func(_ *layers.Ethernet, ip *layers.IPv4) {
		ip.SrcIP = net.ParseIP("192.0.2.99").To4()
	})
	packet := gopacket.NewPacket(frames[3].raw, layers.LayerTypeEthernet, gopacket.Default)
	ethernet := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	ip.Protocol = layers.IPProtocolUDP
	udp := &layers.UDP{SrcPort: 40000, DstPort: 80}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, udp, gopacket.Payload("其他协议的原始通信")); err != nil {
		t.Fatal(err)
	}
	otherUDP := frames[3]
	otherUDP.raw = bytes.Clone(buf.Bytes())
	otherUDP.info.Length, otherUDP.info.CaptureLength = len(otherUDP.raw), len(otherUDP.raw)
	invalid := frames[3]
	invalid.raw = []byte{1, 2, 3}
	invalid.info.Length, invalid.info.CaptureLength = 3, 3
	frames = append(append(frames[:4:4], otherIP, otherUDP, invalid), frames[4:]...)
	input := sessionArchive(t, "packet_other_networks", frames, nil)
	var output bytes.Buffer
	report, err := ExportSession(context.Background(), &output, sessionRequest(input.Manifest.Capture.ID), []SessionInput{input})
	if err != nil || report.Completeness != "full_session" || report.Packets != 9 || len(report.Reasons) != 0 {
		t.Fatal("其他地址或非 TCP 报文混入指定会话", report, err)
	}
}

type cancellingSessionDestination struct {
	cancel context.CancelFunc
	output bytes.Buffer
}

func (w *cancellingSessionDestination) Write(raw []byte) (int, error) {
	w.cancel()
	return w.output.Write(raw)
}

func TestSessionExportCancellationDuringOutputDoesNotConfirmSuccess(t *testing.T) {
	frames := sessionFrames(t)
	repeated := slices.Clone(frames[:4])
	for range 80 {
		repeated = append(repeated, frames[3])
	}
	repeated = append(repeated, frames[4:]...)
	input := sessionArchive(t, "packet_cancel_output", repeated, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target := &cancellingSessionDestination{cancel: cancel}
	_, err := ExportSession(ctx, target, sessionRequest(input.Manifest.Capture.ID), []SessionInput{input})
	if !errors.Is(err, context.Canceled) || target.output.Len() == 0 {
		t.Fatal("输出阶段取消仍确认完整导出", err)
	}
	if _, err := input.File.Seek(0, io.SeekStart); err != nil {
		t.Fatal("取消后原件句柄不可读", err)
	}
}
