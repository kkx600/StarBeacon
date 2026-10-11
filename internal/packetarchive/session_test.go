package packetarchive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/kkx600/StarBeacon/internal/testpcap"
)

type sessionFrame struct {
	raw  []byte
	info gopacket.CaptureInfo
}

func sessionFrames(t *testing.T) []sessionFrame {
	t.Helper()
	raw, e := testpcap.HTTP(false)
	if e != nil {
		t.Fatal(e)
	}
	reader, e := pcapgo.NewReader(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	var frames []sessionFrame
	for {
		raw, ci, e := reader.ReadPacketData()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		frames = append(frames, sessionFrame{bytes.Clone(raw), ci})
	}
	return frames
}
func sessionArchive(t *testing.T, id string, frames []sessionFrame, change func(*Capture)) SessionInput {
	t.Helper()
	header := captureHeader()
	header.ID = id
	if len(frames) > 0 {
		header.StartedAt = frames[0].info.Timestamp.Add(-time.Nanosecond)
	}
	var raw bytes.Buffer
	writer, e := NewRecorder(&raw, header, 1024*1024)
	if e != nil {
		t.Fatal(e)
	}
	for _, frame := range frames {
		if e = writer.Write(frame.info, frame.raw, nil); e != nil {
			t.Fatal(e)
		}
	}
	end := header.StartedAt.Add(time.Second)
	if len(frames) > 0 {
		end = frames[len(frames)-1].info.Timestamp.Add(time.Nanosecond)
	}
	drops := uint64(0)
	capture, e := writer.Seal(end, "rotation", &drops)
	if e != nil {
		t.Fatal(e)
	}
	if change != nil {
		change(&capture)
	}
	// 目录计数的变化同时写入真实统计块，不能用伪元数据测试完整性。
	if change != nil {
		var copy bytes.Buffer
		w, e := NewRecorder(&copy, header, 1024*1024)
		if e != nil {
			t.Fatal(e)
		}
		for _, frame := range frames {
			if e = w.Write(frame.info, frame.raw, nil); e != nil {
				t.Fatal(e)
			}
		}
		capture, e = w.Seal(end, "rotation", capture.KernelDrops)
		if e != nil {
			t.Fatal(e)
		}
		raw = copy
	}
	index, e := EncodeFrames(context.Background(), io.Discard, bytes.NewReader(raw.Bytes()), "zstd", DefaultFrameBytes)
	if e != nil {
		t.Fatal(e)
	}
	file, e := os.CreateTemp(t.TempDir(), "source-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { file.Close() })
	if _, e = file.Write(raw.Bytes()); e != nil {
		t.Fatal(e)
	}
	return SessionInput{Manifest: Manifest{Capture: capture, Encoding: index}, ObjectVersion: "version_" + id, File: file}
}
func sessionRequest(ids ...string) SessionRequest {
	return SessionRequest{ArchiveIDs: ids, Mode: "full_session", ClientIP: "192.0.2.10", ClientPort: 40000, ServerIP: "198.51.100.20", ServerPort: 80, ClientMAC: "02:00:00:00:00:01", ServerMAC: "02:00:00:00:00:02", VLANs: []uint16{}}
}
func mutateSessionTCP(t *testing.T, frame sessionFrame, change func(*layers.TCP)) sessionFrame {
	t.Helper()
	packet := gopacket.NewPacket(frame.raw, layers.LayerTypeEthernet, gopacket.Default)
	ethernet := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	change(tcp)
	if e := tcp.SetNetworkLayerForChecksum(ip); e != nil {
		t.Fatal(e)
	}
	buffer := gopacket.NewSerializeBuffer()
	if e := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, tcp, gopacket.Payload(tcp.Payload)); e != nil {
		t.Fatal(e)
	}
	frame.raw = bytes.Clone(buffer.Bytes())
	frame.info.Length = len(frame.raw)
	frame.info.CaptureLength = len(frame.raw)
	return frame
}
func TestSessionExportCrossSegmentsKeepsEveryOriginalFrameAndSource(t *testing.T) {
	frames := sessionFrames(t)
	first := sessionArchive(t, "packet_first", frames[:4], nil)
	last := sessionArchive(t, "packet_last", frames[4:], nil)
	request := sessionRequest("packet_first", "packet_last")
	var out bytes.Buffer
	report, e := ExportSession(context.Background(), &out, request, []SessionInput{last, first})
	if e != nil || report.Completeness != "full_session" || report.Handshake != "verified" || report.PayloadCoverage != "contiguous_verified" || report.Termination != "fin_verified" || report.Bidirectional != "observed" || report.Packets != 9 || len(report.Reasons) != 0 {
		t.Fatalf("会话序列不成立：%+v %v", report, e)
	}
	reader, e := pcapgo.NewNgReader(bytes.NewReader(out.Bytes()), pcapgo.DefaultNgReaderOptions)
	if e != nil {
		t.Fatal(e)
	}
	var embedded SessionReport
	if e = json.Unmarshal([]byte(reader.SectionInfo().Comment), &embedded); e != nil || embedded.Sources[0].ID != "packet_first" || embedded.Sources[1].ObjectVersion != "version_packet_last" {
		t.Fatalf("来源清单未固化：%+v %v", embedded, e)
	}
	iface, e := reader.Interface(0)
	if e != nil || iface.Name != "eth0" || iface.Comment != "MAC=02:00:00:00:00:01" || iface.TimestampResolution != 9 {
		t.Fatal("接口元数据未保持")
	}
	for i, frame := range frames {
		raw, ci, options, e := reader.ReadPacketDataWithOptions()
		if e != nil || !bytes.Equal(raw, frame.raw) || !ci.Timestamp.Equal(frame.info.Timestamp) || ci.Length != frame.info.Length || options.PacketID == nil || *options.PacketID != uint64(i+1) {
			t.Fatalf("原始帧 %d 被改变：%v", i, e)
		}
		source, offset := "packet_first", i+1
		if i >= 4 {
			source, offset = "packet_last", i-3
		}
		if !strings.Contains(strings.Join(options.Comments, " "), "archive_id="+source) || !strings.Contains(strings.Join(options.Comments, " "), "packet_id="+string([]byte{'0' + byte(offset)})) {
			t.Fatalf("原包映射缺失：%+v", options)
		}
	}
	if _, _, e = reader.ReadPacketData(); e != io.EOF {
		t.Fatal(e)
	}
}
func TestSessionExportStrictFailureNeverSilentlyFallsBack(t *testing.T) {
	for name, alter := range map[string]func([]sessionFrame) []sessionFrame{
		"缺少握手":   func(v []sessionFrame) []sessionFrame { return v[3:] },
		"只有建连快照": func(v []sessionFrame) []sessionFrame { return v[:6] },
		"遗漏请求载荷": func(v []sessionFrame) []sessionFrame { return append(v[:3], v[4:]...) },
		"缺少关闭确认": func(v []sessionFrame) []sessionFrame { return v[:8] },
		"伪造第三次握手": func(v []sessionFrame) []sessionFrame {
			v[2] = mutateSessionTCP(t, v[2], func(tcp *layers.TCP) { tcp.Ack++ })
			v[3] = mutateSessionTCP(t, v[3], func(tcp *layers.TCP) { tcp.Ack++ })
			return v
		},
		"重传字节冲突": func(v []sessionFrame) []sessionFrame {
			copy := mutateSessionTCP(t, v[3], func(tcp *layers.TCP) { tcp.Payload = bytes.Clone(tcp.Payload); tcp.Payload[0] = 'X' })
			return append(append(v[:4:4], copy), v[4:]...)
		},
		"五元组复用": func(v []sessionFrame) []sessionFrame {
			copy := mutateSessionTCP(t, v[0], func(tcp *layers.TCP) { tcp.Seq = 2000 })
			return append(append(v[:4:4], copy), v[4:]...)
		},
		"Fast Open 未验收": func(v []sessionFrame) []sessionFrame {
			v[0] = mutateSessionTCP(t, v[0], func(tcp *layers.TCP) { tcp.Payload = []byte("hello") })
			return v
		},
		"RST 接受条件未知": func(v []sessionFrame) []sessionFrame {
			v[8] = mutateSessionTCP(t, v[8], func(tcp *layers.TCP) { tcp.RST = true })
			return v
		},
		"序号超出预算": func(v []sessionFrame) []sessionFrame {
			v[3] = mutateSessionTCP(t, v[3], func(tcp *layers.TCP) { tcp.Seq += maxDirectionBytes + 1 })
			return v
		},
		"关闭序号冲突": func(v []sessionFrame) []sessionFrame {
			copy := mutateSessionTCP(t, v[6], func(tcp *layers.TCP) { tcp.Seq++ })
			return append(append(v[:7:7], copy), v[7:]...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			frames := alter(sessionFrames(t))
			input := sessionArchive(t, "packet_one", frames, nil)
			request := sessionRequest("packet_one")
			var out bytes.Buffer
			report, e := ExportSession(context.Background(), &out, request, []SessionInput{input})
			if !errors.Is(e, ErrSessionIncomplete) || out.Len() != 0 || len(report.Reasons) == 0 {
				t.Fatalf("严格模式错误返回成功：%+v %v %d", report, e, out.Len())
			}
			request.Mode = "snapshot"
			report, e = ExportSession(context.Background(), &out, request, []SessionInput{input})
			if e != nil || report.Completeness != "snapshot" || out.Len() < 24 {
				t.Fatalf("显式快照失败：%+v %v", report, e)
			}
		})
	}
}
func TestSessionExportRetransmissionReorderingWrapAndUnrelatedFlows(t *testing.T) {
	for _, name := range []string{"相同重传", "乱序载荷", "序号回绕", "其他端口", "显式快照"} {
		t.Run(name, func(t *testing.T) {
			frames := sessionFrames(t)
			request := sessionRequest("packet_one")
			want := uint64(9)
			switch name {
			case "相同重传":
				frames = append(append(frames[:4:4], frames[3]), frames[4:]...)
				want = 10
			case "乱序载荷":
				frames[3], frames[4] = frames[4], frames[3]
			case "序号回绕":
				for i := range frames {
					frames[i] = mutateSessionTCP(t, frames[i], func(tcp *layers.TCP) {
						if tcp.SrcPort == 40000 {
							tcp.Seq += ^uint32(0) - 1030
							if tcp.ACK {
								tcp.Ack += ^uint32(0) - 5030
							}
						} else {
							tcp.Seq += ^uint32(0) - 5030
							tcp.Ack += ^uint32(0) - 1030
						}
					})
				}
			case "其他端口":
				other := mutateSessionTCP(t, frames[0], func(tcp *layers.TCP) { tcp.SrcPort++ })
				frames = append(frames, other)
			case "显式快照":
				request.Mode = "snapshot"
			}
			input := sessionArchive(t, "packet_one", frames, nil)
			var out bytes.Buffer
			report, e := ExportSession(context.Background(), &out, request, []SessionInput{input})
			if e != nil || report.Packets != want {
				t.Fatalf("正常原件被拒绝：%+v %v", report, e)
			}
			if name == "显式快照" && report.Completeness != "snapshot" {
				t.Fatal("忽略了明确请求的快照范围")
			}
		})
	}
}
func TestSessionExportQuotaIdentityCorruptionCancellationAndCaptureQuality(t *testing.T) {
	for name, change := range map[string]func(*SessionRequest){"空清单": func(r *SessionRequest) { r.ArchiveIDs = nil }, "重复清单": func(r *SessionRequest) { r.ArchiveIDs = append(r.ArchiveIDs, r.ArchiveIDs[0]) }, "越界清单": func(r *SessionRequest) { r.ArchiveIDs = append(r.ArchiveIDs, "../other") }, "非法模式": func(r *SessionRequest) { r.Mode = "auto" }, "零端口": func(r *SessionRequest) { r.ClientPort = 0 }, "IPv6 区域": func(r *SessionRequest) { r.ClientIP = "fe80::1%eth0" }, "无效地址": func(r *SessionRequest) { r.ClientIP = "no" }, "多播地址": func(r *SessionRequest) { r.ClientIP = "224.0.0.1" }, "非标准 MAC": func(r *SessionRequest) { r.ClientMAC = "02-00-00-00-00-01" }, "无效 VLAN": func(r *SessionRequest) { r.VLANs = []uint16{4096} }} {
		t.Run(name, func(t *testing.T) {
			r := sessionRequest("packet_one")
			change(&r)
			if r.Validate() == nil {
				t.Fatal("无效请求通过")
			}
		})
	}
	for name, drops := range map[string]*uint64{"未获取丢包计数": nil, "存在内核丢包": func() *uint64 { v := uint64(1); return &v }()} {
		t.Run(name, func(t *testing.T) {
			input := sessionArchive(t, "packet_one", sessionFrames(t), func(c *Capture) { c.KernelDrops = drops })
			var out bytes.Buffer
			r, e := ExportSession(context.Background(), &out, sessionRequest("packet_one"), []SessionInput{input})
			if !errors.Is(e, ErrSessionIncomplete) || len(r.Reasons) == 0 || out.Len() != 0 {
				t.Fatalf("捕获质量错误：%+v %v", r, e)
			}
		})
	}
	input := sessionArchive(t, "packet_one", sessionFrames(t), nil)
	request := sessionRequest("packet_one")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := ExportSession(ctx, io.Discard, request, []SessionInput{input}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := ExportSession(context.Background(), io.Discard, request, nil); !errors.Is(e, ErrIntegrity) {
		t.Fatal(e)
	}
	request.ServerPort = 443
	if _, e := ExportSession(context.Background(), io.Discard, request, []SessionInput{input}); !errors.Is(e, ErrSessionIncomplete) {
		t.Fatal(e)
	}
	request.ServerPort = 80
	if _, e := ExportSession(context.Background(), nil, request, []SessionInput{input}); !errors.Is(e, ErrIntegrity) {
		t.Fatal(e)
	}
	wrong := input
	wrong.ObjectVersion = "null"
	if _, e := ExportSession(context.Background(), io.Discard, request, []SessionInput{wrong}); !errors.Is(e, ErrIntegrity) {
		t.Fatal(e)
	}
	if _, e := input.File.WriteAt([]byte{0}, 24); e != nil {
		t.Fatal(e)
	}
	if _, e := ExportSession(context.Background(), io.Discard, request, []SessionInput{input}); !errors.Is(e, ErrIntegrity) {
		t.Fatal(e)
	}
}
