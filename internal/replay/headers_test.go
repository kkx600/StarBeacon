package replay

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func inspectFrames(t *testing.T, frames [][]byte) Metadata {
	t.Helper()
	path := filepath.Join(t.TempDir(), "frames.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriterNanos(f)
	if err = w.WriteFileHeader(MaxFrameBytes, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for i, raw := range frames {
		if err = w.WritePacket(gopacket.CaptureInfo{CaptureLength: len(raw), Length: len(raw), Timestamp: time.Unix(1000, int64(i)).UTC()}, raw); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := Inspect(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestHeaderReuseKeepsHandshakeAndCaptureBoundaries(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		frames := []handshakeFrame{{seq: 1000, syn: true, ipv6: ipv6}, {server: true, seq: 5000, ack: 1001, syn: true, ackFlag: true, ipv6: ipv6}, {seq: 1001, ack: 5001, ackFlag: true, ipv6: ipv6, payload: "GET / HTTP/1.1\r\n\r\n"}}
		headers, tracker, reference := newHeaderInspector(), newHandshakeTracker(), newHandshakeTracker()
		var rawFrames [][]byte
		for _, frame := range frames {
			packet, raw := handshakePacket(t, frame)
			ci := gopacket.CaptureInfo{CaptureLength: len(raw), Length: len(raw)}
			if !headers.observe(tracker, raw, ci) {
				t.Fatal("完整普通 TCP 帧未使用可复用解码")
			}
			reference.observe(packet, ci)
			rawFrames = append(rawFrames, raw)
		}
		if !reflect.DeepEqual(tracker.result(), reference.result()) || tracker.result().CompleteHandshakes != 1 {
			t.Fatalf("复用后握手语义发生变化：%+v / %+v", tracker.result(), reference.result())
		}
		meta := inspectFrames(t, rawFrames)
		if meta.Packets != 3 || meta.TCPHandshake.CompleteHandshakes != 1 || len(meta.MACs) != 2 || meta.MACsLimited || !meta.First.Equal(time.Unix(1000, 0)) || !meta.Last.Equal(time.Unix(1000, 2)) {
			t.Fatalf("跨帧字节／地址／时间引用未独立：%+v", meta)
		}
	}
}

func TestHeaderReuseFallsBackForComplexAndInvalidFrames(t *testing.T) {
	_, raw := handshakePacket(t, handshakeFrame{seq: 1000, syn: true})
	_, vlan := handshakePacket(t, handshakeFrame{seq: 1000, syn: true, vlan: 10})
	_, application := handshakePacket(t, handshakeFrame{seq: 1000, syn: true, port: 53, payload: "invalid DNS"})
	fragment := append([]byte(nil), raw...)
	binary.BigEndian.PutUint16(fragment[20:22], 0x2000)
	missingIPBytes := append([]byte(nil), raw...)
	binary.BigEndian.PutUint16(missingIPBytes[16:18], uint16(len(raw)-14+10))
	invalidVersion := append([]byte(nil), raw...)
	invalidVersion[14] = 0x65
	for name, data := range map[string][]byte{"VLAN": vlan, "应用协议解码": application, "IP 分片": fragment, "IP 长度超过帧": missingIPBytes, "IP 版本与以太类型不符": invalidVersion, "不完整以太头": raw[:13], "不完整 TCP 头": raw[:40]} {
		t.Run(name, func(t *testing.T) {
			headers, tracker := newHeaderInspector(), newHandshakeTracker()
			ci := gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data)}
			if headers.observe(tracker, data, ci) || tracker.result().AssessedFlows != 0 {
				t.Fatal("复杂或无效数据越过逐层核对")
			}
			// 失败帧不得使解码器把上一帧的 TCP 字段带入后续帧。
			if !headers.observe(tracker, raw, gopacket.CaptureInfo{CaptureLength: len(raw), Length: len(raw)}) || tracker.result().AssessedFlows != 1 {
				t.Fatal("解码器未恢复到当前帧")
			}
		})
	}
	if newHeaderInspector().observe(newHandshakeTracker(), raw, gopacket.CaptureInfo{CaptureLength: len(raw), Length: len(raw) + 1}) {
		t.Fatal("snaplen 截断帧被接受")
	}
}

func TestInvalidIPVersionCannotProveHandshake(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		frames := []handshakeFrame{{seq: 1000, syn: true, ipv6: ipv6}, {server: true, seq: 5000, ack: 1001, syn: true, ackFlag: true, ipv6: ipv6}, {seq: 1001, ack: 5001, ackFlag: true, ipv6: ipv6}}
		var rawFrames [][]byte
		for i, frame := range frames {
			_, data := handshakePacket(t, frame)
			if i == 0 {
				data[14] = 0x60 | data[14]&0x0f
				if ipv6 {
					data[14] = 0x40 | data[14]&0x0f
				}
			}
			rawFrames = append(rawFrames, data)
		}
		result := inspectFrames(t, rawFrames)
		if result.TCPHandshake.CompleteHandshakes != 0 || !result.TCPHandshake.Limited || result.TCPHandshake.SkippedPackets != 1 {
			t.Fatalf("IP 版本不匹配仍被确认为完整握手：%+v", result)
		}
	}
}

func TestDeclaredIPTruncationCannotProveHandshake(t *testing.T) {
	frames := []handshakeFrame{{seq: 1000, syn: true}, {server: true, seq: 5000, ack: 1001, syn: true, ackFlag: true}, {seq: 1001, ack: 5001, ackFlag: true}}
	var rawFrames [][]byte
	for i, frame := range frames {
		_, data := handshakePacket(t, frame)
		if i == 0 {
			binary.BigEndian.PutUint16(data[16:18], uint16(len(data)-14+10))
		}
		rawFrames = append(rawFrames, data)
	}
	result := inspectFrames(t, rawFrames)
	if result.TCPHandshake.CompleteHandshakes != 0 || !result.TCPHandshake.Limited || result.TCPHandshake.SkippedPackets != 1 {
		t.Fatalf("协议声明缺字节仍被补推为完整握手：%+v", result)
	}
}

func TestMACSummaryBoundedWithReusablePacketBuffer(t *testing.T) {
	var frames [][]byte
	for i := 1; i <= 40; i++ {
		_, raw := handshakePacket(t, handshakeFrame{seq: 1000, syn: true})
		raw[11] = byte(i)
		frames = append(frames, raw)
	}
	meta := inspectFrames(t, frames)
	if len(meta.MACs) != 32 || !meta.MACsLimited || meta.MACs[0] != "02:00:00:00:00:01" || meta.MACs[1] != "02:00:00:00:00:02" || meta.Packets != 40 {
		t.Fatalf("MAC 摘要边界失效或共享了帧缓冲区：%+v", meta)
	}
}

func FuzzReusableHeadersAgreeWithLayerDecoding(f *testing.F) {
	// 真实序列化种子覆盖 IPv4、IPv6、VLAN 和截断；模糊输入不能扩展会话推断。
	for _, raw := range [][]byte{{}, make([]byte, 14), {2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 8, 0}} {
		f.Add(raw)
	}
	for _, frame := range []handshakeFrame{{seq: 1000, syn: true}, {seq: 1000, syn: true, ipv6: true}, {seq: 1000, syn: true, vlan: 10}, {seq: 1001, ack: 5001, ackFlag: true, payload: "GET / HTTP/1.1\r\n\r\n"}} {
		_, raw := handshakePacket(f, frame)
		f.Add(raw)
		f.Add(raw[:40])
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxFrameBytes {
			return
		}
		ci := gopacket.CaptureInfo{CaptureLength: len(raw), Length: len(raw)}
		tracker := newHandshakeTracker()
		if !newHeaderInspector().observe(tracker, raw, ci) {
			return
		}
		reference := newHandshakeTracker()
		reference.observe(gopacket.NewPacket(raw, layers.LinkTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true}), ci)
		if !reflect.DeepEqual(tracker.result(), reference.result()) {
			t.Fatalf("可复用解码与逐层观测不同：%+v / %+v", tracker.result(), reference.result())
		}
	})
}
