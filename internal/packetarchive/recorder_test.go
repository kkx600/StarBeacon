package packetarchive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/kkx600/StarBeacon/internal/testpcap"
)

func captureHeader() Capture {
	return Capture{ID: "packet_one", TenantID: "tenant_one", SensorID: "sensor_one", RegistrationID: "registration_one", RunID: "capture_one", Interface: "eth0", InterfaceMAC: "02:00:00:00:00:01", SettingsSHA256: Digest([]byte("frozen-settings")), StartedAt: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)}
}

func TestRecorderRetainsHandshakeBytesTimesMACsAndInterface(t *testing.T) {
	raw, err := testpcap.HTTP(false)
	if err != nil {
		t.Fatal(err)
	}
	input, err := pcapgo.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	r, err := NewRecorder(&output, captureHeader(), 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	packets := [][]byte{}
	times := []time.Time{}
	for {
		data, ci, err := input.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, bytes.Clone(data))
		times = append(times, ci.Timestamp)
		if err = r.Write(ci, data, nil); err != nil {
			t.Fatal(err)
		}
	}
	drops := uint64(0)
	c, err := r.Seal(captureHeader().StartedAt.Add(time.Second), "shutdown", &drops)
	if err != nil || c.Validate() != nil || c.Packets != 9 || c.TruncatedPackets != 0 || c.KernelDrops == nil || c.Format != "pcapng" {
		t.Fatalf("捕获目录不一致：%+v %v", c, err)
	}
	reader, err := pcapgo.NewNgReader(bytes.NewReader(output.Bytes()), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range packets {
		got, ci, err := reader.ReadPacketData()
		if err != nil || !bytes.Equal(want, got) || !ci.Timestamp.Equal(times[i]) || ci.Length != len(want) || ci.InterfaceIndex != 0 {
			t.Fatalf("第 %d 包有变化：%v", i, err)
		}
	}
	if _, _, err = reader.ReadPacketData(); err != io.EOF {
		t.Fatal(err)
	}
	if err = r.Flush(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if _, err = r.Seal(c.EndedAt, "shutdown", nil); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if err = r.Write(gopacket.CaptureInfo{}, nil, nil); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	var stored bytes.Buffer
	encoding, err := EncodeFrames(context.Background(), &stored, bytes.NewReader(output.Bytes()), "zstd", DefaultFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{Capture: c, Encoding: encoding}
	encoded, hash, err := m.JSON()
	if err != nil || hash != Digest(encoded) {
		t.Fatal(err)
	}
	parsed, err := ParseManifest(encoded)
	if err != nil || parsed.Encoding.RawSHA256 != Digest(output.Bytes()) || parsed.Capture.Packets != 9 {
		t.Fatal(err)
	}
}

func TestRecorderLargePacketsTruncationVLANAndRotationAreExplicit(t *testing.T) {
	var output bytes.Buffer
	r, err := NewRecorder(&output, captureHeader(), 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{0xd0}, SnapLength)
	ci := gopacket.CaptureInfo{Timestamp: captureHeader().StartedAt.Add(time.Millisecond), CaptureLength: len(data), Length: len(data) + 4}
	vlan := uint16(123)
	for i := 0; i < 3; i++ {
		if err = r.Write(ci, data, &vlan); err != nil {
			t.Fatal(err)
		}
	}
	if err = r.Write(ci, data, &vlan); !errors.Is(err, ErrRotate) {
		t.Fatal(err)
	}
	if err = r.Flush(); err != nil {
		t.Fatal(err)
	}
	c, err := r.Seal(ci.Timestamp.Add(time.Second), "rotation", nil)
	if err != nil || c.TruncatedPackets != 3 || c.VLANOffloadPackets != 3 || c.CounterState != "unavailable" || c.KernelDrops != nil || output.Len() > 1024*1024 {
		t.Fatalf("大包限制未保留：%+v %v", c, err)
	}
	reader, err := pcapgo.NewNgReader(bytes.NewReader(output.Bytes()), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		got, info, err := reader.ReadPacketData()
		if err != nil || !bytes.Equal(got, data) || info.Length != len(data)+4 {
			t.Fatalf("截断或 VLAN 情况被改写：%v", err)
		}
	}
	if !bytes.Contains(output.Bytes(), []byte("vlan_offload_id=123")) {
		t.Fatal("未保留实际 VLAN 元数据")
	}
}

func TestManifestRejectsUnknownMissingDuplicateFieldsAndCaptureDrift(t *testing.T) {
	var raw bytes.Buffer
	r, err := NewRecorder(&raw, captureHeader(), 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	c, err := r.Seal(captureHeader().StartedAt.Add(time.Second), "configuration", nil)
	if err != nil {
		t.Fatal(err)
	}
	var stored bytes.Buffer
	enc, err := EncodeFrames(context.Background(), &stored, bytes.NewReader(raw.Bytes()), "none", MinFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{Capture: c, Encoding: enc}
	encoded, _, err := m.JSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"{}", string(encoded) + "{}", `{"capture":{},"capture":{},"encoding":{}}`, string(bytes.Replace(encoded, []byte(`"tenant_id"`), []byte(`"TenantID"`), 1)), string(bytes.Replace(encoded, []byte(`"schema"`), []byte(`"unknown"`), 1))} {
		if _, err := ParseManifest([]byte(value)); err == nil {
			t.Fatal("非法 manifest 被接受")
		}
	}
	for name, mutate := range map[string]func(*Capture){
		"身份":     func(v *Capture) { v.TenantID = "../other" },
		"MAC":    func(v *Capture) { v.InterfaceMAC = "bad" },
		"网卡":     func(v *Capture) { v.Interface = "../../eth0" },
		"过滤器":    func(v *Capture) { v.BPFFilter = "tcp\nextra" },
		"摘要":     func(v *Capture) { v.SettingsSHA256 = "" },
		"时间":     func(v *Capture) { v.EndedAt = v.StartedAt.Add(-time.Second) },
		"过长切片":   func(v *Capture) { v.EndedAt = v.StartedAt.Add(2 * time.Hour) },
		"截断计数":   func(v *Capture) { v.TruncatedPackets = 1 },
		"伪造首包":   func(v *Capture) { v.FirstPacketAt = &v.StartedAt },
		"缺少包时间":  func(v *Capture) { v.Packets = 1; v.PacketBytes = 1 },
		"缺少计数":   func(v *Capture) { v.CounterState = "observed" },
		"伪造计数":   func(v *Capture) { n := uint64(0); v.KernelDrops = &n },
		"中断伪装完成": func(v *Capture) { v.Termination = "crashed" },
		"截取长度":   func(v *Capture) { v.SnapLength = 65535 },
	} {
		t.Run(name, func(t *testing.T) {
			v := m
			mutate(&v.Capture)
			if _, _, err := v.JSON(); err == nil {
				t.Fatal("漂移捕获目录被接受")
			}
			b, _ := json.Marshal(v)
			if _, err = ParseManifest(b); err == nil {
				t.Fatal("漂移目录被解码")
			}
		})
	}
}

func TestRecorderRejectsInvalidMetadataAndIOFailures(t *testing.T) {
	if _, err := NewRecorder(failedWriter{}, captureHeader(), 1024*1024); err == nil {
		t.Fatal("头部写入失败被忽略")
	}
	for _, limit := range []int64{0, MaxSegmentBytes + 1} {
		if _, err := NewRecorder(io.Discard, captureHeader(), limit); err == nil {
			t.Fatal("容量无效")
		}
	}
	var raw bytes.Buffer
	r, err := NewRecorder(&raw, captureHeader(), 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	good := gopacket.CaptureInfo{Timestamp: captureHeader().StartedAt, CaptureLength: 2, Length: 2}
	for _, mutate := range []func(*gopacket.CaptureInfo){func(v *gopacket.CaptureInfo) { v.Timestamp = time.Time{} }, func(v *gopacket.CaptureInfo) { v.CaptureLength = 3 }, func(v *gopacket.CaptureInfo) { v.Length = 1 }, func(v *gopacket.CaptureInfo) { v.InterfaceIndex = 1 }, func(v *gopacket.CaptureInfo) { v.Timestamp = time.Date(2300, 1, 1, 0, 0, 0, 0, time.UTC) }} {
		v := good
		mutate(&v)
		if r.Write(v, []byte{1, 2}, nil) == nil {
			t.Fatal("无效包元数据被接受")
		}
	}
	badVLAN := uint16(4096)
	if r.Write(good, []byte{1, 2}, &badVLAN) == nil {
		t.Fatal("无效 VLAN 被接受")
	}
	if _, err = r.Seal(captureHeader().StartedAt, "crash", nil); err == nil {
		t.Fatal("未确认终止状态被接受")
	}
	if _, err = r.Seal(captureHeader().StartedAt.Add(time.Second), "shutdown", nil); err != nil {
		t.Fatal(err)
	}
}
