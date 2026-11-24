package packetarchive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	bolt "go.etcd.io/bbolt"
)

func retentionSpool(t *testing.T) (*Spool, *bolt.DB) {
	t.Helper()
	s, db := testSpool(t)
	s.RetentionFile = filepath.Join(t.TempDir(), "retention.json")
	s.Quota = 64 << 20
	return s, db
}

func installRetention(t *testing.T, s *Spool, raw string) {
	t.Helper()
	tmp := s.RetentionFile + ".next"
	if err := os.WriteFile(tmp, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, s.RetentionFile); err != nil {
		t.Fatal(err)
	}
}

func hotRetention(t *testing.T, s *Spool, id string, at time.Time, frames []sessionFrame) *PendingCapture {
	t.Helper()
	header := captureHeader()
	header.ID, header.StartedAt = id, at
	pending, err := s.Begin(header)
	if err != nil {
		t.Fatal(err)
	}
	for _, frame := range frames {
		if err := pending.Recorder.Write(frame.info, frame.raw, nil); err != nil {
			t.Fatal(err)
		}
	}
	return pending
}

func sealRetention(t *testing.T, pending *PendingCapture, at time.Time) {
	t.Helper()
	drops := uint64(0)
	if err := pending.Seal(at, "rotation", &drops); err != nil {
		t.Fatal(err)
	}
}

func retainedRecord(t *testing.T, s *Spool, id string) (LocalRecord, *os.File) {
	t.Helper()
	ctx := context.Background()
	row, err := s.Prepare(ctx, id, "zstd")
	if err != nil {
		t.Fatal(err)
	}
	stored, _, err := s.OpenStored(id)
	if err != nil {
		t.Fatal(err)
	}
	defer stored.Close()
	file, err := os.Create(filepath.Join(t.TempDir(), "final.pcapng"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	index := row.Manifest.Encoding
	if err := ReadRange(ctx, file, RangeFile(stored), index, 0, index.RawBytes); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifestRawFile(ctx, file, *row.Manifest); err != nil {
		t.Fatal(err)
	}
	raw, sha, err := row.Manifest.JSON()
	if err != nil || sha != row.ManifestSHA256 {
		t.Fatal("留存目录摘要未冻结", err)
	}
	if parsed, err := ParseManifest(raw); err != nil || len(parsed.Sessions) != len(row.Manifest.Sessions) {
		t.Fatal("留存目录未能往返校验", err)
	}
	return row, file
}

func retentionAlertFor(t *testing.T, db *bolt.DB, id, iface string, port uint16, at time.Time) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"event_type": "alert", "in_iface": iface, "proto": "TCP",
		"timestamp": at.Format(time.RFC3339Nano), "src_ip": "198.51.100.20", "src_port": 80,
		"dest_ip": "192.0.2.10", "dest_port": port})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error { return RecordRetentionAlert(tx, raw, id, at) }); err != nil {
		t.Fatal(err)
	}
}

func TestRetentionPolicySwitchFreezesAlertsAndSourceBytesAtSeal(t *testing.T) {
	ctx := context.Background()
	s, db := retentionSpool(t)
	installRetention(t, s, `{"network_domain":"test_domain","revision":1,"mode":"full"}`)
	first := sessionFrames(t)
	at := first[0].info.Timestamp.Add(-time.Second)
	other := make([]sessionFrame, len(first))
	for i, frame := range first {
		other[i] = mutateSessionTCP(t, frame, func(tcp *layers.TCP) {
			if tcp.SrcPort == 40000 {
				tcp.SrcPort = 40001
			} else {
				tcp.DstPort = 40001
			}
		})
	}
	frames := append(slices.Clone(first), other...)
	full := hotRetention(t, s, "test_full", at, frames)
	sealRetention(t, full, at.Add(2*time.Second))
	pending := hotRetention(t, s, "test_alert_only", at, frames)
	alertAt := first[3].info.Timestamp
	retentionAlertFor(t, db, "present", "eth0", 40000, alertAt)
	retentionAlertFor(t, db, "other_scope", "eth1", 40001, alertAt)
	installRetention(t, s, `{"network_domain":"test_domain","revision":2,"mode":"alert_only"}`)
	sealRetention(t, pending, at.Add(2*time.Second))
	retentionAlertFor(t, db, "late", "eth0", 40001, alertAt)
	installRetention(t, s, `{"network_domain":"test_domain","revision":3}`)
	latest, err := NewSpool(db, s.Dir, s.TenantID, s.SensorID, s.RegistrationID, s.Quota, s.SegmentBytes)
	if err != nil {
		t.Fatal(err)
	}
	latest.RetentionFile = s.RetentionFile
	rawPath, _ := s.path(pending.ID, ".raw")
	original, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	archived, _ := retainedRecord(t, latest, full.ID)
	if archived.Capture.Retention.Mode != RetentionFull || archived.Capture.Retention.PolicyRevision != 1 || archived.Capture.Packets != uint64(len(frames)) {
		t.Fatal("旧封段被后来的策略修改", archived.Capture.Retention)
	}
	trimmed, final := retainedRecord(t, latest, pending.ID)
	summary := trimmed.Capture.Retention
	sessions := trimmed.Manifest.Sessions
	if summary.PolicyRevision != 2 || summary.Mode != RetentionAlertOnly || summary.OriginalPackets != uint64(len(frames)) ||
		len(sessions) != 2 || sessions[0].State != retainAll || sessions[1].State != retainMetadata || sessions[1].RetainedBytes != 0 {
		t.Fatalf("告警窗口、元数据或修订不正确：%+v %+v", summary, sessions)
	}
	reader, err := pcapgo.NewNgReader(final, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	for _, frame := range first {
		raw, info, err := reader.ReadPacketData()
		if err != nil || !bytes.Equal(raw, frame.raw) || !info.Timestamp.Equal(frame.info.Timestamp) {
			t.Fatal("告警命中流的报文被修改", err)
		}
	}
	if _, _, err := reader.ReadPacketData(); err != io.EOF {
		t.Fatal("未命中的报文仍在归档中", err)
	}
	request := sessionRequest(trimmed.ID)
	inputs := []SessionInput{{Manifest: *trimmed.Manifest, ObjectVersion: "retention_test_version", File: final}}
	report, err := ExportSession(ctx, io.Discard, request, inputs)
	if err != nil || report.Completeness != "full_session" || report.Sources[0].Retention.State != retainAll {
		t.Fatalf("告警命中流的完整导出失败：%+v %v", report, err)
	}
	request.ClientPort = 40001
	var target bytes.Buffer
	report, err = ExportSession(ctx, &target, request, inputs)
	if !errors.Is(err, ErrSessionIncomplete) || !slices.Contains(report.Reasons, "capture_policy_truncated") || target.Len() != 0 {
		t.Fatalf("仅元数据被接受为完整会话：%+v %v", report, err)
	}
	if got, err := os.ReadFile(rawPath); err != nil || !bytes.Equal(original, got) {
		t.Fatal("原始热段在持久确认前被改写", err)
	}
}

func TestSmartRetentionKeepsFirstMirrorWithinTheWindow(t *testing.T) {
	s, _ := retentionSpool(t)
	installRetention(t, s, `{"network_domain":"test_domain","revision":1}`)
	frames := sessionFrames(t)
	at := frames[0].info.Timestamp.Add(-time.Second)
	duplicate := frames[0]
	duplicate.raw = bytes.Clone(duplicate.raw)
	duplicate.raw[0] ^= 1
	duplicate.raw[22]--
	duplicate.raw[24] ^= 1
	duplicate.info.Timestamp = duplicate.info.Timestamp.Add(5 * time.Millisecond)
	retransmission := frames[0]
	retransmission.info.Timestamp = retransmission.info.Timestamp.Add(80 * time.Millisecond)
	frames = append([]sessionFrame{frames[0], duplicate, retransmission}, frames[1:]...)
	pending := hotRetention(t, s, "test_smart", at, frames)
	sealRetention(t, pending, at.Add(2*time.Second))
	row, final := retainedRecord(t, s, pending.ID)
	if row.Capture.Retention.DuplicateBytes != uint64(len(duplicate.raw)) || row.Capture.Packets != uint64(len(frames)-1) ||
		row.Manifest.Sessions[0].State != retainPrefix {
		t.Fatalf("去重或截断标记不一致：%+v", row.Capture.Retention)
	}
	reader, err := pcapgo.NewNgReader(final, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []uint64{1, 3} {
		raw, _, options, err := reader.ReadPacketDataWithOptions()
		if err != nil || !bytes.Equal(raw, frames[0].raw) || options.PacketID == nil || *options.PacketID != want {
			t.Fatal("去重改变了第一副本、超窗口重传或原包序号", want, err)
		}
	}
	report, err := ExportSession(context.Background(), io.Discard, sessionRequest(row.ID), []SessionInput{{Manifest: *row.Manifest, ObjectVersion: "retention_test_version", File: final}})
	if !errors.Is(err, ErrSessionIncomplete) || !slices.Contains(report.Reasons, "capture_policy_truncated") {
		t.Fatalf("去重后的会话缺少保留标记：%+v %v", report, err)
	}
}

func TestRetentionPressureAndInvalidConfigurationPreserveOriginal(t *testing.T) {
	t.Run("pressure", func(t *testing.T) {
		s, _ := retentionSpool(t)
		installRetention(t, s, `{"network_domain":"test_domain","revision":1,"mode":"alert_only"}`)
		frames := sessionFrames(t)
		at := frames[0].info.Timestamp.Add(-time.Second)
		for i := 0; i < 10; i++ {
			sealRetention(t, hotRetention(t, s, fmt.Sprintf("sealed_%d", i), at, frames), at.Add(2*time.Second))
		}
		for _, tc := range []struct{ id, reason, codec string }{
			{"sealed_3", skipClustering, "zstd"}, {"sealed_6", skipCompression, "none"}, {"sealed_9", keepRaw, "none"},
		} {
			final, file := retainedRecord(t, s, tc.id)
			if final.Code != tc.reason || final.Capture.Retention.Degradation != tc.reason || final.Manifest.Encoding.Codec != tc.codec {
				t.Fatalf("积压未按级落档：%+v", final)
			}
			if tc.reason == keepRaw {
				path, _ := s.path(tc.id, ".raw")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(file)
				if err != nil || !bytes.Equal(raw, data) || final.Capture.Retention.Mode != RetentionFull {
					t.Fatal("原样降级改动了捕获字节", err)
				}
			}
		}
	})
	t.Run("invalid or stale", func(t *testing.T) {
		s, _ := retentionSpool(t)
		frames := sessionFrames(t)
		at := frames[0].info.Timestamp.Add(-time.Second)
		for i, input := range []string{
			`{"network_domain":"test_domain","revision":2}`,
			`{"network_domain":"test_domain","revision":1,"mode":"alert_only"}`,
			`{"network_domain":"test_domain","revision":2,"mode":"alert_only"}`,
			`{"network_domain":"test_domain","revision":3,"dedup_millis":1}`,
			`{"network_domain":"test_domain","revision":3,"revision":4}`,
		} {
			installRetention(t, s, input)
			p := hotRetention(t, s, fmt.Sprintf("invalid_%d", i), at, frames)
			sealRetention(t, p, at.Add(2*time.Second))
			row, _ := retainedRecord(t, s, p.ID)
			if i > 0 && (row.Code != invalidPolicy || row.Capture.Retention.Mode != RetentionFull || row.Capture.Packets != uint64(len(frames))) {
				t.Fatal("非法策略导致捕获丢失", row.Code, row.Capture.Retention)
			}
			if err := s.Confirm(acknowledgement(row)); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestRetentionUnattributedDurableAlertProtectsTheWindow(t *testing.T) {
	s, db := retentionSpool(t)
	installRetention(t, s, `{"network_domain":"test_domain","revision":1,"mode":"alert_only"}`)
	frames := sessionFrames(t)
	at := frames[0].info.Timestamp
	p := hotRetention(t, s, "unattributed_alert", at, frames)
	if err := db.Update(func(tx *bolt.Tx) error {
		return RecordRetentionAlert(tx, []byte(`{"event_type":"alert","proto":"ICMP"}`), "unattributed", at)
	}); err != nil {
		t.Fatal(err)
	}
	sealRetention(t, p, at.Add(time.Second))
	row, _ := retainedRecord(t, s, p.ID)
	if row.Code != alertGap || row.Capture.Retention.Mode != RetentionFull || row.Capture.Packets != uint64(len(frames)) {
		t.Fatal("无确切定位的告警应保留捕获窗口", row.Code)
	}
}

func TestRetentionVLANIPv6ProtectionAndManifestAccounting(t *testing.T) {
	s, _ := retentionSpool(t)
	installRetention(t, s, `{"network_domain":"test_domain","revision":2,"observe":["2001:db8:2::/64"]}`)
	at := captureHeader().StartedAt
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeDot1Q}
	vlan := &layers.Dot1Q{VLANIdentifier: 251, Type: layers.EthernetTypeIPv6}
	ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolUDP, HopLimit: 64, SrcIP: net.ParseIP("2001:db8:1::1"), DstIP: net.ParseIP("2001:db8:2::1")}
	udp := &layers.UDP{SrcPort: 40500, DstPort: 443}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	data := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(data, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, vlan, ip, udp, gopacket.Payload([]byte{0xc0, 0, 0, 0, 1, 1, 0x55, 1, 0x56, 0x57})); err != nil {
		t.Fatal(err)
	}
	first := sessionFrame{raw: bytes.Clone(data.Bytes()), info: gopacket.CaptureInfo{Timestamp: at, Length: len(data.Bytes()), CaptureLength: len(data.Bytes())}}
	copy := sessionFrame{raw: bytes.Clone(first.raw), info: first.info}
	copy.raw[0] ^= 2
	copy.raw[14] ^= 1
	copy.raw[25]--
	copy.info.Timestamp = at.Add(time.Millisecond)
	hdr := captureHeader()
	hdr.ID = "ipv6_watch"
	p, err := s.Begin(hdr)
	if err != nil {
		t.Fatal(err)
	}
	offload := uint16(30)
	for _, frame := range []sessionFrame{first, copy} {
		if err := p.Recorder.Write(frame.info, frame.raw, &offload); err != nil {
			t.Fatal(err)
		}
	}
	sealRetention(t, p, at.Add(time.Second))
	archived, _ := retainedRecord(t, s, p.ID)
	c := archived.Capture
	if c.Retention.DuplicateBytes != 0 || c.PacketBytes != 2*uint64(len(first.raw)) || c.Packets != 2 || c.VLANOffloadPackets != 2 {
		t.Fatalf("名单内镜像证据或 VLAN 计数遗漏 %+v", c)
	}
	if len(archived.Manifest.Sessions) != 2 || archived.Manifest.Sessions[0].VLAN != "30,251" || archived.Manifest.Sessions[0].Protocol != "quic" {
		t.Fatalf("双层 VLAN 或 IPv6 目录错误 %+v", archived.Manifest.Sessions)
	}
	for _, change := range []func(*Manifest){
		func(m *Manifest) { m.Sessions[0].VLAN = "30,049" },
		func(m *Manifest) { m.Sessions[0].VLAN = "1,2,3,4,5,6,7,8,9" },
		func(m *Manifest) { m.Sessions[0].VLAN = "4096" },
		func(m *Manifest) { m.Sessions[0].Transport = "tcp" },
		func(m *Manifest) { m.Sessions[0].Protocol = "http" },
		func(m *Manifest) { m.Sessions[0].Protocol = "unknown" },
		func(m *Manifest) { m.Sessions[0].RetainedBytes-- },
		func(m *Manifest) { m.Sessions = nil },
		func(m *Manifest) { m.Capture.Retention = nil },
		func(m *Manifest) { m.Capture.Retention.PolicyRevision = 0 },
		func(m *Manifest) { m.Capture.Retention.Degradation = "invalid" },
		func(m *Manifest) { m.Capture.Retention.Degradation = keepRaw },
	} {
		damaged := *archived.Manifest
		retention := *damaged.Capture.Retention
		damaged.Capture.Retention = &retention
		damaged.Sessions = slices.Clone(damaged.Sessions)
		change(&damaged)
		if damaged.Validate() == nil {
			t.Fatal("错误的留存目录通过验证", damaged.Sessions)
		}
	}
}

func TestRetentionAlertHistoryEvictionAndUnknownPolicyFailOpen(t *testing.T) {
	s, db := retentionSpool(t)
	frames := sessionFrames(t)
	at := frames[0].info.Timestamp.Add(-time.Second)
	unset := hotRetention(t, s, "unset", at, frames)
	sealRetention(t, unset, at.Add(2*time.Second))
	record, _ := retainedRecord(t, s, unset.ID)
	if record.Capture.Retention.PolicyRevision != 0 || record.Code != invalidPolicy || record.Capture.Retention.OriginalBytes != record.Capture.PacketBytes {
		t.Fatal("首次策略读取失败丢失原件", record.Code)
	}

	installRetention(t, s, `{"network_domain":"test_domain","revision":1,"mode":"alert_only"}`)
	retentionAlertFor(t, db, "original", "eth0", 40000, frames[2].info.Timestamp)
	archived := hotRetention(t, s, "older", at, frames)
	sealRetention(t, archived, at.Add(2*time.Second))
	retentionAlertFor(t, db, "newer", "eth0", 40002, at.Add(retentionAlertHistory+time.Minute))
	record, _ = retainedRecord(t, s, archived.ID)
	if record.Code != alertGap || record.Capture.Retention.OriginalBytes != record.Capture.PacketBytes {
		t.Fatal("窗口过期后错误地裁剪未封段告警的原件", record.Code)
	}
}

func TestRetentionFlowBudgetFallsBackToAnUnchangedRawSegment(t *testing.T) {
	s, _ := retentionSpool(t)
	installRetention(t, s, `{"network_domain":"test_domain","revision":1,"mode":"alert_only"}`)
	frame := sessionFrames(t)[0]
	frames := make([]sessionFrame, 0, maxSessionRecords+1)
	for i := 0; i <= maxSessionRecords; i++ {
		frames = append(frames, mutateSessionTCP(t, frame, func(tcp *layers.TCP) { tcp.SrcPort = layers.TCPPort(30000 + i) }))
	}
	at := frame.info.Timestamp
	p := hotRetention(t, s, "over_budget", at, frames)
	sealRetention(t, p, at.Add(time.Second))
	row, final := retainedRecord(t, s, p.ID)
	if row.Code != sessionBudget || row.Capture.Retention.Mode != RetentionFull || len(row.Manifest.Sessions) != 0 {
		t.Fatal("目录超额时裁剪了无法列明的会话", row.Code)
	}
	original, err := os.ReadFile(filepath.Join(s.Dir, p.ID+".raw"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(final)
	if err != nil || !bytes.Equal(body, original) {
		t.Fatal("目录超额回退未原样保存", err)
	}
}
