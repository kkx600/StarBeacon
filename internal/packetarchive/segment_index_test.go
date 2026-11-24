package packetarchive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/kkx600/StarBeacon/internal/testpcap"
)

func indexedFixture(t *testing.T) (*Spool, LocalRecord, []testpcap.SegmentFrame) {
	t.Helper()
	s, _ := retentionSpool(t)
	s.SegmentBytes = 8 << 20
	installRetention(t, s, `{"network_domain":"test_domain","revision":1,"mode":"full"}`)
	mixed, selected, err := testpcap.IndexedSegment()
	if err != nil {
		t.Fatal(err)
	}
	frames := make([]sessionFrame, 0, len(mixed))
	for _, frame := range mixed {
		frames = append(frames, sessionFrame{frame.Raw, frame.Info})
	}
	start := frames[0].info.Timestamp.Add(-time.Second)
	pending := hotRetention(t, s, "indexed", start, frames)
	sealRetention(t, pending, frames[len(frames)-1].info.Timestamp.Add(time.Second))
	row, _ := retainedRecord(t, s, pending.ID)
	return s, row, selected
}

func TestPackedSegmentRangeReadsAdaptivelyEncodedFlowAndKeepsPacketIdentity(t *testing.T) {
	ctx := context.Background()
	s, row, expected := indexedFixture(t)
	m := *row.Manifest
	if m.Encoding.Schema != PackedSchema || m.Encoding.Level != "zstd-3" || len(m.Encoding.Frames) < 5 {
		t.Fatalf("定稿帧格式不正确 %+v", m.Encoding)
	}
	methods := map[string]bool{}
	for _, frame := range m.Encoding.Frames[1 : len(m.Encoding.Frames)-1] {
		methods[frame.Codec] = true
	}
	if !methods["none"] || !methods["zstd"] {
		t.Fatal("高熵帧和易压缩帧使用了同一编码", methods)
	}
	stored, _, err := s.OpenStored(row.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer stored.Close()
	index, err := row.Index.Decode(m)
	if err != nil || len(index.Flows) != 3 {
		t.Fatal("三个双向流目录未生成", err)
	}
	key, _ := orderedFlow(netip.MustParseAddrPort("192.0.2.10:40000"), netip.MustParseAddrPort("198.51.100.20:80"), "tcp", "")
	selected := index.framesFor(key)
	if !hasFrame(selected, 1) {
		t.Fatal("同一流没有聚集在同一帧")
	}
	for i := 2; i < len(m.Encoding.Frames); i++ {
		if hasFrame(selected, i) {
			t.Fatal("同一会话散落到其他帧", i)
		}
	}
	var observed []int64
	ranges := func(ctx context.Context, offset, size int64) (io.ReadCloser, error) {
		observed = append(observed, offset)
		return RangeFile(stored)(ctx, offset, size)
	}
	request := sessionRequest(row.ID)
	input := SessionInput{Manifest: m, ObjectVersion: "indexed_version", Range: ranges, Index: &index}
	var output bytes.Buffer
	report, err := ExportSession(ctx, &output, request, []SessionInput{input})
	if err != nil || report.Completeness != "full_session" || !slices.Equal(observed, []int64{m.Encoding.Frames[1].StoredOffset}) {
		t.Fatalf("会话导出读取了无关帧或未证明完整 %+v %v %v", report.Reasons, observed, err)
	}
	reader, err := pcapgo.NewNgReader(bytes.NewReader(output.Bytes()), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	for i, expected := range expected {
		raw, info, options, err := reader.ReadPacketDataWithOptions()
		if err != nil || !bytes.Equal(raw, expected.Raw) || !info.Timestamp.Equal(expected.Info.Timestamp) || len(options.Comments) == 0 ||
			options.Comments[0] != "StarBeacon: archive_id=indexed; packet_id="+decimal(uint64(i*9+1)) {
			t.Fatal("导出丢失字节、纳秒时间或原始捕获序号", i, options, err)
		}
	}
	request.ClientPort = 1234
	observed = nil
	_, err = ExportSession(ctx, io.Discard, request, []SessionInput{input})
	if !errors.Is(err, ErrSessionIncomplete) || len(observed) != 0 {
		t.Fatal("端点缺失时仍读取归档", observed, err)
	}
	original, _, err := testpcap.IndexedSegment()
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := InspectPacket(ctx, RangeFile(stored), m, s.Dir, 2)
	if err != nil || inspection.PacketSHA256 != Digest(original[1].Raw) || !inspection.CapturedAt.Equal(original[1].Info.Timestamp) {
		t.Fatal("聚簇改变了逐包查看的捕获顺序", err)
	}
}

func TestFlowIndexIntegrityRebuildAndCorruptRange(t *testing.T) {
	ctx := context.Background()
	s, row, _ := indexedFixture(t)
	m := *row.Manifest
	stored, _, err := s.OpenStored(row.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer stored.Close()
	broken := row.Index
	broken.Data = append(bytes.Clone(broken.Data), 0)
	if err = s.update(row.ID, func(r *LocalRecord) error { r.Index = broken; return nil }); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.Record(row.ID)
	if err != nil {
		t.Fatal(err)
	}
	index, err := s.RebuildIndex(ctx, stored, loaded)
	if err != nil || len(index.Flows) != 3 {
		t.Fatal("损坏索引无法从原包重建", err)
	}
	fixed, err := s.Record(row.ID)
	if err != nil || fixed.Index.SHA256 != row.Index.SHA256 || !bytes.Equal(fixed.Index.Data, row.Index.Data) {
		t.Fatal("重建改变了冻结索引的内容", err)
	}
	notTouched := func(context.Context, int64, int64) (io.ReadCloser, error) {
		t.Fatal("完好索引应直接使用")
		return nil, os.ErrNotExist
	}
	if _, err = ResolveSegmentIndex(ctx, fixed.Index, m, notTouched, s.Dir, func(IndexRecord) error { t.Fatal("已有索引不应持久化"); return nil }); err != nil {
		t.Fatal(err)
	}
	deny := errors.New("索引目录不可写")
	ranges := RangeFile(stored)
	for _, tc := range []struct {
		name, staging string
		source        RangeSource
		save          func(IndexRecord) error
		want          error
	}{
		{"遗漏写回", s.Dir, ranges, nil, ErrIntegrity},
		{"缺失暂存", filepath.Join(s.Dir, "missing"), ranges, func(IndexRecord) error { return nil }, os.ErrNotExist},
		{"对象读取中断", s.Dir, func(context.Context, int64, int64) (io.ReadCloser, error) { return nil, io.ErrUnexpectedEOF }, func(IndexRecord) error { return nil }, io.ErrUnexpectedEOF},
		{"索引写回失败", s.Dir, ranges, func(IndexRecord) error { return deny }, deny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ResolveSegmentIndex(ctx, broken, m, tc.source, tc.staging, tc.save); !errors.Is(err, tc.want) {
				t.Fatal("重建失败原因未保留", err)
			}
		})
	}
	for _, damage := range []func(*SegmentIndex){
		func(index *SegmentIndex) { index.Schema = "unknown" },
		func(index *SegmentIndex) { index.Header[0] ^= 1 },
		func(index *SegmentIndex) { index.Addresses[0] ^= 1 },
		func(index *SegmentIndex) { index.Flows[0].Frames[0] |= 1 },
		func(index *SegmentIndex) { index.Flows[0].Packets = 0 },
		func(index *SegmentIndex) { index.Flows[0].State = retainMetadata },
		func(index *SegmentIndex) { index.Flows[0], index.Flows[1] = index.Flows[1], index.Flows[0] },
	} {
		copy, err := row.Index.Decode(m)
		if err != nil {
			t.Fatal(err)
		}
		damage(&copy)
		if _, err = copy.Record(m); !errors.Is(err, ErrIntegrity) {
			t.Fatal("损坏的索引通过验证", err)
		}
	}
	badFrame := func(ctx context.Context, offset, length int64) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(make([]byte, length))), nil
	}
	request := sessionRequest(row.ID)
	if _, err = ExportSession(ctx, io.Discard, request, []SessionInput{{Manifest: m, ObjectVersion: "indexed_version", Range: badFrame, Index: &index}}); !errors.Is(err, ErrIntegrity) {
		t.Fatal("损坏帧被导出", err)
	}
}

func TestPackedSegmentUDPSnapshotAndUnclassifiedFrame(t *testing.T) {
	ctx := context.Background()
	s, _ := retentionSpool(t)
	installRetention(t, s, `{"network_domain":"test_domain","revision":1,"mode":"full"}`)
	frames := sessionFrames(t)
	udpFrame := func(i int) sessionFrame {
		frame := frames[i]
		packet := gopacket.NewPacket(frame.raw, layers.LayerTypeEthernet, gopacket.Default)
		ethernet := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		udp := &layers.UDP{SrcPort: layers.UDPPort(tcp.SrcPort), DstPort: layers.UDPPort(tcp.DstPort)}
		ip.Protocol = layers.IPProtocolUDP
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, udp, gopacket.Payload("测试报文")); err != nil {
			t.Fatal(err)
		}
		frame.raw = buffer.Bytes()
		frame.info.Length, frame.info.CaptureLength = len(frame.raw), len(frame.raw)
		return frame
	}
	fragment := sessionNetworkFrame(t, frames[3], false, nil, func(_ *layers.Ethernet, ip *layers.IPv4) { ip.Flags |= layers.IPv4MoreFragments })
	pending := hotRetention(t, s, "indexed_udp", frames[0].info.Timestamp.Add(-time.Second), []sessionFrame{frames[0], udpFrame(1), udpFrame(2), fragment})
	sealRetention(t, pending, frames[3].info.Timestamp.Add(time.Second))
	row, _ := retainedRecord(t, s, pending.ID)
	store, _, err := s.OpenStored(row.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	index, err := row.Index.Decode(*row.Manifest)
	if err != nil || !hasFrame(index.Unclassified, 1) || len(index.Flows) != 2 {
		t.Fatal("UDP 和未分类帧索引不正确", err)
	}
	req := sessionRequest(row.ID)
	req.Transport = "udp"
	input := SessionInput{Manifest: *row.Manifest, ObjectVersion: "udp_version", Index: &index, Range: RangeFile(store)}
	if _, err = ExportSession(ctx, io.Discard, req, []SessionInput{input}); !errors.Is(err, ErrIntegrity) {
		t.Fatal("UDP 得到了完整 TCP 会话资格", err)
	}
	req.Mode = "snapshot"
	report, err := ExportSession(ctx, io.Discard, req, []SessionInput{input})
	if err != nil || report.Packets != 2 || report.Completeness != "snapshot" || report.Bidirectional != "observed" ||
		!slices.Contains(report.Reasons, "fragment_or_tunnel_scope_unsupported") {
		t.Fatal("UDP 快照混入 TCP 或丢失解析范围", report, err)
	}
	_, proof, err := prepareSession(ctx, req, []SessionInput{input})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := orderedFlow(netip.MustParseAddrPort("192.0.2.10:40000"), netip.MustParseAddrPort("198.51.100.20:80"), "udp", "")
	count, size := uint64(maxSessionPackets), int64(0)
	if _, err = readIndexedSession(ctx, input, key, proof, &count, &size); !errors.Is(err, ErrLimit) {
		t.Fatal("按帧读取超出扫描预算", err)
	}
	count, size = 0, MaxSegmentBytes-65536
	if _, err = readIndexedSession(ctx, input, key, proof, &count, &size); !errors.Is(err, ErrLimit) {
		t.Fatal("按帧读取超出导出预算", err)
	}
}
