package packetarchive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/kkx600/StarBeacon/internal/contract"
)

const MaxSessionInputs = 16
const MaxSessionInputBytes int64 = 256 * 1024 * 1024
const maxSessionPackets = 1048576
const maxDirectionBytes = 32 * 1024 * 1024

var ErrSessionIncomplete = errors.New("所选原包未满足完整 TCP 会话条件")

// SessionRequest 固定双方的网络与链路层身份；不将端口复用、跨探针或 NAT 候选自动合并。
type SessionRequest struct {
	ArchiveIDs []string `json:"archive_ids"`
	Mode       string   `json:"mode"`
	ClientIP   string   `json:"client_ip"`
	ClientPort uint16   `json:"client_port"`
	ServerIP   string   `json:"server_ip"`
	ServerPort uint16   `json:"server_port"`
	ClientMAC  string   `json:"client_mac"`
	ServerMAC  string   `json:"server_mac"`
	VLANs      []uint16 `json:"vlans"`
}

func (r *SessionRequest) UnmarshalJSON(raw []byte) error {
	fields := []string{"archive_ids", "mode", "client_ip", "client_port", "server_ip", "server_port", "client_mac", "server_mac", "vlans"}
	if contract.JSONFields(string(raw), fields, 32768) != nil {
		return ErrIntegrity
	}
	type value SessionRequest
	var decoded value
	reader := json.NewDecoder(bytes.NewReader(raw))
	reader.DisallowUnknownFields()
	if reader.Decode(&decoded) != nil || reader.Decode(new(any)) != io.EOF {
		return ErrIntegrity
	}
	*r = SessionRequest(decoded)
	if r.VLANs == nil {
		r.VLANs = []uint16{}
	}
	return r.Validate()
}

func (r SessionRequest) Validate() error {
	if len(r.ArchiveIDs) < 1 || len(r.ArchiveIDs) > MaxSessionInputs || r.Mode != "full_session" && r.Mode != "snapshot" || r.ClientPort == 0 || r.ServerPort == 0 || len(r.VLANs) > 8 {
		return ErrIntegrity
	}
	seen := map[string]bool{}
	for _, id := range r.ArchiveIDs {
		if !contract.ValidID(id) || seen[id] {
			return ErrIntegrity
		}
		seen[id] = true
	}
	for _, value := range []string{r.ClientIP, r.ServerIP} {
		ip, e := netip.ParseAddr(value)
		if e != nil || ip.Zone() != "" || ip.Is4In6() || ip.IsUnspecified() || ip.IsMulticast() || ip.String() != value {
			return ErrIntegrity
		}
	}
	if r.ClientIP == r.ServerIP && r.ClientPort == r.ServerPort {
		return ErrIntegrity
	}
	for _, value := range []string{r.ClientMAC, r.ServerMAC} {
		mac, e := net.ParseMAC(value)
		if e != nil || len(mac) != 6 || mac.String() != value {
			return ErrIntegrity
		}
	}
	for _, v := range r.VLANs {
		if v > 4095 {
			return ErrIntegrity
		}
	}
	return nil
}

type SessionInput struct {
	Manifest      Manifest
	ObjectVersion string
	File          *os.File
}
type SessionReference struct {
	ID             string `json:"id"`
	ObjectVersion  string `json:"object_version"`
	RawSHA256      string `json:"raw_sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
}
type SessionReport struct {
	Schema             string             `json:"schema"`
	Request            SessionRequest     `json:"request"`
	Sources            []SessionReference `json:"sources"`
	Completeness       string             `json:"completeness"`
	Handshake          string             `json:"handshake_status"`
	Bidirectional      string             `json:"bidirectional_status"`
	PayloadCoverage    string             `json:"payload_coverage"`
	PayloadVisibility  string             `json:"payload_visibility"`
	Termination        string             `json:"termination_status"`
	ChecksumValidation string             `json:"checksum_validation"`
	Packets            uint64             `json:"packets"`
	PacketBytes        uint64             `json:"packet_bytes"`
	FirstPacketAt      *time.Time         `json:"first_packet_at"`
	LastPacketAt       *time.Time         `json:"last_packet_at"`
	Reasons            []string           `json:"reasons"`
}

type sessionSpan struct {
	offset uint32
	data   []byte
}
type sessionHalf struct {
	syn       bool
	seq       uint32
	fin       bool
	finOffset uint32
	maxACK    uint32
	spans     []sessionSpan
	bytes     int64
}
type sessionProof struct {
	report    SessionReport
	half      [2]sessionHalf
	synAck    bool
	handshake bool
	reset     bool
	macs      [2][]byte
	ips       [2]netip.Addr
}

func (p *sessionProof) reason(code string) {
	if !slices.Contains(p.report.Reasons, code) {
		p.report.Reasons = append(p.report.Reasons, code)
	}
}

func prepareSession(ctx context.Context, request SessionRequest, inputs []SessionInput) ([]SessionInput, *sessionProof, error) {
	if request.Validate() != nil || len(inputs) != len(request.ArchiveIDs) {
		return nil, nil, ErrIntegrity
	}
	ordered := slices.Clone(inputs)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Manifest.Capture.StartedAt.Before(ordered[j].Manifest.Capture.StartedAt)
	})
	p := &sessionProof{report: SessionReport{Schema: "packet.session.v1", Request: request, Sources: []SessionReference{}, Completeness: "snapshot", Handshake: "not_observed", Bidirectional: "one_sided", PayloadCoverage: "unknown", PayloadVisibility: "unknown", Termination: "not_observed", ChecksumValidation: "not_checked", Reasons: []string{}}}
	p.macs[0], _ = net.ParseMAC(request.ClientMAC)
	p.macs[1], _ = net.ParseMAC(request.ServerMAC)
	p.ips[0], _ = netip.ParseAddr(request.ClientIP)
	p.ips[1], _ = netip.ParseAddr(request.ServerIP)
	seen := map[string]bool{}
	var total int64
	base := ordered[0].Manifest.Capture
	for i, v := range ordered {
		c := v.Manifest.Capture
		if v.File == nil || v.Manifest.Validate() != nil || !ValidObjectVersion(v.ObjectVersion) || !slices.Contains(request.ArchiveIDs, c.ID) || seen[c.ID] || c.TenantID != base.TenantID || c.SensorID != base.SensorID || c.RegistrationID != base.RegistrationID || c.RunID != base.RunID || c.Interface != base.Interface || c.InterfaceMAC != base.InterfaceMAC || c.SettingsSHA256 != base.SettingsSHA256 {
			return nil, nil, ErrIntegrity
		}
		seen[c.ID] = true
		total += v.Manifest.Encoding.RawBytes
		if total > MaxSessionInputBytes {
			return nil, nil, ErrLimit
		}
		if i > 0 && c.StartedAt.Before(ordered[i-1].Manifest.Capture.EndedAt) {
			p.reason("overlapping_capture_windows")
		}
		if c.KernelDrops == nil {
			p.reason("capture_drop_counter_unavailable")
		} else if *c.KernelDrops != 0 {
			p.reason("capture_drops_observed")
		}
		if c.TruncatedPackets > 0 {
			p.reason("capture_truncation_observed")
		}
		if c.VLANOffloadPackets > 0 {
			p.reason("vlan_bytes_unavailable")
		}
		if _, e := v.File.Seek(0, io.SeekStart); e != nil {
			return nil, nil, e
		}
		info, e := v.File.Stat()
		if e != nil {
			return nil, nil, e
		}
		if !info.Mode().IsRegular() || info.Size() != v.Manifest.Encoding.RawBytes {
			return nil, nil, ErrIntegrity
		}
		hash := sha256.New()
		if _, e := io.Copy(hash, contextReader{ctx: ctx, reader: v.File}); e != nil {
			return nil, nil, e
		}
		if hex.EncodeToString(hash.Sum(nil)) != v.Manifest.Encoding.RawSHA256 {
			return nil, nil, ErrIntegrity
		}
		if e := ValidateRawFile(ctx, v.File, c); e != nil {
			return nil, nil, e
		}
		_, manifestSHA, e := v.Manifest.JSON()
		if e != nil {
			return nil, nil, e
		}
		p.report.Sources = append(p.report.Sources, SessionReference{c.ID, v.ObjectVersion, v.Manifest.Encoding.RawSHA256, manifestSHA})
	}
	if ordered[len(ordered)-1].Manifest.Capture.EndedAt.Sub(base.StartedAt) > time.Hour {
		return nil, nil, ErrLimit
	}
	return ordered, p, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.reader.Read(b)
}

// walkSession 使用锁版 PCAPNG 读取器；零拷贝报文仅在当前回调内有效。
func walkSession(ctx context.Context, inputs []SessionInput, proof *sessionProof, observe bool, write func([]byte, gopacket.CaptureInfo, pcapgo.NgPacketOptions, Capture) error) error {
	var scanned uint64
	for _, input := range inputs {
		if _, e := input.File.Seek(0, io.SeekStart); e != nil {
			return e
		}
		reader, e := pcapgo.NewNgReader(input.File, pcapgo.DefaultNgReaderOptions)
		if e != nil {
			return e
		}
		for {
			if e = ctx.Err(); e != nil {
				return e
			}
			raw, ci, opts, e := reader.ZeroCopyReadPacketDataWithOptions()
			if e == io.EOF {
				break
			}
			if e != nil {
				return e
			}
			scanned++
			if scanned > maxSessionPackets {
				return ErrLimit
			}
			tcp, direction, matched := proof.match(raw, observe)
			if !matched {
				continue
			}
			if observe {
				proof.report.Packets++
				proof.report.PacketBytes += uint64(len(raw))
				if proof.report.PacketBytes > uint64(MaxSegmentBytes-65536) {
					return ErrLimit
				}
				stamp := ci.Timestamp.UTC()
				if proof.report.FirstPacketAt == nil || stamp.Before(*proof.report.FirstPacketAt) {
					proof.report.FirstPacketAt = &stamp
				}
				if proof.report.LastPacketAt == nil || stamp.After(*proof.report.LastPacketAt) {
					proof.report.LastPacketAt = &stamp
				}
				if ci.CaptureLength < ci.Length {
					proof.reason("selected_packet_truncated")
				}
				if e = proof.observe(tcp, direction); e != nil {
					return e
				}
			}
			if write != nil {
				if e = write(raw, ci, opts, input.Manifest.Capture); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
func (p *sessionProof) match(raw []byte, observe bool) (*layers.TCP, int, bool) {
	packet := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: false, NoCopy: true})
	ethernet, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if !ok {
		return nil, 0, false
	}
	direction := -1
	if bytes.Equal(ethernet.SrcMAC, p.macs[0]) && bytes.Equal(ethernet.DstMAC, p.macs[1]) {
		direction = 0
	} else if bytes.Equal(ethernet.SrcMAC, p.macs[1]) && bytes.Equal(ethernet.DstMAC, p.macs[0]) {
		direction = 1
	}
	if direction < 0 {
		return nil, 0, false
	}
	var source, destination netip.Addr
	switch ip := packet.NetworkLayer().(type) {
	case *layers.IPv4:
		source, _ = netip.AddrFromSlice(ip.SrcIP)
		destination, _ = netip.AddrFromSlice(ip.DstIP)
	case *layers.IPv6:
		source, _ = netip.AddrFromSlice(ip.SrcIP)
		destination, _ = netip.AddrFromSlice(ip.DstIP)
	default:
		return nil, 0, false
	}
	if source != p.ips[direction] || destination != p.ips[1-direction] {
		return nil, 0, false
	}
	vlans := []uint16{}
	networks := 0
	for _, layer := range packet.Layers() {
		switch v := layer.(type) {
		case *layers.Dot1Q:
			vlans = append(vlans, v.VLANIdentifier)
		case *layers.IPv4, *layers.IPv6:
			networks++
		}
	}
	if !slices.Equal(vlans, p.report.Request.VLANs) {
		return nil, 0, false
	}
	if networks != 1 || packet.Layer(layers.LayerTypeIPv6Fragment) != nil {
		if observe {
			p.reason("fragment_or_tunnel_scope_unsupported")
		}
		return nil, 0, false
	}
	if ip, ok := packet.NetworkLayer().(*layers.IPv4); ok && (ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0) {
		if observe {
			p.reason("fragment_or_tunnel_scope_unsupported")
		}
		return nil, 0, false
	}
	tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		return nil, 0, false
	}
	ports := [2]uint16{p.report.Request.ClientPort, p.report.Request.ServerPort}
	if uint16(tcp.SrcPort) != ports[direction] || uint16(tcp.DstPort) != ports[1-direction] {
		return nil, 0, false
	}
	if packet.ErrorLayer() != nil || packet.Metadata().Truncated {
		if observe {
			p.reason("packet_decode_unconfirmed")
		}
	}
	return tcp, direction, true
}
func (p *sessionProof) observe(tcp *layers.TCP, direction int) error {
	h, peer := &p.half[direction], &p.half[1-direction]
	if p.reset && len(tcp.Payload) > 0 {
		p.reason("payload_after_reset")
	}
	if tcp.SYN {
		if h.syn && h.seq != tcp.Seq {
			p.reason("tuple_reuse_or_simultaneous_open")
			return nil
		}
		h.syn, h.seq = true, tcp.Seq
		if len(tcp.Payload) > 0 {
			p.reason("tcp_fast_open_unqualified")
		}
		if direction == 1 {
			if !tcp.ACK || !peer.syn || tcp.Ack != peer.seq+1 {
				p.reason("syn_ack_unconfirmed")
			} else {
				p.synAck = true
			}
		} else if tcp.ACK {
			p.reason("tuple_reuse_or_simultaneous_open")
		}
	}
	if direction == 0 && p.synAck && !tcp.SYN && tcp.ACK && tcp.Seq == h.seq+1 && tcp.Ack == peer.seq+1 {
		p.handshake = true
	}
	if !h.syn {
		p.reason("connection_start_not_observed")
		return nil
	}
	offset := tcp.Seq - (h.seq + 1)
	if tcp.SYN {
		offset = 0
	}
	if offset > maxDirectionBytes || uint64(offset)+uint64(len(tcp.Payload)) > maxDirectionBytes {
		p.reason("sequence_space_unqualified")
		return nil
	}
	if tcp.ACK && peer.syn {
		ack := tcp.Ack - (peer.seq + 1)
		if ack > maxDirectionBytes+1 {
			p.reason("acknowledgement_space_unqualified")
		} else if ack > peer.maxACK {
			peer.maxACK = ack
		}
	}
	if len(tcp.Payload) > 0 {
		h.bytes += int64(len(tcp.Payload))
		if h.bytes > int64(MaxSegmentBytes) {
			return ErrLimit
		}
		h.spans = append(h.spans, sessionSpan{offset, bytes.Clone(tcp.Payload)})
	}
	if tcp.FIN {
		position := offset + uint32(len(tcp.Payload))
		if h.fin && h.finOffset != position {
			p.reason("fin_sequence_conflict")
		}
		h.fin, h.finOffset = true, position
	}
	if tcp.RST {
		p.reset = true
	}
	return nil
}
func (p *sessionProof) finish() {
	if p.half[0].syn && p.half[1].syn {
		p.report.Bidirectional = "observed"
	}
	if p.handshake {
		p.report.Handshake = "verified"
	} else {
		p.reason("handshake_not_verified")
	}
	contiguous := true
	for i := range p.half {
		h := &p.half[i]
		sort.SliceStable(h.spans, func(i, j int) bool { return h.spans[i].offset < h.spans[j].offset })
		var base, end uint32
		var merged []byte
		for _, span := range h.spans {
			if span.offset > end {
				p.reason("payload_sequence_gap")
				contiguous = false
				base = span.offset
				merged = nil
				end = span.offset
			}
			overlap := min(end-span.offset, uint32(len(span.data)))
			if overlap > 0 && !bytes.Equal(merged[span.offset-base:span.offset-base+overlap], span.data[:overlap]) {
				p.reason("conflicting_retransmission")
				contiguous = false
			}
			merged = append(merged, span.data[overlap:]...)
			end = span.offset + uint32(len(span.data[overlap:])) + overlap
			// 完全包含的重传不降低已观察连续区间的结束位置。
			end = max(end, base+uint32(len(merged)))
		}
		if h.fin && h.finOffset != end {
			p.reason("payload_or_fin_sequence_gap")
			contiguous = false
		}
		covered := end
		if h.fin {
			covered++
		}
		if h.maxACK > covered {
			p.reason("peer_acknowledges_missing_bytes")
			contiguous = false
		}
		if !h.fin || h.maxACK != h.finOffset+1 {
			p.reason("connection_end_not_verified")
		}
	}
	if contiguous && p.handshake {
		p.report.PayloadCoverage = "contiguous_verified"
	} else if !contiguous {
		p.report.PayloadCoverage = "gap_detected"
	}
	if p.reset {
		p.report.Termination = "rst_observed"
		p.reason("reset_acceptance_unqualified")
	} else if p.half[0].fin && p.half[1].fin && p.half[0].maxACK == p.half[0].finOffset+1 && p.half[1].maxACK == p.half[1].finOffset+1 {
		p.report.Termination = "fin_verified"
	} else if p.handshake {
		p.report.Termination = "active_at_cutoff"
	}
	if p.report.Packets == 0 {
		p.reason("no_matching_packets")
	}
	if len(p.report.Reasons) == 0 && p.report.Handshake == "verified" && p.report.Termination == "fin_verified" {
		p.report.Completeness = "full_session"
	}
}

// ExportSession 只复制实际匹配的原始帧。严格条件不足时不输出文件，也不自动降级为快照。
// 容器、时间和选项由官方库处理；载荷可见性及端到端校验和始终与字节连续性分开。
func ExportSession(ctx context.Context, target io.Writer, request SessionRequest, inputs []SessionInput) (report SessionReport, err error) {
	defer func() {
		if recover() != nil {
			err = ErrIntegrity
		}
	}()
	ordered, proof, err := prepareSession(ctx, request, inputs)
	if err != nil {
		return report, err
	}
	if err = walkSession(ctx, ordered, proof, true, nil); err != nil {
		return proof.report, err
	}
	proof.finish()
	report = proof.report
	if report.Packets == 0 || request.Mode == "full_session" && report.Completeness != "full_session" {
		return report, ErrSessionIncomplete
	}
	if target == nil {
		return report, ErrIntegrity
	}
	// 明确选择快照时，即使闭合序列齐全，文件仍采用调用方请求的快照标签。
	if request.Mode == "snapshot" {
		report.Completeness = "snapshot"
	}
	metadata, err := json.Marshal(report)
	if err != nil || len(metadata) > 49152 {
		return report, ErrLimit
	}
	base := ordered[0].Manifest.Capture
	counter := &boundedSessionWriter{target: target}
	writer, err := pcapgo.NewNgWriterInterface(counter, pcapgo.NgInterface{Name: base.Interface, Comment: "MAC=" + base.InterfaceMAC, Filter: base.BPFFilter, LinkType: layers.LinkTypeEthernet, SnapLength: SnapLength, TimestampResolution: 9}, pcapgo.NgWriterOptions{SectionInfo: pcapgo.NgSectionInfo{Application: "StarBeacon", Comment: string(metadata)}})
	if err != nil {
		return report, err
	}
	var sequence uint64
	err = walkSession(ctx, ordered, proof, false, func(raw []byte, ci gopacket.CaptureInfo, opts pcapgo.NgPacketOptions, c Capture) error {
		if opts.PacketID == nil {
			return ErrIntegrity
		}
		original := *opts.PacketID
		sequence++
		opts.PacketID = &sequence
		opts.Comments = append(slices.Clone(opts.Comments), fmt.Sprintf("StarBeacon: archive_id=%s; packet_id=%d", c.ID, original))
		return writer.WritePacketWithOptions(ci, raw, opts)
	})
	if err == nil {
		err = writer.Flush()
	}
	return report, err
}

type boundedSessionWriter struct {
	target io.Writer
	size   int64
}

func (w *boundedSessionWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > MaxSegmentBytes-w.size {
		return 0, ErrLimit
	}
	n, e := w.target.Write(p)
	w.size += int64(n)
	if n < len(p) && e == nil {
		e = io.ErrShortWrite
	}
	return n, e
}
