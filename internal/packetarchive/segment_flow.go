package packetarchive

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/kkx600/StarBeacon/internal/contract"
)

// SegmentFlowRequest 标识冻结切片中的双向五元组与 VLAN，不推断通信方向或连接完整性。
type SegmentFlowRequest struct {
	flowKey
	ManifestSHA256 string `json:"manifest_sha256"`
	RawSHA256      string `json:"archive_raw_sha256"`
}

func (r *SegmentFlowRequest) UnmarshalJSON(raw []byte) error {
	fields := []string{"endpoint_a", "endpoint_b", "transport", "vlan", "manifest_sha256", "archive_raw_sha256"}
	if contract.JSONFields(string(raw), fields, 2048) != nil {
		return ErrIntegrity
	}
	type request SegmentFlowRequest
	var parsed request
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return err
	}
	*r = SegmentFlowRequest(parsed)
	return r.validate()
}

func (r SegmentFlowRequest) validate() error {
	if !r.flowKey.valid() || !validDigest(r.ManifestSHA256) || !validDigest(r.RawSHA256) {
		return ErrIntegrity
	}
	return nil
}

type SegmentFlow struct {
	Request   SegmentFlowRequest `json:"flow"`
	Retention string             `json:"retention"`
	Capture   Capture            `json:"-"`
	packets   []retrievedPacket
}

type SegmentFlowInspection struct {
	PacketInspection
	Flow      SegmentFlowRequest `json:"flow"`
	Retention string             `json:"retention"`
}

// ReadSegmentFlow 从查证过的归档范围提取当前轮转窗口的报文。按原捕获序号排序并保留原始帧。
func ReadSegmentFlow(ctx context.Context, request SegmentFlowRequest, input SessionInput) (out SegmentFlow, err error) {
	defer func() {
		if recover() != nil {
			err = ErrIntegrity
		}
	}()
	if request.validate() != nil || !ValidObjectVersion(input.ObjectVersion) {
		return out, ErrIntegrity
	}
	m := input.Manifest
	_, digest, err := m.JSON()
	if err != nil || request.ManifestSHA256 != digest || request.RawSHA256 != m.Encoding.RawSHA256 {
		return out, ErrIntegrity
	}
	key := request.flowKey
	out = SegmentFlow{Request: request, Retention: retainAll, Capture: m.Capture}
	var matchedBytes uint64
	seen := make(map[uint64]struct{})
	visit := func(raw []byte, ci gopacket.CaptureInfo, opts pcapgo.NgPacketOptions) error {
		if retentionFlow(raw, captureVLAN(opts)).key != key {
			return nil
		}
		if opts.PacketID == nil || *opts.PacketID == 0 {
			return ErrIntegrity
		}
		if _, exists := seen[*opts.PacketID]; exists {
			return ErrIntegrity
		}
		seen[*opts.PacketID] = struct{}{}
		matchedBytes += uint64(len(raw))
		if matchedBytes > m.Capture.PacketBytes || uint64(len(out.packets)) >= m.Capture.Packets {
			return ErrIntegrity
		}
		out.packets = append(out.packets, retainPacket(raw, ci, opts))
		return nil
	}
	if m.Encoding.Schema == PackedSchema {
		if input.Index == nil || !input.Index.valid(m) {
			return out, ErrIntegrity
		}
		i, found := slices.BinarySearchFunc(input.Index.Flows, key, func(flow IndexedFlow, target flowKey) int { return flowOrder(flow.flowKey, target) })
		if !found || input.Index.Flows[i].State == retainMetadata {
			return out, ErrPacketNotFound
		}
		flow := input.Index.Flows[i]
		out.Retention = flow.State
		if err := walkIndexedFlow(ctx, input, key, visit); err != nil {
			return out, err
		}
		if uint64(len(out.packets)) != flow.Packets || matchedBytes != flow.RetainedBytes {
			return out, ErrIntegrity
		}
	} else {
		if input.File == nil {
			return out, ErrIntegrity
		}
		if err := verifySessionFile(ctx, input); err != nil {
			return out, err
		}
		reader, err := pcapgo.NewNgReader(input.File, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return out, err
		}
		if err := walkArchivePackets(ctx, reader, visit); err != nil {
			return out, err
		}
		for _, session := range m.Sessions {
			if session.flowKey == key {
				out.Retention = session.State
				if matchedBytes != session.RetainedBytes {
					return out, ErrIntegrity
				}
				break
			}
		}
	}
	if len(out.packets) == 0 {
		return out, ErrPacketNotFound
	}
	slices.SortFunc(out.packets, func(a, b retrievedPacket) int { return cmp.Compare(*a.options.PacketID, *b.options.PacketID) })
	return out, nil
}

func (f SegmentFlow) Inspect(number int) (SegmentFlowInspection, error) {
	if number < 1 || number > len(f.packets) {
		return SegmentFlowInspection{}, ErrPacketNotFound
	}
	packet := f.packets[number-1]
	out := inspectFrame(packet.raw, packet.info)
	out.ArchiveID, out.ManifestSHA256, out.RawSHA256 = f.Capture.ID, f.Request.ManifestSHA256, f.Request.RawSHA256
	out.Number, out.Total, out.Interface = number, uint64(len(f.packets)), f.Capture.Interface
	out.VLANOffload = captureVLAN(packet.options) != nil
	return SegmentFlowInspection{PacketInspection: out, Flow: f.Request, Retention: f.Retention}, nil
}

func (f SegmentFlow) WriteSnapshot(ctx context.Context, target io.Writer) error {
	if len(f.packets) == 0 {
		return ErrPacketNotFound
	}
	metadata, err := json.Marshal(struct {
		Schema       string `json:"schema"`
		Completeness string `json:"completeness"`
		ArchiveID    string `json:"archive_id"`
		SegmentFlow
	}{Schema: "packet.segment-snapshot.v1", Completeness: "snapshot", ArchiveID: f.Capture.ID, SegmentFlow: f})
	if err != nil {
		return err
	}
	c := f.Capture
	writer, err := pcapgo.NewNgWriterInterface(&boundedSessionWriter{target: target}, pcapgo.NgInterface{Name: c.Interface, Comment: "MAC=" + c.InterfaceMAC, Filter: c.BPFFilter, LinkType: layers.LinkTypeEthernet, SnapLength: SnapLength, TimestampResolution: 9}, pcapgo.NgWriterOptions{SectionInfo: pcapgo.NgSectionInfo{Application: "StarBeacon", Comment: string(metadata)}})
	if err != nil {
		return err
	}
	for i, packet := range f.packets {
		if err := ctx.Err(); err != nil {
			return err
		}
		options := packet.options
		sequence := uint64(i + 1)
		options.Comments = append(slices.Clone(options.Comments), fmt.Sprintf("StarBeacon: archive_id=%s; packet_id=%d", c.ID, *options.PacketID))
		options.PacketID = &sequence
		if err := writer.WritePacketWithOptions(packet.info, packet.raw, options); err != nil {
			return err
		}
	}
	return writer.Flush()
}
