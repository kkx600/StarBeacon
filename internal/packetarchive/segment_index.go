package packetarchive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/bits"
	"os"
	"slices"
	"strings"
	"time"
)

const MaxFlowIndexBytes = 1 << 20
const flowIndexSchema = "packet.flow.v1"

type IndexedFlow struct {
	flowKey
	StartedAt     time.Time `json:"started_at"`
	EndedAt       time.Time `json:"ended_at"`
	Packets       uint64    `json:"packets"`
	OriginalBytes uint64    `json:"original_bytes"`
	RetainedBytes uint64    `json:"retained_bytes"`
	State         string    `json:"state"`
	Frames        []byte    `json:"frames"`
}

type SegmentIndex struct {
	Schema       string        `json:"schema"`
	RawSHA256    string        `json:"raw_sha256"`
	Header       []byte        `json:"header"`
	Addresses    []byte        `json:"addresses"`
	Endpoints    []byte        `json:"endpoints"`
	Unclassified []byte        `json:"unclassified"`
	Flows        []IndexedFlow `json:"flows"`
}

// IndexRecord 独立于归档清单，损坏时可以从同一原包对象重建。
type IndexRecord struct {
	Data   []byte
	SHA256 string
}

func (index SegmentIndex) Record(manifest Manifest) (IndexRecord, error) {
	if !index.valid(manifest) {
		return IndexRecord{}, ErrIntegrity
	}
	raw, err := json.Marshal(index)
	if err != nil || len(raw) > MaxFlowIndexBytes {
		return IndexRecord{}, ErrLimit
	}
	return IndexRecord{Data: raw, SHA256: Digest(raw)}, nil
}

func (record IndexRecord) Decode(manifest Manifest) (out SegmentIndex, err error) {
	if len(record.Data) == 0 || len(record.Data) > MaxFlowIndexBytes || Digest(record.Data) != record.SHA256 {
		return out, ErrIntegrity
	}
	reader := json.NewDecoder(bytes.NewReader(record.Data))
	reader.DisallowUnknownFields()
	if reader.Decode(&out) != nil || reader.Decode(new(any)) != io.EOF || !out.valid(manifest) {
		return out, ErrIntegrity
	}
	return out, nil
}

func flowOrder(a, b flowKey) int {
	if cmp := a.A.Compare(b.A); cmp != 0 {
		return cmp
	}
	if cmp := a.B.Compare(b.B); cmp != 0 {
		return cmp
	}
	if cmp := strings.Compare(a.Transport, b.Transport); cmp != 0 {
		return cmp
	}
	return strings.Compare(a.VLAN, b.VLAN)
}

func bitmapSize(frames int) int              { return (frames + 7) / 8 }
func setFrame(bitmap []byte, frame int)      { bitmap[frame/8] |= 1 << (frame % 8) }
func hasFrame(bitmap []byte, frame int) bool { return bitmap[frame/8]&(1<<(frame%8)) != 0 }

func validFrameBitmap(bitmap []byte, frames int) bool {
	if len(bitmap) != bitmapSize(frames) || hasFrame(bitmap, 0) || hasFrame(bitmap, frames-1) {
		return false
	}
	extra := len(bitmap)*8 - frames
	return extra == 0 || bitmap[len(bitmap)-1]>>(8-extra) == 0
}

func bloomSize(flows int) int {
	return 1 << bits.Len(uint(max(31, 4*flows-1)))
}

func bloomMatch(bloom []byte, value string, insert bool) bool {
	hash := sha256.Sum256([]byte(value))
	for offset := 0; offset < 8; offset += 2 {
		bit := int(binary.LittleEndian.Uint16(hash[offset:])) % (len(bloom) * 8)
		if insert {
			setFrame(bloom, bit)
		} else if !hasFrame(bloom, bit) {
			return false
		}
	}
	return true
}

func indexBlooms(flows []IndexedFlow) (addresses, endpoints []byte) {
	addresses, endpoints = make([]byte, bloomSize(len(flows))), make([]byte, bloomSize(len(flows)))
	for _, flow := range flows {
		bloomMatch(addresses, flow.A.Addr().String(), true)
		bloomMatch(addresses, flow.B.Addr().String(), true)
		bloomMatch(endpoints, flow.A.String(), true)
		bloomMatch(endpoints, flow.B.String(), true)
	}
	return addresses, endpoints
}

func (index SegmentIndex) valid(m Manifest) bool {
	frames := m.Encoding.Frames
	if m.Capture.Retention == nil || !m.Capture.Retention.valid(m.Capture) || m.Encoding.Schema != PackedSchema || len(frames) < 2 || index.Schema != flowIndexSchema || index.RawSHA256 != m.Encoding.RawSHA256 ||
		len(index.Header) == 0 || len(index.Header) > maxSectionBytes || int64(len(index.Header)) != frames[0].RawLength || Digest(index.Header) != frames[0].RawSHA256 ||
		len(index.Flows) > maxSessionRecords || !validFrameBitmap(index.Unclassified, len(frames)) {
		return false
	}
	var count, original, retained uint64
	for i, flow := range index.Flows {
		if !flow.flowKey.valid() || i > 0 && flowOrder(index.Flows[i-1].flowKey, flow.flowKey) >= 0 ||
			flow.StartedAt.IsZero() || flow.EndedAt.Before(flow.StartedAt) ||
			flow.Packets > m.Capture.Packets-count || flow.OriginalBytes == 0 || flow.OriginalBytes > m.Capture.Retention.OriginalBytes-original ||
			flow.Packets > flow.RetainedBytes || flow.RetainedBytes > flow.OriginalBytes || flow.RetainedBytes > m.Capture.PacketBytes-retained ||
			flow.State != retentionState(flow.OriginalBytes, flow.RetainedBytes) || !validFrameBitmap(flow.Frames, len(frames)) ||
			(flow.Packets == 0) != !slices.ContainsFunc(flow.Frames, func(value byte) bool { return value != 0 }) {
			return false
		}
		count += flow.Packets
		original += flow.OriginalBytes
		retained += flow.RetainedBytes
	}
	addresses, endpoints := indexBlooms(index.Flows)
	return original == m.Capture.Retention.OriginalBytes-m.Capture.Retention.UnclassifiedBytes &&
		retained == m.Capture.PacketBytes-m.Capture.Retention.UnclassifiedRetainedBytes &&
		bytes.Equal(addresses, index.Addresses) && bytes.Equal(endpoints, index.Endpoints)
}

func (index SegmentIndex) framesFor(key flowKey) []byte {
	selected := slices.Clone(index.Unclassified)
	if !bloomMatch(index.Addresses, key.A.Addr().String(), false) || !bloomMatch(index.Addresses, key.B.Addr().String(), false) ||
		!bloomMatch(index.Endpoints, key.A.String(), false) || !bloomMatch(index.Endpoints, key.B.String(), false) {
		return selected
	}
	i, found := slices.BinarySearchFunc(index.Flows, key, func(flow IndexedFlow, key flowKey) int { return flowOrder(flow.flowKey, key) })
	if found {
		for offset, value := range index.Flows[i].Frames {
			selected[offset] |= value
		}
	}
	return selected
}

func indexSegmentBlocks(ctx context.Context, blocks segmentBlocks, encoding Encoding, c Capture, sessions []RetentionSession) (SegmentIndex, error) {
	frameCount := len(encoding.Frames)
	index := SegmentIndex{Schema: flowIndexSchema, RawSHA256: encoding.RawSHA256, Header: blocks.header, Unclassified: make([]byte, bitmapSize(frameCount)), Flows: []IndexedFlow{}}
	if frameCount < 2 || len(sessions) > maxSessionRecords || encoding.Frames[0].RawLength != int64(len(blocks.header)) ||
		encoding.Frames[frameCount-1].RawOffset != blocks.end.offset || encoding.Frames[frameCount-1].RawLength != int64(blocks.end.size) {
		return index, ErrIntegrity
	}
	positions := make(map[flowKey]int, len(sessions))
	retained := make(map[flowKey]uint64, len(sessions))
	for _, session := range sessions {
		pos, exists := positions[session.flowKey]
		if !exists {
			pos = len(index.Flows)
			positions[session.flowKey] = pos
			index.Flows = append(index.Flows, IndexedFlow{flowKey: session.flowKey, StartedAt: session.StartedAt, EndedAt: session.EndedAt, Frames: make([]byte, bitmapSize(frameCount))})
		}
		flow := &index.Flows[pos]
		if session.StartedAt.Before(flow.StartedAt) {
			flow.StartedAt = session.StartedAt
		}
		if session.EndedAt.After(flow.EndedAt) {
			flow.EndedAt = session.EndedAt
		}
		flow.OriginalBytes += session.OriginalBytes
		retained[session.flowKey] += session.RetainedBytes
	}
	frame := 1
	for _, block := range blocks.data {
		if err := ctx.Err(); err != nil {
			return index, err
		}
		for frame < frameCount-1 && block.offset >= encoding.Frames[frame].RawOffset+encoding.Frames[frame].RawLength {
			frame++
		}
		if frame >= frameCount-1 || block.offset < encoding.Frames[frame].RawOffset ||
			block.offset+int64(block.size) > encoding.Frames[frame].RawOffset+encoding.Frames[frame].RawLength {
			return index, ErrIntegrity
		}
		if block.uncertain {
			setFrame(index.Unclassified, frame)
		}
		if block.flow.A.IsValid() {
			pos, exists := positions[block.flow]
			if !exists {
				return index, ErrIntegrity
			}
			flow := &index.Flows[pos]
			flow.Packets++
			flow.RetainedBytes += block.bytes
			setFrame(flow.Frames, frame)
		}
	}
	for i := range index.Flows {
		flow := &index.Flows[i]
		if flow.RetainedBytes != retained[flow.flowKey] {
			return index, ErrIntegrity
		}
		flow.State = retentionState(flow.OriginalBytes, flow.RetainedBytes)
	}
	slices.SortFunc(index.Flows, func(a, b IndexedFlow) int { return flowOrder(a.flowKey, b.flowKey) })
	index.Addresses, index.Endpoints = indexBlooms(index.Flows)
	if !index.valid(Manifest{Capture: c, Encoding: encoding, Sessions: sessions}) {
		return index, ErrIntegrity
	}
	return index, nil
}

func BuildSegmentIndex(ctx context.Context, file *os.File, m Manifest) (IndexRecord, error) {
	if m.Validate() != nil || m.Encoding.Schema != PackedSchema {
		return IndexRecord{}, ErrIntegrity
	}
	blocks, err := scanSegmentBlocks(ctx, file, m.Capture)
	if err != nil {
		return IndexRecord{}, err
	}
	index, err := indexSegmentBlocks(ctx, blocks, m.Encoding, m.Capture, m.Sessions)
	if err != nil {
		return IndexRecord{}, err
	}
	return index.Record(m)
}

// ResolveSegmentIndex 校验绑定摘要。只有索引不可用时才读取完整的同版本对象以恢复索引。
func ResolveSegmentIndex(ctx context.Context, record IndexRecord, m Manifest, source RangeSource, staging string, save func(IndexRecord) error) (SegmentIndex, error) {
	if m.Validate() != nil || m.Encoding.Schema != PackedSchema || save == nil {
		return SegmentIndex{}, ErrIntegrity
	}
	if index, err := record.Decode(m); err == nil {
		return index, nil
	}
	file, err := os.CreateTemp(staging, ".packet-index-rebuild-")
	if err != nil {
		return SegmentIndex{}, err
	}
	defer file.Close()
	defer os.Remove(file.Name())
	err = ReadRange(ctx, file, source, m.Encoding, 0, m.Encoding.RawBytes)
	if err == nil {
		err = ValidateManifestRawFile(ctx, file, m)
	}
	if err != nil {
		return SegmentIndex{}, err
	}
	rebuilt, err := BuildSegmentIndex(ctx, file, m)
	if err != nil {
		return SegmentIndex{}, err
	}
	if err = save(rebuilt); err != nil {
		return SegmentIndex{}, err
	}
	return rebuilt.Decode(m)
}
