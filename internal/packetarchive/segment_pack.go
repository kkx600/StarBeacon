package packetarchive

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"sort"

	"github.com/gopacket/gopacket/pcapgo"
	"github.com/klauspost/compress/zstd"
)

const (
	sectionBlock    = 0x0a0d0d0a
	interfaceBlock  = 1
	statisticsBlock = 5
	packetBlockType = 6
	maxSectionBytes = 8192
)

type segmentBlock struct {
	offset    int64
	size      int
	flow      flowKey
	group     int
	bytes     uint64
	uncertain bool
}

type segmentBlocks struct {
	header []byte
	data   []segmentBlock
	end    segmentBlock
}

// 只编排本机记录器产生的单接口 PCAPNG 块。报文块连同原始时间、选项和捕获序号原样移动。
func scanSegmentBlocks(ctx context.Context, file *os.File, c Capture) (segmentBlocks, error) {
	var out segmentBlocks
	info, err := file.Stat()
	if err != nil {
		return out, err
	}
	size := info.Size()
	if size < 24 || size > MaxSegmentBytes || !info.Mode().IsRegular() {
		return out, ErrIntegrity
	}
	physical := bufio.NewReader(io.NewSectionReader(file, 0, size))
	reader, err := pcapgo.NewNgReader(io.NewSectionReader(file, 0, size), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return out, err
	}
	out.data = make([]segmentBlock, 0, c.Packets)
	groups := make(map[flowKey]int)
	position := int64(0)
	for position < size {
		if err = ctx.Err(); err != nil {
			return out, err
		}
		header, err := physical.Peek(8)
		if err != nil {
			return out, err
		}
		kind, length := binary.LittleEndian.Uint32(header[:4]), int(binary.LittleEndian.Uint32(header[4:]))
		if length < 12 || length%4 != 0 || length > MaxFrameBytes || int64(length) > size-position {
			return out, ErrIntegrity
		}
		block := segmentBlock{offset: position, size: length}
		switch kind {
		case sectionBlock, interfaceBlock:
			if kind == sectionBlock && position != 0 || kind == interfaceBlock && (position == 0 || len(out.data) > 0 || out.end.size != 0) || len(out.header)+length > maxSectionBytes {
				return out, ErrIntegrity
			}
			before := len(out.header)
			out.header = append(out.header, make([]byte, length)...)
			if _, err = file.ReadAt(out.header[before:], position); err != nil {
				return out, err
			}
		case packetBlockType:
			if len(out.header) == 0 || out.end.size != 0 || uint64(len(out.data)) >= c.Packets {
				return out, ErrIntegrity
			}
			raw, _, options, err := reader.ZeroCopyReadPacketDataWithOptions()
			if err != nil {
				return out, err
			}
			flow := retentionFlow(raw, captureVLAN(options))
			block.flow, block.bytes, block.uncertain = flow.key, uint64(len(raw)), flow.uncertain
			if block.flow.A.IsValid() {
				block.group = groups[block.flow]
				if block.group == 0 {
					block.group = len(groups) + 1
					groups[block.flow] = block.group
				}
			}
			out.data = append(out.data, block)
		case statisticsBlock:
			if position+int64(length) != size || out.end.size != 0 {
				return out, ErrIntegrity
			}
			out.end = block
		default:
			return out, ErrIntegrity
		}
		if _, err = physical.Discard(length); err != nil {
			return out, err
		}
		position += int64(length)
	}
	if len(out.header) == 0 || out.end.size == 0 || uint64(len(out.data)) != c.Packets {
		return out, ErrIntegrity
	}
	return out, nil
}

func encodePackedSegment(ctx context.Context, stored io.Writer, raw *os.File, c Capture, sessions []RetentionSession, codec string, cluster bool) (Encoding, SegmentIndex, error) {
	index := Encoding{Schema: PackedSchema, Codec: codec, FrameBytes: MaxFrameBytes, Implementation: "identity", Level: "none", Frames: []Frame{}}
	if codec != "none" && codec != "zstd" {
		return index, SegmentIndex{}, ErrLimit
	}
	blocks, err := scanSegmentBlocks(ctx, raw, c)
	if err != nil {
		return index, SegmentIndex{}, err
	}
	if cluster {
		sort.SliceStable(blocks.data, func(i, j int) bool { return blocks.data[i].group < blocks.data[j].group })
	}
	var encoder *zstd.Encoder
	if codec == "zstd" {
		encoder, err = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(3)), zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(MaxFrameBytes), zstd.WithEncoderCRC(true))
		if err != nil {
			return index, SegmentIndex{}, err
		}
		defer encoder.Close()
		index.Implementation, index.Level = CodecVersion, "zstd-3"
	}
	rawHash, storedHash := sha256.New(), sha256.New()
	var compressed []byte
	flush := func(raw []byte) error {
		body, method := raw, "none"
		if encoder != nil {
			sample := raw[:min(64<<10, len(raw))]
			trial := encoder.EncodeAll(sample, compressed[:0])
			compressed = trial
			if len(trial)*100 <= len(sample)*95 {
				if len(sample) < len(raw) {
					compressed = encoder.EncodeAll(raw, trial[:0])
				}
				if len(compressed) < len(raw) {
					body, method = compressed, "zstd"
				}
			}
		}
		if _, err := io.Copy(stored, bytes.NewReader(body)); err != nil {
			return err
		}
		_, _ = rawHash.Write(raw)
		_, _ = storedHash.Write(body)
		index.Frames = append(index.Frames, Frame{RawOffset: index.RawBytes, RawLength: int64(len(raw)), StoredOffset: index.StoredBytes, StoredLength: int64(len(body)), RawSHA256: Digest(raw), StoredSHA256: Digest(body), Codec: method})
		index.RawBytes += int64(len(raw))
		index.StoredBytes += int64(len(body))
		return nil
	}
	if err = flush(blocks.header); err != nil {
		return index, SegmentIndex{}, err
	}
	frame := make([]byte, 0, MaxFrameBytes)
	logicalOffset := int64(len(blocks.header))
	for i := range blocks.data {
		if err = ctx.Err(); err != nil {
			return index, SegmentIndex{}, err
		}
		block := &blocks.data[i]
		if len(frame)+block.size > MaxFrameBytes {
			if err = flush(frame); err != nil {
				return index, SegmentIndex{}, err
			}
			frame = frame[:0]
		}
		used := len(frame)
		frame = frame[:used+block.size]
		if _, err = raw.ReadAt(frame[used:], block.offset); err != nil {
			return index, SegmentIndex{}, err
		}
		block.offset = logicalOffset
		logicalOffset += int64(block.size)
	}
	if len(frame) != 0 {
		if err = flush(frame); err != nil {
			return index, SegmentIndex{}, err
		}
	}
	frame = frame[:blocks.end.size]
	if _, err = raw.ReadAt(frame, blocks.end.offset); err != nil {
		return index, SegmentIndex{}, err
	}
	blocks.end.offset = logicalOffset
	if err = flush(frame); err != nil {
		return index, SegmentIndex{}, err
	}
	index.RawSHA256, index.StoredSHA256 = hex.EncodeToString(rawHash.Sum(nil)), hex.EncodeToString(storedHash.Sum(nil))
	if err = index.Validate(); err != nil {
		return index, SegmentIndex{}, err
	}
	directory, err := indexSegmentBlocks(ctx, blocks, index, c, sessions)
	return index, directory, err
}
