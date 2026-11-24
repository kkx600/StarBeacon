package packetarchive

import (
	"bytes"
	"context"
	"io"
	"os"
	"slices"
	"sort"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
)

type retrievedPacket struct {
	raw     []byte
	info    gopacket.CaptureInfo
	options pcapgo.NgPacketOptions
}

func StageSessionSource(ctx context.Context, staging string, manifest Manifest, source RangeSource) (*os.File, error) {
	file, err := os.CreateTemp(staging, ".session-source-")
	if err != nil {
		return nil, err
	}
	if err = ReadRange(ctx, file, source, manifest.Encoding, 0, manifest.Encoding.RawBytes); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, err
	}
	return file, nil
}

// 候选帧只从指定版本读取一次。捕获摘要和单帧摘要独立核验，导出只使用匹配的实际帧。
func readIndexedSession(ctx context.Context, input SessionInput, key flowKey, proof *sessionProof, count *uint64, size *int64) ([]retrievedPacket, error) {
	if input.Range == nil || input.Index == nil || !input.Index.valid(input.Manifest) {
		return nil, ErrIntegrity
	}
	encoding := input.Manifest.Encoding
	decoder, err := frameDecoder(encoding.Codec)
	if err != nil {
		return nil, err
	}
	if decoder != nil {
		defer decoder.Close()
	}
	var packets []retrievedPacket
	selected := input.Index.framesFor(key)
	for i, frame := range encoding.Frames {
		if !hasFrame(selected, i) {
			continue
		}
		raw, _, err := readArchiveFrame(ctx, input.Range, frame, encoding.frameCodec(frame), decoder)
		if err != nil {
			return nil, err
		}
		reader, err := pcapgo.NewNgReader(io.MultiReader(bytes.NewReader(input.Index.Header), bytes.NewReader(raw)), pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, err
		}
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			data, ci, options, err := reader.ZeroCopyReadPacketDataWithOptions()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			*count += 1
			if *count > maxSessionPackets {
				return nil, ErrLimit
			}
			_, _, matches := proof.match(data, true)
			if !matches {
				continue
			}
			if options.PacketID == nil || *options.PacketID == 0 || *options.PacketID > input.Manifest.Capture.Retention.OriginalPackets {
				return nil, ErrIntegrity
			}
			*size += int64(len(data))
			if *size > MaxSegmentBytes-65536 {
				return nil, ErrLimit
			}
			original := *options.PacketID
			options.PacketID = &original
			options.Comments = slices.Clone(options.Comments)
			packets = append(packets, retrievedPacket{bytes.Clone(data), ci, options})
		}
	}
	sort.Slice(packets, func(i, j int) bool {
		if compared := packets[i].info.Timestamp.Compare(packets[j].info.Timestamp); compared != 0 {
			return compared < 0
		}
		return *packets[i].options.PacketID < *packets[j].options.PacketID
	})
	return packets, nil
}
