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
	var packets []retrievedPacket
	err := walkIndexedFlow(ctx, input, key, func(data []byte, ci gopacket.CaptureInfo, options pcapgo.NgPacketOptions) error {
		*count += 1
		if *count > maxSessionPackets {
			return ErrLimit
		}
		_, _, matches := proof.match(data, true)
		if !matches {
			return nil
		}
		*size += int64(len(data))
		if *size > MaxSegmentBytes-65536 {
			return ErrLimit
		}
		packets = append(packets, retainPacket(data, ci, options))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(packets, func(i, j int) bool {
		if compared := packets[i].info.Timestamp.Compare(packets[j].info.Timestamp); compared != 0 {
			return compared < 0
		}
		return *packets[i].options.PacketID < *packets[j].options.PacketID
	})
	return packets, nil
}

func retainPacket(data []byte, ci gopacket.CaptureInfo, options pcapgo.NgPacketOptions) retrievedPacket {
	original := *options.PacketID
	options.PacketID = &original
	options.Comments = slices.Clone(options.Comments)
	return retrievedPacket{bytes.Clone(data), ci, options}
}

type archivePacketVisitor func([]byte, gopacket.CaptureInfo, pcapgo.NgPacketOptions) error

func walkIndexedFlow(ctx context.Context, input SessionInput, key flowKey, visit archivePacketVisitor) error {
	if input.Range == nil || input.Index == nil || !input.Index.valid(input.Manifest) {
		return ErrIntegrity
	}
	encoding := input.Manifest.Encoding
	decoder, err := frameDecoder(encoding.Codec)
	if err != nil {
		return err
	}
	if decoder != nil {
		defer decoder.Close()
	}
	selected := input.Index.framesFor(key)
	for i, frame := range encoding.Frames {
		if !hasFrame(selected, i) {
			continue
		}
		raw, _, err := readArchiveFrame(ctx, input.Range, frame, encoding.frameCodec(frame), decoder)
		if err != nil {
			return err
		}
		reader, err := pcapgo.NewNgReader(io.MultiReader(bytes.NewReader(input.Index.Header), bytes.NewReader(raw)), pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return err
		}
		if err := walkArchivePackets(ctx, reader, func(data []byte, ci gopacket.CaptureInfo, options pcapgo.NgPacketOptions) error {
			if options.PacketID == nil || *options.PacketID == 0 || *options.PacketID > input.Manifest.Capture.Retention.OriginalPackets {
				return ErrIntegrity
			}
			return visit(data, ci, options)
		}); err != nil {
			return err
		}
	}
	return nil
}

func walkArchivePackets(ctx context.Context, reader *pcapgo.NgReader, visit archivePacketVisitor) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, info, options, err := reader.ZeroCopyReadPacketDataWithOptions()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := visit(data, info, options); err != nil {
			return err
		}
	}
}
