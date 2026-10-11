// Package packetarchive 保存捕获原字节及独立压缩帧目录，不从检测载荷重建网络报文。
package packetarchive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"github.com/klauspost/compress/zstd"
)

const (
	Schema                  = "packet.archive.v1"
	CodecVersion            = "klauspost/compress/v1.20.1"
	MaxSegmentBytes   int64 = 64 * 1024 * 1024
	MaxStoredBytes    int64 = 128 * 1024 * 1024
	MinFrameBytes           = 64 * 1024
	DefaultFrameBytes       = 256 * 1024
	MaxFrameBytes           = 1024 * 1024
	MaxFrames               = 1024
)

var ErrIntegrity = errors.New("原包归档内容与持久目录不一致")
var ErrLimit = errors.New("原包归档超过处理预算")

type Frame struct {
	RawOffset    int64  `json:"raw_offset"`
	RawLength    int64  `json:"raw_length"`
	StoredOffset int64  `json:"stored_offset"`
	StoredLength int64  `json:"stored_length"`
	RawSHA256    string `json:"raw_sha256"`
	StoredSHA256 string `json:"stored_sha256"`
}

type Encoding struct {
	Schema         string  `json:"schema"`
	Codec          string  `json:"codec"`
	Implementation string  `json:"implementation"`
	Level          string  `json:"level"`
	FrameBytes     int     `json:"frame_bytes"`
	RawBytes       int64   `json:"raw_bytes"`
	StoredBytes    int64   `json:"stored_bytes"`
	RawSHA256      string  `json:"raw_sha256"`
	StoredSHA256   string  `json:"stored_sha256"`
	Frames         []Frame `json:"frames"`
}

func Digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func validDigest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == value
}

func (index Encoding) Validate() error {
	if index.Schema != Schema || index.FrameBytes < MinFrameBytes || index.FrameBytes > MaxFrameBytes || index.FrameBytes&(index.FrameBytes-1) != 0 || index.RawBytes < 24 || index.RawBytes > MaxSegmentBytes || index.StoredBytes < 1 || index.StoredBytes > MaxStoredBytes || len(index.Frames) < 1 || len(index.Frames) > MaxFrames || !validDigest(index.RawSHA256) || !validDigest(index.StoredSHA256) {
		return ErrIntegrity
	}
	if index.Codec == "none" {
		if index.Implementation != "identity" || index.Level != "none" || index.RawBytes != index.StoredBytes || index.RawSHA256 != index.StoredSHA256 {
			return ErrIntegrity
		}
	} else if index.Codec != "zstd" || index.Implementation != CodecVersion || index.Level != "SpeedFastest" {
		return ErrIntegrity
	}
	var rawOffset, storedOffset int64
	for i, frame := range index.Frames {
		if frame.RawOffset != rawOffset || frame.StoredOffset != storedOffset || frame.RawLength < 1 || frame.RawLength > int64(index.FrameBytes) || frame.StoredLength < 1 || frame.StoredLength > 2*MaxFrameBytes || !validDigest(frame.RawSHA256) || !validDigest(frame.StoredSHA256) || i < len(index.Frames)-1 && frame.RawLength != int64(index.FrameBytes) {
			return ErrIntegrity
		}
		if index.Codec == "none" && (frame.RawLength != frame.StoredLength || frame.RawSHA256 != frame.StoredSHA256) {
			return ErrIntegrity
		}
		rawOffset += frame.RawLength
		storedOffset += frame.StoredLength
		if rawOffset > MaxSegmentBytes || storedOffset > MaxStoredBytes {
			return ErrIntegrity
		}
	}
	if rawOffset != index.RawBytes || storedOffset != index.StoredBytes {
		return ErrIntegrity
	}
	return nil
}

// EncodeFrames 在已经封存的原包副本上执行；失败时调用者保留原副本，不提交半成品目录。
// 每帧独立编码并有独立摘要，读取器不把原始偏移直接用于压缩对象 Range。
func EncodeFrames(ctx context.Context, target io.Writer, source io.Reader, codec string, frameBytes int) (Encoding, error) {
	index := Encoding{Schema: Schema, Codec: codec, FrameBytes: frameBytes, Frames: []Frame{}}
	if source == nil || target == nil || frameBytes < MinFrameBytes || frameBytes > MaxFrameBytes || frameBytes&(frameBytes-1) != 0 || codec != "none" && codec != "zstd" {
		return index, ErrLimit
	}
	index.Implementation, index.Level = "identity", "none"
	var encoder *zstd.Encoder
	if codec == "zstd" {
		var err error
		encoder, err = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(MaxFrameBytes), zstd.WithEncoderCRC(true))
		if err != nil {
			return index, err
		}
		defer encoder.Close()
		index.Implementation, index.Level = CodecVersion, "SpeedFastest"
	}
	rawHash, storedHash := sha256.New(), sha256.New()
	buffer := make([]byte, frameBytes)
	var compressed []byte
	for {
		if err := ctx.Err(); err != nil {
			return index, err
		}
		n, err := io.ReadFull(source, buffer)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return index, err
		}
		if n == 0 {
			break
		}
		if index.RawBytes+int64(n) > MaxSegmentBytes || len(index.Frames) == MaxFrames {
			return index, ErrLimit
		}
		raw, stored := buffer[:n], buffer[:n]
		if encoder != nil {
			compressed = encoder.EncodeAll(raw, compressed[:0])
			stored = compressed
		}
		if len(stored) > 2*MaxFrameBytes || index.StoredBytes+int64(len(stored)) > MaxStoredBytes {
			return index, ErrLimit
		}
		if _, e := io.Copy(target, bytes.NewReader(stored)); e != nil {
			return index, e
		}
		_, _ = rawHash.Write(raw)
		_, _ = storedHash.Write(stored)
		index.Frames = append(index.Frames, Frame{RawOffset: index.RawBytes, RawLength: int64(n), StoredOffset: index.StoredBytes, StoredLength: int64(len(stored)), RawSHA256: Digest(raw), StoredSHA256: Digest(stored)})
		index.RawBytes += int64(n)
		index.StoredBytes += int64(len(stored))
		if err != nil {
			break
		}
	}
	index.RawSHA256, index.StoredSHA256 = hex.EncodeToString(rawHash.Sum(nil)), hex.EncodeToString(storedHash.Sum(nil))
	if err := index.Validate(); err != nil {
		return index, err
	}
	return index, nil
}

// RangeSource 必须绑定已授权对象的不可变版本；目录来自受信持久存储，不能由下载者提供。
type RangeSource func(context.Context, int64, int64) (io.ReadCloser, error)

func ReadRange(ctx context.Context, target io.Writer, source RangeSource, index Encoding, offset, length int64) error {
	if index.Validate() != nil || target == nil || source == nil || offset < 0 || length < 1 || offset >= index.RawBytes || length > index.RawBytes-offset {
		return ErrIntegrity
	}
	var decoder *zstd.Decoder
	if index.Codec == "zstd" {
		var err error
		decoder, err = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(2*MaxFrameBytes), zstd.WithDecoderMaxWindow(MaxFrameBytes), zstd.WithDecodeAllCapLimit(true))
		if err != nil {
			return err
		}
		defer decoder.Close()
	}
	full := offset == 0 && length == index.RawBytes
	rawHash, storedHash := sha256.New(), sha256.New()
	end := offset + length
	for _, frame := range index.Frames {
		if frame.RawOffset+frame.RawLength <= offset || frame.RawOffset >= end {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		reader, err := source(ctx, frame.StoredOffset, frame.StoredLength)
		if err != nil {
			return err
		}
		// 声明长度之外仍读取一个字节，拒绝忽略 Range 或返回额外内容的存储端。
		stored, readErr := io.ReadAll(io.LimitReader(reader, frame.StoredLength+1))
		closeErr := reader.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if int64(len(stored)) != frame.StoredLength || Digest(stored) != frame.StoredSHA256 {
			return ErrIntegrity
		}
		raw := stored
		if decoder != nil {
			raw, err = decoder.DecodeAll(stored, make([]byte, 0, frame.RawLength))
			if err != nil {
				return ErrIntegrity
			}
		}
		if int64(len(raw)) != frame.RawLength || Digest(raw) != frame.RawSHA256 {
			return ErrIntegrity
		}
		if full {
			_, _ = rawHash.Write(raw)
			_, _ = storedHash.Write(stored)
		}
		first, last := max(offset-frame.RawOffset, 0), min(end-frame.RawOffset, frame.RawLength)
		if _, err = io.Copy(target, bytes.NewReader(raw[first:last])); err != nil {
			return err
		}
	}
	if full && (hex.EncodeToString(rawHash.Sum(nil)) != index.RawSHA256 || hex.EncodeToString(storedHash.Sum(nil)) != index.StoredSHA256) {
		return ErrIntegrity
	}
	return nil
}
