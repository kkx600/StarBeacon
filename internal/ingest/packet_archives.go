package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var packetTransfers = make(chan struct{}, 4)

func (s *Server) UploadPacketArchive(stream grpc.ClientStreamingServer[sensorv1.PacketArchiveChunk, sensorv1.PacketArchiveAck]) error {
	if !s.ControlOnly || s.Packets == nil || s.PacketStaging == "" {
		return status.Error(codes.Unimplemented, "原包归档存储未配置")
	}
	select {
	case packetTransfers <- struct{}{}:
	default:
		return status.Error(codes.ResourceExhausted, "原包传输额度已满，请保留本地原包重试")
	}
	ctx, cancel := context.WithTimeout(stream.Context(), 90*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { defer func() { <-packetTransfers }(); done <- s.receivePacketArchive(ctx, stream) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return status.Error(codes.DeadlineExceeded, "原包传输超时，请保留本地原包")
	}
}
func (s *Server) receivePacketArchive(ctx context.Context, stream grpc.ClientStreamingServer[sensorv1.PacketArchiveChunk, sensorv1.PacketArchiveAck]) error {
	id, err := s.identity(ctx)
	if err != nil {
		return err
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first == nil || first.Offset != 0 || len(first.Data) != 0 || len(first.ManifestJson) > packetarchive.MaxManifestBytes || len(first.ManifestJson) == 0 {
		return status.Error(codes.InvalidArgument, "原包首个消息需为有界冻结目录")
	}
	manifest, err := packetarchive.ParseManifest(first.ManifestJson)
	if err != nil {
		return status.Error(codes.InvalidArgument, "原包目录格式无效")
	}
	row, acquired, err := s.DB.BeginPacketArchive(ctx, id, manifest, s.PacketQuota)
	if err != nil {
		if errors.Is(err, packetarchive.ErrQuota) || errors.Is(err, store.ErrPacketBusy) {
			return status.Error(codes.ResourceExhausted, "原包归档额度不足或已有传输，请保留原包")
		}
		return status.Error(codes.FailedPrecondition, "原包身份、目录或持久状态未能核对")
	}
	if acquired {
		defer func() {
			release, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.DB.ReleasePacketLease(release, id, row)
		}()
	}
	file, err := os.CreateTemp(s.PacketStaging, ".packet-transfer-")
	if err != nil {
		return status.Error(codes.Unavailable, "原包验证暂存不可用")
	}
	defer file.Close()
	defer os.Remove(file.Name())
	hash := sha256.New()
	var offset, checked int64
	for {
		if ctx.Err() != nil {
			return status.Error(codes.DeadlineExceeded, "原包传输已取消")
		}
		chunk, e := stream.Recv()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if chunk == nil || len(chunk.ManifestJson) != 0 || len(chunk.Data) < 1 || len(chunk.Data) > 128*1024 || chunk.Offset != uint64(offset) || int64(len(chunk.Data)) > manifest.Encoding.StoredBytes-offset {
			return status.Error(codes.InvalidArgument, "原包块偏移、长度或目录不符合冻结约定")
		}
		if offset == 0 || offset-checked >= 4*1024*1024 {
			if _, e = s.identity(ctx); e != nil {
				return e
			}
			checked = offset
		}
		n, e := file.Write(chunk.Data)
		if e != nil || n != len(chunk.Data) {
			return status.Error(codes.Unavailable, "原包验证暂存写入中断")
		}
		_, _ = hash.Write(chunk.Data)
		offset += int64(n)
	}
	if offset != manifest.Encoding.StoredBytes || hex.EncodeToString(hash.Sum(nil)) != manifest.Encoding.StoredSHA256 {
		return status.Error(codes.DataLoss, "原包存储字节与冻结摘要不一致")
	}
	if err = file.Sync(); err != nil {
		return status.Error(codes.Unavailable, "原包验证暂存尚未持久")
	}
	decoded, err := os.CreateTemp(s.PacketStaging, ".packet-validation-")
	if err != nil {
		return status.Error(codes.Unavailable, "原包格式验证暂存不可用")
	}
	defer decoded.Close()
	defer os.Remove(decoded.Name())
	if err = packetarchive.ReadRange(ctx, decoded, packetarchive.RangeFile(file), manifest.Encoding, 0, manifest.Encoding.RawBytes); err == nil {
		err = decoded.Sync()
	}
	if err == nil {
		err = packetarchive.ValidateRawFile(ctx, decoded, manifest.Capture)
	}
	if err != nil {
		return status.Error(codes.DataLoss, "原包解码或捕获目录不一致，本地原件不得回收")
	}
	if !acquired {
		source := func(ctx context.Context, start, length int64) (io.ReadCloser, error) {
			return s.Packets.Range(ctx, row.ObjectKey, row.ObjectVersion, start, length)
		}
		if err = packetarchive.ReadRange(ctx, io.Discard, source, row.Manifest.Encoding, 0, row.Manifest.Encoding.RawBytes); err != nil {
			return status.Error(codes.Unavailable, "原包既有对象版本无法确认")
		}
	} else {
		if _, err = file.Seek(0, io.SeekStart); err != nil {
			return status.Error(codes.Unavailable, "原包制品读取不可用")
		}
		version, e := s.Packets.Put(ctx, row.ObjectKey, file, manifest.Encoding.StoredBytes, manifest.Encoding.StoredSHA256)
		if e != nil {
			return status.Error(codes.Unavailable, "原包对象版本未持久确认，请保留原件")
		}
		if err = s.DB.RegisterPacketObject(ctx, id, row, version); err != nil {
			return status.Error(codes.Unavailable, "原包对象版本目录未持久确认")
		}
		row, err = s.DB.CompletePacketArchive(ctx, id, row)
		if err != nil {
			return status.Error(codes.Unavailable, "原包目录提交结果尚未确认")
		}
	}
	if _, err = s.identity(ctx); err != nil {
		return err
	}
	ack := row.Acknowledgement()
	return stream.SendAndClose(&sensorv1.PacketArchiveAck{Id: ack.ID, ManifestSha256: ack.ManifestSHA256, RawSha256: ack.RawSHA256, StoredSha256: ack.StoredSHA256, StoredBytes: uint64(ack.StoredBytes), ObjectVersion: ack.ObjectVersion, ExpiresAt: timestamppb.New(ack.ExpiresAt)})
}
