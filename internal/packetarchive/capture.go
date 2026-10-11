package packetarchive

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/gopacket/gopacket"
)

var ErrPollTimeout = errors.New("原包捕获轮询超时")

// PacketSource 的原字节只在下一次 Read 之前有效，捕获循环必须同步写入后再读下一帧。
type PacketSource interface {
	Read() ([]byte, gopacket.CaptureInfo, *uint16, error)
	Drops() (*uint64, error)
	Close()
}

type CaptureProgress struct {
	ID         string    `json:"id"`
	Interface  string    `json:"interface"`
	State      string    `json:"state"`
	Code       string    `json:"code,omitempty"`
	Packets    string    `json:"packets"`
	ObservedAt time.Time `json:"observed_at"`
}

// CapturePackets 独立保存接收字节，不依赖 Suricata 告警、流重组深度或 bypass 状态。
// 容量不足只停止该证据捕获循环；调用者负责呈现缺失范围，不能把缺失当作无流量。
func CapturePackets(ctx context.Context, s *Spool, header Capture, rotate time.Duration, source PacketSource, now func() time.Time, report func(CaptureProgress)) error {
	if source == nil || s == nil || rotate < time.Second || rotate > time.Hour || now == nil {
		return ErrIntegrity
	}
	defer source.Close()
	header.ID = ""
	header.StartedAt = now().UTC()
	pending, err := s.Begin(header)
	if err != nil {
		return err
	}
	baseline, baseErr := source.Drops()
	reportAt := time.Time{}
	progress := func(state, code string) {
		if report != nil {
			report(CaptureProgress{ID: pending.ID, Interface: header.Interface, State: state, Code: code, Packets: decimal(pending.Recorder.Capture.Packets), ObservedAt: now().UTC()})
		}
	}
	progress("capturing", "")
	seal := func(termination string) error {
		current, e := source.Drops()
		counterErr := e
		var drops *uint64
		if baseErr == nil && e == nil && baseline != nil && current != nil && *current >= *baseline {
			value := *current - *baseline
			drops = &value
		}
		end := now().UTC()
		if end.Before(pending.Recorder.Capture.StartedAt) {
			end = pending.Recorder.Capture.StartedAt
		}
		if e = pending.Seal(end, termination, drops); e != nil {
			return e
		}
		progress("sealed", "")
		baseline, baseErr = current, counterErr
		// 当前读取失败不能被 Seal 的成功状态覆盖为已观测计数。
		if current == nil {
			baseErr = ErrIntegrity
		}
		return nil
	}
	for {
		if ctx.Err() != nil {
			termination := "shutdown"
			if errors.Is(context.Cause(ctx), ErrConfiguration) {
				termination = "configuration"
			}
			if err = seal(termination); err != nil {
				return err
			}
			return nil
		}
		data, ci, vlan, readErr := source.Read()
		if readErr != nil && !errors.Is(readErr, ErrPollTimeout) {
			_ = pending.Abort("capture_source_interrupted")
			progress("quarantined", "capture_source_interrupted")
			return readErr
		}
		if now().Sub(pending.Recorder.Capture.StartedAt) >= rotate || len(data) > 0 && pending.Recorder.Capture.Packets >= 1048576 {
			if err = seal("rotation"); err != nil {
				return err
			}
			header.StartedAt = now().UTC()
			pending, err = s.Begin(header)
			if err != nil {
				return err
			}
			progress("capturing", "")
		}
		if readErr != nil {
			continue
		}
		if ci.CaptureLength != len(data) || len(data) < 1 {
			_ = pending.Abort("capture_record_invalid")
			return ErrIntegrity
		}
		if ci.CaptureLength > SnapLength {
			data = data[:SnapLength]
			ci.CaptureLength = SnapLength
		}
		err = pending.Recorder.Write(ci, data, vlan)
		if errors.Is(err, ErrRotate) {
			if err = seal("rotation"); err != nil {
				return err
			}
			header.StartedAt = now().UTC()
			pending, err = s.Begin(header)
			if err != nil {
				return err
			}
			err = pending.Recorder.Write(ci, data, vlan)
		}
		if err != nil {
			_ = pending.Abort("capture_write_unconfirmed")
			progress("quarantined", "capture_write_unconfirmed")
			return err
		}
		if now().Sub(reportAt) >= time.Second {
			progress("capturing", "")
			reportAt = now()
		}
	}
}

var ErrConfiguration = errors.New("原包捕获配置已变更")

// RangeFile 只读取已封存的同一个文件句柄，避免以路径重新打开造成对象版本漂移。
func RangeFile(file io.ReaderAt) RangeSource {
	return func(_ context.Context, offset, length int64) (io.ReadCloser, error) {
		return io.NopCloser(io.NewSectionReader(file, offset, length)), nil
	}
}
