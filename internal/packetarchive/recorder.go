package packetarchive

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

var ErrRotate = errors.New("原包切片已达到轮转阈值")

// Recorder 仅用于单个捕获循环，不重写 MAC、载荷、时间或长度，不恢复网卡已移除的 VLAN 字节。
type Recorder struct {
	Capture Capture
	writer  *pcapgo.NgWriter
	bytes   *countWriter
	limit   int64
	closed  bool
}

type countWriter struct {
	target io.Writer
	size   int64
}

func (w *countWriter) Write(p []byte) (int, error) {
	n, err := w.target.Write(p)
	w.size += int64(n)
	if n < len(p) && err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}

func captureStart(c Capture) (Capture, error) {
	check := c
	check.EndedAt, check.Termination, check.Format, check.Source, check.SnapLength, check.CounterState = c.StartedAt, "rotation", "pcapng", "AF_PACKET", SnapLength, "unavailable"
	check.KernelDrops = nil
	if check.Validate() != nil || c.Packets != 0 || c.FirstPacketAt != nil || c.LastPacketAt != nil {
		return Capture{}, ErrIntegrity
	}
	c = check
	c.EndedAt, c.Termination = time.Time{}, ""
	return c, nil
}

func NewRecorder(target io.Writer, c Capture, limit int64) (*Recorder, error) {
	var err error
	c, err = captureStart(c)
	if err != nil || target == nil || limit < 1024*1024 || limit > MaxSegmentBytes {
		return nil, ErrIntegrity
	}
	counter := &countWriter{target: target}
	writer, err := pcapgo.NewNgWriterInterface(counter, pcapgo.NgInterface{Name: c.Interface, Description: "StarBeacon 原包捕获", Comment: "MAC=" + c.InterfaceMAC, Filter: c.BPFFilter, OS: "linux", LinkType: layers.LinkTypeEthernet, SnapLength: SnapLength, TimestampResolution: 9}, pcapgo.NgWriterOptions{SectionInfo: pcapgo.NgSectionInfo{OS: "linux", Application: "StarBeacon", Comment: "原始内核捕获字节；镜像完整性与校验和卸载未独立验证"}})
	if err != nil {
		return nil, err
	}
	if err = writer.Flush(); err != nil {
		return nil, err
	}
	return &Recorder{Capture: c, writer: writer, bytes: counter, limit: limit}, nil
}

func (r *Recorder) Write(ci gopacket.CaptureInfo, data []byte, vlanOffloadID *uint16) error {
	if r.closed {
		return io.ErrClosedPipe
	}
	if ci.Timestamp.IsZero() || ci.Timestamp.UnixNano() <= 0 || ci.Timestamp.Year() > 2261 || ci.CaptureLength != len(data) || ci.CaptureLength < 1 || ci.CaptureLength > SnapLength || ci.Length < ci.CaptureLength || ci.Length > 16*1024*1024 || ci.InterfaceIndex != 0 || vlanOffloadID != nil && *vlanOffloadID > 4095 {
		return ErrIntegrity
	}
	// 锁定的 pcapgo 使用 4 KiB 缓冲；额外留出 8 KiB 覆盖未刷写字节、选项和统计块。
	// 捕获循环不为每个包强制刷新，不依赖压缩后的大小决定能否捕获。
	if int64(len(data))+8192 > r.limit-r.bytes.size || r.Capture.Packets >= 1048576 {
		return ErrRotate
	}
	opts := pcapgo.NgPacketOptions{}
	id := r.Capture.Packets + 1
	opts.PacketID = &id
	if vlanOffloadID != nil {
		opts.Comments = []string{fmt.Sprintf("StarBeacon: vlan_offload_id=%d; VLAN 头由网卡移除，原字节未重建", *vlanOffloadID)}
	}
	if err := r.writer.WritePacketWithOptions(ci, data, opts); err != nil {
		return err
	}
	r.Capture.Packets++
	r.Capture.PacketBytes += uint64(len(data))
	if ci.CaptureLength < ci.Length {
		r.Capture.TruncatedPackets++
	}
	if vlanOffloadID != nil {
		r.Capture.VLANOffloadPackets++
	}
	at := ci.Timestamp.UTC()
	if r.Capture.FirstPacketAt == nil || at.Before(*r.Capture.FirstPacketAt) {
		r.Capture.FirstPacketAt = &at
	}
	if r.Capture.LastPacketAt == nil || at.After(*r.Capture.LastPacketAt) {
		r.Capture.LastPacketAt = &at
	}
	return nil
}

func (r *Recorder) Flush() error {
	if r.closed {
		return io.ErrClosedPipe
	}
	return r.writer.Flush()
}

func (r *Recorder) Seal(ended time.Time, termination string, drops *uint64) (Capture, error) {
	if r.closed {
		return r.Capture, io.ErrClosedPipe
	}
	c := r.Capture
	c.EndedAt, c.Termination = ended.UTC(), termination
	c.KernelDrops = nil
	c.CounterState = "unavailable"
	if drops != nil {
		value := *drops
		c.KernelDrops = &value
		c.CounterState = "observed"
	}
	if c.Validate() != nil {
		return c, ErrIntegrity
	}
	count := uint64(pcapgo.NgNoValue64)
	if drops != nil {
		count = *drops
	}
	if err := r.writer.WriteInterfaceStats(0, pcapgo.NgInterfaceStatistics{StartTime: c.StartedAt, EndTime: c.EndedAt, LastUpdate: c.EndedAt, PacketsReceived: pcapgo.NgNoValue64, PacketsDropped: count}); err != nil {
		return c, err
	}
	if err := r.writer.Flush(); err != nil {
		return c, err
	}
	if r.bytes.size > r.limit {
		return c, ErrLimit
	}
	r.Capture, r.closed = c, true
	return c, nil
}
