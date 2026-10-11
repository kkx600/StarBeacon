package packetarchive

import (
	"context"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/kkx600/StarBeacon/internal/replay"
)

// ValidateRawFile 在对象提交前核对原生 PCAPNG 内容与冻结捕获目录，格式仍由维护中的库解析。
func ValidateRawFile(ctx context.Context, f *os.File, c Capture) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrIntegrity
		}
	}()
	if c.Validate() != nil {
		return ErrIntegrity
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > MaxSegmentBytes || !info.Mode().IsRegular() {
		return ErrLimit
	}
	if err = replay.CheckPCAPNGBounds(ctx, f, info.Size()); err != nil {
		return err
	}
	sections := 0
	statsCount := 0
	statsValid := true
	options := pcapgo.NgReaderOptions{ErrorOnMismatchingLinkType: true, SectionEndCallback: func([]pcapgo.NgInterface, pcapgo.NgSectionInfo) { sections++ }, StatisticsCallback: func(id int, v pcapgo.NgInterfaceStatistics) {
		statsCount++
		if id != 0 || !v.StartTime.Equal(c.StartedAt) || !v.EndTime.Equal(c.EndedAt) || v.PacketsReceived != pcapgo.NgNoValue64 {
			statsValid = false
		}
		if c.KernelDrops == nil {
			statsValid = statsValid && v.PacketsDropped == pcapgo.NgNoValue64
		} else {
			statsValid = statsValid && v.PacketsDropped == *c.KernelDrops
		}
	}}
	reader, err := pcapgo.NewNgReader(f, options)
	if err != nil {
		return err
	}
	iface, err := reader.Interface(0)
	if err != nil || reader.NInterfaces() != 1 || reader.LinkType() != layers.LinkTypeEthernet || iface.Name != c.Interface || iface.Comment != "MAC="+c.InterfaceMAC || iface.Filter != c.BPFFilter || iface.SnapLength != SnapLength || iface.TimestampResolution != 9 {
		return ErrIntegrity
	}
	var packets, bytes, truncated, vlan uint64
	var first, last *time.Time
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		data, ci, opts, e := reader.ZeroCopyReadPacketDataWithOptions()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if sections != 0 || reader.NInterfaces() != 1 || ci.InterfaceIndex != 0 || ci.CaptureLength != len(data) || ci.CaptureLength < 1 || ci.CaptureLength > SnapLength || ci.Length < ci.CaptureLength || ci.Length > 16*1024*1024 || ci.Timestamp.IsZero() || ci.Timestamp.UnixNano() <= 0 {
			return ErrIntegrity
		}
		packets++
		bytes += uint64(len(data))
		if ci.Length > ci.CaptureLength {
			truncated++
		}
		if packets > 1048576 || bytes > uint64(MaxSegmentBytes) || opts.PacketID == nil || *opts.PacketID != packets {
			return ErrIntegrity
		}
		for _, comment := range opts.Comments {
			if strings.HasPrefix(comment, "StarBeacon: vlan_offload_id=") {
				vlan++
				break
			}
		}
		stamp := ci.Timestamp.UTC()
		if first == nil || stamp.Before(*first) {
			first = &stamp
		}
		if last == nil || stamp.After(*last) {
			last = &stamp
		}
	}
	if sections != 0 || reader.NInterfaces() != 1 || statsCount != 1 || !statsValid || packets != c.Packets || bytes != c.PacketBytes || truncated != c.TruncatedPackets || vlan != c.VLANOffloadPackets || !equalTime(first, c.FirstPacketAt) || !equalTime(last, c.LastPacketAt) {
		return ErrIntegrity
	}
	_, err = f.Seek(0, io.SeekStart)
	return err
}
func equalTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}
