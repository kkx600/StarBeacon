package replay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	"github.com/gopacket/gopacket/pcapgo"
)

// NormalizeNG 保留帧字节、原始长度与纳秒时间，转换为 libpcap 离线检测兼容的单链路 PCAP。
func NormalizeNG(ctx context.Context, source, destination string) (string, error) {
	input, e := os.Open(source)
	if e != nil {
		return "", e
	}
	defer input.Close()
	reader, e := pcapgo.NewNgReader(input, pcapgo.NgReaderOptions{ErrorOnMismatchingLinkType: true})
	if e != nil {
		return "", e
	}
	out, e := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return "", e
	}
	defer out.Close()
	h := sha256.New()
	writer := pcapgo.NewWriterNanos(io.MultiWriter(out, h))
	if e = writer.WriteFileHeader(MaxFrameBytes, reader.LinkType()); e != nil {
		return "", e
	}
	for {
		if e = ctx.Err(); e != nil {
			return "", e
		}
		data, ci, e := reader.ReadPacketData()
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", e
		}
		if e = writer.WritePacket(ci, data); e != nil {
			return "", e
		}
	}
	if e = out.Sync(); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
