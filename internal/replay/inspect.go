package replay

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

const MaxFrameBytes = 1024 * 1024

type Metadata struct {
	Packets          int64      `json:"packets"`
	TruncatedPackets int64      `json:"truncated_packets"`
	First            *time.Time `json:"first_packet_at,omitempty"`
	Last             *time.Time `json:"last_packet_at,omitempty"`
	LinkType         string     `json:"link_type"`
	MACs             []string   `json:"mac_addresses"`
}
type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

// 库负责容器与协议解析。前置块边界检查限制 PCAPNG 头部声明导致的分配，不复制协议解析器。
func checkNG(ctx context.Context, f *os.File, size int64) error {
	var offset int64
	var order binary.ByteOrder
	interfaces, blocks := 0, 0
	header := make([]byte, 32)
	for offset < size {
		if e := ctx.Err(); e != nil {
			return e
		}
		blocks++
		if blocks > 1000000 {
			return errors.New("PCAPNG 块数量超过边界")
		}
		if _, e := f.ReadAt(header[:12], offset); e != nil {
			return errors.New("PCAPNG 块头不完整")
		}
		section := binary.BigEndian.Uint32(header[:4]) == 0x0a0d0d0a
		if section {
			interfaces = 0
			switch binary.BigEndian.Uint32(header[8:12]) {
			case 0x1a2b3c4d:
				order = binary.BigEndian
			case 0x4d3c2b1a:
				order = binary.LittleEndian
			default:
				return errors.New("PCAPNG 字节序无效")
			}
		}
		if order == nil {
			return errors.New("PCAPNG 缺少节头")
		}
		kind, length := order.Uint32(header[:4]), order.Uint32(header[4:8])
		if length < 12 || length%4 != 0 || length > MaxFrameBytes+4096 || int64(length) > size-offset {
			return errors.New("PCAPNG 块长度无效或超过 1 MiB 帧边界")
		}
		tail := make([]byte, 4)
		if _, e := f.ReadAt(tail, offset+int64(length)-4); e != nil || order.Uint32(tail) != length {
			return errors.New("PCAPNG 块尾长度不一致")
		}
		switch kind {
		case 0x0a0d0d0a:
			if length < 28 {
				return errors.New("PCAPNG 节头不完整")
			}
		case 1:
			interfaces++
			if interfaces > 256 || length < 20 {
				return errors.New("PCAPNG 接口数量或长度无效")
			}
			if _, e := f.ReadAt(header[:16], offset); e != nil {
				return e
			}
			if order.Uint32(header[12:16]) > MaxFrameBytes {
				return errors.New("PCAPNG snaplen 超过 1 MiB")
			}
		case 2, 6:
			if length < 32 {
				return errors.New("PCAPNG 数据块不完整")
			}
			if _, e := f.ReadAt(header[:28], offset); e != nil {
				return e
			}
			captured, original := order.Uint32(header[20:24]), order.Uint32(header[24:28])
			if captured > MaxFrameBytes || captured > original || captured > length-32 {
				return errors.New("PCAPNG 帧长度无效")
			}
		case 3:
			if length < 16 {
				return errors.New("PCAPNG 简单数据块不完整")
			}
			if order.Uint32(header[8:12]) > MaxFrameBytes {
				return errors.New("PCAPNG 简单帧声明超过边界")
			}
		case 10:
			return errors.New("重放不接受包含解密密钥块的 PCAPNG，请移除密钥块后导入")
		}
		offset += int64(length)
	}
	_, e := f.Seek(0, io.SeekStart)
	return e
}
func Inspect(ctx context.Context, path string) (out Metadata, err error) {
	defer func() {
		if recover() != nil {
			out = Metadata{}
			err = errors.New("样本容器解析失败")
		}
	}()
	out = Metadata{MACs: []string{}}
	f, e := os.Open(path)
	if e != nil {
		return out, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || info.Size() > MaxSampleBytes {
		return out, errors.New("样本大小超出边界")
	}
	header := make([]byte, 24)
	if _, e = f.ReadAt(header, 0); e != nil {
		return out, e
	}
	kind, e := format(header)
	if e != nil {
		return out, e
	}
	var reader packetReader
	var link layers.LinkType
	if kind == "pcapng" {
		if e = checkNG(ctx, f, info.Size()); e != nil {
			return out, e
		}
		ng, e := pcapgo.NewNgReader(f, pcapgo.NgReaderOptions{ErrorOnMismatchingLinkType: true})
		if e != nil {
			return out, e
		}
		reader = ng
		link = ng.LinkType()
	} else {
		pcap, e := pcapgo.NewReader(f)
		if e != nil {
			return out, e
		}
		if pcap.Snaplen() > MaxFrameBytes {
			return out, errors.New("PCAP snaplen 超过 1 MiB")
		}
		reader = pcap
		link = pcap.LinkType()
	}
	out.LinkType = link.String()
	seen := map[string]bool{}
	for {
		if e = ctx.Err(); e != nil {
			return out, e
		}
		data, ci, e := reader.ReadPacketData()
		if e == io.EOF {
			break
		}
		if e != nil {
			return out, e
		}
		out.Packets++
		if out.Packets > 1000000 {
			return out, errors.New("样本超过 100 万个数据包")
		}
		if ci.CaptureLength < ci.Length {
			out.TruncatedPackets++
		}
		if !ci.Timestamp.IsZero() {
			stamp := ci.Timestamp.UTC()
			if out.First == nil || stamp.Before(*out.First) {
				v := stamp
				out.First = &v
			}
			if out.Last == nil || stamp.After(*out.Last) {
				v := stamp
				out.Last = &v
			}
		}
		if link == layers.LinkTypeEthernet && len(seen) < 32 {
			packet := gopacket.NewPacket(data, link, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			if eth, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok {
				for _, mac := range []string{eth.SrcMAC.String(), eth.DstMAC.String()} {
					if !seen[mac] {
						seen[mac] = true
						out.MACs = append(out.MACs, mac)
					}
				}
			}
		}
	}
	if out.Packets == 0 {
		return out, errors.New("样本不包含数据包")
	}
	return out, nil
}
