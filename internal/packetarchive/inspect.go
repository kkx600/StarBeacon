package packetarchive

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

var ErrPacketNumber = errors.New("原包序号无效")
var ErrPacketNotFound = errors.New("原包序号不存在")
var errDecodeBudget = errors.New("协议解析达到 16 层预算")

const MaxInspectionLayers = 16

type PacketField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type PacketLayer struct {
	Name   string        `json:"name"`
	Offset *int          `json:"offset"`
	Length int           `json:"length"`
	Fields []PacketField `json:"fields"`
}

// PacketInspection 中时间只有网卡捕获时间；不推断入站、出站、攻击结果或解密内容。
type PacketInspection struct {
	Schema             string        `json:"schema"`
	ArchiveID          string        `json:"archive_id"`
	ManifestSHA256     string        `json:"manifest_sha256"`
	RawSHA256          string        `json:"raw_sha256"`
	PacketSHA256       string        `json:"packet_sha256"`
	Number             int           `json:"number"`
	Total              uint64        `json:"total"`
	CapturedAt         time.Time     `json:"captured_at"`
	CapturedLength     int           `json:"captured_length"`
	OriginalLength     int           `json:"original_length"`
	Truncated          bool          `json:"truncated"`
	Interface          string        `json:"interface"`
	VLANOffload        bool          `json:"vlan_offload"`
	DecodeStatus       string        `json:"decode_status"`
	Layers             []PacketLayer `json:"layers"`
	Packet             string        `json:"packet"`
	ChecksumValidation string        `json:"checksum_validation"`
	PayloadVisibility  string        `json:"payload_visibility"`
}

func InspectionNumber(raw string, query url.Values) (int, error) {
	number, err := strconv.Atoi(raw)
	if err != nil || strconv.Itoa(number) != raw || number < 1 || number > 1048576 || len(query) != 0 {
		return 0, ErrPacketNumber
	}
	return number, nil
}

// 每次读取指定版本、完整摘要和原生目录后才解析一个包；私有暂存由函数回收。
func InspectPacket(ctx context.Context, source RangeSource, m Manifest, staging string, number int) (out PacketInspection, err error) {
	if number < 1 || number > 1048576 {
		return out, ErrPacketNumber
	}
	if m.Validate() != nil || source == nil || staging == "" {
		return out, ErrIntegrity
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if uint64(number) > m.Capture.Packets {
		return out, ErrPacketNotFound
	}
	file, err := os.CreateTemp(staging, ".packet-inspect-")
	if err != nil {
		return out, err
	}
	defer file.Close()
	defer os.Remove(file.Name())
	if err = ReadRange(ctx, file, source, m.Encoding, 0, m.Encoding.RawBytes); err != nil {
		return out, err
	}
	if err = ValidateRawFile(ctx, file, m.Capture); err != nil {
		return out, err
	}
	reader, err := pcapgo.NewNgReader(file, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return out, err
	}
	for index := 1; index <= number; index++ {
		if err = ctx.Err(); err != nil {
			return PacketInspection{}, err
		}
		data, info, options, e := reader.ZeroCopyReadPacketDataWithOptions()
		if e != nil {
			return PacketInspection{}, e
		}
		if index != number {
			continue
		}
		_, manifestDigest, e := m.JSON()
		if e != nil {
			return PacketInspection{}, e
		}
		out = inspectFrame(data, info)
		out.ArchiveID, out.ManifestSHA256, out.RawSHA256 = m.Capture.ID, manifestDigest, m.Encoding.RawSHA256
		out.Number, out.Total, out.Interface = number, m.Capture.Packets, m.Capture.Interface
		for _, comment := range options.Comments {
			if strings.HasPrefix(comment, "StarBeacon: vlan_offload_id=") {
				out.VLANOffload = true
			}
		}
		return out, nil
	}
	return PacketInspection{}, io.ErrUnexpectedEOF
}

type boundedDecoder struct {
	gopacket.Decoder
	remaining int
}

func (d boundedDecoder) Decode(data []byte, builder gopacket.PacketBuilder) error {
	if d.remaining < 1 {
		return errDecodeBudget
	}
	return d.Decoder.Decode(data, boundedBuilder{PacketBuilder: builder, remaining: d.remaining})
}

type boundedBuilder struct {
	gopacket.PacketBuilder
	remaining int
}

func (b boundedBuilder) NextDecoder(next gopacket.Decoder) error {
	if next == nil {
		return b.PacketBuilder.NextDecoder(nil)
	}
	return b.PacketBuilder.NextDecoder(boundedDecoder{Decoder: next, remaining: b.remaining - 1})
}

// 解码器不能将通信正文输出到进程日志。
func (b boundedBuilder) DumpPacketData() {}

func inspectFrame(data []byte, info gopacket.CaptureInfo) PacketInspection {
	out := PacketInspection{Schema: "packet.inspect.v1", CapturedAt: info.Timestamp.UTC(), CapturedLength: len(data), OriginalLength: info.Length, Truncated: info.CaptureLength < info.Length, Packet: base64.StdEncoding.EncodeToString(data), PacketSHA256: Digest(data), DecodeStatus: "parsed", ChecksumValidation: "not_checked", PayloadVisibility: "not_decoded", Layers: []PacketLayer{}}
	packet := gopacket.NewPacket(data, boundedDecoder{Decoder: layers.LayerTypeEthernet, remaining: MaxInspectionLayers}, gopacket.DecodeOptions{NoCopy: true})
	if e := packet.ErrorLayer(); e != nil {
		out.DecodeStatus = "partial"
		if errors.Is(e.Error(), errDecodeBudget) {
			out.DecodeStatus = "limited"
		}
	}
	offset := 0
	for _, layer := range packet.Layers() {
		if layer.LayerType() == gopacket.LayerTypeDecodeFailure || len(out.Layers) >= MaxInspectionLayers {
			break
		}
		contents := layer.LayerContents()
		// 部分解码器在返回错误前登记空层；其默认值不属于已经观测到的字段。
		if len(contents) == 0 {
			continue
		}
		view := PacketLayer{Name: layer.LayerType().String(), Length: len(contents), Fields: []PacketField{}}
		if offset+len(contents) <= len(data) && bytes.Equal(data[offset:offset+len(contents)], contents) {
			start := offset
			view.Offset = &start
			offset += len(contents)
		}
		add := func(name, value string) { view.Fields = append(view.Fields, PacketField{Name: name, Value: value}) }
		num := func(name string, value uint64) { add(name, strconv.FormatUint(value, 10)) }
		flag := func(name string, value bool) { add(name, strconv.FormatBool(value)) }
		switch v := layer.(type) {
		case *layers.Ethernet:
			add("eth.src", v.SrcMAC.String())
			add("eth.dst", v.DstMAC.String())
			add("eth.type", "0x"+strconv.FormatUint(uint64(v.EthernetType), 16))
		case *layers.Dot1Q:
			num("vlan.id", uint64(v.VLANIdentifier))
			num("vlan.priority", uint64(v.Priority))
			flag("vlan.dei", v.DropEligible)
		case *layers.IPv4:
			add("ip.src", v.SrcIP.String())
			add("ip.dst", v.DstIP.String())
			num("ip.ttl", uint64(v.TTL))
			num("ip.id", uint64(v.Id))
			num("ip.len", uint64(v.Length))
			num("ip.proto", uint64(v.Protocol))
			num("ip.frag_offset", uint64(v.FragOffset))
			num("ip.flags", uint64(v.Flags))
		case *layers.IPv6:
			add("ipv6.src", v.SrcIP.String())
			add("ipv6.dst", v.DstIP.String())
			num("ipv6.hlim", uint64(v.HopLimit))
			num("ipv6.plen", uint64(v.Length))
			num("ipv6.flow", uint64(v.FlowLabel))
			num("ipv6.nxt", uint64(v.NextHeader))
		case *layers.TCP:
			num("tcp.srcport", uint64(v.SrcPort))
			num("tcp.dstport", uint64(v.DstPort))
			num("tcp.seq", uint64(v.Seq))
			num("tcp.ack", uint64(v.Ack))
			num("tcp.window_size_value", uint64(v.Window))
			flag("tcp.flags.syn", v.SYN)
			flag("tcp.flags.ack", v.ACK)
			flag("tcp.flags.fin", v.FIN)
			flag("tcp.flags.reset", v.RST)
			flag("tcp.flags.push", v.PSH)
			flag("tcp.flags.urg", v.URG)
			flag("tcp.flags.ece", v.ECE)
			flag("tcp.flags.cwr", v.CWR)
			flag("tcp.flags.ns", v.NS)
		case *layers.UDP:
			num("udp.srcport", uint64(v.SrcPort))
			num("udp.dstport", uint64(v.DstPort))
			num("udp.length", uint64(v.Length))
		case *layers.ARP:
			num("arp.opcode", uint64(v.Operation))
			add("arp.src.hw", net.HardwareAddr(v.SourceHwAddress).String())
			add("arp.dst.hw", net.HardwareAddr(v.DstHwAddress).String())
			if v.Protocol == layers.EthernetTypeIPv4 && len(v.SourceProtAddress) == 4 && len(v.DstProtAddress) == 4 {
				add("arp.src.proto_ipv4", net.IP(v.SourceProtAddress).String())
				add("arp.dst.proto_ipv4", net.IP(v.DstProtAddress).String())
			}
		case *layers.IPv6Fragment:
			num("ipv6.frag.offset", uint64(v.FragmentOffset))
			num("ipv6.frag.id", uint64(v.Identification))
			flag("ipv6.frag.more", v.MoreFragments)
		case *layers.ICMPv4:
			num("icmp.type", uint64(v.TypeCode.Type()))
			num("icmp.code", uint64(v.TypeCode.Code()))
			num("icmp.ident", uint64(v.Id))
			num("icmp.seq", uint64(v.Seq))
		case *layers.ICMPv6:
			num("icmpv6.type", uint64(v.TypeCode.Type()))
			num("icmpv6.code", uint64(v.TypeCode.Code()))
		}
		out.Layers = append(out.Layers, view)
	}
	return out
}
