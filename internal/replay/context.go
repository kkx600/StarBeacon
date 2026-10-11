package replay

import (
	"context"
	"encoding/hex"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type PacketSnippet struct {
	Packet          int64  `json:"packet"`
	Protocol        string `json:"protocol"`
	SourceIP        string `json:"source_ip"`
	DestinationIP   string `json:"destination_ip"`
	SourcePort      uint16 `json:"source_port"`
	DestinationPort uint16 `json:"destination_port"`
	PayloadHex      string `json:"payload_hex"`
	PayloadLimited  bool   `json:"payload_limited"`
}

// InspectContext 只向模型暴露前 128 帧中最多 8 段 TCP/UDP 载荷，每段最多 256 字节。
// 帧序号可回溯至原文件；不进行流重组、TLS 解密、HTTP 规范化或攻击结果推断。
func InspectContext(ctx context.Context, path string) (Metadata, []PacketSnippet, bool, error) {
	snippets := []PacketSnippet{}
	limited := false
	metadata, err := inspect(ctx, path, func(index int64, data []byte, link layers.LinkType) {
		if index > 128 || len(snippets) >= 8 {
			limited = true
			return
		}
		packet := gopacket.NewPacket(data, link, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		network := packet.NetworkLayer()
		if network == nil {
			limited = true
			return
		}
		if ip, ok := network.(*layers.IPv4); ok && (ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0) {
			limited = true
			return
		}
		// 停止在传输层，不能把端口驱动的应用解析失败当作原始载荷缺失。
		// IPv6 分片由库解码为 Fragment，不产生 TCP/UDP 传输层，保持有界跳过。
		transport := packet.TransportLayer()
		if transport == nil {
			limited = true
			return
		}
		var payload []byte
		row := PacketSnippet{Packet: index, SourceIP: network.NetworkFlow().Src().String(), DestinationIP: network.NetworkFlow().Dst().String()}
		contents := transport.LayerContents()
		length := len(contents) + len(transport.LayerPayload())
		if length > cap(contents) {
			limited = true
			return
		}
		raw := contents[:length]
		if tcp, ok := transport.(*layers.TCP); ok {
			var checked layers.TCP
			if checked.DecodeFromBytes(raw, gopacket.NilDecodeFeedback) != nil {
				limited = true
				return
			}
			row.Protocol = "tcp"
			row.SourcePort = uint16(tcp.SrcPort)
			row.DestinationPort = uint16(tcp.DstPort)
			payload = tcp.Payload
		} else if udp, ok := transport.(*layers.UDP); ok {
			var checked layers.UDP
			if checked.DecodeFromBytes(raw, gopacket.NilDecodeFeedback) != nil {
				limited = true
				return
			}
			row.Protocol = "udp"
			row.SourcePort = uint16(udp.SrcPort)
			row.DestinationPort = uint16(udp.DstPort)
			payload = udp.Payload
		}
		if len(payload) == 0 {
			return
		}
		row.PayloadLimited = len(payload) > 256
		limited = limited || row.PayloadLimited
		row.PayloadHex = hex.EncodeToString(payload[:min(256, len(payload))])
		snippets = append(snippets, row)
	})
	return metadata, snippets, limited, err
}
