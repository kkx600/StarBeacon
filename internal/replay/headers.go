package replay

import (
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// headerInspector 复用官方协议层，仅接收无 VLAN／隧道／扩展头的完整 TCP 帧。
// 对象仅属于一次 Inspect 调用；下一帧覆盖底层字节前只保留值类型会话键。
type headerInspector struct {
	eth     layers.Ethernet
	ipv4    layers.IPv4
	ipv6    layers.IPv6
	tcp     layers.TCP
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
}

func newHeaderInspector() *headerInspector {
	h := &headerInspector{decoded: make([]gopacket.LayerType, 0, 4)}
	h.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &h.eth, &h.ipv4, &h.ipv6, &h.tcp)
	h.parser.IgnoreUnsupported = true
	return h
}

func (h *headerInspector) observe(tracker *handshakeTracker, raw []byte, ci gopacket.CaptureInfo) bool {
	if ci.CaptureLength < ci.Length || h.parser.DecodeLayers(raw, &h.decoded) != nil || h.parser.Truncated || len(h.decoded) != 3 || h.decoded[0] != layers.LayerTypeEthernet || h.decoded[2] != layers.LayerTypeTCP || h.tcp.NextLayerType() != gopacket.LayerTypePayload {
		return false
	}
	var src, dst netip.Addr
	switch h.decoded[1] {
	case layers.LayerTypeIPv4:
		if h.ipv4.Version != 4 || h.ipv4.FragOffset != 0 || h.ipv4.Flags&layers.IPv4MoreFragments != 0 {
			return false
		}
		src, _ = netip.AddrFromSlice(h.ipv4.SrcIP)
		dst, _ = netip.AddrFromSlice(h.ipv4.DstIP)
	case layers.LayerTypeIPv6:
		if h.ipv6.Version != 6 {
			return false
		}
		src, _ = netip.AddrFromSlice(h.ipv6.SrcIP)
		dst, _ = netip.AddrFromSlice(h.ipv6.DstIP)
	default:
		return false
	}
	if !src.IsValid() || !dst.IsValid() {
		return false
	}
	key, first := tracker.key(ci, src, dst, &h.tcp)
	if first {
		copy(key.MACs[:6], h.eth.SrcMAC)
		copy(key.MACs[6:], h.eth.DstMAC)
	} else {
		copy(key.MACs[:6], h.eth.DstMAC)
		copy(key.MACs[6:], h.eth.SrcMAC)
	}
	tracker.observeTCP(key, first, &h.tcp)
	return true
}
