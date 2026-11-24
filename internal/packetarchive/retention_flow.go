package packetarchive

import (
	"crypto/sha256"
	"net/netip"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type flowKey struct {
	A         netip.AddrPort `json:"endpoint_a"`
	B         netip.AddrPort `json:"endpoint_b"`
	Transport string         `json:"transport"`
	VLAN      string         `json:"vlan,omitempty"`
}

func orderedFlow(a, b netip.AddrPort, transport, vlan string) (flowKey, int) {
	if a.Compare(b) > 0 {
		return flowKey{A: b, B: a, Transport: transport, VLAN: vlan}, 1
	}
	return flowKey{A: a, B: b, Transport: transport, VLAN: vlan}, 0
}

func (key flowKey) valid() bool {
	return key.A.IsValid() && key.B.IsValid() && !key.A.Addr().Is4In6() && !key.B.Addr().Is4In6() &&
		key.A.Addr().Zone() == "" && key.B.Addr().Zone() == "" && key.A.Compare(key.B) <= 0 &&
		(key.Transport == "tcp" || key.Transport == "udp") && validVLANScope(key.VLAN)
}

func validVLANScope(raw string) bool {
	if raw == "" {
		return true
	}
	tags := strings.Split(raw, ",")
	if len(tags) > 8 {
		return false
	}
	for _, tag := range tags {
		v, err := strconv.ParseUint(tag, 10, 12)
		if err != nil || strconv.FormatUint(v, 10) != tag {
			return false
		}
	}
	return true
}

func vlanScope(values []uint16) string {
	raw := make([]byte, 0, len(values)*5)
	for _, value := range values {
		if len(raw) != 0 {
			raw = append(raw, ',')
		}
		raw = strconv.AppendUint(raw, uint64(value), 10)
	}
	return string(raw)
}

type retentionFrame struct {
	key       flowKey
	direction int
	tcp       *layers.TCP
	payload   []byte
	ipHeader  []byte
	ipPayload []byte
	uncertain bool
}

func retentionFlow(raw []byte, offload *uint16) (out retentionFrame) {
	packet := gopacket.NewPacket(raw, boundedDecoder{Decoder: layers.LayerTypeEthernet, remaining: MaxInspectionLayers}, gopacket.DecodeOptions{NoCopy: true})
	var source, destination netip.Addr
	var transport layers.IPProtocol
	switch ip := packet.NetworkLayer().(type) {
	case *layers.IPv4:
		source, _ = netip.AddrFromSlice(ip.SrcIP)
		destination, _ = netip.AddrFromSlice(ip.DstIP)
		out.ipHeader, out.ipPayload = ip.Contents, ip.Payload
		transport = ip.Protocol
		if ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0 {
			return retentionFrame{uncertain: true}
		}
	case *layers.IPv6:
		source, _ = netip.AddrFromSlice(ip.SrcIP)
		destination, _ = netip.AddrFromSlice(ip.DstIP)
		out.ipHeader, out.ipPayload = ip.Contents, ip.Payload
		transport = ip.NextHeader
	default:
		_, isARP := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
		return retentionFrame{uncertain: !isARP}
	}
	var tags []uint16
	if offload != nil {
		tags = append(tags, *offload)
	}
	for _, layer := range packet.Layers() {
		if tag, ok := layer.(*layers.Dot1Q); ok {
			tags = append(tags, tag.VLANIdentifier)
		}
	}
	if len(tags) > 8 || !source.IsValid() || !destination.IsValid() {
		return retentionFrame{uncertain: true}
	}
	var a, b uint16
	var protocol string
	switch transport {
	case layers.IPProtocolTCP:
		tcp, ok := packet.TransportLayer().(*layers.TCP)
		if !ok || len(tcp.Contents) == 0 {
			return retentionFrame{uncertain: true}
		}
		out.tcp, out.payload = tcp, tcp.Payload
		a, b, protocol = uint16(tcp.SrcPort), uint16(tcp.DstPort), "tcp"
	case layers.IPProtocolUDP:
		udp, ok := packet.TransportLayer().(*layers.UDP)
		if !ok || len(udp.Contents) == 0 {
			return retentionFrame{uncertain: true}
		}
		out.payload = udp.Payload
		a, b, protocol = uint16(udp.SrcPort), uint16(udp.DstPort), "udp"
	default:
		return retentionFrame{uncertain: true}
	}
	out.key, out.direction = orderedFlow(netip.AddrPortFrom(source.Unmap(), a), netip.AddrPortFrom(destination.Unmap(), b), protocol, vlanScope(tags))
	out.uncertain = packet.Metadata().Truncated
	return out
}

func (f retentionFrame) mirrorDigest() [sha256.Size]byte {
	hash := sha256.New()
	if f.key.A.Addr().Is4() && f.ipHeader[0]>>4 == 4 {
		_, _ = hash.Write(f.ipHeader[:8])
		_, _ = hash.Write(f.ipHeader[9:10])
		_, _ = hash.Write(f.ipHeader[12:])
	} else {
		_, _ = hash.Write(f.ipHeader[:7])
		_, _ = hash.Write(f.ipHeader[8:])
	}
	_, _ = hash.Write(f.ipPayload)
	var digest [sha256.Size]byte
	hash.Sum(digest[:0])
	return digest
}
