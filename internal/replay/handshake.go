package replay

import (
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

const maxHandshakeFlows = 32768

// HandshakeObservation 描述样本中可见的 TCP 建连序列，不证明载荷完整或通信成功。
type HandshakeObservation struct {
	Algorithm          string   `json:"algorithm"`
	AssessedFlows      int64    `json:"assessed_flows"`
	CompleteHandshakes int64    `json:"complete_handshakes"`
	IncompleteFlows    int64    `json:"incomplete_flows"`
	ReusedTuples       int64    `json:"reused_tuples"`
	SkippedPackets     int64    `json:"skipped_packets"`
	Limited            bool     `json:"limited"`
	LimitReasons       []string `json:"limit_reasons"`
	ChecksumValidation string   `json:"checksum_validation"`
}

type handshakeKey struct {
	Section   int
	Interface int
	First     netip.AddrPort
	Second    netip.AddrPort
	MACs      [12]byte
	VLANs     [8]uint16
	VLANCount uint8
}

type handshakeState struct {
	clientFirst bool
	syn         bool
	synAck      bool
	complete    bool
	reused      bool
	reset       bool
	clientSeq   uint32
	clientBytes uint32
	serverSeq   uint32
	serverBytes uint32
	clientAck   uint32
}

type handshakeTracker struct {
	section int
	flows   map[handshakeKey]*handshakeState
	out     HandshakeObservation
}

func newHandshakeTracker() *handshakeTracker {
	return &handshakeTracker{flows: make(map[handshakeKey]*handshakeState), out: HandshakeObservation{Algorithm: "tcp-handshake-observation-v1", LimitReasons: []string{}, ChecksumValidation: "not_checked"}}
}

func (h *handshakeTracker) limit(reason string) {
	h.out.Limited = true
	for _, value := range h.out.LimitReasons {
		if value == reason {
			return
		}
	}
	h.out.LimitReasons = append(h.out.LimitReasons, reason)
}

func (h *handshakeTracker) observe(packet gopacket.Packet, ci gopacket.CaptureInfo) {
	if ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok && (ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0) {
		h.out.SkippedPackets++
		h.limit("ip_fragmentation")
		return
	}
	if packet.Layer(layers.LayerTypeIPv6Fragment) != nil {
		h.out.SkippedPackets++
		h.limit("ip_fragmentation")
		return
	}
	tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		if packet.ErrorLayer() != nil {
			h.out.SkippedPackets++
			h.limit("decode_error")
		}
		return
	}
	// snaplen 截断不能用于确认含数据 SYN 的序号占用；跳过整帧并保留质量限制。
	if ci.CaptureLength < ci.Length || packet.Metadata().Truncated || packet.ErrorLayer() != nil {
		h.out.SkippedPackets++
		h.limit("truncated_or_invalid_packet")
		return
	}
	var src, dst netip.Addr
	networks := 0
	for _, layer := range packet.Layers() {
		if layer.LayerType() == layers.LayerTypeIPv4 || layer.LayerType() == layers.LayerTypeIPv6 {
			networks++
		}
	}
	if networks != 1 {
		h.out.SkippedPackets++
		h.limit("unsupported_network_layer")
		return
	}
	switch ip := packet.NetworkLayer().(type) {
	case *layers.IPv4:
		if ip.Version != 4 {
			h.out.SkippedPackets++
			h.limit("truncated_or_invalid_packet")
			return
		}
		src, _ = netip.AddrFromSlice(ip.SrcIP)
		dst, _ = netip.AddrFromSlice(ip.DstIP)
	case *layers.IPv6:
		if ip.Version != 6 {
			h.out.SkippedPackets++
			h.limit("truncated_or_invalid_packet")
			return
		}
		src, _ = netip.AddrFromSlice(ip.SrcIP)
		dst, _ = netip.AddrFromSlice(ip.DstIP)
	}
	if !src.IsValid() || !dst.IsValid() {
		h.out.SkippedPackets++
		h.limit("unsupported_network_layer")
		return
	}
	key, first := h.key(ci, src, dst, tcp)
	for _, layer := range packet.Layers() {
		switch v := layer.(type) {
		case *layers.Ethernet:
			if first {
				copy(key.MACs[:6], v.SrcMAC)
				copy(key.MACs[6:], v.DstMAC)
			} else {
				copy(key.MACs[:6], v.DstMAC)
				copy(key.MACs[6:], v.SrcMAC)
			}
		case *layers.Dot1Q:
			if int(key.VLANCount) == len(key.VLANs) {
				h.out.SkippedPackets++
				h.limit("vlan_depth")
				return
			}
			key.VLANs[key.VLANCount] = v.VLANIdentifier
			key.VLANCount++
		}
	}
	h.observeTCP(key, first, tcp)
}

func (h *handshakeTracker) key(ci gopacket.CaptureInfo, src, dst netip.Addr, tcp *layers.TCP) (handshakeKey, bool) {
	source := netip.AddrPortFrom(src, uint16(tcp.SrcPort))
	destination := netip.AddrPortFrom(dst, uint16(tcp.DstPort))
	first := src.Compare(dst) < 0 || src == dst && source.Port() < destination.Port()
	key := handshakeKey{Section: h.section, Interface: ci.InterfaceIndex, First: source, Second: destination}
	if !first {
		key.First, key.Second = destination, source
	}
	return key, first
}

func (h *handshakeTracker) observeTCP(key handshakeKey, first bool, tcp *layers.TCP) {
	state := h.flows[key]
	if state == nil {
		if len(h.flows) >= maxHandshakeFlows {
			h.out.SkippedPackets++
			h.limit("flow_limit")
			return
		}
		state = &handshakeState{}
		h.flows[key] = state
	}
	if tcp.SYN && !tcp.ACK && !tcp.FIN && !tcp.RST {
		if state.syn && (state.clientFirst != first || state.clientSeq != tcp.Seq) {
			if !state.reused {
				state.reused = true
				h.out.ReusedTuples++
			}
			h.limit("tuple_reuse_or_simultaneous_open")
			state.synAck, state.complete, state.reset = false, false, false
		}
		if !state.syn || state.clientFirst != first || state.clientSeq != tcp.Seq {
			state.syn, state.clientFirst, state.clientSeq, state.clientBytes = true, first, tcp.Seq, uint32(len(tcp.Payload))
			state.reset = false
		}
		return
	}
	if tcp.RST {
		state.reset = true
	}
	if !state.syn || state.complete || state.reset {
		return
	}
	if tcp.SYN && tcp.ACK && !tcp.FIN && first != state.clientFirst && tcp.Ack-(state.clientSeq+1) <= state.clientBytes {
		state.synAck, state.serverSeq, state.serverBytes, state.clientAck = true, tcp.Seq, uint32(len(tcp.Payload)), tcp.Ack
		return
	}
	// uint32 运算保持 TCP 序号回绕语义；不以“任意 ACK”替代第三次握手。
	if state.synAck && !tcp.SYN && tcp.ACK && first == state.clientFirst && tcp.Seq == state.clientAck && tcp.Ack-(state.serverSeq+1) <= state.serverBytes {
		state.complete = true
		h.out.CompleteHandshakes++
	}
}

func (h *handshakeTracker) result() HandshakeObservation {
	h.out.AssessedFlows = int64(len(h.flows))
	h.out.IncompleteFlows = 0
	for _, flow := range h.flows {
		if !flow.complete {
			h.out.IncompleteFlows++
		}
	}
	return h.out
}
