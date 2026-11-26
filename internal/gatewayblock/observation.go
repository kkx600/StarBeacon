package gatewayblock

import (
	"context"
	"encoding/binary"
	"net/netip"
	"slices"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/response"
)

const (
	ObserveWindow    = 5 * time.Second
	FollowUpWindow   = 15 * time.Second
	FlowPaused       = "paused"
	FlowContinued    = "continued"
	FlowUnknown      = "unknown"
	maxEgressPackets = 1 << 20
)

// FollowUp 将授权固定在本策略、同一采集器的已下发插件代次与选定方向。
type FollowUp struct {
	PluginID     string `json:"plugin_id"`
	Generation   int64  `json:"generation"`
	ConnectorID  string `json:"connector_id"`
	ConfigSHA256 string `json:"config_sha256"`
	TargetSide   string `json:"target_side"`
	TTLSeconds   int    `json:"ttl_seconds"`
}

type FollowUpDevice struct {
	PluginID      string `json:"plugin_id"`
	Generation    int64  `json:"generation"`
	Version       int    `json:"version"`
	ConnectorID   string `json:"connector_id"`
	DeviceID      string `json:"device_id"`
	ConfigSHA256  string `json:"config_sha256"`
	MaxTTLSeconds int    `json:"max_ttl_seconds"`
}

func (p FollowUp) Matches(d FollowUpDevice) bool {
	return p.PluginID == d.PluginID && p.Generation == d.Generation && p.ConnectorID == d.ConnectorID &&
		p.ConfigSHA256 == d.ConfigSHA256 && p.TTLSeconds <= d.MaxTTLSeconds
}

func (p FollowUp) Valid() bool {
	return contract.ValidID(p.PluginID) && p.Generation > 0 && p.Generation <= MaxRevision &&
		contract.ValidID(p.ConnectorID) && ValidDigest(p.ConfigSHA256) &&
		(p.TargetSide == "source" || p.TargetSide == "destination") &&
		p.TTLSeconds >= 30 && p.TTLSeconds <= response.MaxTTLSeconds
}

func (p FollowUp) Target(f Flow) string {
	if p.TargetSide == "destination" {
		return f.DestinationIP.String()
	}
	return f.SourceIP.String()
}

type Observation struct {
	State           string    `json:"state"`
	Code            string    `json:"code"`
	Interface       string    `json:"interface"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
	EgressPackets   uint32    `json:"egress_packets"`
	OriginalPackets uint32    `json:"original_packets"`
	Reconnect       *Flow     `json:"reconnect,omitempty"`
}

// ObserveEgress 在明确指定的网关出侧接口仅读取报头，记录有限窗口内的流量证据。
func ObserveEgress(ctx context.Context, name string, flow Flow, verified, lease time.Time) Observation {
	return observeEgress(ctx, name, flow, verified, lease)
}

func observationInterface(name string) bool {
	if len(name) < 1 || len(name) > 15 || name == "." || name == ".." {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func (o Observation) valid(r Result, finished time.Time) bool {
	if !observationInterface(o.Interface) || o.StartedAt.Before(r.VerifiedAt) ||
		o.StartedAt.After(r.VerifiedAt.Add(time.Second)) || o.FinishedAt.Before(o.StartedAt) ||
		o.FinishedAt.After(finished) || o.FinishedAt.Sub(o.StartedAt) > ObserveWindow+time.Second ||
		o.EgressPackets > maxEgressPackets || o.OriginalPackets > o.EgressPackets ||
		o.Reconnect != nil && (!reconnects(r.Flow, *o.Reconnect) || o.OriginalPackets >= o.EgressPackets) {
		return false
	}
	if o.State == FlowUnknown {
		return slices.Contains([]string{"observer_unavailable", "window_short", "packet_loss", "packet_format",
			"egress_idle", "observer_changed"}, o.Code)
	}
	if o.Code != "" || o.FinishedAt.Sub(o.StartedAt) < ObserveWindow || !o.FinishedAt.Before(r.LeaseUntil) {
		return false
	}
	switch o.State {
	case FlowPaused:
		return o.EgressPackets > 0 && o.OriginalPackets == 0 && o.Reconnect == nil
	case FlowContinued:
		return o.OriginalPackets > 0 || o.Reconnect != nil
	default:
		return false
	}
}

func reconnects(original, next Flow) bool {
	return next.Valid() && next.SourceIP == original.SourceIP && next.DestinationIP == original.DestinationIP &&
		next.Transport == original.Transport && next.DestinationPort == original.DestinationPort &&
		next.SourcePort != original.SourcePort
}

// countPacket 仅读取与原连接同向的网络头和传输头。碎片或无法判定的同端点报文使观察降为未知。
func (o *Observation) countPacket(prefix []byte, size int, flow Flow) bool {
	if len(prefix) == 0 {
		return false
	}
	var src, dst netip.Addr
	var offset, length int
	var protocol byte
	switch prefix[0] >> 4 {
	case 4:
		if len(prefix) < 20 {
			return false
		}
		src, dst = netip.AddrFrom4([4]byte(prefix[12:16])), netip.AddrFrom4([4]byte(prefix[16:20]))
		offset, length, protocol = int(prefix[0]&15)*4, int(binary.BigEndian.Uint16(prefix[2:4])), prefix[9]
	case 6:
		if len(prefix) < 40 {
			return false
		}
		src, dst = netip.AddrFrom16([16]byte(prefix[8:24])), netip.AddrFrom16([16]byte(prefix[24:40]))
		offset, length, protocol = 40, 40+int(binary.BigEndian.Uint16(prefix[4:6])), prefix[6]
	default:
		return false
	}
	if src != flow.SourceIP || dst != flow.DestinationIP {
		return true
	}
	if prefix[0]>>4 == 6 && slices.Contains([]byte{0, 43, 44, 50, 51, 60}, protocol) {
		return false
	}
	if protocol != 6 && protocol != 17 || protocol == 6 && flow.Transport != "tcp" || protocol == 17 && flow.Transport != "udp" {
		return true
	}
	if offset < 20 || length > size || offset+8 > length || offset+8 > len(prefix) ||
		prefix[0]>>4 == 4 && binary.BigEndian.Uint16(prefix[6:8])&0x3fff != 0 {
		return false
	}
	header := prefix[offset:]
	if binary.BigEndian.Uint16(header[2:4]) != flow.DestinationPort {
		return true
	}
	port := binary.BigEndian.Uint16(header[:2])
	if port == 0 {
		return false
	}
	transportLength := length - offset
	var data, newConnection bool
	if protocol == 6 {
		if len(header) < 20 {
			return false
		}
		headerLength := int(header[12]>>4) * 4
		if headerLength < 20 || headerLength > transportLength {
			return false
		}
		data = transportLength > headerLength
		newConnection = header[13]&0x12 == 0x02
	} else {
		headerLength := int(binary.BigEndian.Uint16(header[4:6]))
		if headerLength < 8 || headerLength > transportLength {
			return false
		}
		data = headerLength > 8
		newConnection = data
	}
	if port == flow.SourcePort && (data || newConnection) {
		o.OriginalPackets++
	} else if port != flow.SourcePort && newConnection && o.Reconnect == nil {
		next := flow
		next.SourcePort = port
		o.Reconnect = &next
	}
	return true
}
