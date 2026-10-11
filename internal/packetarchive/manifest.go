package packetarchive

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

const SnapLength = 262144
const MaxManifestBytes = 512 * 1024

// Capture 描述独立原包捕获的实际观测范围；镜像源是否漏包及网卡卸载仍属于外部限制。
type Capture struct {
	ID                 string     `json:"id"`
	TenantID           string     `json:"tenant_id"`
	SensorID           string     `json:"sensor_id"`
	RegistrationID     string     `json:"registration_id"`
	RunID              string     `json:"run_id"`
	Interface          string     `json:"interface"`
	InterfaceMAC       string     `json:"interface_mac"`
	SettingsSHA256     string     `json:"settings_sha256"`
	BPFFilter          string     `json:"bpf_filter"`
	Promiscuous        bool       `json:"promiscuous"`
	StartedAt          time.Time  `json:"started_at"`
	EndedAt            time.Time  `json:"ended_at"`
	FirstPacketAt      *time.Time `json:"first_packet_at"`
	LastPacketAt       *time.Time `json:"last_packet_at"`
	Packets            uint64     `json:"packets"`
	PacketBytes        uint64     `json:"packet_bytes"`
	TruncatedPackets   uint64     `json:"truncated_packets"`
	VLANOffloadPackets uint64     `json:"vlan_offload_packets"`
	KernelDrops        *uint64    `json:"kernel_drops,string"`
	CounterState       string     `json:"counter_state"`
	Termination        string     `json:"termination"`
	Format             string     `json:"format"`
	Source             string     `json:"source"`
	SnapLength         uint32     `json:"snap_length"`
}

type Manifest struct {
	Capture  Capture  `json:"capture"`
	Encoding Encoding `json:"encoding"`
}

func (c Capture) Validate() error {
	for _, id := range []string{c.ID, c.TenantID, c.SensorID, c.RegistrationID, c.RunID} {
		if !contract.ValidID(id) {
			return ErrIntegrity
		}
	}
	mac, err := net.ParseMAC(c.InterfaceMAC)
	if err != nil || len(mac) != 6 || mac.String() != c.InterfaceMAC || len(c.Interface) < 1 || len(c.Interface) > 15 || strings.ContainsAny(c.Interface, "/\\\x00\r\n ") || len(c.BPFFilter) > 2048 || strings.ContainsAny(c.BPFFilter, "\x00\r\n") || !validDigest(c.SettingsSHA256) || c.StartedAt.IsZero() || c.EndedAt.Before(c.StartedAt) || c.EndedAt.IsZero() || c.EndedAt.Sub(c.StartedAt) > time.Hour || c.Format != "pcapng" || c.Source != "AF_PACKET" || c.SnapLength != SnapLength || c.Packets > 1048576 || c.PacketBytes > uint64(MaxSegmentBytes) || c.TruncatedPackets > c.Packets || c.VLANOffloadPackets > c.Packets {
		return ErrIntegrity
	}
	if c.Packets == 0 {
		if c.FirstPacketAt != nil || c.LastPacketAt != nil || c.PacketBytes != 0 {
			return ErrIntegrity
		}
	} else if c.FirstPacketAt == nil || c.LastPacketAt == nil || c.FirstPacketAt.IsZero() || c.LastPacketAt.Before(*c.FirstPacketAt) || c.PacketBytes == 0 {
		return ErrIntegrity
	}
	if c.CounterState == "observed" {
		if c.KernelDrops == nil {
			return ErrIntegrity
		}
	} else if c.CounterState != "unavailable" || c.KernelDrops != nil {
		return ErrIntegrity
	}
	switch c.Termination {
	case "rotation", "configuration", "shutdown":
	default:
		return ErrIntegrity
	}
	return nil
}

func (m Manifest) Validate() error {
	if m.Capture.Validate() != nil || m.Encoding.Validate() != nil || m.Capture.PacketBytes > uint64(m.Encoding.RawBytes) {
		return ErrIntegrity
	}
	return nil
}

func (m Manifest) JSON() ([]byte, string, error) {
	if m.Validate() != nil {
		return nil, "", ErrIntegrity
	}
	raw, err := json.Marshal(m)
	if err != nil || len(raw) > MaxManifestBytes {
		return nil, "", ErrLimit
	}
	return raw, Digest(raw), nil
}

var manifestFields = []string{"capture", "encoding", "id", "tenant_id", "sensor_id", "registration_id", "run_id", "interface", "interface_mac", "settings_sha256", "bpf_filter", "promiscuous", "started_at", "ended_at", "first_packet_at", "last_packet_at", "packets", "packet_bytes", "truncated_packets", "vlan_offload_packets", "kernel_drops", "counter_state", "termination", "format", "source", "snap_length", "schema", "codec", "implementation", "level", "frame_bytes", "raw_bytes", "stored_bytes", "raw_sha256", "stored_sha256", "frames", "raw_offset", "raw_length", "stored_offset", "stored_length"}

func ParseManifest(raw []byte) (Manifest, error) {
	var m Manifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if contract.JSONFields(string(raw), manifestFields, MaxManifestBytes) != nil || decoder.Decode(&m) != nil || decoder.Decode(new(any)) != io.EOF || m.Validate() != nil {
		return m, ErrIntegrity
	}
	return m, nil
}
