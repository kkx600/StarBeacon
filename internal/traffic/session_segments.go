package traffic

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
)

const PacketSessionKind = "flow_segment"
const PacketSessionDataset = "starbeacon.packet_flow"
const PacketSessionSchema = "starbeacon.packet-flow.v1"

// PacketSessionSegment 描述一个实际采集窗口的观察，双方端点按规范顺序排列。
type PacketSessionSegment struct {
	Schema          string    `json:"schema"`
	ArchiveID       string    `json:"archive_id"`
	ManifestSHA256  string    `json:"manifest_sha256"`
	ArchiveRawSHA   string    `json:"archive_raw_sha256"`
	RunID           string    `json:"run_id"`
	Interface       string    `json:"interface"`
	NetworkDomain   string    `json:"network_domain,omitempty"`
	PolicyRevision  uint64    `json:"policy_revision,omitempty"`
	WindowStart     time.Time `json:"window_start"`
	WindowEnd       time.Time `json:"window_end"`
	FirstObserved   time.Time `json:"first_observed"`
	LastObserved    time.Time `json:"last_observed"`
	VLAN            string    `json:"vlan"`
	Retention       string    `json:"retention"`
	OriginalBytes   uint64    `json:"original_bytes,string"`
	RetainedBytes   uint64    `json:"retained_bytes,string"`
	RetainedPackets uint64    `json:"retained_packets,string"`
	KernelDrops     *uint64   `json:"kernel_drops,string"`
	Limited         bool      `json:"limited"`
}

func ParsePacketSession(doc model.Alert) (*PacketSessionSegment, error) {
	var segment PacketSessionSegment
	raw := []byte(doc.Event.Original)
	digest := sha256.Sum256(raw)
	if doc.Event.Kind != PacketSessionKind || doc.Event.Dataset != PacketSessionDataset || len(raw) > 8192 ||
		doc.RawSHA256 != hex.EncodeToString(digest[:]) || json.Unmarshal(raw, &segment) != nil ||
		segment.Schema != PacketSessionSchema || !contract.ValidID(segment.ArchiveID) || segment.ArchiveID != doc.SourceGenerationID ||
		!contract.ValidID(segment.RunID) || segment.WindowStart.IsZero() || segment.WindowEnd.Before(segment.WindowStart) ||
		segment.WindowEnd.Sub(segment.WindowStart) > time.Hour || !segment.WindowEnd.Equal(doc.ObservedAt) ||
		len(segment.Interface) < 1 || len(segment.Interface) > 15 || strings.ContainsAny(segment.Interface, "/\\\x00\r\n ") ||
		!validPacketDigest(segment.ManifestSHA256) || !validPacketDigest(segment.ArchiveRawSHA) ||
		(segment.NetworkDomain == "") != (segment.PolicyRevision == 0) || segment.NetworkDomain != "" && !contract.ValidID(segment.NetworkDomain) ||
		segment.FirstObserved.IsZero() || segment.LastObserved.Before(segment.FirstObserved) || !segment.LastObserved.Equal(doc.Timestamp) ||
		segment.OriginalBytes == 0 || segment.RetainedBytes > segment.OriginalBytes || segment.RetainedPackets > segment.RetainedBytes {
		return nil, errors.New("会话分段与归档来源不一致")
	}
	state := "retained"
	switch {
	case segment.RetainedBytes == 0:
		state = "metadata_only"
	case segment.RetainedBytes < segment.OriginalBytes:
		state = "policy_truncated"
	}
	if state != segment.Retention || (segment.RetainedPackets == 0) != (segment.RetainedBytes == 0) {
		return nil, errors.New("会话分段留存计数不一致")
	}
	return &segment, nil
}

func validPacketDigest(digest string) bool {
	if len(digest) != sha256.Size*2 || strings.ToLower(digest) != digest {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}
