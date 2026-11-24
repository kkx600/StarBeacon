package packetarchive

import (
	"encoding/json"
	"io"
	"net/netip"
	"slices"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	bolt "go.etcd.io/bbolt"
)

const (
	RetentionSmart     = "smart"
	RetentionFull      = "full"
	RetentionAlertOnly = "alert_only"

	retainAll       = "retained"
	retainPrefix    = "policy_truncated"
	retainMetadata  = "metadata_only"
	skipClustering  = "packet_seal_skip_clustering"
	skipCompression = "packet_seal_skip_compression"
	keepRaw         = "packet_seal_raw_fallback"
	invalidPolicy   = "packet_seal_policy_unavailable"
	alertGap        = "packet_seal_alert_window_unavailable"
	sessionBudget   = "packet_seal_session_budget"

	maxPolicyRevision = 1<<53 - 1
	maxSessionRecords = 1024
	maxPolicyBytes    = 16 * 1024
)

var retentionPolicies = []byte("packet_retention_policies")

// RetentionPolicy 由采集器读取，封段时冻结。IP 和网段名单只影响留存决策。
type RetentionPolicy struct {
	NetworkDomain  string         `json:"network_domain"`
	Revision       uint64         `json:"revision"`
	Mode           string         `json:"mode"`
	EncryptedBytes *int           `json:"encrypted_bytes,omitempty"`
	PlainBytes     int            `json:"plain_bytes,omitempty"`
	DedupMillis    *int           `json:"dedup_millis,omitempty"`
	Protect        []netip.Prefix `json:"protect,omitempty"`
	Observe        []netip.Prefix `json:"observe,omitempty"`
}

func readRetentionPolicy(path string) (RetentionPolicy, error) {
	policy := RetentionPolicy{Mode: RetentionSmart, PlainBytes: 1 << 20}
	encrypted, dedup := 16<<10, 50
	policy.EncryptedBytes, policy.DedupMillis = &encrypted, &dedup
	file, err := openFile(path, maxPolicyBytes)
	if err != nil {
		return policy, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxPolicyBytes+1))
	if err != nil {
		return policy, err
	}
	fields := []string{"network_domain", "revision", "mode", "encrypted_bytes", "plain_bytes", "dedup_millis", "protect", "observe"}
	if contract.JSONFields(string(raw), fields, maxPolicyBytes) != nil || json.Unmarshal(raw, &policy) != nil || !policy.valid() {
		return policy, ErrIntegrity
	}
	return policy, nil
}

func retentionMode(mode string) bool {
	return mode == RetentionSmart || mode == RetentionFull || mode == RetentionAlertOnly
}

func (p RetentionPolicy) valid() bool {
	if !contract.ValidID(p.NetworkDomain) || p.Revision == 0 || p.Revision > maxPolicyRevision || !retentionMode(p.Mode) ||
		p.PlainBytes < 64<<10 || p.PlainBytes > 64<<20 || p.EncryptedBytes == nil || *p.EncryptedBytes < 0 || *p.EncryptedBytes > 1<<20 ||
		p.DedupMillis == nil || *p.DedupMillis != 0 && (*p.DedupMillis < 10 || *p.DedupMillis > 500) {
		return false
	}
	for _, list := range [][]netip.Prefix{p.Protect, p.Observe} {
		if len(list) > 128 {
			return false
		}
		seen := make(map[netip.Prefix]bool, len(list))
		for _, prefix := range list {
			if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Masked() != prefix || seen[prefix] {
				return false
			}
			seen[prefix] = true
		}
	}
	return true
}

func (p RetentionPolicy) protects(key flowKey) bool {
	for _, list := range [][]netip.Prefix{p.Protect, p.Observe} {
		for _, prefix := range list {
			if prefix.Contains(key.A.Addr()) || prefix.Contains(key.B.Addr()) {
				return true
			}
		}
	}
	return false
}

// 保留摘要只描述成功写入热段的字节。网卡截断和丢包仍由原捕获字段说明。
type RetentionSummary struct {
	NetworkDomain             string `json:"network_domain"`
	PolicyRevision            uint64 `json:"policy_revision"`
	Mode                      string `json:"mode"`
	OriginalPackets           uint64 `json:"original_packets"`
	OriginalBytes             uint64 `json:"original_bytes"`
	RetainedBytes             uint64 `json:"retained_bytes"`
	UnclassifiedBytes         uint64 `json:"unclassified_bytes"`
	UnclassifiedRetainedBytes uint64 `json:"unclassified_retained_bytes"`
	DuplicateBytes            uint64 `json:"duplicate_bytes"`
	Degradation               string `json:"degradation,omitempty"`
}

type RetentionSession struct {
	flowKey
	FirstPacket    uint64    `json:"first_packet"`
	StartedAt      time.Time `json:"started_at"`
	EndedAt        time.Time `json:"ended_at"`
	Protocol       string    `json:"protocol"`
	State          string    `json:"state"`
	OriginalBytes  uint64    `json:"original_bytes"`
	RetainedBytes  uint64    `json:"retained_bytes"`
	PolicyRevision uint64    `json:"policy_revision"`
}

func retentionState(original, retained uint64) string {
	switch {
	case retained == original:
		return retainAll
	case retained == 0:
		return retainMetadata
	default:
		return retainPrefix
	}
}

func (r RetentionSummary) valid(c Capture) bool {
	switch r.Degradation {
	case "", skipClustering, skipCompression:
	case keepRaw, invalidPolicy, alertGap, sessionBudget:
		if r.Mode != RetentionFull {
			return false
		}
	default:
		return false
	}
	if r.PolicyRevision == 0 {
		if r.NetworkDomain != "" || r.Degradation != invalidPolicy {
			return false
		}
	} else if r.PolicyRevision > maxPolicyRevision || !contract.ValidID(r.NetworkDomain) {
		return false
	}
	return retentionMode(r.Mode) && r.OriginalPackets >= c.Packets && r.OriginalPackets <= 1048576 &&
		r.OriginalBytes >= r.OriginalPackets && r.OriginalBytes <= uint64(MaxSegmentBytes) && r.OriginalBytes >= r.RetainedBytes &&
		r.RetainedBytes == c.PacketBytes && r.DuplicateBytes <= r.OriginalBytes-r.RetainedBytes &&
		r.UnclassifiedBytes <= r.OriginalBytes && r.UnclassifiedRetainedBytes <= r.UnclassifiedBytes &&
		r.UnclassifiedRetainedBytes <= r.RetainedBytes &&
		(r.Mode != RetentionFull || r.OriginalPackets == c.Packets && r.OriginalBytes == r.RetainedBytes)
}

func (m Manifest) validRetention() bool {
	r := m.Capture.Retention
	if r == nil {
		return len(m.Sessions) == 0
	}
	if len(m.Sessions) > maxSessionRecords {
		return false
	}
	original, retained := r.UnclassifiedBytes, r.UnclassifiedRetainedBytes
	var previous uint64
	for _, flow := range m.Sessions {
		switch flow.Protocol {
		case "tcp", "http", "tls", "ssh":
			if flow.Transport != "tcp" {
				return false
			}
		case "udp", "quic":
			if flow.Transport != "udp" {
				return false
			}
		default:
			return false
		}
		if !flow.flowKey.valid() || flow.PolicyRevision != r.PolicyRevision || flow.FirstPacket <= previous || flow.FirstPacket > r.OriginalPackets ||
			flow.StartedAt.IsZero() || flow.EndedAt.Before(flow.StartedAt) || flow.OriginalBytes == 0 || flow.RetainedBytes > flow.OriginalBytes ||
			flow.OriginalBytes > r.OriginalBytes-original || flow.RetainedBytes > r.RetainedBytes-retained || flow.State != retentionState(flow.OriginalBytes, flow.RetainedBytes) {
			return false
		}
		original += flow.OriginalBytes
		retained += flow.RetainedBytes
		previous = flow.FirstPacket
	}
	return original == r.OriginalBytes && retained == r.RetainedBytes
}

type sealPlan struct {
	Policy      RetentionPolicy `json:"policy"`
	AlertCutoff uint64          `json:"alert_cutoff"`
	Degradation string          `json:"degradation,omitempty"`
}

func freezeRetention(tx *bolt.Tx, policy RetentionPolicy, failed bool) (*sealPlan, error) {
	plan := &sealPlan{Policy: policy, AlertCutoff: uint64(tx.ID())}
	if failed {
		plan.Policy = RetentionPolicy{Mode: RetentionFull}
		plan.Degradation = invalidPolicy
		return plan, nil
	}
	bucket, err := tx.CreateBucketIfNotExists(retentionPolicies)
	if err != nil {
		return nil, err
	}
	key := []byte(policy.NetworkDomain)
	var previous RetentionPolicy
	if raw := bucket.Get(key); raw != nil {
		if json.Unmarshal(raw, &previous) != nil || !previous.valid() {
			return nil, ErrIntegrity
		}
	}
	if policy.Revision < previous.Revision || policy.Revision == previous.Revision && !sameRetentionPolicy(previous, policy) {
		plan.Policy, plan.Degradation = previous, invalidPolicy
		return plan, nil
	}
	if policy.Revision > previous.Revision {
		raw, err := json.Marshal(policy)
		if err != nil {
			return nil, err
		}
		if err = bucket.Put(key, raw); err != nil {
			return nil, err
		}
	}
	switch pending := tx.Bucket(spoolWork).Stats().KeyN; {
	case pending >= 9:
		plan.Degradation = keepRaw
	case pending >= 6:
		plan.Degradation = skipCompression
	case pending >= 3:
		plan.Degradation = skipClustering
	}
	return plan, nil
}

func sameRetentionPolicy(a, b RetentionPolicy) bool {
	return a.NetworkDomain == b.NetworkDomain && a.Mode == b.Mode && a.Revision == b.Revision &&
		*a.EncryptedBytes == *b.EncryptedBytes && a.PlainBytes == b.PlainBytes && *a.DedupMillis == *b.DedupMillis &&
		slices.Equal(a.Protect, b.Protect) && slices.Equal(a.Observe, b.Observe)
}

func (p sealPlan) rawFallback() bool {
	return p.Degradation == keepRaw || p.Degradation == invalidPolicy
}

func (p sealPlan) summary(c Capture) RetentionSummary {
	mode := p.Policy.Mode
	if p.rawFallback() {
		mode = RetentionFull
	}
	return RetentionSummary{NetworkDomain: p.Policy.NetworkDomain, PolicyRevision: p.Policy.Revision, Mode: mode,
		OriginalPackets: c.Packets, OriginalBytes: c.PacketBytes, RetainedBytes: c.PacketBytes, Degradation: p.Degradation}
}
