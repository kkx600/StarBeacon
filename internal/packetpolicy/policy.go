// Package packetpolicy 定义采集器本地配置、签名下发与健康回读共用的留存契约。
package packetpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

const (
	Smart       = "smart"
	Full        = "full"
	AlertOnly   = "alert_only"
	MaxRevision = 1<<53 - 1
	MaxBytes    = 16 * 1024
)

var ErrInput = errors.New("留存策略参数、修订或摘要无效")

func validDigest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == value
}

// Policy 由采集器读取，封段时冻结。IP 和网段名单只影响留存决策。
type Policy struct {
	NetworkDomain  string         `json:"network_domain"`
	Revision       uint64         `json:"revision"`
	Mode           string         `json:"mode"`
	EncryptedBytes *int           `json:"encrypted_bytes,omitempty"`
	PlainBytes     int            `json:"plain_bytes,omitempty"`
	DedupMillis    *int           `json:"dedup_millis,omitempty"`
	Protect        []netip.Prefix `json:"protect,omitempty"`
	Observe        []netip.Prefix `json:"observe,omitempty"`
}

func ValidMode(mode string) bool {
	return mode == Smart || mode == Full || mode == AlertOnly
}

func (p Policy) Valid() bool {
	if !contract.ValidID(p.NetworkDomain) || p.Revision == 0 || p.Revision > MaxRevision || !ValidMode(p.Mode) ||
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

func (a Policy) Equal(b Policy) bool {
	return a.EncryptedBytes != nil && b.EncryptedBytes != nil && a.DedupMillis != nil && b.DedupMillis != nil &&
		a.NetworkDomain == b.NetworkDomain && a.Mode == b.Mode && a.Revision == b.Revision &&
		*a.EncryptedBytes == *b.EncryptedBytes && a.PlainBytes == b.PlainBytes && *a.DedupMillis == *b.DedupMillis &&
		slices.Equal(a.Protect, b.Protect) && slices.Equal(a.Observe, b.Observe)
}

// Change 绑定已观察的修订和内容，避免同一修订的不同内容被覆盖。
type Change struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	ExpectedSHA256   string `json:"expected_sha256"`
	Policy           Policy `json:"policy"`
}

func (p *Change) UnmarshalJSON(raw []byte) error {
	fields := []string{"expected_revision", "expected_sha256", "policy", "network_domain", "revision", "mode", "encrypted_bytes", "plain_bytes", "dedup_millis", "protect", "observe"}
	if contract.JSONFields(string(raw), fields, MaxBytes) != nil {
		return ErrInput
	}
	type change Change
	var decoded change
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*p = Change(decoded)
	return p.Validate()
}

func (p Change) Validate() error {
	if p.ExpectedRevision == 0 || p.ExpectedRevision >= MaxRevision || !validDigest(p.ExpectedSHA256) ||
		!p.Policy.Valid() || p.Policy.Revision != p.ExpectedRevision+1 {
		return ErrInput
	}
	return nil
}

func (p Policy) Digest() string {
	raw, _ := json.Marshal(p)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

type Observation struct {
	Policy    Policy     `json:"policy"`
	SHA256    string     `json:"sha256"`
	Origin    string     `json:"origin"`
	TaskID    string     `json:"task_id,omitempty"`
	AppliedAt *time.Time `json:"applied_at,omitempty"`
}

func (o Observation) Valid() bool {
	if !o.Policy.Valid() || o.SHA256 != o.Policy.Digest() {
		return false
	}
	stamped := o.AppliedAt != nil && !o.AppliedAt.IsZero()
	switch o.Origin {
	case "file":
		return o.TaskID == "" && o.AppliedAt == nil
	case "local":
		return o.TaskID == "" && stamped
	case "platform":
		return contract.ValidID(o.TaskID) && stamped
	default:
		return false
	}
}

func (o Observation) Matches(p Change) bool {
	return o.Valid() && p.ExpectedRevision == o.Policy.Revision && p.ExpectedSHA256 == o.SHA256 &&
		p.Policy.NetworkDomain == o.Policy.NetworkDomain
}

func (p Change) Confirms(o Observation, taskID string) bool {
	return p.Validate() == nil && o.Valid() && o.Origin == "platform" && o.TaskID == taskID && o.SHA256 == p.Policy.Digest()
}

// Status 同时报告用于下次封存的配置和热层配额账目。
type Status struct {
	State         string       `json:"state"`
	ObservedAt    time.Time    `json:"observed_at"`
	Configuration *Observation `json:"configuration,omitempty"`
	ReservedBytes *string      `json:"reserved_bytes"`
	QuotaBytes    string       `json:"quota_bytes"`
	SegmentBytes  string       `json:"segment_bytes"`
	RotateSeconds int          `json:"rotate_seconds"`
}

func (s Status) Valid() bool {
	if s.ObservedAt.IsZero() {
		return false
	}
	if s.State == "not_configured" {
		return s.Configuration == nil && s.ReservedBytes == nil && s.QuotaBytes == "0" && s.SegmentBytes == "0" && s.RotateSeconds == 0
	}
	if s.State == "ready" {
		if s.Configuration == nil || !s.Configuration.Valid() {
			return false
		}
	} else if s.State != "unavailable" || s.Configuration != nil {
		return false
	}
	quota, ok := retentionByteCount(s.QuotaBytes)
	if !ok || quota < 100<<20 || s.RotateSeconds < 1 || s.RotateSeconds > 3600 {
		return false
	}
	segment, ok := retentionByteCount(s.SegmentBytes)
	if !ok || segment < 1<<20 || segment > 64<<20 || segment*3+512*1024 > quota {
		return false
	}
	if s.ReservedBytes != nil {
		_, ok = retentionByteCount(*s.ReservedBytes)
	}
	return ok
}

func retentionByteCount(value string) (int64, bool) {
	count, err := strconv.ParseInt(value, 10, 64)
	return count, err == nil && count >= 0 && strconv.FormatInt(count, 10) == value
}
