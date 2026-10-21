package syslogdata

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/netip"
	"strconv"
	"time"

	"github.com/kkx600/StarBeacon/internal/strictjson"
)

// ReceiverBinding 只记录来源公开属性，正文的 HOSTNAME 不参与身份或租户绑定。
type ReceiverBinding struct {
	SourceID      string `json:"source_id"`
	SourceName    string `json:"source_name"`
	NetworkDomain string `json:"network_domain"`
	ConfigSHA256  string `json:"config_sha256"`
	Transport     string `json:"transport"`
	Format        string `json:"format"`
	Timezone      string `json:"timezone"`
	YearPolicy    string `json:"year_policy"`
}

func (s Source) Binding() ReceiverBinding {
	return ReceiverBinding{s.ID, s.Name, s.NetworkDomain, s.SHA256(), s.Transport, s.Format, s.Timezone, s.YearPolicy}
}
func (b ReceiverBinding) Valid() bool {
	if !ValidID(b.SourceID) || !validText(b.SourceName, 128) || !ValidID(b.NetworkDomain) || !validHash(b.ConfigSHA256) || b.Transport != "tls" && b.Transport != "tcp" && b.Transport != "udp" {
		return false
	}
	if b.Format == "rfc5424" {
		return b.Timezone == "" && b.YearPolicy == ""
	}
	_, err := time.LoadLocation(b.Timezone)
	return b.Format == "rfc3164" && b.Timezone != "" && err == nil && b.YearPolicy == "nearest_received_year"
}

type Peer struct {
	IP                string `json:"ip"`
	Port              uint16 `json:"port"`
	CertificateSHA256 string `json:"certificate_sha256"`
}

type Record struct {
	SchemaVersion  string          `json:"schema_version"`
	Binding        ReceiverBinding `json:"binding"`
	SourceEpoch    string          `json:"source_epoch"`
	SourceSequence string          `json:"source_sequence"`
	ObservedAt     time.Time       `json:"observed_at"`
	Peer           Peer            `json:"peer"`
	RawBase64      string          `json:"raw_base64,omitempty"`
	RawSHA256      string          `json:"raw_sha256"`
}

func decodeStrict(raw []byte, target any) error {
	fields := []string{"schema_version", "sources", "id", "name", "network_domain", "listen", "transport", "format", "timezone", "year_policy", "allowed_peers", "accept_unauthenticated", "accept_datagram_loss", "max_message_bytes", "max_connections", "max_events_per_second", "tls", "certificate_file", "private_key_file", "client_ca_file", "client_fingerprints", "binding", "source_id", "source_name", "config_sha256", "source_epoch", "source_sequence", "observed_at", "peer", "ip", "port", "certificate_sha256", "raw_base64", "raw_sha256"}
	if strictjson.Fields(string(raw), fields, 128*1024) != nil {
		return ErrInput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return ErrInput
	}
	return nil
}

func DecodeRecord(payload []byte) (Record, []byte, error) {
	var v Record
	if decodeStrict(payload, &v) != nil || v.SchemaVersion != Schema || !v.Binding.Valid() || !ValidID(v.SourceEpoch) || v.ObservedAt.IsZero() || v.ObservedAt.Year() < 2000 || v.ObservedAt.Year() > 2261 || !validHash(v.RawSHA256) {
		return v, nil, ErrInput
	}
	n, err := strconv.ParseUint(v.SourceSequence, 10, 64)
	if err != nil || n == 0 || n == math.MaxUint64 || strconv.FormatUint(n, 10) != v.SourceSequence {
		return v, nil, ErrInput
	}
	ip, e := netip.ParseAddr(v.Peer.IP)
	if e != nil || ip.Zone() != "" || ip.Is4In6() || ip.IsUnspecified() || ip.IsMulticast() || ip.String() != v.Peer.IP || v.Peer.Port == 0 || v.Binding.Transport == "tls" && !validHash(v.Peer.CertificateSHA256) || v.Binding.Transport != "tls" && v.Peer.CertificateSHA256 != "" {
		return v, nil, ErrInput
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(v.RawBase64)
	if e != nil || base64.StdEncoding.EncodeToString(raw) != v.RawBase64 || len(raw) == 0 || len(raw) > MaxMessageBytes || Hash(raw) != v.RawSHA256 {
		return v, nil, ErrInput
	}
	canonical, e := json.Marshal(v)
	if e != nil || !bytes.Equal(canonical, payload) {
		return v, nil, ErrInput
	}
	return v, raw, nil
}
