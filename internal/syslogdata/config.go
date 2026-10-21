// Package syslogdata 固定外部 Syslog 的来源、原始字节和解析质量，不赋予安全处置权限。
package syslogdata

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/privatefile"
)

const MaxSources = 16
const MaxMessageBytes = 64 * 1024
const ParserVersion = "leodido/go-syslog/v4@v4.6.0/strict-1"
const Schema = "syslog.raw.v1"

var ErrInput = errors.New("Syslog 来源或数据格式无效")
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func ValidID(s string) bool  { return idPattern.MatchString(s) }
func Hash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func validHash(s string) bool {
	_, e := hex.DecodeString(s)
	return len(s) == 64 && strings.ToLower(s) == s && e == nil
}
func validText(s string, n int) bool {
	return s != "" && len(s) <= n && utf8.ValidString(s) && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, unicode.IsControl)
}

type TLSFiles struct {
	CertificateFile    string   `json:"certificate_file"`
	PrivateKeyFile     string   `json:"private_key_file"`
	ClientCAFile       string   `json:"client_ca_file"`
	ClientFingerprints []string `json:"client_fingerprints"`
}

type Source struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	NetworkDomain         string   `json:"network_domain"`
	Listen                string   `json:"listen"`
	Transport             string   `json:"transport"`
	Format                string   `json:"format"`
	Timezone              string   `json:"timezone"`
	YearPolicy            string   `json:"year_policy"`
	AllowedPeers          []string `json:"allowed_peers"`
	AcceptUnauthenticated bool     `json:"accept_unauthenticated"`
	AcceptDatagramLoss    bool     `json:"accept_datagram_loss"`
	MaxMessageBytes       int      `json:"max_message_bytes"`
	MaxConnections        int      `json:"max_connections"`
	MaxEventsPerSecond    int      `json:"max_events_per_second"`
	TLS                   TLSFiles `json:"tls"`
}

func (s Source) Validate() error {
	address, err := netip.ParseAddrPort(s.Listen)
	if !ValidID(s.ID) || !validText(s.Name, 128) || !ValidID(s.NetworkDomain) || err != nil || address.Port() < 1024 || address.Addr().IsMulticast() || address.Addr().Is4In6() || address.Addr().Zone() != "" || address.String() != s.Listen {
		return ErrInput
	}
	if s.MaxMessageBytes < 256 || s.MaxMessageBytes > MaxMessageBytes || s.MaxConnections < 1 || s.MaxConnections > 32 || s.MaxEventsPerSecond < 1 || s.MaxEventsPerSecond > 10000 || len(s.AllowedPeers) < 1 || len(s.AllowedPeers) > 32 {
		return ErrInput
	}
	seen := map[string]bool{}
	for _, raw := range s.AllowedPeers {
		p, e := netip.ParsePrefix(raw)
		if e != nil || p.Masked().String() != raw || p.Addr().Is4In6() || seen[raw] {
			return ErrInput
		}
		seen[raw] = true
	}
	if s.Format != "rfc5424" && s.Format != "rfc3164" {
		return ErrInput
	}
	if s.Format == "rfc3164" {
		if _, e := time.LoadLocation(s.Timezone); e != nil || s.Timezone == "" || s.YearPolicy != "nearest_received_year" {
			return ErrInput
		}
	} else if s.Timezone != "" || s.YearPolicy != "" {
		return ErrInput
	}
	switch s.Transport {
	case "tls":
		if s.AcceptUnauthenticated || s.AcceptDatagramLoss || !filepath.IsAbs(s.TLS.CertificateFile) || !filepath.IsAbs(s.TLS.PrivateKeyFile) || !filepath.IsAbs(s.TLS.ClientCAFile) || len(s.TLS.ClientFingerprints) < 1 || len(s.TLS.ClientFingerprints) > 8 {
			return ErrInput
		}
		seen = map[string]bool{}
		for _, f := range s.TLS.ClientFingerprints {
			if !validHash(f) || seen[f] {
				return ErrInput
			}
			seen[f] = true
		}
	case "tcp", "udp":
		if !s.AcceptUnauthenticated || s.Transport == "udp" && !s.AcceptDatagramLoss || s.Transport == "tcp" && s.AcceptDatagramLoss || s.TLS.CertificateFile != "" || s.TLS.PrivateKeyFile != "" || s.TLS.ClientCAFile != "" || len(s.TLS.ClientFingerprints) != 0 {
			return ErrInput
		}
	default:
		return ErrInput
	}
	return nil
}

func (s Source) SHA256() string { raw, _ := json.Marshal(s); return Hash(raw) }
func (s Source) Allows(peer netip.Addr) bool {
	peer = peer.Unmap()
	if !peer.IsValid() || peer.IsUnspecified() || peer.IsMulticast() {
		return false
	}
	for _, raw := range s.AllowedPeers {
		p, e := netip.ParsePrefix(raw)
		if e == nil && p.Contains(peer) {
			return true
		}
	}
	return false
}

type File struct {
	SchemaVersion string   `json:"schema_version"`
	Sources       []Source `json:"sources"`
}

func LoadFile(path string) (File, error) {
	var file File
	raw, err := privatefile.Read(path, 128*1024)
	if err != nil {
		return file, ErrInput
	}
	if err := decodeStrict(raw, &file); err != nil || file.SchemaVersion != "syslog.sources.v1" || len(file.Sources) > MaxSources {
		return file, ErrInput
	}
	ids, endpoints := map[string]bool{}, map[string]bool{}
	for _, s := range file.Sources {
		key := s.Listen + "/tcp"
		if s.Transport == "udp" {
			key = s.Listen + "/udp"
		}
		if s.Validate() != nil || ids[s.ID] || endpoints[key] {
			return File{}, ErrInput
		}
		ids[s.ID], endpoints[key] = true, true
	}
	return file, nil
}
