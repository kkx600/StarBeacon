package syslogdata

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strconv"
	"time"

	"github.com/kkx600/StarBeacon/internal/strictjson"
)

type SearchQuery struct {
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
	SensorID      string    `json:"sensor_id"`
	SourceID      string    `json:"source_id"`
	NetworkDomain string    `json:"network_domain"`
	PeerIP        string    `json:"peer_ip"`
	Hostname      string    `json:"hostname"`
	Application   string    `json:"application"`
	State         string    `json:"state"`
	Severity      *int      `json:"severity"`
	Keyword       string    `json:"keyword"`
	Cursor        string    `json:"cursor"`
	Limit         int       `json:"limit"`
}
type searchCursor struct {
	Time  time.Time `json:"time"`
	ID    string    `json:"id"`
	Query string    `json:"query"`
}

func (q SearchQuery) fingerprint(tenant string) string {
	q.Cursor = ""
	q.Start = q.Start.UTC()
	q.End = q.End.UTC()
	raw, _ := json.Marshal(q)
	return Hash(append([]byte("syslog.search.v1/"+tenant+"/"), raw...))
}
func (q SearchQuery) Validate(tenant string) error {
	if !ValidID(tenant) || q.Start.IsZero() || q.Start.Year() < 2000 || q.End.Year() > 2261 || !q.Start.Before(q.End) || q.End.Sub(q.Start) > 31*24*time.Hour || q.Limit < 1 || q.Limit > 100 {
		return ErrInput
	}
	for _, id := range []string{q.SensorID, q.SourceID, q.NetworkDomain} {
		if id != "" && !ValidID(id) {
			return ErrInput
		}
	}
	if q.PeerIP != "" {
		ip, err := netip.ParseAddr(q.PeerIP)
		if err != nil || ip.Is4In6() || ip.Zone() != "" || ip.String() != q.PeerIP {
			return ErrInput
		}
	}
	for _, v := range []string{q.Hostname, q.Application, q.Keyword} {
		if v != "" && !validText(v, 256) {
			return ErrInput
		}
	}
	if q.State != "" && q.State != "parsed" && q.State != "quarantined" || q.Severity != nil && (*q.Severity < 0 || *q.Severity > 7) {
		return ErrInput
	}
	_, _, err := q.Position(tenant)
	return err
}
func (q SearchQuery) Position(tenant string) (time.Time, string, error) {
	if q.Cursor == "" {
		return time.Time{}, "", nil
	}
	if len(q.Cursor) > 512 {
		return time.Time{}, "", ErrInput
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(q.Cursor)
	var c searchCursor
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != q.Cursor || strictjson.Fields(string(raw), []string{"time", "id", "query"}, 384) != nil || json.Unmarshal(raw, &c) != nil || !validHash(c.ID) || c.Query != q.fingerprint(tenant) || c.Time.Before(q.Start) || !c.Time.Before(q.End) {
		return time.Time{}, "", ErrInput
	}
	return c.Time.UTC(), c.ID, nil
}
func (q SearchQuery) Next(tenant string, t time.Time, id string) string {
	raw, _ := json.Marshal(searchCursor{t.UTC(), id, q.fingerprint(tenant)})
	return base64.RawURLEncoding.EncodeToString(raw)
}

type SourceQuery struct {
	SensorID string `json:"sensor_id"`
	SourceID string `json:"source_id"`
	Cursor   string `json:"cursor"`
	Limit    int    `json:"limit"`
}
type sourceCursor struct {
	SensorID string `json:"sensor_id"`
	SourceID string `json:"source_id"`
	Query    string `json:"query"`
}

func (q SourceQuery) fingerprint() string {
	q.Cursor = ""
	raw, _ := json.Marshal(q)
	return Hash(append([]byte("syslog.sources.v1/"), raw...))
}
func (q SourceQuery) Validate() error {
	if q.Limit < 1 || q.Limit > 100 || q.SensorID != "" && !ValidID(q.SensorID) || q.SourceID != "" && !ValidID(q.SourceID) {
		return ErrInput
	}
	_, _, err := q.Position()
	return err
}
func (q SourceQuery) Position() (string, string, error) {
	if q.Cursor == "" {
		return "", "", nil
	}
	if len(q.Cursor) > 512 {
		return "", "", ErrInput
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(q.Cursor)
	var c sourceCursor
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != q.Cursor || strictjson.Fields(string(raw), []string{"sensor_id", "source_id", "query"}, 384) != nil || json.Unmarshal(raw, &c) != nil || !ValidID(c.SensorID) || !ValidID(c.SourceID) || c.Query != q.fingerprint() {
		return "", "", ErrInput
	}
	return c.SensorID, c.SourceID, nil
}
func (q SourceQuery) Next(sensor, source string) string {
	raw, _ := json.Marshal(sourceCursor{sensor, source, q.fingerprint()})
	return base64.RawURLEncoding.EncodeToString(raw)
}
func canonicalCounter(s string) bool {
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && strconv.FormatUint(n, 10) == s
}
