// Package traffic 从实际 EVE 提取有界展示字段，不补造丢失的报文、方向或解密结果。
package traffic

import (
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/normalize"
)

type Flow struct {
	Start           *time.Time `json:"start"`
	End             *time.Time `json:"end"`
	State           string     `json:"state"`
	Reason          string     `json:"reason"`
	PacketsToServer string     `json:"packets_to_server"`
	PacketsToClient string     `json:"packets_to_client"`
	BytesToServer   string     `json:"bytes_to_server"`
	BytesToClient   string     `json:"bytes_to_client"`
}
type Query struct {
	Name string `json:"name"`
	Type string `json:"type"`
}
type DNS struct {
	Version string  `json:"version"`
	Type    string  `json:"type"`
	RCode   string  `json:"rcode"`
	Queries []Query `json:"queries"`
}
type TLS struct {
	SNI         string `json:"sni"`
	Version     string `json:"version"`
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	Fingerprint string `json:"fingerprint"`
}
type Details struct {
	State           string   `json:"state"`
	Truncated       bool     `json:"truncated"`
	Flow            *Flow    `json:"flow"`
	TLS             *TLS     `json:"tls"`
	DNS             *DNS     `json:"dns"`
	SourceMACs      []string `json:"source_macs"`
	DestinationMACs []string `json:"destination_macs"`
	CommunityID     string   `json:"community_id"`
	PacketSource    string   `json:"packet_source"`
	Direction       string   `json:"direction"`
}
type Record struct {
	model.Alert
	Details Details `json:"details"`
}
type Result struct {
	Items    []Record `json:"items"`
	Total    int64    `json:"total"`
	Page     int      `json:"page"`
	PageSize int      `json:"page_size"`
}

var errMetadata = errors.New("流量展示元数据无效")

func Parse(original string) Details {
	out := Details{State: "unavailable", SourceMACs: []string{}, DestinationMACs: []string{}}
	trimmed := strings.TrimSpace(original)
	if len(trimmed) == 0 || trimmed[0] != '{' || len(original) > 131072 || !utf8.ValidString(original) {
		return out
	}
	var raw struct {
		CommunityID  string `json:"community_id"`
		PacketSource string `json:"pkt_src"`
		Direction    string `json:"direction"`
		Flow         *struct {
			Start           string      `json:"start"`
			End             string      `json:"end"`
			State           string      `json:"state"`
			Reason          string      `json:"reason"`
			PacketsToServer json.Number `json:"pkts_toserver"`
			PacketsToClient json.Number `json:"pkts_toclient"`
			BytesToServer   json.Number `json:"bytes_toserver"`
			BytesToClient   json.Number `json:"bytes_toclient"`
		} `json:"flow"`
		TLS *struct {
			SNI         string `json:"sni"`
			Version     string `json:"version"`
			Subject     string `json:"subject"`
			Issuer      string `json:"issuerdn"`
			Fingerprint string `json:"fingerprint"`
		} `json:"tls"`
		DNS *struct {
			Version json.Number `json:"version"`
			Type    string      `json:"type"`
			RCode   string      `json:"rcode"`
			Queries []struct {
				Name string `json:"rrname"`
				Type string `json:"rrtype"`
			} `json:"queries"`
		} `json:"dns"`
		Ether struct {
			Source      []string `json:"src_macs"`
			Destination []string `json:"dest_macs"`
		} `json:"ether"`
	}
	if json.Unmarshal([]byte(original), &raw) != nil {
		return out
	}
	text := func(value string, limit int) string {
		if strings.IndexFunc(value, unicode.IsControl) != -1 {
			out.Truncated = true
			return ""
		}
		runes := []rune(value)
		if len(runes) > limit {
			out.Truncated = true
			return string(runes[:limit])
		}
		return value
	}
	out.CommunityID, out.PacketSource, out.Direction = text(raw.CommunityID, 128), text(raw.PacketSource, 128), text(raw.Direction, 32)
	if raw.Flow != nil {
		f := raw.Flow
		view := &Flow{State: text(f.State, 64), Reason: text(f.Reason, 128)}
		for _, pair := range []struct {
			raw    string
			target **time.Time
		}{{f.Start, &view.Start}, {f.End, &view.End}} {
			if pair.raw != "" {
				v, err := normalize.ParseTimestamp(pair.raw)
				if err != nil {
					return Details{State: "unavailable", SourceMACs: []string{}, DestinationMACs: []string{}}
				}
				v = v.UTC()
				*pair.target = &v
			}
		}
		if view.Start != nil && view.End != nil && view.End.Before(*view.Start) {
			return Details{State: "unavailable", SourceMACs: []string{}, DestinationMACs: []string{}}
		}
		for _, pair := range []struct {
			raw    json.Number
			target *string
		}{{f.PacketsToServer, &view.PacketsToServer}, {f.PacketsToClient, &view.PacketsToClient}, {f.BytesToServer, &view.BytesToServer}, {f.BytesToClient, &view.BytesToClient}} {
			v, err := counter(pair.raw)
			if err != nil {
				return Details{State: "unavailable", SourceMACs: []string{}, DestinationMACs: []string{}}
			}
			*pair.target = v
		}
		out.Flow = view
	}
	if raw.TLS != nil {
		v := raw.TLS
		out.TLS = &TLS{SNI: text(v.SNI, 1024), Version: text(v.Version, 64), Subject: text(v.Subject, 2048), Issuer: text(v.Issuer, 2048), Fingerprint: text(v.Fingerprint, 256)}
	}
	if raw.DNS != nil {
		v := raw.DNS
		view := &DNS{Version: v.Version.String(), Type: text(v.Type, 32), RCode: text(v.RCode, 64), Queries: []Query{}}
		if v.Version != "" && v.Version != "2" && v.Version != "3" {
			out.Truncated = true
			view.Version = ""
		}
		// 不把 v2 不同语义的顶层 rrname 填成 v3 查询数组。
		if len(v.Queries) > 32 {
			out.Truncated = true
		}
		for _, q := range v.Queries[:min(len(v.Queries), 32)] {
			view.Queries = append(view.Queries, Query{Name: text(q.Name, 1024), Type: text(q.Type, 64)})
		}
		out.DNS = view
	}
	for _, pair := range []struct {
		raw    []string
		target *[]string
	}{{raw.Ether.Source, &out.SourceMACs}, {raw.Ether.Destination, &out.DestinationMACs}} {
		if len(pair.raw) > 16 {
			out.Truncated = true
		}
		for _, value := range pair.raw[:min(len(pair.raw), 16)] {
			mac, err := net.ParseMAC(value)
			if err != nil || len(mac) != 6 {
				out.Truncated = true
				continue
			}
			*pair.target = append(*pair.target, mac.String())
		}
	}
	out.State = "available"
	return out
}

func counter(value json.Number) (string, error) {
	if value == "" {
		return "", nil
	}
	n, err := strconv.ParseUint(value.String(), 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != value.String() {
		return "", errMetadata
	}
	return value.String(), nil
}
