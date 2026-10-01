// Package normalize 保留原始 EVE，并以显式字段映射生成检索文档。
package normalize

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/model"
)

type Eve struct {
	Timestamp string      `json:"timestamp"`
	EventType string      `json:"event_type"`
	SrcIP     string      `json:"src_ip"`
	DestIP    string      `json:"dest_ip"`
	SrcPort   uint16      `json:"src_port"`
	DestPort  uint16      `json:"dest_port"`
	Proto     string      `json:"proto"`
	AppProto  string      `json:"app_proto"`
	FlowID    json.Number `json:"flow_id"`
	Ether     struct {
		Src  string `json:"src_mac"`
		Dest string `json:"dest_mac"`
	} `json:"ether"`
	Alert struct {
		SignatureID json.Number `json:"signature_id"`
		Rev         json.Number `json:"rev"`
		Signature   string      `json:"signature"`
		Severity    int         `json:"severity"`
		Action      string      `json:"action"`
	} `json:"alert"`
	HTTP struct {
		Method   string `json:"http_method"`
		URL      string `json:"url"`
		Hostname string `json:"hostname"`
	} `json:"http"`
}

func Decode(raw []byte) (Eve, error) {
	var v Eve
	if !utf8.Valid(raw) {
		return v, fmt.Errorf("EVE 不是有效的 UTF-8 JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	e := d.Decode(&v)
	if e != nil {
		return v, e
	}
	if d.Decode(new(any)) == io.EOF {
		return v, nil
	}
	return v, fmt.Errorf("EVE 包含额外文档")
}
func Normalize(tenant, sensor, registration string, r *sensorv1.EventRecord, received time.Time) (model.Alert, error) {
	var out model.Alert
	v, e := Decode(r.Payload)
	if e != nil {
		return out, e
	}
	if v.EventType == "" {
		return out, fmt.Errorf("缺少事件类型")
	}
	ts, e := time.Parse(time.RFC3339Nano, v.Timestamp)
	if e != nil {
		return out, fmt.Errorf("EVE 时间不合法")
	}
	out.SchemaVersion = "1.0"
	out.EventID = r.EventId
	out.TenantID = tenant
	out.SensorID = sensor
	out.RegistrationID = registration
	out.SourceGenerationID = r.SourceGenerationId
	out.SourceOffset = strconv.FormatUint(r.SourceOffset, 10)
	out.Sequence = strconv.FormatUint(r.Sequence, 10)
	out.RawSHA256 = hex.EncodeToString(r.RawSha256)
	out.Timestamp = ts.UTC()
	out.ObservedAt = r.ObservedAt.AsTime()
	out.ReceivedAt = received
	out.Event.Kind = v.EventType
	out.Event.Dataset = "suricata.eve"
	out.Event.Original = string(r.Payload)
	for _, p := range []struct {
		raw    string
		target *model.Endpoint
	}{{v.SrcIP, &out.Source}, {v.DestIP, &out.Destination}} {
		if p.raw != "" {
			ip, e := netip.ParseAddr(p.raw)
			if e != nil {
				return out, fmt.Errorf("IP 地址不合法")
			}
			p.target.IP = ip.Unmap().String()
		}
	}
	out.Source.Port = v.SrcPort
	out.Destination.Port = v.DestPort
	for _, p := range []struct {
		raw    string
		target *string
	}{{v.Ether.Src, &out.Source.MAC}, {v.Ether.Dest, &out.Destination.MAC}} {
		if p.raw != "" {
			mac, e := net.ParseMAC(p.raw)
			if e != nil {
				return out, fmt.Errorf("MAC 地址不合法")
			}
			*p.target = mac.String()
		}
	}
	out.Network.Transport = strings.ToLower(v.Proto)
	out.Network.Protocol = strings.ToLower(v.AppProto)
	out.Rule.ID = v.Alert.SignatureID.String()
	out.Rule.Revision = v.Alert.Rev.String()
	out.Rule.Name = v.Alert.Signature
	out.HTTP.Method = strings.ToUpper(v.HTTP.Method)
	out.HTTP.Path = v.HTTP.URL
	out.HTTP.Hostname = v.HTTP.Hostname
	out.Suricata.FlowID = v.FlowID.String()
	out.Suricata.Action = v.Alert.Action
	out.Severity = "unknown"
	if v.EventType == "alert" {
		switch v.Alert.Severity {
		case 1:
			out.Severity = "high"
		case 2:
			out.Severity = "medium"
		case 3:
			out.Severity = "low"
		}
	}
	out.EvidenceStatus = "not_linked"
	return out, nil
}
