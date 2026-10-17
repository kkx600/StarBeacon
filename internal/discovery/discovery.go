// Package discovery 从实际流记录提取有界地址观测，不推定设备身份、服务角色或资产归属。
package discovery

import (
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
)

const MaxAddresses = 512

var (
	ErrInput      = errors.New("资产发现范围无效")
	ErrIncomplete = errors.New("流量观测未能完整核对")
	ErrLimit      = errors.New("观测地址超过单次 512 个的上限，请缩短时间或缩小地址前缀")
)

type Query struct {
	NetworkID       string    `json:"network_id"`
	NetworkRevision int64     `json:"network_revision"`
	SensorID        string    `json:"sensor_id"`
	RegistrationID  string    `json:"registration_id"`
	Prefix          string    `json:"prefix"`
	Start           time.Time `json:"start"`
	End             time.Time `json:"end"`
}

func (q Query) Validate() error {
	if !contract.ValidID(q.NetworkID) || !contract.ValidID(q.SensorID) || !contract.ValidID(q.RegistrationID) || q.NetworkRevision < 1 || q.NetworkRevision > 9007199254740991 || q.Start.IsZero() || q.Start.Year() < 2000 || q.End.Year() > 2100 || !q.End.After(q.Start) || q.End.Sub(q.Start) > 24*time.Hour {
		return ErrInput
	}
	if p, err := netip.ParsePrefix(q.Prefix); err != nil || p.Addr().Is4In6() || p.Masked().String() != q.Prefix {
		return ErrInput
	}
	return nil
}

type Scope struct {
	NetworkID       string `json:"network_id"`
	NetworkRevision int64  `json:"network_revision"`
	NetworkName     string `json:"network_name"`
	NetworkDomain   string `json:"network_domain"`
	NetworkPrefix   string `json:"network_prefix"`
	SensorID        string `json:"sensor_id"`
	SensorName      string `json:"sensor_name"`
	RegistrationID  string `json:"registration_id"`
}

func (s Scope) Validate(q Query) error {
	outer, err := netip.ParsePrefix(s.NetworkPrefix)
	inner, innerErr := netip.ParsePrefix(q.Prefix)
	if q.Validate() != nil || err != nil || innerErr != nil || outer.Addr().Is4In6() || outer.Masked().String() != s.NetworkPrefix || s.NetworkID != q.NetworkID || s.NetworkRevision != q.NetworkRevision || s.SensorID != q.SensorID || s.RegistrationID != q.RegistrationID || s.NetworkName == "" || s.NetworkDomain == "" || s.SensorName == "" || outer.Addr().BitLen() != inner.Addr().BitLen() || outer.Bits() > inner.Bits() || !outer.Contains(inner.Addr()) {
		return ErrInput
	}
	return nil
}

type Witness struct {
	EventID      string         `json:"event_id"`
	Timestamp    time.Time      `json:"timestamp"`
	ObservedAt   time.Time      `json:"observed_at"`
	GenerationID string         `json:"generation_id"`
	Sequence     string         `json:"sequence"`
	RawSHA256    string         `json:"raw_sha256"`
	FlowID       string         `json:"flow_id"`
	Side         string         `json:"side"`
	Source       model.Endpoint `json:"source"`
	Destination  model.Endpoint `json:"destination"`
}

type Address struct {
	IP                 string  `json:"ip"`
	SourceRecords      string  `json:"source_records"`
	DestinationRecords string  `json:"destination_records"`
	First              Witness `json:"first"`
	Last               Witness `json:"last"`
}

type Result struct {
	SchemaVersion       string    `json:"schema_version"`
	Query               Query     `json:"query"`
	Scope               Scope     `json:"scope"`
	QueriedAt           time.Time `json:"queried_at"`
	Addresses           []Address `json:"addresses"`
	SourceExcluded      string    `json:"source_excluded"`
	DestinationExcluded string    `json:"destination_excluded"`
	PartitionStatus     string    `json:"partition_status"`
}

func endpoint(ip string) bool {
	value, err := netip.ParseAddr(ip)
	return err == nil && value.Zone() == "" && !value.Is4In6() && value.String() == ip && !value.IsUnspecified() && !value.IsMulticast() && ip != "255.255.255.255"
}

// DSL 只读取已有 flow 文档；两个方向独立聚合，计数不等于会话数或设备数。
// 使用首末代表记录保留 date_nanos 原值，不采用会降低精度的数值日期聚合。
func DSL(tenant string, q Query) ([]byte, error) {
	if !contract.ValidID(tenant) || q.Validate() != nil {
		return nil, ErrInput
	}
	projection := []string{"schema_version", "event_id", "tenant_id", "sensor_id", "sensor_registration_id", "source_generation_id", "sequence", "raw_sha256", "@timestamp", "observed_at", "event.kind", "source", "destination", "suricata.flow_id"}
	aggs := map[string]any{}
	for _, side := range []string{"source", "destination"} {
		field := side + ".ip"
		excluded := []any{}
		for _, prefix := range []string{"0.0.0.0/32", "224.0.0.0/4", "255.255.255.255/32", "::/128", "ff00::/8"} {
			excluded = append(excluded, map[string]any{"term": map[string]string{field: prefix}})
		}
		samples := map[string]any{}
		for label, order := range map[string]string{"first": "asc", "last": "desc"} {
			samples[label] = map[string]any{"top_hits": map[string]any{"size": 1, "_source": projection, "sort": []any{map[string]any{"@timestamp": map[string]string{"order": order, "format": "strict_date_optional_time_nanos"}}, map[string]string{"event_id": order}}}}
		}
		aggs[side] = map[string]any{"filter": map[string]any{"term": map[string]string{field: q.Prefix}}, "aggs": map[string]any{"eligible": map[string]any{
			"filter": map[string]any{"bool": map[string]any{"must_not": excluded}},
			"aggs":   map[string]any{"addresses": map[string]any{"composite": map[string]any{"size": MaxAddresses + 1, "sources": []any{map[string]any{"address": map[string]any{"terms": map[string]string{"field": field}}}}}, "aggs": samples}},
		}}}
	}
	return json.Marshal(map[string]any{"size": 0, "track_total_hits": false, "timeout": "5s", "query": map[string]any{"bool": map[string]any{"filter": []any{
		map[string]any{"term": map[string]string{"tenant_id": tenant}}, map[string]any{"term": map[string]string{"sensor_id": q.SensorID}}, map[string]any{"term": map[string]string{"sensor_registration_id": q.RegistrationID}}, map[string]any{"term": map[string]string{"event.kind": "flow"}},
		map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": q.Start.UTC(), "lt": q.End.UTC()}}},
	}}}, "aggs": aggs})
}

type rawHits struct {
	Hits struct {
		Hits []struct {
			ID     string      `json:"_id"`
			Index  string      `json:"_index"`
			Source model.Alert `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}
type rawSide struct {
	Count    *int64 `json:"doc_count"`
	Eligible struct {
		Count     *int64 `json:"doc_count"`
		Addresses struct {
			Buckets []struct {
				Key   map[string]string `json:"key"`
				Count *int64            `json:"doc_count"`
				First rawHits           `json:"first"`
				Last  rawHits           `json:"last"`
			} `json:"buckets"`
		} `json:"addresses"`
	} `json:"eligible"`
}

func witness(sample rawHits, tenant string, q Query, side, ip string) (Witness, error) {
	if len(sample.Hits.Hits) != 1 {
		return Witness{}, ErrIncomplete
	}
	hit := sample.Hits.Hits[0]
	v := hit.Source
	day, dateErr := time.Parse("2006.01.02", strings.TrimPrefix(hit.Index, "sb-context-"+tenant+"-"))
	index, err := contract.IndexName(tenant, "context", day.Format("2006-01-02"))
	if dateErr != nil || err != nil || hit.Index != index || hit.ID != v.EventID || !contract.ValidID(v.EventID) || v.SchemaVersion != "1.0" || v.TenantID != tenant || v.SensorID != q.SensorID || v.RegistrationID != q.RegistrationID || !contract.ValidID(v.SourceGenerationID) || v.Event.Kind != "flow" || v.Event.Original != "" || v.Timestamp.Before(q.Start) || !v.Timestamp.Before(q.End) || v.ObservedAt.IsZero() || !hexDigest(v.RawSHA256) {
		return Witness{}, ErrIncomplete
	}
	for _, value := range []string{v.Sequence, v.Suricata.FlowID} {
		number, err := strconv.ParseUint(value, 10, 64)
		if err != nil || strconv.FormatUint(number, 10) != value {
			return Witness{}, ErrIncomplete
		}
	}
	for _, e := range []model.Endpoint{v.Source, v.Destination} {
		if e.IP != "" {
			addr, err := netip.ParseAddr(e.IP)
			if err != nil || addr.Zone() != "" || addr.Is4In6() || addr.String() != e.IP {
				return Witness{}, ErrIncomplete
			}
		}
		if e.MAC != "" {
			mac, err := net.ParseMAC(e.MAC)
			if err != nil || len(mac) != 6 || mac.String() != e.MAC {
				return Witness{}, ErrIncomplete
			}
		}
	}
	if side == "source" && v.Source.IP != ip || side == "destination" && v.Destination.IP != ip {
		return Witness{}, ErrIncomplete
	}
	return Witness{v.EventID, v.Timestamp, v.ObservedAt, v.SourceGenerationID, v.Sequence, v.RawSHA256, v.Suricata.FlowID, side, v.Source, v.Destination}, nil
}

func hexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

func earlier(a, b Witness) bool {
	return a.Timestamp.Before(b.Timestamp) || a.Timestamp.Equal(b.Timestamp) && a.EventID < b.EventID
}

func Decode(raw []byte, tenant string, q Query) (Result, error) {
	if !contract.ValidID(tenant) || q.Validate() != nil {
		return Result{}, ErrInput
	}
	if len(raw) > 8*1024*1024 {
		return Result{}, ErrIncomplete
	}
	var value struct {
		TimedOut *bool                                             `json:"timed_out"`
		Shards   struct{ Total, Successful, Skipped, Failed *int } `json:"_shards"`
		Aggs     map[string]rawSide                                `json:"aggregations"`
		Hits     *struct {
			Hits  []json.RawMessage `json:"hits"`
			Total *struct {
				Value    *int64 `json:"value"`
				Relation string `json:"relation"`
			} `json:"total"`
		} `json:"hits"`
	}
	if json.Unmarshal(raw, &value) != nil || value.TimedOut == nil || *value.TimedOut || value.Shards.Total == nil || *value.Shards.Total < 0 || value.Shards.Successful == nil || *value.Shards.Successful != *value.Shards.Total || value.Shards.Failed == nil || *value.Shards.Failed != 0 || value.Shards.Skipped == nil || *value.Shards.Skipped < 0 || *value.Shards.Skipped > *value.Shards.Total {
		return Result{}, ErrIncomplete
	}
	// 空目标搜索不返回聚合；只接受明确零分片与显式空命中列表，不能把错误或缺失字段补成零。
	if *value.Shards.Total == 0 {
		if len(value.Aggs) != 0 || value.Hits == nil || value.Hits.Hits == nil || len(value.Hits.Hits) != 0 || value.Hits.Total != nil && (value.Hits.Total.Value == nil || *value.Hits.Total.Value != 0 || value.Hits.Total.Relation != "eq") {
			return Result{}, ErrIncomplete
		}
		return Result{SchemaVersion: "1.0", Query: q, Addresses: []Address{}, SourceExcluded: "0", DestinationExcluded: "0", PartitionStatus: "absent"}, nil
	}
	prefix, _ := netip.ParsePrefix(q.Prefix)
	byIP := map[string]Address{}
	result := Result{SchemaVersion: "1.0", Query: q, Addresses: []Address{}, PartitionStatus: "available"}
	for _, side := range []string{"source", "destination"} {
		group, ok := value.Aggs[side]
		if !ok || group.Count == nil || group.Eligible.Count == nil || *group.Eligible.Count < 0 || *group.Count < *group.Eligible.Count || group.Eligible.Addresses.Buckets == nil {
			return Result{}, ErrIncomplete
		}
		if *value.Shards.Total == *value.Shards.Skipped && *group.Count != 0 {
			return Result{}, ErrIncomplete
		}
		if len(group.Eligible.Addresses.Buckets) > MaxAddresses {
			return Result{}, ErrLimit
		}
		excluded := strconv.FormatInt(*group.Count-*group.Eligible.Count, 10)
		if side == "source" {
			result.SourceExcluded = excluded
		} else {
			result.DestinationExcluded = excluded
		}
		seen, total := map[string]bool{}, int64(0)
		for _, bucket := range group.Eligible.Addresses.Buckets {
			ip := bucket.Key["address"]
			addr, err := netip.ParseAddr(ip)
			if err != nil || !endpoint(ip) || !prefix.Contains(addr) || len(bucket.Key) != 1 || seen[ip] || bucket.Count == nil || *bucket.Count < 1 || *bucket.Count > math.MaxInt64-total {
				return Result{}, ErrIncomplete
			}
			seen[ip], total = true, total+*bucket.Count
			first, err := witness(bucket.First, tenant, q, side, ip)
			if err != nil {
				return Result{}, err
			}
			last, err := witness(bucket.Last, tenant, q, side, ip)
			if err != nil || earlier(last, first) || (*bucket.Count == 1) != (first.EventID == last.EventID) {
				return Result{}, ErrIncomplete
			}
			row, exists := byIP[ip]
			if !exists {
				row = Address{IP: ip, SourceRecords: "0", DestinationRecords: "0", First: first, Last: last}
			}
			if earlier(first, row.First) {
				row.First = first
			}
			if earlier(row.Last, last) {
				row.Last = last
			}
			if side == "source" {
				row.SourceRecords = strconv.FormatInt(*bucket.Count, 10)
			} else {
				row.DestinationRecords = strconv.FormatInt(*bucket.Count, 10)
			}
			byIP[ip] = row
			if len(byIP) > MaxAddresses {
				return Result{}, ErrLimit
			}
		}
		if total != *group.Eligible.Count {
			return Result{}, ErrIncomplete
		}
	}
	for _, row := range byIP {
		result.Addresses = append(result.Addresses, row)
	}
	slices.SortFunc(result.Addresses, func(a, b Address) int { return netip.MustParseAddr(a.IP).Compare(netip.MustParseAddr(b.IP)) })
	return result, nil
}
