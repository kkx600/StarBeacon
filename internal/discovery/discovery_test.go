package discovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func queryFixture() Query {
	return Query{NetworkID: "obj_network", NetworkRevision: 1, SensorID: "sensor_owned", RegistrationID: "reg_owned", Prefix: "192.0.2.0/24", Start: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 10, 18, 1, 0, 0, 0, time.UTC)}
}
func sourceFixture(q Query, ip, side, id string, at time.Time) map[string]any {
	local, peer := map[string]any{"ip": ip, "mac": "02:00:00:00:00:01", "port": 80}, map[string]any{"ip": "198.51.100.20", "mac": "02:00:00:00:00:02", "port": 40000}
	if strings.Contains(ip, ":") {
		peer["ip"] = "2001:db8:1::20"
	}
	src, dst := local, peer
	if side == "destination" {
		src, dst = peer, local
	}
	return map[string]any{"_id": id, "_index": "sb-context-tenant_owned-" + at.UTC().Format("2006.01.02"), "_source": map[string]any{
		"schema_version": "1.0", "event_id": id, "tenant_id": "tenant_owned", "sensor_id": q.SensorID, "sensor_registration_id": q.RegistrationID, "source_generation_id": "epoch_owned", "sequence": "18446744073709551615", "raw_sha256": strings.Repeat("a", 64), "@timestamp": at, "observed_at": at.Add(time.Second), "event": map[string]any{"kind": "flow"}, "source": src, "destination": dst, "suricata": map[string]any{"flow_id": "18446744073709551615"},
	}}
}
func bucketFixture(q Query, ip, side string, count int64, first, last time.Time) map[string]any {
	a := sourceFixture(q, ip, side, "event_"+side+"_first", first)
	b := a
	if count > 1 {
		b = sourceFixture(q, ip, side, "event_"+side+"_last", last)
	}
	return map[string]any{"key": map[string]any{"address": ip}, "doc_count": count, "first": map[string]any{"hits": map[string]any{"hits": []any{a}}}, "last": map[string]any{"hits": map[string]any{"hits": []any{b}}}}
}
func groupFixture(count int64, buckets ...any) map[string]any {
	if buckets == nil {
		buckets = []any{}
	}
	return map[string]any{"doc_count": count, "eligible": map[string]any{"doc_count": count, "addresses": map[string]any{"buckets": buckets}}}
}
func responseFixture(q Query) map[string]any {
	return map[string]any{"timed_out": false, "_shards": map[string]any{"total": 1, "successful": 1, "skipped": 0, "failed": 0}, "aggregations": map[string]any{
		"source":      groupFixture(2, bucketFixture(q, "192.0.2.10", "source", 2, q.Start.Add(time.Nanosecond), q.Start.Add(2*time.Nanosecond))),
		"destination": groupFixture(3, bucketFixture(q, "192.0.2.10", "destination", 3, q.Start, q.Start.Add(3*time.Nanosecond))),
	}}
}
func encoded(v any) []byte { data, _ := json.Marshal(v); return data }
func firstSource(v map[string]any) map[string]any {
	return v["aggregations"].(map[string]any)["source"].(map[string]any)["eligible"].(map[string]any)["addresses"].(map[string]any)["buckets"].([]any)[0].(map[string]any)
}
func firstDocument(v map[string]any) map[string]any {
	return firstSource(v)["first"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
}

func TestDiscoveryQueryAndDeclaredNetworkBoundaries(t *testing.T) {
	q := queryFixture()
	s := Scope{NetworkID: q.NetworkID, NetworkRevision: 1, NetworkName: "观测范围", NetworkDomain: "office", NetworkPrefix: "192.0.0.0/16", SensorID: q.SensorID, SensorName: "办公探针", RegistrationID: q.RegistrationID}
	if q.Validate() != nil || s.Validate(q) != nil {
		t.Fatal("合法发现范围被拒绝")
	}
	for name, change := range map[string]func(*Query){
		"foreign_network": func(v *Query) { v.NetworkID = "../other" }, "zero_revision": func(v *Query) { v.NetworkRevision = 0 }, "unsafe_revision": func(v *Query) { v.NetworkRevision = 9007199254740992 }, "missing_registration": func(v *Query) { v.RegistrationID = "" }, "sensor": func(v *Query) { v.SensorID = "*" }, "too_long": func(v *Query) { v.End = v.Start.Add(24*time.Hour + time.Nanosecond) }, "reversed": func(v *Query) { v.End = v.Start }, "zero": func(v *Query) { v.Start = time.Time{} }, "old": func(v *Query) { v.Start = v.Start.AddDate(-100, 0, 0); v.End = v.Start.Add(time.Hour) }, "future": func(v *Query) { v.End = v.Start.AddDate(100, 0, 0) }, "host_prefix": func(v *Query) { v.Prefix = "192.0.2.5/24" }, "mapped_prefix": func(v *Query) { v.Prefix = "::ffff:192.0.2.0/120" }, "prefix_missing": func(v *Query) { v.Prefix = "" },
	} {
		t.Run(name, func(t *testing.T) {
			v := q
			change(&v)
			if v.Validate() == nil {
				t.Fatal("非法查询被接受")
			}
		})
	}
	for name, change := range map[string]func(*Scope){"scope_revision": func(v *Scope) { v.NetworkRevision++ }, "scope_network": func(v *Scope) { v.NetworkID = "obj_other" }, "scope_sensor": func(v *Scope) { v.SensorID = "other" }, "scope_registration": func(v *Scope) { v.RegistrationID = "other" }, "outside": func(v *Scope) { v.NetworkPrefix = "198.51.100.0/24" }, "family": func(v *Scope) { v.NetworkPrefix = "2001:db8::/32" }, "broad_child": func(v *Scope) { v.NetworkPrefix = "192.0.2.0/25" }, "empty_domain": func(v *Scope) { v.NetworkDomain = "" }, "empty_name": func(v *Scope) { v.NetworkName = "" }, "empty_sensor": func(v *Scope) { v.SensorName = "" }, "malformed_parent": func(v *Scope) { v.NetworkPrefix = "bad" }} {
		t.Run(name, func(t *testing.T) {
			v := s
			change(&v)
			if v.Validate(q) == nil {
				t.Fatal("范围归属校验失效")
			}
		})
	}
}

func TestDiscoveryMergesDirectionsPreservesNanosAndIntegerCounts(t *testing.T) {
	q := queryFixture()
	raw := responseFixture(q)
	g := raw["aggregations"].(map[string]any)["source"].(map[string]any)
	g["doc_count"] = int64(9007199254740995)
	g["eligible"].(map[string]any)["doc_count"] = int64(9007199254740993)
	firstSource(raw)["doc_count"] = int64(9007199254740993)
	r, err := Decode(encoded(raw), "tenant_owned", q)
	if err != nil || len(r.Addresses) != 1 {
		t.Fatal(r, err)
	}
	a := r.Addresses[0]
	if a.IP != "192.0.2.10" || a.SourceRecords != "9007199254740993" || a.DestinationRecords != "3" || r.SourceExcluded != "2" || r.DestinationExcluded != "0" || !a.First.Timestamp.Equal(q.Start) || !a.Last.Timestamp.Equal(q.Start.Add(3*time.Nanosecond)) || a.First.Side != "destination" || a.Last.FlowID != "18446744073709551615" || a.First.Source.MAC != "02:00:00:00:00:02" || a.First.Destination.MAC != "02:00:00:00:00:01" {
		t.Fatal("方向、原始精度或观测出处被改写", a)
	}
	query, err := DSL("tenant_owned", q)
	if err != nil || strings.Contains(string(query), "event.original") || !strings.Contains(string(query), `"event.kind":"flow"`) || !strings.Contains(string(query), `"sensor_registration_id":"reg_owned"`) || !strings.Contains(string(query), `"tenant_id":"tenant_owned"`) || strings.Contains(string(query), `"script"`) {
		t.Fatal("查询越过来源或载荷边界", string(query), err)
	}
	if _, err := DSL("*", q); !errors.Is(err, ErrInput) {
		t.Fatal("任意租户模式被接受")
	}
}

func TestDiscoveryRejectsIncompleteOrMismatchedEvidence(t *testing.T) {
	q := queryFixture()
	for name, change := range map[string]func(map[string]any){
		"timed_out": func(v map[string]any) { v["timed_out"] = true }, "missing_timeout": func(v map[string]any) { delete(v, "timed_out") }, "shard_failure": func(v map[string]any) { v["_shards"].(map[string]any)["failed"] = 1 }, "missing_shards": func(v map[string]any) { delete(v, "_shards") }, "skipped_range": func(v map[string]any) { v["_shards"].(map[string]any)["skipped"] = 2 }, "all_skipped_with_data": func(v map[string]any) { v["_shards"].(map[string]any)["skipped"] = 1 }, "incomplete_success": func(v map[string]any) { v["_shards"].(map[string]any)["successful"] = 0 }, "missing_side": func(v map[string]any) { delete(v["aggregations"].(map[string]any), "source") }, "missing_buckets": func(v map[string]any) {
			v["aggregations"].(map[string]any)["source"].(map[string]any)["eligible"].(map[string]any)["addresses"] = map[string]any{}
		},
		"partial_count": func(v map[string]any) { firstSource(v)["doc_count"] = 1 }, "counter_sum": func(v map[string]any) {
			v["aggregations"].(map[string]any)["source"].(map[string]any)["eligible"].(map[string]any)["doc_count"] = 3
		}, "negative": func(v map[string]any) { firstSource(v)["doc_count"] = -1 }, "fractional": func(v map[string]any) { firstSource(v)["doc_count"] = 1.5 }, "overflow": func(v map[string]any) { firstSource(v)["doc_count"] = json.Number("9223372036854775808") }, "outside_prefix": func(v map[string]any) { firstSource(v)["key"].(map[string]any)["address"] = "198.51.100.20" }, "multicast": func(v map[string]any) { firstSource(v)["key"].(map[string]any)["address"] = "224.0.0.1" }, "invalid_key": func(v map[string]any) { firstSource(v)["key"].(map[string]any)["address"] = "bad" }, "extra_key": func(v map[string]any) { firstSource(v)["key"].(map[string]any)["other"] = "untrusted" },
		"invalid_index_day": func(v map[string]any) { firstDocument(v)["_index"] = "sb-context-tenant_owned-2026.02.30" }, "prefix_tenant_index": func(v map[string]any) { firstDocument(v)["_index"] = "sb-context-tenant_owned-shadow-2026.10.18" }, "foreign_index": func(v map[string]any) { firstDocument(v)["_index"] = "sb-context-tenant_other-2026.10.18" }, "wrong_id": func(v map[string]any) { firstDocument(v)["_id"] = "event_other" }, "foreign_tenant": func(v map[string]any) { firstDocument(v)["_source"].(map[string]any)["tenant_id"] = "other" }, "foreign_sensor": func(v map[string]any) { firstDocument(v)["_source"].(map[string]any)["sensor_id"] = "other" }, "foreign_registration": func(v map[string]any) {
			firstDocument(v)["_source"].(map[string]any)["sensor_registration_id"] = "other"
		}, "generation": func(v map[string]any) {
			firstDocument(v)["_source"].(map[string]any)["source_generation_id"] = "../other"
		}, "raw_original": func(v map[string]any) {
			firstDocument(v)["_source"].(map[string]any)["event"].(map[string]any)["original"] = "private"
		}, "non_flow": func(v map[string]any) {
			firstDocument(v)["_source"].(map[string]any)["event"].(map[string]any)["kind"] = "alert"
		}, "missing_observed": func(v map[string]any) { delete(firstDocument(v)["_source"].(map[string]any), "observed_at") }, "wrong_sha": func(v map[string]any) {
			firstDocument(v)["_source"].(map[string]any)["raw_sha256"] = strings.Repeat("z", 64)
		}, "missing_sequence": func(v map[string]any) { firstDocument(v)["_source"].(map[string]any)["sequence"] = "" }, "large_flow_id": func(v map[string]any) {
			firstDocument(v)["_source"].(map[string]any)["suricata"].(map[string]any)["flow_id"] = "18446744073709551616"
		}, "before_window": func(v map[string]any) {
			firstDocument(v)["_source"].(map[string]any)["@timestamp"] = q.Start.Add(-time.Nanosecond)
		}, "wrong_ip": func(v map[string]any) {
			firstDocument(v)["_source"].(map[string]any)["source"].(map[string]any)["ip"] = "192.0.2.11"
		}, "invalid_mac": func(v map[string]any) {
			firstDocument(v)["_source"].(map[string]any)["destination"].(map[string]any)["mac"] = "bad"
		}, "wrong_version": func(v map[string]any) { firstDocument(v)["_source"].(map[string]any)["schema_version"] = "unknown" },
	} {
		t.Run(name, func(t *testing.T) {
			v := responseFixture(q)
			change(v)
			if _, err := Decode(encoded(v), "tenant_owned", q); !errors.Is(err, ErrIncomplete) {
				t.Fatal("不完整或越界响应被接受", err)
			}
		})
	}
	for _, raw := range [][]byte{nil, []byte(`{"broken"`), make([]byte, 8*1024*1024+1)} {
		if _, err := Decode(raw, "tenant_owned", q); err == nil {
			t.Fatal("非法响应被接受")
		}
	}
}

func TestDiscoveryEmptyIPv6LimitsAndDeterministicOrdering(t *testing.T) {
	q := queryFixture()
	v := responseFixture(q)
	aggs := v["aggregations"].(map[string]any)
	aggs["source"], aggs["destination"] = groupFixture(0), groupFixture(0)
	r, err := Decode(encoded(v), "tenant_owned", q)
	if err != nil || r.Addresses == nil || len(r.Addresses) != 0 {
		t.Fatal("空观测被伪造或拒绝", r, err)
	}
	q.Prefix = "2001:db8::/64"
	first, last := q.Start, q.Start.Add(time.Nanosecond)
	aggs["source"] = groupFixture(3, bucketFixture(q, "2001:db8::20", "source", 1, first, first), bucketFixture(q, "2001:db8::10", "source", 2, first, last))
	r, err = Decode(encoded(v), "tenant_owned", q)
	if err != nil || len(r.Addresses) != 2 || r.Addresses[0].IP != "2001:db8::10" {
		t.Fatal("IPv6 或确定顺序失效", r, err)
	}
	buckets := []any{}
	for i := 1; i <= MaxAddresses+1; i++ {
		buckets = append(buckets, bucketFixture(q, fmt.Sprintf("2001:db8::%x", i), "source", 1, first, first))
	}
	aggs["source"] = groupFixture(MaxAddresses+1, buckets...)
	if _, err := Decode(encoded(v), "tenant_owned", q); !errors.Is(err, ErrLimit) {
		t.Fatal("地址超限返回了截断目录", err)
	}
	aggs["source"] = groupFixture(2, buckets[0], buckets[0])
	if _, err := Decode(encoded(v), "tenant_owned", q); !errors.Is(err, ErrIncomplete) {
		t.Fatal("重复桶被接受", err)
	}
	q.Prefix = "bad"
	if _, err := Decode(encoded(v), "tenant_owned", q); !errors.Is(err, ErrInput) {
		t.Fatal("非法窗口被接受", err)
	}
}

func TestDiscoveryAllowsLateEventInDifferentRoutingDay(t *testing.T) {
	q := queryFixture()
	raw := responseFixture(q)
	firstDocument(raw)["_index"] = "sb-context-tenant_owned-2026.10.19"
	encoded, _ := json.Marshal(raw)
	if _, err := Decode(encoded, "tenant_owned", q); err != nil {
		t.Fatal("上传路由日期不应被当作事件日期", err)
	}
}

func TestDiscoveryEmptyResolvedTargetsRequireExplicitCompleteEvidence(t *testing.T) {
	q := queryFixture()
	for _, raw := range []string{
		`{"timed_out":false,"_shards":{"total":0,"successful":0,"skipped":0,"failed":0},"hits":{"hits":[]}}`,
		`{"timed_out":false,"_shards":{"total":0,"successful":0,"skipped":0,"failed":0},"hits":{"total":{"value":0,"relation":"eq"},"hits":[]}}`,
	} {
		result, err := Decode([]byte(raw), "tenant_owned", q)
		if err != nil || result.PartitionStatus != "absent" || len(result.Addresses) != 0 {
			t.Fatal("真实空目标响应未被识别", err)
		}
	}
	for _, hits := range []string{`null`, `{}`, `{"hits":null}`, `{"hits":[{}]}`, `{"total":{"value":1,"relation":"eq"},"hits":[]}`, `{"total":{"value":0,"relation":"gte"},"hits":[]}`, `{"total":{},"hits":[]}`} {
		raw := `{"timed_out":false,"_shards":{"total":0,"successful":0,"skipped":0,"failed":0},"hits":` + hits + `}`
		if _, err := Decode([]byte(raw), "tenant_owned", q); !errors.Is(err, ErrIncomplete) {
			t.Fatal("不完整空目标被当作无数据", err)
		}
	}
	raw := `{"timed_out":false,"_shards":{"total":0,"successful":0,"skipped":0,"failed":0},"hits":{"hits":[]},"aggregations":{"source":{}}}`
	if _, err := Decode([]byte(raw), "tenant_owned", q); !errors.Is(err, ErrIncomplete) {
		t.Fatal("零分片与聚合矛盾未拒绝", err)
	}
}
