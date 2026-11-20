package watchlist

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
)

func impactDefinition() Definition {
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	return Definition{SchemaVersion: Schema, Kind: "observe", MatchType: "ip", Values: []string{"192.0.2.10", "192.0.2.11"}, Sensors: []Sensor{{"probe_a", "registration_a"}}, ValidFrom: at, ValidUntil: at.Add(180 * 24 * time.Hour)}
}

func impactWindow() (time.Time, time.Time) {
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	return start, start.Add(24 * time.Hour)
}

// impactAlert 构造一条满足 DecodeImpact 全部一致性条件的样本。
func impactAlert(event, ip string, at time.Time) model.Alert {
	var a model.Alert
	a.SchemaVersion = "alert.v1"
	a.EventID = event
	a.TenantID = "tenant_a"
	a.SensorID = "probe_a"
	a.RegistrationID = "registration_a"
	a.RawSHA256 = strings.Repeat("a", 64)
	a.Timestamp = at
	a.ObservedAt = at
	a.ReceivedAt = at
	a.Event.Kind = "alert"
	a.Event.Dataset = "suricata.eve"
	a.Source.IP = ip
	a.Destination.IP = "198.51.100.1"
	a.Severity = "high"
	a.Rule.ID = "2100498"
	a.Rule.Name = "测试规则"
	return a
}

// impactBody 返回一份结构完整的检索回执，供各用例按需篡改单个字段。
func impactBody(t *testing.T, alerts []model.Alert, total int64, counts []int64) map[string]any {
	t.Helper()
	index, err := contract.EventIndexName("alerts", 180, contract.PeriodDay, "2026-11-01")
	if err != nil {
		t.Fatalf("构造共享索引名失败：%v", err)
	}
	hits := make([]any, 0, len(alerts))
	for _, a := range alerts {
		raw, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("序列化告警失败：%v", err)
		}
		var source map[string]any
		if err := json.Unmarshal(raw, &source); err != nil {
			t.Fatalf("还原告警失败：%v", err)
		}
		hits = append(hits, map[string]any{"_id": a.EventID, "_index": index, "_source": source})
	}
	buckets := map[string]any{}
	for i, c := range counts {
		buckets[bucketKey(i)] = map[string]any{"doc_count": c}
	}
	return map[string]any{
		"timed_out":    false,
		"_shards":      map[string]any{"total": 1, "successful": 1, "failed": 0},
		"hits":         map[string]any{"total": map[string]any{"value": total, "relation": "eq"}, "hits": hits},
		"aggregations": map[string]any{"values": map[string]any{"buckets": buckets}},
	}
}

func encodeImpact(t *testing.T, body map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("序列化回执失败：%v", err)
	}
	return raw
}

func TestImpactRequestRejectsUnboundedWindows(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	good := ImpactRequest{Revision: 1, Start: start, End: start.Add(24 * time.Hour)}
	if good.Validate(now) != nil {
		t.Fatal("合法预览窗口被拒绝")
	}
	for name, mutate := range map[string]func(*ImpactRequest){
		"修订为零":    func(r *ImpactRequest) { r.Revision = 0 },
		"修订为负":    func(r *ImpactRequest) { r.Revision = -1 },
		"修订超上限":   func(r *ImpactRequest) { r.Revision = MaxRevision + 1 },
		"起点为零值":   func(r *ImpactRequest) { r.Start = time.Time{} },
		"终点为零值":   func(r *ImpactRequest) { r.End = time.Time{} },
		"窗口为空":    func(r *ImpactRequest) { r.End = r.Start },
		"终点早于起点":  func(r *ImpactRequest) { r.End = r.Start.Add(-time.Hour) },
		"窗口超过上限":  func(r *ImpactRequest) { r.End = r.Start.Add(MaxImpactWindow + time.Second) },
		"终点超出当前":  func(r *ImpactRequest) { r.End = now.Add(time.Hour) },
		"起点早于起始年": func(r *ImpactRequest) { r.Start = time.Date(1999, 12, 31, 0, 0, 0, 0, time.UTC) },
	} {
		c := good
		mutate(&c)
		if !errors.Is(c.Validate(now), ErrInput) {
			t.Fatalf("%s 的预览请求未被拒绝", name)
		}
	}
	// 终点允许落在当前时刻之后的 30 秒容差内，避免客户端与服务端的轻微时钟偏差误判。
	tolerant := good
	tolerant.End = now.Add(20 * time.Second)
	if tolerant.Validate(now) != nil {
		t.Fatal("30 秒容差内的终点被拒绝")
	}
}

func TestImpactFieldsExcludeUnindexedTargets(t *testing.T) {
	if fields := ImpactFields("domain"); len(fields) != 1 || fields[0] != FieldHTTPHost {
		t.Fatalf("域名预览字段为 %v，TLS SNI 与 DNS 查询名没有检索字段，不能进入预览范围", fields)
	}
	for _, kind := range []string{"ip", "cidr"} {
		fields := ImpactFields(kind)
		if len(fields) != 2 || fields[0] != FieldSourceIP || fields[1] != FieldDestinationIP {
			t.Fatalf("%s 预览字段为 %v", kind, fields)
		}
	}
}

func TestImpactDSLConstrainsTenantStreamAndScope(t *testing.T) {
	d := impactDefinition()
	start, end := impactWindow()
	raw, err := ImpactDSL("tenant_a", d, start, end)
	if err != nil {
		t.Fatalf("构造检索请求失败：%v", err)
	}
	var body struct {
		Size           int    `json:"size"`
		TrackTotalHits bool   `json:"track_total_hits"`
		Timeout        string `json:"timeout"`
		Query          struct {
			Bool struct {
				Filter []json.RawMessage `json:"filter"`
			} `json:"bool"`
		} `json:"query"`
		Aggs struct {
			Values struct {
				Filters struct {
					Filters map[string]json.RawMessage `json:"filters"`
				} `json:"filters"`
			} `json:"values"`
		} `json:"aggs"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("解析检索请求失败：%v", err)
	}
	if body.Size != MaxImpactSamples || !body.TrackTotalHits || body.Timeout == "" {
		t.Fatalf("样本上限、精确计数或超时未设定：size=%d track=%v timeout=%q", body.Size, body.TrackTotalHits, body.Timeout)
	}
	text := string(raw)
	for _, want := range []string{`"tenant_id":"tenant_a"`, `"event.kind":"alert"`, `"sensor_id":"probe_a"`, `"sensor_registration_id":"registration_a"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("检索请求缺少约束 %s", want)
		}
	}
	if len(body.Query.Bool.Filter) != 5 {
		t.Fatalf("过滤条件为 %d 项，期望租户、数据流、时间、范围与名单值五项", len(body.Query.Bool.Filter))
	}
	if len(body.Aggs.Values.Filters.Filters) != len(d.Values) {
		t.Fatalf("聚合桶 %d 个，与 %d 个名单值不一一对应", len(body.Aggs.Values.Filters.Filters), len(d.Values))
	}
	for i := range d.Values {
		if _, ok := body.Aggs.Values.Filters.Filters[bucketKey(i)]; !ok {
			t.Fatalf("缺少聚合桶 %s", bucketKey(i))
		}
	}
	// 域名预览按原文入索引，需要忽略大小写才能命中同一主机名。
	domain := impactDefinition()
	domain.MatchType, domain.Values = "domain", []string{"service.example.com"}
	raw, err = ImpactDSL("tenant_a", domain, start, end)
	if err != nil {
		t.Fatalf("构造域名检索请求失败：%v", err)
	}
	if !strings.Contains(string(raw), `"case_insensitive":true`) {
		t.Fatal("域名预览未忽略大小写")
	}
	for name, mutate := range map[string]func(*Definition){
		"定义不合法": func(d *Definition) { d.Values = nil },
	} {
		c := impactDefinition()
		mutate(&c)
		if _, err := ImpactDSL("tenant_a", c, start, end); !errors.Is(err, ErrInput) {
			t.Fatalf("%s 时仍构造了检索请求", name)
		}
	}
	if _, err := ImpactDSL("TENANT", d, start, end); !errors.Is(err, ErrInput) {
		t.Fatal("非法租户标识仍构造了检索请求")
	}
	if _, err := ImpactDSL("tenant_a", d, end, start); !errors.Is(err, ErrInput) {
		t.Fatal("倒置窗口仍构造了检索请求")
	}
}

func TestDecodeImpactAcceptsCompleteResult(t *testing.T) {
	d := impactDefinition()
	start, end := impactWindow()
	later := impactAlert("alert_later", "192.0.2.10", start.Add(2*time.Hour))
	earlier := impactAlert("alert_earlier", "192.0.2.11", start.Add(time.Hour))
	raw := encodeImpact(t, impactBody(t, []model.Alert{later, earlier}, 2, []int64{1, 1}))
	total, values, samples, err := DecodeImpact(raw, "tenant_a", d, start, end)
	if err != nil {
		t.Fatalf("完整结果被拒绝：%v", err)
	}
	if total != 2 || len(values) != 2 || len(samples) != 2 {
		t.Fatalf("总数 %d、逐值 %d 项、样本 %d 条", total, len(values), len(samples))
	}
	for i, v := range values {
		if v.Value != d.Values[i] || v.Count != 1 {
			t.Fatalf("第 %d 个名单值计数为 %+v", i, v)
		}
	}
	if samples[0].EventID != "alert_later" || samples[1].EventID != "alert_earlier" {
		t.Fatalf("样本未按观测时间倒序：%s, %s", samples[0].EventID, samples[1].EventID)
	}
	if len(samples[0].Matches) != 1 || samples[0].Matches[0].Field != FieldSourceIP || samples[0].Matches[0].Value != "192.0.2.10" {
		t.Fatalf("样本匹配值为 %+v", samples[0].Matches)
	}
	if samples[0].Severity != "high" || samples[0].RuleName != "测试规则" {
		t.Fatalf("样本摘要为 %+v", samples[0])
	}
}

// 尚无告警索引时没有分片参与检索，空结果不携带聚合桶，此时仍须给出逐值零计数而不是报错。
func TestDecodeImpactAcceptsEmptyResultWithoutIndices(t *testing.T) {
	d := impactDefinition()
	start, end := impactWindow()
	body := impactBody(t, nil, 0, nil)
	body["_shards"] = map[string]any{"total": 0, "successful": 0, "failed": 0}
	total, values, samples, err := DecodeImpact(encodeImpact(t, body), "tenant_a", d, start, end)
	if err != nil {
		t.Fatalf("空结果被拒绝：%v", err)
	}
	if total != 0 || len(samples) != 0 || len(values) != len(d.Values) {
		t.Fatalf("空结果为 total=%d samples=%d values=%d", total, len(samples), len(values))
	}
	for i, v := range values {
		if v.Value != d.Values[i] || v.Count != 0 {
			t.Fatalf("空结果第 %d 个名单值为 %+v", i, v)
		}
	}
}

func TestDecodeImpactRejectsIncompleteOrInconsistentMaterials(t *testing.T) {
	d := impactDefinition()
	start, end := impactWindow()
	later := impactAlert("alert_later", "192.0.2.10", start.Add(2*time.Hour))
	earlier := impactAlert("alert_earlier", "192.0.2.11", start.Add(time.Hour))
	sample := func() []model.Alert { return []model.Alert{later, earlier} }

	for name, mutate := range map[string]func(map[string]any){
		"检索超时":     func(b map[string]any) { b["timed_out"] = true },
		"缺少超时标记":   func(b map[string]any) { delete(b, "timed_out") },
		"分片部分失败":   func(b map[string]any) { b["_shards"] = map[string]any{"total": 3, "successful": 2, "failed": 1} },
		"分片成功数不足":  func(b map[string]any) { b["_shards"] = map[string]any{"total": 3, "successful": 2, "failed": 0} },
		"缺少分片信息":   func(b map[string]any) { delete(b, "_shards") },
		"总数为估算值":   func(b map[string]any) { b["hits"].(map[string]any)["total"].(map[string]any)["relation"] = "gte" },
		"总数缺失":     func(b map[string]any) { delete(b["hits"].(map[string]any)["total"].(map[string]any), "value") },
		"总数为负":     func(b map[string]any) { b["hits"].(map[string]any)["total"].(map[string]any)["value"] = -1 },
		"样本数与总数不符": func(b map[string]any) { b["hits"].(map[string]any)["total"].(map[string]any)["value"] = 5 },
		"聚合桶数量不符": func(b map[string]any) {
			delete(b["aggregations"].(map[string]any)["values"].(map[string]any)["buckets"].(map[string]any), bucketKey(1))
		},
		"聚合桶计数缺失": func(b map[string]any) {
			b["aggregations"].(map[string]any)["values"].(map[string]any)["buckets"].(map[string]any)[bucketKey(0)] = map[string]any{}
		},
		"聚合桶计数为负": func(b map[string]any) {
			b["aggregations"].(map[string]any)["values"].(map[string]any)["buckets"].(map[string]any)[bucketKey(0)] = map[string]any{"doc_count": -1}
		},
		"聚合桶计数超总数": func(b map[string]any) {
			b["aggregations"].(map[string]any)["values"].(map[string]any)["buckets"].(map[string]any)[bucketKey(0)] = map[string]any{"doc_count": 99}
		},
	} {
		body := impactBody(t, sample(), 2, []int64{1, 1})
		mutate(body)
		if _, _, _, err := DecodeImpact(encodeImpact(t, body), "tenant_a", d, start, end); !errors.Is(err, ErrIncomplete) {
			t.Fatalf("%s 时未判定结果不完整，err=%v", name, err)
		}
	}

	for name, mutate := range map[string]func(map[string]any){
		"样本来自其他索引":  func(h map[string]any) { h["_index"] = "sb-v2-logs-r180-d2026.11.01" },
		"文档标识与事件不符": func(h map[string]any) { h["_id"] = "other" },
		"样本属于其他租户":  func(h map[string]any) { h["_source"].(map[string]any)["tenant_id"] = "tenant_b" },
		"样本不是告警":    func(h map[string]any) { h["_source"].(map[string]any)["event"].(map[string]any)["kind"] = "network" },
		"原始摘要不合法":   func(h map[string]any) { h["_source"].(map[string]any)["raw_sha256"] = "short" },
		"严重级别不合法":   func(h map[string]any) { h["_source"].(map[string]any)["severity"] = "fatal" },
		"样本早于窗口起点":  func(h map[string]any) { h["_source"].(map[string]any)["@timestamp"] = start.Add(-time.Hour) },
		"样本不早于窗口终点": func(h map[string]any) { h["_source"].(map[string]any)["@timestamp"] = end },
		"探针不在固定范围":  func(h map[string]any) { h["_source"].(map[string]any)["sensor_id"] = "probe_other" },
		"注册代次不在范围":  func(h map[string]any) { h["_source"].(map[string]any)["sensor_registration_id"] = "registration_other" },
		"样本不匹配名单值":  func(h map[string]any) { h["_source"].(map[string]any)["source"].(map[string]any)["ip"] = "203.0.113.9" },
	} {
		body := impactBody(t, sample(), 2, []int64{1, 1})
		mutate(body["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any))
		if _, _, _, err := DecodeImpact(encodeImpact(t, body), "tenant_a", d, start, end); !errors.Is(err, ErrIncomplete) {
			t.Fatalf("%s 时未判定结果不完整，err=%v", name, err)
		}
	}

	// 排序被破坏说明检索结果不可信，不能据此给出部分计数。
	body := impactBody(t, []model.Alert{earlier, later}, 2, []int64{1, 1})
	if _, _, _, err := DecodeImpact(encodeImpact(t, body), "tenant_a", d, start, end); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("样本顺序颠倒时未判定不完整，err=%v", err)
	}

	// 同一观测时间必须按事件标识升序，相等标识属于重复材料。
	same := impactAlert("alert_a", "192.0.2.10", start.Add(time.Hour))
	duplicate := impactAlert("alert_a", "192.0.2.11", start.Add(time.Hour))
	body = impactBody(t, []model.Alert{same, duplicate}, 2, []int64{1, 1})
	if _, _, _, err := DecodeImpact(encodeImpact(t, body), "tenant_a", d, start, end); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("重复事件标识未判定不完整，err=%v", err)
	}

	if _, _, _, err := DecodeImpact([]byte("{"), "tenant_a", d, start, end); !errors.Is(err, ErrIncomplete) {
		t.Fatal("损坏的回执未判定不完整")
	}
	oversized := make([]byte, MaxImpactBytes+1)
	if _, _, _, err := DecodeImpact(oversized, "tenant_a", d, start, end); !errors.Is(err, ErrIncomplete) {
		t.Fatal("超长回执未判定不完整")
	}
}

// 样本数以 MaxImpactSamples 为上限；总数更大时只截断样本，不改变精确总数。
func TestDecodeImpactCapsSamplesWithoutChangingTotal(t *testing.T) {
	d := impactDefinition()
	start, end := impactWindow()
	alerts := make([]model.Alert, 0, MaxImpactSamples)
	for i := range MaxImpactSamples {
		at := start.Add(time.Duration(MaxImpactSamples-i) * time.Minute)
		alerts = append(alerts, impactAlert("alert_"+strings.Repeat("0", 2-len(itoa(i)))+itoa(i), "192.0.2.10", at))
	}
	raw := encodeImpact(t, impactBody(t, alerts, 500, []int64{500, 0}))
	total, _, samples, err := DecodeImpact(raw, "tenant_a", d, start, end)
	if err != nil {
		t.Fatalf("截断样本的结果被拒绝：%v", err)
	}
	if total != 500 || len(samples) != MaxImpactSamples {
		t.Fatalf("总数 %d、样本 %d 条", total, len(samples))
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var out []byte
	for v > 0 {
		out = append([]byte{byte('0' + v%10)}, out...)
		v /= 10
	}
	return string(out)
}
