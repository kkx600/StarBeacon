//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/syslogdata"
)

func logsDBRequest(t *testing.T, ctx context.Context, esURL, method, path string, data any, status int) []byte {
	t.Helper()
	var body io.Reader
	if data != nil {
		raw, err := json.Marshal(data)
		require(t, err)
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, esURL+path, body)
	require(t, err)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	require(t, err)
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	require(t, err)
	if res.StatusCode != status {
		t.Fatalf("验收索引 %s %s，响应 %d：%s", method, path, res.StatusCode, raw)
	}
	return raw
}

func logsDBDecode[T any](t *testing.T, raw []byte) (out T) {
	t.Helper()
	require(t, json.Unmarshal(raw, &out))
	return
}

func logsDBReadSettings(t *testing.T, ctx context.Context, esURL, index string) map[string]any {
	t.Helper()
	type response struct {
		Settings map[string]any `json:"settings"`
	}
	settings := logsDBDecode[map[string]response](t, logsDBRequest(t, ctx, esURL, "GET", "/"+index+"/_settings?flat_settings=true", nil, 200))
	if len(settings) != 1 || settings[index].Settings["index.provided_name"] != index {
		t.Fatal("验收使用的索引名未精确回读")
	}
	return settings[index].Settings
}

func TestBasicLogsDBRegularIndicesQueriesAndStorage(t *testing.T) {
	esURL := os.Getenv("SB_ES_URL")
	if esURL == "" || os.Getenv("SB_MODE") != "development" {
		t.Skip("需要专属 Elasticsearch 验收集群")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	version := logsDBDecode[struct {
		Version struct{ Number string }
	}](t, logsDBRequest(t, ctx, esURL, "GET", "/?filter_path=version.number", nil, 200))
	license := logsDBDecode[struct {
		License struct{ Type, Status string }
	}](t, logsDBRequest(t, ctx, esURL, "GET", "/_license?filter_path=license.type,license.status", nil, 200))
	if version.Version.Number != "9.5.4" || license.License.Type != "basic" || license.License.Status != "active" {
		t.Fatal("验收需要 Elasticsearch 9.5.4 Basic", version, license)
	}
	es, err := store.OpenES(esURL, "")
	require(t, err)
	require(t, es.EnsurePolicy(ctx))
	stamp := time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, rand.IntN(15000))
	partition := stamp.Format("2006-01-02")
	const count = 12000

	for _, stream := range []string{"context", "logs"} {
		t.Run(stream, func(t *testing.T) {
			candidate, err := contract.EventIndexName(stream, 180, contract.PeriodDay, partition)
			require(t, err)
			legacy := strings.Replace(candidate, "-logsdb-", "-", 1)
			indices := []string{legacy, candidate}
			settings := make(map[string]map[string]any)
			for _, index := range indices {
				// 使用未来的随机日期和精确物理名。若不是本轮新建的索引，立即停止。
				logsDBRequest(t, ctx, esURL, "HEAD", "/"+index, nil, 404)
				createErr := es.EnsureIndex(ctx, index, partition)
				head, err := es.API.Indices.Exists([]string{index}, es.API.Indices.Exists.WithContext(ctx))
				require(t, err)
				exists := head.StatusCode == 200
				head.Body.Close()
				if exists {
					settings[index] = logsDBReadSettings(t, ctx, esURL, index)
					uuid, ok := settings[index]["index.uuid"].(string)
					if !ok || uuid == "" {
						t.Fatal("验收索引缺少身份")
					}
					t.Cleanup(func() {
						clean, stop := context.WithTimeout(context.Background(), 20*time.Second)
						defer stop()
						current := logsDBReadSettings(t, clean, esURL, index)
						t.Logf("LogsDB 验收清理清单 %s %s", index, uuid)
						if current["index.uuid"] != uuid {
							t.Error("验收索引身份变化，保留现场")
							return
						}
						logsDBRequest(t, clean, esURL, "DELETE", "/"+index, nil, 200)
					})
				}
				require(t, createErr)
				logsDBRequest(t, ctx, esURL, "PUT", "/"+index+"/_settings", map[string]any{"index.refresh_interval": "-1"}, 200)
			}
			clockField := "@timestamp"
			if stream == "logs" {
				clockField = "received_at"
			}
			got := settings[candidate]
			if got["index.mode"] != "logsdb" || got["index.mapping.source.mode"] != "stored" || got["index.codec"] != "best_compression" ||
				!reflect.DeepEqual(got["index.sort.field"], []any{"tenant_id", "sensor_id", clockField}) ||
				!reflect.DeepEqual(got["index.sort.order"], []any{"asc", "asc", "desc"}) ||
				settings[legacy]["index.mode"] == "logsdb" {
				t.Fatal("新旧索引模式、源字段或排序漂移")
			}
			events, logs := logsDBCorpus(stamp, count)
			write := make(map[string]time.Duration)
			for start := 0; start < count; start += 400 {
				order := indices
				if start/400%2 == 1 {
					order = []string{candidate, legacy}
				}
				for _, index := range order {
					begin := time.Now()
					var results []error
					if stream == "logs" {
						results = es.BulkLogs(ctx, index, logs[start:start+400])
					} else {
						results = es.Bulk(ctx, index, events[start:start+400])
					}
					write[index] += time.Since(begin)
					for _, err := range results {
						require(t, err)
					}
				}
			}
			var expected map[string]any
			var expectedDoc any = events[0]
			if stream == "logs" {
				expectedDoc = logs[0]
			}
			raw, err := json.Marshal(expectedDoc)
			require(t, err)
			require(t, json.Unmarshal(raw, &expected))
			for _, index := range indices {
				logsDBRequest(t, ctx, esURL, "PUT", "/"+index+"/_settings", map[string]any{"index.blocks.write": true}, 200)
				logsDBRequest(t, ctx, esURL, "POST", "/"+index+"/_refresh", nil, 200)
				logsDBRequest(t, ctx, esURL, "POST", "/"+index+"/_forcemerge?max_num_segments=1&flush=true", nil, 200)
				logsDBRequest(t, ctx, esURL, "POST", "/"+index+"/_flush?force=true&wait_if_ongoing=true", nil, 200)
				logsDBRequest(t, ctx, esURL, "POST", "/"+index+"/_refresh", nil, 200)
				source := logsDBDecode[struct {
					Source map[string]any `json:"_source"`
				}](t, logsDBRequest(t, ctx, esURL, "GET", "/"+index+"/_doc/t27_fixture_00000", nil, 200))
				want := maps.Clone(expected)
				if index == candidate && stream == "logs" {
					want["@timestamp"] = want["received_at"]
				}
				if !reflect.DeepEqual(source.Source, want) {
					t.Fatal("读取的 _source 与写入文档不一致", index)
				}
				if stream == "logs" {
					// 日志原文按路由日精确读取，精简映射须保留该条件。
					body := map[string]any{"query": map[string]any{"term": map[string]string{"partition": partition}}}
					route := logsDBDecode[struct{ Count int }](t, logsDBRequest(t, ctx, esURL, "POST", "/"+index+"/_count", body, 200))
					if route.Count != count {
						t.Fatal("日志原文的路由日条件未命中完整样本", index, route.Count)
					}
				}
			}

			query := logsDBQuery(stream, clockField, stamp)
			first := logsDBSearch(t, ctx, esURL, legacy, query)
			if len(first) == 0 || !slices.Equal(first, logsDBSearch(t, ctx, esURL, candidate, query)) {
				t.Fatal("相同样本的检索身份和顺序不一致")
			}
			samples := map[string][]time.Duration{}
			for round := range 32 {
				order := indices
				if round%2 == 1 {
					order = []string{candidate, legacy}
				}
				for _, index := range order {
					start := time.Now()
					hits := logsDBSearch(t, ctx, esURL, index, query)
					samples[index] = append(samples[index], time.Since(start))
					if !slices.Equal(hits, first) {
						t.Fatal("重复查询的命中漂移")
					}
				}
			}
			for _, index := range indices {
				segmentBytes := logsDBPrimarySegmentBytes(t, ctx, esURL, index, count)
				slices.Sort(samples[index])
				mode := "standard"
				if index == candidate {
					mode = "logsdb"
				}
				t.Logf("LogsDB 对照实测 %s %s %d 条，主分片已提交单段 %d 字节，写入 %.1f 条/秒，典型检索 P95 %s（%d 次），索引 %s",
					stream, mode, count, segmentBytes, float64(count)/write[index].Seconds(), samples[index][30], len(samples[index]), index)
			}
		})
	}
}

func logsDBPrimarySegmentBytes(t *testing.T, ctx context.Context, esURL, index string, count int) int64 {
	t.Helper()
	type segment struct {
		Count     int   `json:"num_docs"`
		Bytes     int64 `json:"size_in_bytes"`
		Committed bool  `json:"committed"`
		Search    bool  `json:"search"`
	}
	type shard struct {
		Routing  struct{ Primary bool }
		Segments map[string]segment
	}
	data := logsDBDecode[struct {
		Indices map[string]struct{ Shards map[string][]shard }
	}](t, logsDBRequest(t, ctx, esURL, "GET", "/"+index+"/_segments", nil, 200))
	shards := data.Indices[index].Shards["0"]
	if len(data.Indices[index].Shards) != 1 || len(shards) != 1 || !shards[0].Routing.Primary || len(shards[0].Segments) != 1 {
		t.Fatal("磁盘计量要求一个主分片、一个活跃段", index)
	}
	for _, entry := range shards[0].Segments {
		if !entry.Committed || !entry.Search || entry.Count != count || entry.Bytes < 1 {
			t.Fatal("磁盘计量要求已提交且可查询的完整样本", index, entry)
		}
		return entry.Bytes
	}
	t.Fatal("主分片没有可计量的段", index)
	return 0
}

func logsDBCorpus(stamp time.Time, count int) ([]model.Alert, []syslogdata.Document) {
	events := make([]model.Alert, count)
	logs := make([]syslogdata.Document, count)
	random := rand.New(rand.NewPCG(35, 27))
	for i := range count {
		tenant, sensor := fmt.Sprintf("t27_tenant_%02d", random.IntN(16)), fmt.Sprintf("fixture_sensor_%02d", random.IntN(8))
		id, sourceIP := fmt.Sprintf("t27_fixture_%05d", i), fmt.Sprintf("192.0.2.%d", 1+random.IntN(100))
		at := stamp.Add(time.Duration(i) * 15 * time.Millisecond)
		message := fmt.Sprintf("正常连接 accepted connection from %s to service on node %s sample=%d", sourceIP, sensor, i)
		doc := model.Alert{SchemaVersion: "1.0", EventID: id, TenantID: tenant, SensorID: sensor, RegistrationID: "fixture_registration",
			SourceGenerationID: "fixture_eve", Sequence: strconv.Itoa(i + 1), SourceOffset: strconv.Itoa(i * 230),
			Timestamp: at, ObservedAt: at, ReceivedAt: at, Source: model.Endpoint{IP: sourceIP, Port: 443}, Destination: model.Endpoint{IP: "198.51.100.10", Port: 443},
			Severity: "unknown", EvidenceStatus: "not_linked"}
		doc.Event.Dataset, doc.Network.Transport = "suricata.eve", "tcp"
		switch i % 3 {
		case 0:
			doc.Event.Kind = "flow"
			doc.Event.Original = fmt.Sprintf(`{"timestamp":%q,"event_type":"flow","src_ip":%q,"dest_ip":"198.51.100.10","flow":{"pkts_toserver":17,"pkts_toclient":12}}`, at.Format(time.RFC3339Nano), sourceIP)
		case 1:
			doc.Event.Kind, doc.Network.Protocol = "http", "http"
			doc.HTTP.Method, doc.HTTP.Hostname, doc.HTTP.Path = "GET", "service.example", fmt.Sprintf("/status/%d", i%13)
			doc.Event.Original = fmt.Sprintf(`{"timestamp":%q,"event_type":"http","src_ip":%q,"dest_ip":"198.51.100.10","http":{"http_method":"GET","hostname":"service.example","url":%q}}`, at.Format(time.RFC3339Nano), sourceIP, doc.HTTP.Path)
		case 2:
			doc.Event.Kind, doc.Network.Protocol = "tls", "tls"
			doc.Event.Original = fmt.Sprintf(`{"timestamp":%q,"event_type":"tls","src_ip":%q,"dest_ip":"198.51.100.10","tls":{"sni":"service.example","version":"TLS 1.3"}}`, at.Format(time.RFC3339Nano), sourceIP)
		}
		doc.RawSHA256 = syslogdata.Hash([]byte(doc.Event.Original))
		events[i] = doc
		raw := []byte("<134>1 " + at.Format(time.RFC3339Nano) + " fixture-host service 811 - - " + message)
		record := syslogdata.Record{SchemaVersion: syslogdata.Schema, SourceEpoch: "fixture_epoch", SourceSequence: strconv.Itoa(i + 1), ObservedAt: at,
			RawBase64: base64.StdEncoding.EncodeToString(raw), RawSHA256: syslogdata.Hash(raw), Peer: syslogdata.Peer{IP: sourceIP, Port: 514},
			Binding: syslogdata.ReceiverBinding{SourceID: "fixture_source", SourceName: "验收日志源", NetworkDomain: "fixture_network", Format: "rfc5424", Transport: "tcp", ConfigSHA256: syslogdata.Hash([]byte(sensor))}}
		logs[i] = syslogdata.Document{SchemaVersion: syslogdata.Schema, EventID: id, TenantID: tenant, SensorID: sensor, RegistrationID: "fixture_registration",
			Sequence: strconv.Itoa(i + 1), PayloadSHA256: syslogdata.Hash(raw), Partition: at.Format("2006-01-02"), ReceivedAt: at,
			Record: record, Parsed: syslogdata.Parse(record, raw)}
	}
	return events, logs
}

func logsDBQuery(stream, clockField string, stamp time.Time) map[string]any {
	filters := []any{
		map[string]any{"term": map[string]string{"tenant_id": "t27_tenant_01"}},
		map[string]any{"term": map[string]string{"sensor_id": "fixture_sensor_02"}},
		map[string]any{"range": map[string]any{clockField: map[string]any{"gte": stamp, "lt": stamp.Add(time.Minute)}}},
	}
	boolean := map[string]any{"filter": filters}
	if stream == "logs" {
		boolean["must"] = []any{map[string]any{"multi_match": map[string]any{"query": "正常连接 accepted", "fields": []string{"parsed.message", "parsed.message.standard"}, "operator": "and"}}}
	}
	return map[string]any{"size": 25, "query": map[string]any{"bool": boolean},
		"sort": []map[string]string{{clockField: "desc"}, {"event_id": "asc"}}}
}

func logsDBSearch(t *testing.T, ctx context.Context, esURL, index string, query map[string]any) []string {
	t.Helper()
	page := logsDBDecode[struct {
		Hits struct {
			Items []struct {
				ID string `json:"_id"`
			} `json:"hits"`
		}
	}](t, logsDBRequest(t, ctx, esURL, "POST", "/"+index+"/_search?request_cache=false&allow_partial_search_results=false", query, 200))
	ids := make([]string, 0, len(page.Hits.Items))
	for _, item := range page.Hits.Items {
		ids = append(ids, item.ID)
	}
	return ids
}
