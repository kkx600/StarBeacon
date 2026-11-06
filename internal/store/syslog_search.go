package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/syslogdata"
)

type SyslogSearchPage struct {
	Items      []syslogdata.Document  `json:"items"`
	Query      syslogdata.SearchQuery `json:"query"`
	NextCursor string                 `json:"next_cursor"`
}

func (s *Elasticsearch) SearchLogs(ctx context.Context, tenant string, q syslogdata.SearchQuery) (SyslogSearchPage, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	out := SyslogSearchPage{Items: []syslogdata.Document{}, Query: q}
	if q.Validate(tenant) != nil {
		return out, syslogdata.ErrInput
	}
	filters := []any{map[string]any{"term": map[string]any{"tenant_id": tenant}}, map[string]any{"range": map[string]any{"received_at": map[string]any{"gte": q.Start.UTC().Format(time.RFC3339Nano), "lt": q.End.UTC().Format(time.RFC3339Nano)}}}}
	for _, pair := range []struct{ field, value string }{{"sensor_id", q.SensorID}, {"record.binding.source_id", q.SourceID}, {"record.binding.network_domain", q.NetworkDomain}, {"record.peer.ip", q.PeerIP}, {"parsed.hostname", q.Hostname}, {"parsed.application", q.Application}, {"parsed.state", q.State}} {
		if pair.value != "" {
			filters = append(filters, map[string]any{"term": map[string]any{pair.field: pair.value}})
		}
	}
	if q.Severity != nil {
		filters = append(filters, map[string]any{"term": map[string]any{"parsed.severity": *q.Severity}})
	}
	boolean := map[string]any{"filter": filters}
	if q.Keyword != "" {
		boolean["must"] = []any{map[string]any{"multi_match": map[string]any{"query": q.Keyword, "fields": []string{"parsed.message", "parsed.message.standard"}, "type": "best_fields", "operator": "and"}}}
	}
	body := map[string]any{"size": q.Limit + 1, "track_total_hits": false, "_source": map[string]any{"excludes": []string{"record.raw_base64", "parsed.structured_data"}}, "query": map[string]any{"bool": boolean}, "sort": []any{map[string]any{"received_at": map[string]any{"order": "desc", "format": "strict_date_optional_time_nanos"}}, map[string]any{"event_id": "desc"}}}
	if t, id, _ := q.Position(tenant); id != "" {
		body["search_after"] = []any{t.Format(time.RFC3339Nano), id}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return out, err
	}
	var page struct {
		TimedOut bool `json:"timed_out"`
		Shards   struct {
			Failed int `json:"failed"`
		} `json:"_shards"`
		Hits struct {
			Items []struct {
				ID     string              `json:"_id"`
				Index  string              `json:"_index"`
				Source syslogdata.Document `json:"_source"`
				Sort   []json.RawMessage   `json:"sort"`
			} `json:"hits"`
		} `json:"hits"`
	}
	res, err := s.API.Search(s.API.Search.WithIndex(contract.SearchIndices("logs", tenant)...), s.API.Search.WithBody(strings.NewReader(string(raw))), s.API.Search.WithIgnoreUnavailable(true), s.API.Search.WithAllowNoIndices(true), s.API.Search.WithAllowPartialSearchResults(false), s.API.Search.WithContext(ctx))
	if err = response(res, err, &page); err != nil {
		return out, err
	}
	if page.TimedOut || page.Shards.Failed > 0 || len(page.Hits.Items) > q.Limit+1 {
		return out, fmt.Errorf("日志检索结果不完整")
	}
	previousTime := q.End
	previousID := ""
	if t, id, _ := q.Position(tenant); id != "" {
		previousTime, previousID = t, id
	}
	for _, hit := range page.Hits.Items {
		v := hit.Source
		var sortTime, sortID string
		if len(hit.Sort) != 2 || json.Unmarshal(hit.Sort[0], &sortTime) != nil || json.Unmarshal(hit.Sort[1], &sortID) != nil {
			return out, fmt.Errorf("日志排序结果无效")
		}
		t, timeErr := time.Parse(time.RFC3339Nano, sortTime)
		if !logIndexServes(hit.Index, tenant, v.Partition) || timeErr != nil || !t.Equal(v.ReceivedAt) || sortID != hit.ID || hit.ID != v.EventID || v.TenantID != tenant || v.SchemaVersion != "syslog.index.v1" || !v.Record.Binding.Valid() || v.Record.RawBase64 != "" || v.ReceivedAt.Before(q.Start) || !v.ReceivedAt.Before(q.End) || v.ReceivedAt.After(previousTime) || v.ReceivedAt.Equal(previousTime) && (previousID == "" || v.EventID >= previousID) {
			return out, fmt.Errorf("日志来源或排序无法核对")
		}
		// 查询级隔离之外，再核对不可变身份，避免跨租户或损坏来源混入结果。
		sourceSequence, err := parsePositiveSequence(v.Record.SourceSequence)
		if err != nil || v.EventID != contract.SyslogEventID(tenant, v.RegistrationID, v.Record.Binding.SourceID, v.Record.SourceEpoch, sourceSequence) {
			return out, fmt.Errorf("日志事件身份无效")
		}
		previousTime, previousID = v.ReceivedAt, v.EventID
		if len(out.Items) < q.Limit {
			if runes := []rune(v.Parsed.Message); len(runes) > 512 {
				v.Parsed.Message = string(runes[:512])
				v.MessageTruncated = true
			}
			out.Items = append(out.Items, v)
		}
	}
	if len(page.Hits.Items) > q.Limit {
		last := out.Items[len(out.Items)-1]
		out.NextCursor = q.Next(tenant, last.ReceivedAt, last.EventID)
	}
	return out, nil
}

// logIndexServes 核对日志所在索引：共享索引须覆盖记录的路由日，旧版索引须属于同一租户与同一日期。
func logIndexServes(index, tenant, partition string) bool {
	target, err := contract.ParseEventIndex(index)
	return err == nil && target.Stream == "logs" && (!target.Legacy || target.Tenant == tenant) && target.Covers(partition)
}

// LogDetail 在租户可读的日志索引中按事件身份与路由日精确读取；共享索引同时保存多个租户，依赖查询中的租户过滤与回读核对。
func (s *Elasticsearch) LogDetail(ctx context.Context, tenant, partition, id string) (syslogdata.Document, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	var empty syslogdata.Document
	if day, err := time.Parse("2006-01-02", partition); err != nil || day.Format("2006-01-02") != partition || !contract.ValidID(tenant) || len(id) != 64 {
		return empty, syslogdata.ErrInput
	}
	body, _ := json.Marshal(map[string]any{"size": 2, "track_total_hits": true, "timeout": "3s", "query": map[string]any{"bool": map[string]any{"filter": []any{
		map[string]any{"term": map[string]string{"tenant_id": tenant}}, map[string]any{"term": map[string]string{"event_id": id}}, map[string]any{"term": map[string]string{"partition": partition}},
	}}}})
	var page struct {
		TimedOut *bool `json:"timed_out"`
		Shards   struct {
			Failed *int `json:"failed"`
		} `json:"_shards"`
		Hits struct {
			Total struct {
				Value    int64  `json:"value"`
				Relation string `json:"relation"`
			} `json:"total"`
			Items []struct {
				ID     string              `json:"_id"`
				Index  string              `json:"_index"`
				Source syslogdata.Document `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	res, err := s.API.Search(s.API.Search.WithIndex(contract.SearchIndices("logs", tenant)...), s.API.Search.WithBody(strings.NewReader(string(body))), s.API.Search.WithAllowNoIndices(true), s.API.Search.WithAllowPartialSearchResults(false), s.API.Search.WithContext(ctx))
	if err = response(res, err, &page); err != nil {
		return empty, err
	}
	if page.TimedOut == nil || *page.TimedOut || page.Shards.Failed == nil || *page.Shards.Failed != 0 || page.Hits.Total.Relation != "eq" || page.Hits.Total.Value != int64(len(page.Hits.Items)) || len(page.Hits.Items) > 1 {
		return empty, fmt.Errorf("日志原始事实无法核对")
	}
	if len(page.Hits.Items) == 0 {
		return empty, pgx.ErrNoRows
	}
	hit := page.Hits.Items[0]
	v := hit.Source
	raw, err := json.Marshal(v.Record)
	record, original, decodeErr := syslogdata.DecodeRecord(raw)
	seq, seqErr := parsePositiveSequence(record.SourceSequence)
	if err != nil || decodeErr != nil || seqErr != nil || !logIndexServes(hit.Index, tenant, partition) || v.MessageTruncated || hit.ID != id || v.EventID != id || v.TenantID != tenant || v.SchemaVersion != "syslog.index.v1" || v.Partition != partition || v.EventID != contract.SyslogEventID(tenant, v.RegistrationID, record.Binding.SourceID, record.SourceEpoch, seq) || syslogdata.Hash(raw) != v.PayloadSHA256 {
		return empty, fmt.Errorf("日志原始事实无法核对")
	}
	expected := syslogdata.Parse(record, original)
	want, _ := json.Marshal(expected)
	actual, _ := json.Marshal(v.Parsed)
	if string(want) != string(actual) {
		return empty, fmt.Errorf("日志解析事实无法核对")
	}
	return v, nil
}

func parsePositiveSequence(s string) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != s {
		return 0, syslogdata.ErrInput
	}
	return n, nil
}
