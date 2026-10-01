package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/elastic/elastic-transport-go/v8/elastictransport"
	"github.com/elastic/go-elasticsearch/v9/esapi"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
)

type Elasticsearch struct {
	API     *esapi.API
	client  *elastictransport.Client
	mu      sync.Mutex
	indices map[string]bool
}
type IndexItemError struct{ Status int }

func (e *IndexItemError) Error() string { return fmt.Sprintf("ES 分项写入失败: %d", e.Status) }

func OpenES(address, key string) (*Elasticsearch, error) {
	u, e := url.Parse(address)
	if e != nil || u.Host == "" {
		return nil, fmt.Errorf("ES 地址不合法")
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 16
	t.ResponseHeaderTimeout = 15 * time.Second
	c, e := elastictransport.New(elastictransport.Config{URLs: []*url.URL{u}, APIKey: key, Transport: t, MaxRetries: 2, RetryOnStatus: []int{429, 502, 503, 504}})
	if e != nil {
		return nil, e
	}
	return &Elasticsearch{API: esapi.New(c), client: c, indices: map[string]bool{}}, nil
}
func (s *Elasticsearch) Ping(ctx context.Context) error {
	res, e := s.API.Info(s.API.Info.WithContext(ctx))
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.IsError() {
		return fmt.Errorf("ES 健康检查失败: %d", res.StatusCode)
	}
	return nil
}
func response(res *esapi.Response, err error, target any) error {
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.IsError() {
		return fmt.Errorf("ES 请求失败: %d", res.StatusCode)
	}
	if target == nil {
		_, e := io.Copy(io.Discard, res.Body)
		return e
	}
	return json.NewDecoder(io.LimitReader(res.Body, 16*1024*1024)).Decode(target)
}
func (s *Elasticsearch) EnsurePolicy(ctx context.Context) error {
	res, e := s.API.ILM.PutLifecycle(strings.NewReader(`{"policy":{"phases":{"delete":{"min_age":"180d","actions":{"delete":{}}}}}}`), "sb-default-180d", s.API.ILM.PutLifecycle.WithContext(ctx))
	return response(res, e, nil)
}

const mapping = `{"dynamic":"strict","properties":{
"schema_version":{"type":"keyword"},"event_id":{"type":"keyword"},"tenant_id":{"type":"keyword"},"sensor_id":{"type":"keyword"},"sensor_registration_id":{"type":"keyword"},"source_generation_id":{"type":"keyword"},"source_offset":{"type":"keyword"},"sequence":{"type":"keyword"},"raw_sha256":{"type":"keyword"},"@timestamp":{"type":"date_nanos"},"observed_at":{"type":"date_nanos"},"received_at":{"type":"date_nanos"},
"event":{"properties":{"kind":{"type":"keyword"},"dataset":{"type":"keyword"},"original":{"type":"text","index":false}}},
"source":{"properties":{"ip":{"type":"ip"},"port":{"type":"integer"},"mac":{"type":"keyword"}}},"destination":{"properties":{"ip":{"type":"ip"},"port":{"type":"integer"},"mac":{"type":"keyword"}}},
"network":{"properties":{"transport":{"type":"keyword"},"protocol":{"type":"keyword"}}},"rule":{"properties":{"id":{"type":"keyword"},"revision":{"type":"keyword"},"name":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":512}}}}},
"http":{"properties":{"method":{"type":"keyword"},"hostname":{"type":"keyword"},"path":{"type":"wildcard"}}},"suricata":{"properties":{"flow_id":{"type":"keyword"},"action":{"type":"keyword"}}},"severity":{"type":"keyword"},"evidence_status":{"type":"keyword"}}}`

func (s *Elasticsearch) EnsureIndex(ctx context.Context, index, partition string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.indices[index] {
		return nil
	}
	d, e := time.Parse("2006-01-02", partition)
	if e != nil {
		return e
	}
	body := fmt.Sprintf(`{"settings":{"number_of_shards":1,"number_of_replicas":1,"index.lifecycle.name":"sb-default-180d","index.lifecycle.origination_date":%d},"mappings":%s}`, d.UnixMilli(), mapping)
	res, e := s.API.Indices.Create(index, s.API.Indices.Create.WithBody(strings.NewReader(body)), s.API.Indices.Create.WithContext(ctx))
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.IsError() {
		var failure struct {
			Error struct {
				Type string `json:"type"`
			} `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(res.Body, 65536)).Decode(&failure)
		if failure.Error.Type != "resource_already_exists_exception" {
			return fmt.Errorf("创建索引失败: %d", res.StatusCode)
		}
	}
	if len(s.indices) > 1024 {
		s.indices = map[string]bool{}
	}
	s.indices[index] = true
	return nil
}
func (s *Elasticsearch) Bulk(ctx context.Context, index string, items []model.Alert) []error {
	out := make([]error, len(items))
	if len(items) == 0 {
		return out
	}
	var b bytes.Buffer
	for _, item := range items {
		meta, _ := json.Marshal(map[string]any{"create": map[string]string{"_id": item.EventID}})
		b.Write(meta)
		b.WriteByte('\n')
		doc, e := json.Marshal(item)
		if e != nil {
			for i := range out {
				out[i] = e
			}
			return out
		}
		b.Write(doc)
		b.WriteByte('\n')
	}
	var result struct {
		Items []map[string]struct {
			Status int    `json:"status"`
			ID     string `json:"_id"`
		} `json:"items"`
	}
	res, e := s.API.Bulk(&b, s.API.Bulk.WithIndex(index), s.API.Bulk.WithContext(ctx))
	if e = response(res, e, &result); e != nil {
		for i := range out {
			out[i] = e
		}
		return out
	}
	if len(result.Items) != len(items) {
		for i := range out {
			out[i] = fmt.Errorf("ES 分项结果数量不匹配")
		}
		return out
	}
	for i, v := range result.Items {
		status := v["create"].Status
		if v["create"].ID != items[i].EventID {
			out[i] = fmt.Errorf("ES 分项身份不匹配")
			continue
		}
		switch status {
		case 201:
		case 409:
			out[i] = s.verifyDuplicate(ctx, index, items[i])
		default:
			out[i] = &IndexItemError{Status: status}
		}
	}
	return out
}
func (s *Elasticsearch) verifyDuplicate(ctx context.Context, index string, want model.Alert) error {
	var v struct {
		Source model.Alert `json:"_source"`
	}
	res, e := s.API.Get(index, want.EventID, s.API.Get.WithContext(ctx))
	if e = response(res, e, &v); e != nil {
		return e
	}
	if v.Source.TenantID != want.TenantID || v.Source.EventID != want.EventID || v.Source.RawSHA256 != want.RawSHA256 || v.Source.SourceGenerationID != want.SourceGenerationID || v.Source.SourceOffset != want.SourceOffset {
		return fmt.Errorf("不可变事件发生冲突")
	}
	return nil
}
func ValidateSearch(q *model.SearchRequest) error {
	if q.Start.IsZero() || q.End.IsZero() || !q.End.After(q.Start) || q.End.Sub(q.Start) > 31*24*time.Hour {
		return fmt.Errorf("检索时间范围必须在 31 天内")
	}
	if q.Page == 0 {
		q.Page = 1
	}
	if q.PageSize == 0 {
		q.PageSize = 20
	}
	if q.Page < 1 || q.PageSize < 1 || q.PageSize > 100 || q.Page > 10000/q.PageSize {
		return fmt.Errorf("分页超出支持范围")
	}
	for _, ip := range []string{q.SourceIP, q.DestinationIP} {
		if ip != "" {
			if _, e := netip.ParseAddr(ip); e != nil {
				return fmt.Errorf("检索 IP 地址不合法")
			}
		}
	}
	if len(q.Keyword) > 256 || len(q.Path) > 1024 || len(q.Protocol) > 32 || len(q.Method) > 16 {
		return fmt.Errorf("检索条件长度超限")
	}
	if q.Severity != "" && q.Severity != "high" && q.Severity != "medium" && q.Severity != "low" && q.Severity != "unknown" {
		return fmt.Errorf("严重级别不合法")
	}
	return nil
}
func (s *Elasticsearch) Search(ctx context.Context, tenant string, q model.SearchRequest) (model.SearchResult, error) {
	result := model.SearchResult{Items: []model.Alert{}, Page: q.Page, PageSize: q.PageSize}
	if !contract.ValidID(tenant) {
		return result, fmt.Errorf("租户标识不合法")
	}
	if e := ValidateSearch(&q); e != nil {
		return result, e
	}
	result.Page = q.Page
	result.PageSize = q.PageSize
	filter := []any{map[string]any{"term": map[string]string{"tenant_id": tenant}}, map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": q.Start, "lt": q.End}}}}
	for _, pair := range []struct{ field, value string }{{"source.ip", q.SourceIP}, {"destination.ip", q.DestinationIP}, {"http.method", strings.ToUpper(q.Method)}, {"severity", q.Severity}} {
		if pair.value != "" {
			filter = append(filter, map[string]any{"term": map[string]string{pair.field: pair.value}})
		}
	}
	if q.Protocol != "" {
		protocol := strings.ToLower(q.Protocol)
		filter = append(filter, map[string]any{"bool": map[string]any{"minimum_should_match": 1, "should": []any{map[string]any{"term": map[string]string{"network.protocol": protocol}}, map[string]any{"term": map[string]string{"network.transport": protocol}}}}})
	}
	if q.Path != "" {
		filter = append(filter, map[string]any{"prefix": map[string]string{"http.path": q.Path}})
	}
	boolQuery := map[string]any{"filter": filter}
	if q.Keyword != "" {
		boolQuery["must"] = []any{map[string]any{"match_phrase": map[string]string{"rule.name": q.Keyword}}}
	}
	body, _ := json.Marshal(map[string]any{"from": (q.Page - 1) * q.PageSize, "size": q.PageSize, "track_total_hits": true, "query": map[string]any{"bool": boolQuery}, "sort": []any{map[string]string{"@timestamp": "desc"}, map[string]string{"event_id": "asc"}}})
	var decoded struct {
		Hits struct {
			Total struct {
				Value int64 `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source model.Alert `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	res, e := s.API.Search(s.API.Search.WithIndex("sb-alerts-"+tenant+"-*"), s.API.Search.WithBody(bytes.NewReader(body)), s.API.Search.WithIgnoreUnavailable(true), s.API.Search.WithAllowNoIndices(true), s.API.Search.WithContext(ctx))
	if e = response(res, e, &decoded); e != nil {
		return result, e
	}
	result.Total = decoded.Hits.Total.Value
	for _, h := range decoded.Hits.Hits {
		result.Items = append(result.Items, h.Source)
	}
	return result, nil
}
