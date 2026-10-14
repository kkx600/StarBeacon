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
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/elastic/elastic-transport-go/v8/elastictransport"
	"github.com/elastic/go-elasticsearch/v9/esapi"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/searchfilter"
	"golang.org/x/sync/singleflight"
)

type Elasticsearch struct {
	API           *esapi.API
	client        *elastictransport.Client
	mu            sync.Mutex
	indices       map[string]bool
	policies      map[int]bool
	indexFlight   singleflight.Group
	templateReady bool
}
type IndexItemError struct{ Status int }

func (e *IndexItemError) Error() string { return fmt.Sprintf("ES 分项写入失败: %d", e.Status) }

type IndexCreateError struct {
	Status          int
	CapacityLimited bool
}

func (e *IndexCreateError) Error() string {
	if e.CapacityLimited {
		return "ES 分片容量不足，索引尚未创建；请核对过期索引回收或集群容量"
	}
	return fmt.Sprintf("创建索引失败: %d", e.Status)
}

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
	return &Elasticsearch{API: esapi.New(c), client: c, indices: map[string]bool{}, policies: map[int]bool{}}, nil
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
	if err := s.EnsureEventTemplate(ctx); err != nil {
		return err
	}
	return s.ensureRetentionPolicy(ctx, 180)
}
func retentionPolicyName(days int) string {
	if days == 180 {
		return "sb-default-180d"
	}
	return fmt.Sprintf("sb-retention-%dd", days)
}
func (s *Elasticsearch) ensureRetentionPolicy(ctx context.Context, days int) error {
	if days < 1 || days > 3650 {
		return fmt.Errorf("索引保留期必须为 1–3650 天")
	}
	s.mu.Lock()
	known := s.policies[days]
	s.mu.Unlock()
	if known {
		return nil
	}
	_, err, _ := s.indexFlight.Do("policy/"+retentionPolicyName(days), func() (any, error) {
		s.mu.Lock()
		known := s.policies[days]
		s.mu.Unlock()
		if known {
			return nil, nil
		}
		exists, err := s.retentionPolicyExists(ctx, days)
		if err != nil {
			return nil, err
		}
		if !exists {
			body := fmt.Sprintf(`{"policy":{"phases":{"delete":{"min_age":"%dd","actions":{"delete":{}}}}}}`, days)
			res, err := s.API.ILM.PutLifecycle(strings.NewReader(body), retentionPolicyName(days), s.API.ILM.PutLifecycle.WithContext(ctx))
			if err = response(res, err, nil); err != nil {
				return nil, err
			}
			if ready, err := s.retentionPolicyExists(ctx, days); err != nil || !ready {
				if err != nil {
					return nil, err
				}
				return nil, fmt.Errorf("索引生命周期创建结果未确认")
			}
		}
		s.mu.Lock()
		s.policies[days] = true
		s.mu.Unlock()
		return nil, nil
	})
	return err
}
func (s *Elasticsearch) IndexKnown(index string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.indices[index]
}

const mapping = `{"dynamic":"strict","properties":{
"schema_version":{"type":"keyword"},"event_id":{"type":"keyword"},"tenant_id":{"type":"keyword"},"sensor_id":{"type":"keyword"},"sensor_registration_id":{"type":"keyword"},"source_generation_id":{"type":"keyword"},"source_offset":{"type":"keyword"},"sequence":{"type":"keyword"},"raw_sha256":{"type":"keyword"},"@timestamp":{"type":"date_nanos"},"observed_at":{"type":"date_nanos"},"received_at":{"type":"date_nanos"},
"event":{"properties":{"kind":{"type":"keyword"},"dataset":{"type":"keyword"},"original":{"type":"text","index":false}}},
"source":{"properties":{"ip":{"type":"ip"},"port":{"type":"integer"},"mac":{"type":"keyword"}}},"destination":{"properties":{"ip":{"type":"ip"},"port":{"type":"integer"},"mac":{"type":"keyword"}}},
"network":{"properties":{"transport":{"type":"keyword"},"protocol":{"type":"keyword"}}},"rule":{"properties":{"id":{"type":"keyword"},"revision":{"type":"keyword"},"name":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":512}}}}},
"http":{"properties":{"method":{"type":"keyword"},"hostname":{"type":"keyword"},"path":{"type":"wildcard"}}},"suricata":{"properties":{"flow_id":{"type":"keyword"},"action":{"type":"keyword"}}},"severity":{"type":"keyword"},"evidence_status":{"type":"keyword"},
"application":` + applicationMapping + `}}`

const applicationMapping = `{"properties":{"schema_version":{"type":"keyword"},"deployment_id":{"type":"keyword"},"state_sha256":{"type":"keyword"},"raw_sha256":{"type":"keyword"},"product_id":{"type":"keyword"},"product_name":{"type":"keyword","ignore_above":512},"category_id":{"type":"keyword"},"result":{"properties":{"schema_version":{"type":"keyword"},"origin":{"type":"keyword"},"protocol":{"type":"keyword"},"status":{"type":"keyword"},"reason":{"type":"keyword"},"evaluated_at":{"type":"date_nanos"},"observation_sha256":{"type":"keyword"},"rules_sha256":{"type":"keyword"},"rule_count":{"type":"short"},"matched_rule_count":{"type":"short"},"matches":{"type":"object","enabled":false},"limited":{"type":"boolean"}}}}}`

func (s *Elasticsearch) EnsureIndex(ctx context.Context, index, partition string) error {
	return s.EnsureIndexRetention(ctx, index, partition, 180)
}
func (s *Elasticsearch) EnsureIndexRetention(ctx context.Context, index, partition string, days int) error {
	if days < 1 || days > 3650 {
		return fmt.Errorf("索引保留期必须为 1–3650 天")
	}
	d, e := time.Parse("2006-01-02", partition)
	if e != nil {
		return e
	}
	stream := "alerts"
	prefix := "sb-alerts-"
	if strings.HasPrefix(index, "sb-context-") {
		stream = "context"
		prefix = "sb-context-"
	}
	tenant := strings.TrimSuffix(strings.TrimPrefix(index, prefix), "-"+strings.ReplaceAll(partition, "-", "."))
	expected, err := contract.IndexName(tenant, stream, partition)
	if err != nil || expected != index {
		return fmt.Errorf("索引身份与日期分区不一致")
	}
	if s.IndexKnown(index) {
		return nil
	}
	_, err, _ = s.indexFlight.Do("index/"+index, func() (any, error) {
		if s.IndexKnown(index) {
			return nil, nil
		}
		if err := s.EnsureEventTemplate(ctx); err != nil {
			return nil, err
		}
		if err := s.ensureRetentionPolicy(ctx, days); err != nil {
			return nil, err
		}
		body := fmt.Sprintf(`{"settings":{"number_of_shards":1,"number_of_replicas":1,"index.lifecycle.name":%q,"index.lifecycle.origination_date":%d},"mappings":%s}`, retentionPolicyName(days), d.UnixMilli(), mapping)
		res, e := s.API.Indices.Create(index, s.API.Indices.Create.WithBody(strings.NewReader(body)), s.API.Indices.Create.WithContext(ctx))
		if e != nil {
			return nil, e
		}
		defer res.Body.Close()
		if res.IsError() {
			var failure struct {
				Error struct {
					Type   string `json:"type"`
					Reason string `json:"reason"`
				} `json:"error"`
			}
			_ = json.NewDecoder(io.LimitReader(res.Body, 65536)).Decode(&failure)
			if failure.Error.Type != "resource_already_exists_exception" {
				// 不向日志透传依赖返回的原文；分片上限保持集群配置，由运维核对容量。
				limited := failure.Error.Type == "validation_exception" && strings.Contains(failure.Error.Reason, "maximum") && strings.Contains(failure.Error.Reason, "shards")
				return nil, &IndexCreateError{Status: res.StatusCode, CapacityLimited: limited}
			}
			// 只添加可选分类字段，不覆盖既有字段、分片、生命周期或历史文档。
			updated, err := s.API.Indices.PutMapping([]string{index}, strings.NewReader(`{"properties":{"application":`+applicationMapping+`}}`), s.API.Indices.PutMapping.WithContext(ctx))
			if err := response(updated, err, nil); err != nil {
				return nil, err
			}
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.indices) > 1024 {
			s.indices = map[string]bool{}
		}
		s.indices[index] = true
		return nil, nil
	})
	return err
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
	if res != nil && res.StatusCode == 404 {
		s.mu.Lock()
		delete(s.indices, index)
		s.mu.Unlock()
	}
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
			if status == 404 {
				s.mu.Lock()
				delete(s.indices, index)
				s.mu.Unlock()
			}
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
	if q.Start.IsZero() || q.End.IsZero() || q.Start.Year() < 1 || q.End.Year() > 9999 || !q.End.After(q.Start) || q.End.Sub(q.Start) > 31*24*time.Hour {
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
	for _, ip := range []*string{&q.SourceIP, &q.DestinationIP} {
		if *ip != "" {
			address, e := netip.ParseAddr(*ip)
			if e != nil || address.Zone() != "" {
				return fmt.Errorf("检索 IP 地址不合法")
			}
			*ip = address.Unmap().String()
		}
	}
	for _, text := range []string{q.Keyword, q.Path, q.Protocol, q.Method} {
		if !utf8.ValidString(text) || strings.IndexFunc(text, unicode.IsControl) != -1 {
			return fmt.Errorf("检索条件不能包含无效编码或控制字符")
		}
	}
	if len(q.Keyword) > 256 || len(q.Path) > 1024 || len(q.Protocol) > 32 || len(q.Method) > 16 {
		return fmt.Errorf("检索条件长度超限")
	}
	if q.Severity != "" && q.Severity != "high" && q.Severity != "medium" && q.Severity != "low" && q.Severity != "unknown" {
		return fmt.Errorf("严重级别不合法")
	}
	if _, e := searchfilter.Compile(q.Filter); e != nil {
		return e
	}
	return nil
}
func (s *Elasticsearch) Search(ctx context.Context, tenant string, q model.SearchRequest) (model.SearchResult, error) {
	return s.searchEvents(ctx, tenant, q, "alerts", []string{"alert"}, nil)
}

var trafficKinds = []string{"flow", "http", "http2", "dns", "tls", "quic", "ssh", "smtp", "ftp", "smb", "nfs", "dhcp", "rdp", "anomaly", "fileinfo"}

func ValidateTrafficSearch(q *model.TrafficSearchRequest) error {
	if err := ValidateSearch(&q.SearchRequest); err != nil {
		return err
	}
	if _, err := searchfilter.CompileForDataset(q.Filter, "context"); err != nil {
		return err
	}
	if q.Keyword != "" || q.Severity != "" {
		return fmt.Errorf("流量检索不支持告警名称或告警级别条件")
	}
	if q.EventKind != "" {
		found := false
		for _, kind := range trafficKinds {
			found = found || kind == q.EventKind
		}
		if !found {
			return fmt.Errorf("流量记录类型不受支持")
		}
	}
	for _, id := range []string{q.SensorID, q.RegistrationID, q.GenerationID} {
		if id != "" && !contract.ValidID(id) {
			return fmt.Errorf("流量来源标识无效")
		}
	}
	if (q.RegistrationID != "" && q.SensorID == "") || (q.GenerationID != "" && (q.SensorID == "" || q.RegistrationID == "")) {
		return fmt.Errorf("来源代次检索需要同时指定探针和注册代次")
	}
	if q.FlowID != "" {
		flow, err := strconv.ParseUint(q.FlowID, 10, 64)
		if err != nil || strconv.FormatUint(flow, 10) != q.FlowID {
			return fmt.Errorf("流标识必须为规范的 64 位无符号十进制整数")
		}
	}
	return nil
}

func (s *Elasticsearch) SearchTraffic(ctx context.Context, tenant string, q model.TrafficSearchRequest) (model.SearchResult, error) {
	if err := ValidateTrafficSearch(&q); err != nil {
		return model.SearchResult{}, err
	}
	kinds, filters := trafficScope(q)
	return s.searchEvents(ctx, tenant, q.SearchRequest, "context", kinds, filters)
}

func trafficScope(q model.TrafficSearchRequest) ([]string, []any) {
	kinds := trafficKinds
	if q.EventKind != "" {
		kinds = []string{q.EventKind}
	}
	filters := []any{}
	for _, pair := range []struct{ field, value string }{{"sensor_id", q.SensorID}, {"sensor_registration_id", q.RegistrationID}, {"source_generation_id", q.GenerationID}, {"suricata.flow_id", q.FlowID}} {
		if pair.value != "" {
			filters = append(filters, map[string]any{"term": map[string]string{pair.field: pair.value}})
		}
	}
	return kinds, filters
}

func (s *Elasticsearch) searchEvents(ctx context.Context, tenant string, q model.SearchRequest, stream string, kinds []string, extra []any) (model.SearchResult, error) {
	result := model.SearchResult{Items: []model.Alert{}, Page: q.Page, PageSize: q.PageSize}
	if !contract.ValidID(tenant) {
		return result, fmt.Errorf("租户标识不合法")
	}
	if e := ValidateSearch(&q); e != nil {
		return result, e
	}
	result.Page = q.Page
	result.PageSize = q.PageSize
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	boolQuery, e := eventQuery(tenant, q, kinds, extra)
	if e != nil {
		return result, e
	}
	body, _ := json.Marshal(map[string]any{"from": (q.Page - 1) * q.PageSize, "size": q.PageSize, "track_total_hits": true, "timeout": "5s", "query": map[string]any{"bool": boolQuery}, "sort": []any{map[string]string{"@timestamp": "desc"}, map[string]string{"event_id": "asc"}}})
	return s.readEventPage(ctx, tenant, q, stream, kinds, body)
}

// 列表与快照导出使用同一过滤条件，防止导出扩大查询范围。
func eventQuery(tenant string, q model.SearchRequest, kinds []string, extra []any) (map[string]any, error) {
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
	if q.Filter != "" {
		advanced, e := searchfilter.Compile(q.Filter)
		if e != nil {
			return nil, e
		}
		if advanced != nil {
			filter = append(filter, advanced)
			boolQuery["filter"] = filter
		}
	}
	if q.Keyword != "" {
		boolQuery["must"] = []any{map[string]any{"match_phrase": map[string]string{"rule.name": q.Keyword}}}
	}
	if len(kinds) == 1 {
		filter = append(filter, map[string]any{"term": map[string]string{"event.kind": kinds[0]}})
	} else {
		filter = append(filter, map[string]any{"terms": map[string][]string{"event.kind": kinds}})
	}
	filter = append(filter, extra...)
	boolQuery["filter"] = filter
	return boolQuery, nil
}

func (s *Elasticsearch) readEventPage(ctx context.Context, tenant string, q model.SearchRequest, stream string, kinds []string, body []byte) (model.SearchResult, error) {
	result := model.SearchResult{Items: []model.Alert{}, Page: q.Page, PageSize: q.PageSize}
	var decoded struct {
		TimedOut *bool `json:"timed_out"`
		Shards   struct {
			Total      *int `json:"total"`
			Successful *int `json:"successful"`
			Failed     *int `json:"failed"`
		} `json:"_shards"`
		Hits struct {
			Total struct {
				Value    *int64 `json:"value"`
				Relation string `json:"relation"`
			} `json:"total"`
			Hits []struct {
				ID     string      `json:"_id"`
				Index  string      `json:"_index"`
				Source model.Alert `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	prefix := "sb-" + stream + "-" + tenant + "-"
	res, e := s.API.Search(s.API.Search.WithIndex(prefix+"*"), s.API.Search.WithBody(bytes.NewReader(body)), s.API.Search.WithAllowPartialSearchResults(false), s.API.Search.WithAllowNoIndices(true), s.API.Search.WithContext(ctx))
	if e = response(res, e, &decoded); e != nil {
		return result, e
	}
	// HTTP 成功不代表检索完整；无匹配索引与不可用索引须分别处理。
	if decoded.TimedOut == nil || *decoded.TimedOut || decoded.Shards.Total == nil || *decoded.Shards.Total < 0 || decoded.Shards.Successful == nil || *decoded.Shards.Successful != *decoded.Shards.Total || decoded.Shards.Failed == nil || *decoded.Shards.Failed != 0 || decoded.Hits.Total.Value == nil || *decoded.Hits.Total.Value < 0 || decoded.Hits.Total.Relation != "eq" || decoded.Hits.Hits == nil {
		return result, fmt.Errorf("事件检索结果不完整，不能确认命中数量")
	}
	total := *decoded.Hits.Total.Value
	expected := min(int64(q.PageSize), max(total-int64((q.Page-1)*q.PageSize), 0))
	if int64(len(decoded.Hits.Hits)) != expected {
		return result, fmt.Errorf("事件检索分页结果与精确计数不一致")
	}
	seen := make(map[string]bool, len(decoded.Hits.Hits))
	for _, h := range decoded.Hits.Hits {
		date, dateErr := time.Parse("2006.01.02", strings.TrimPrefix(h.Index, prefix))
		index, indexErr := contract.IndexName(tenant, stream, date.Format("2006-01-02"))
		allowed := false
		for _, kind := range kinds {
			allowed = allowed || kind == h.Source.Event.Kind
		}
		if dateErr != nil || indexErr != nil || h.Index != index || !contract.ValidID(h.ID) || h.ID != h.Source.EventID || h.Source.TenantID != tenant || !allowed || h.Source.Timestamp.Before(q.Start) || !h.Source.Timestamp.Before(q.End) || seen[h.ID] {
			return model.SearchResult{Items: []model.Alert{}, Page: q.Page, PageSize: q.PageSize}, fmt.Errorf("事件检索记录不符合来源、时间或唯一性约束")
		}
		seen[h.ID] = true
		result.Items = append(result.Items, h.Source)
	}
	result.Total = total
	return result, nil
}
