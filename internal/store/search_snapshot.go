package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v9/esapi"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/searchsnapshot"
)

const snapshotPageSize = 500

type snapshotShards struct {
	Total      *int `json:"total"`
	Successful *int `json:"successful"`
	Skipped    *int `json:"skipped"`
	Failed     *int `json:"failed"`
}

func (s snapshotShards) complete() bool {
	return s.Total != nil && *s.Total >= 0 && s.Successful != nil && *s.Successful == *s.Total && s.Skipped != nil && *s.Skipped >= 0 && *s.Skipped <= *s.Total && s.Failed != nil && *s.Failed == 0
}

type snapshotPage struct {
	PITID    string         `json:"pit_id"`
	TimedOut *bool          `json:"timed_out"`
	Shards   snapshotShards `json:"_shards"`
	Hits     struct {
		Total struct {
			Value    *int64 `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		Hits []struct {
			ID     string            `json:"_id"`
			Index  string            `json:"_index"`
			Source model.Alert       `json:"_source"`
			Sort   []json.RawMessage `json:"sort"`
		} `json:"hits"`
	} `json:"hits"`
}

var snapshotFields = []string{"schema_version", "event_id", "tenant_id", "sensor_id", "sensor_registration_id", "source_generation_id", "source_offset", "sequence", "raw_sha256", "@timestamp", "observed_at", "received_at", "event.kind", "source.ip", "source.port", "source.mac", "destination.ip", "destination.port", "destination.mac", "network.transport", "network.protocol", "rule.id", "rule.revision", "rule.name", "http.method", "http.hostname", "http.path", "suricata.flow_id", "severity", "evidence_status"}

// ExportEvents 在同一 PIT 内读取全部命中；任何失败均不返回部分文件。
// authorize 在各批次前后回读当前会话，撤权后不继续读取或交付内容。
func (s *Elasticsearch) ExportEvents(ctx context.Context, tenant, dataset string, q model.TrafficSearchRequest, authorize func(context.Context) error) (raw []byte, rows int, err error) {
	if !contract.ValidID(tenant) || authorize == nil {
		return nil, 0, errors.New("导出身份或授权核验未配置")
	}
	kinds, extra := []string{"alert"}, []any(nil)
	switch dataset {
	case "alerts":
		if q.EventKind != "" || q.SensorID != "" || q.RegistrationID != "" || q.GenerationID != "" || q.FlowID != "" {
			return nil, 0, errors.New("告警导出不能混用协议来源条件")
		}
		err = ValidateSearch(&q.SearchRequest)
	case "context":
		err = ValidateTrafficSearch(&q)
		kinds, extra = trafficScope(q)
	default:
		return nil, 0, errors.New("导出数据集无效")
	}
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err = authorize(ctx); err != nil {
		return nil, 0, err
	}
	query, err := eventQuery(tenant, q.SearchRequest, kinds, extra)
	if err != nil {
		return nil, 0, err
	}
	index := "sb-" + dataset + "-" + tenant + "-"
	filter, _ := json.Marshal(map[string]any{"index_filter": map[string]any{"bool": query}})
	var opened struct {
		ID     string         `json:"id"`
		Shards snapshotShards `json:"_shards"`
	}
	res, err := s.API.OpenPointInTime([]string{index + "*"}, time.Minute, s.API.OpenPointInTime.WithAllowPartialSearchResults(false), s.API.OpenPointInTime.WithIgnoreUnavailable(false), s.API.OpenPointInTime.WithExpandWildcards("open", "closed"), s.API.OpenPointInTime.WithMaxConcurrentShardRequests(2), s.API.OpenPointInTime.WithBody(bytes.NewReader(filter)), s.API.OpenPointInTime.WithContext(ctx))
	if err = snapshotResponse(res, err, &opened); err != nil {
		return nil, 0, err
	}
	if !validPIT(opened.ID) {
		return nil, 0, errors.New("检索快照身份缺失或超限")
	}
	pit := opened.ID
	defer func() {
		// 客户端取消也必须释放快照；使用独立、严格有界的清理期限。
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer stop()
		body, _ := json.Marshal(map[string]string{"id": pit})
		var closed struct {
			Succeeded *bool `json:"succeeded"`
			Freed     *int  `json:"num_freed"`
		}
		res, closeErr := s.API.ClosePointInTime(bytes.NewReader(body), s.API.ClosePointInTime.WithContext(cleanup))
		closeErr = snapshotResponse(res, closeErr, &closed)
		if closeErr == nil && (closed.Succeeded == nil || !*closed.Succeeded || closed.Freed == nil || *closed.Freed < 0) {
			closeErr = errors.New("检索快照释放未确认")
		}
		if closeErr != nil {
			err = errors.Join(err, closeErr)
			raw, rows = nil, 0
		}
	}()
	if !opened.Shards.complete() {
		return nil, 0, errors.New("检索快照分片不完整")
	}
	// index_filter 排除的分片没有 PIT 上下文；后续搜索必须覆盖其余全部上下文。
	activeShards := *opened.Shards.Total - *opened.Shards.Skipped
	csv := searchsnapshot.NewCSV()
	seen := make(map[string]bool)
	var after json.Number
	total := int64(-1)
	for {
		if err = authorize(ctx); err != nil {
			return nil, 0, err
		}
		body := map[string]any{"size": snapshotPageSize, "track_total_hits": true, "timeout": "5s", "query": map[string]any{"bool": query}, "pit": map[string]string{"id": pit, "keep_alive": "1m"}, "sort": []any{map[string]string{"_shard_doc": "asc"}}, "_source": snapshotFields}
		if after != "" {
			body["search_after"] = []json.Number{after}
		}
		encoded, _ := json.Marshal(body)
		var page snapshotPage
		res, err := s.API.Search(s.API.Search.WithBody(bytes.NewReader(encoded)), s.API.Search.WithAllowPartialSearchResults(false), s.API.Search.WithContext(ctx))
		if err = snapshotResponse(res, err, &page); err != nil {
			return nil, 0, err
		}
		// 每次搜索都可能替换 PIT 身份，后续读取和最终关闭均使用最新身份。
		if validPIT(page.PITID) {
			pit = page.PITID
		} else {
			return nil, 0, errors.New("检索快照续期身份无效")
		}
		if page.TimedOut == nil || *page.TimedOut || !page.Shards.complete() || *page.Shards.Total != activeShards || page.Hits.Total.Value == nil || *page.Hits.Total.Value < 0 || page.Hits.Total.Relation != "eq" || page.Hits.Hits == nil {
			return nil, 0, errors.New("快照结果不完整，导出未生成")
		}
		if total == -1 {
			total = *page.Hits.Total.Value
		}
		if total > searchsnapshot.MaxRows {
			return nil, 0, searchsnapshot.ErrLimit
		}
		if total != *page.Hits.Total.Value || int64(len(page.Hits.Hits)) != min(int64(snapshotPageSize), total-int64(csv.Rows())) {
			return nil, 0, errors.New("快照计数或分页完整性不一致")
		}
		for _, hit := range page.Hits.Hits {
			date, dateErr := time.Parse("2006.01.02", strings.TrimPrefix(hit.Index, index))
			expected, indexErr := contract.IndexName(tenant, dataset, date.Format("2006-01-02"))
			allowed := false
			for _, kind := range kinds {
				allowed = allowed || kind == hit.Source.Event.Kind
			}
			if dateErr != nil || indexErr != nil || hit.Index != expected || !contract.ValidID(hit.ID) || hit.ID != hit.Source.EventID || hit.Source.TenantID != tenant || !allowed || hit.Source.Timestamp.Before(q.Start) || !hit.Source.Timestamp.Before(q.End) || seen[hit.ID] || hit.Source.Event.Original != "" || len(hit.Sort) != 1 {
				return nil, 0, errors.New("导出记录与身份、时间或来源约束不一致")
			}
			number := string(hit.Sort[0])
			ordinal, sortErr := strconv.ParseInt(number, 10, 64)
			if sortErr != nil || ordinal < 0 || strconv.FormatInt(ordinal, 10) != number {
				return nil, 0, errors.New("快照排序游标无效")
			}
			if after != "" {
				previous, _ := after.Int64()
				if ordinal <= previous {
					return nil, 0, errors.New("快照排序未向前推进")
				}
			}
			seen[hit.ID], after = true, json.Number(number)
			if err = csv.Append(hit.Source); err != nil {
				return nil, 0, err
			}
		}
		if err = authorize(ctx); err != nil {
			return nil, 0, err
		}
		if int64(csv.Rows()) == total {
			return csv.Bytes(), csv.Rows(), nil
		}
	}
}

func validPIT(id string) bool {
	return len(id) > 0 && len(id) <= 65536 && strings.IndexFunc(id, func(r rune) bool { return r < 33 || r > 126 }) == -1
}

func snapshotResponse(res *esapi.Response, err error, target any) error {
	if err != nil {
		if res != nil && res.Body != nil {
			res.Body.Close()
		}
		return err
	}
	defer res.Body.Close()
	if res.IsError() {
		return fmt.Errorf("检索快照请求失败：%d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16*1024*1024+1))
	if err != nil || len(raw) > 16*1024*1024 {
		return errors.New("检索快照响应读取失败或超过预算")
	}
	return json.Unmarshal(raw, target)
}
