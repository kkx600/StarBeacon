package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/assessment"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
)

var ErrAlertIdentity = errors.New("告警身份不唯一或与原始记录不一致")

// 精确查询只回读身份字段，拒绝跨分区歧义和不完整分片结果，不复制原始载荷到操作库。
func (s *Elasticsearch) VerifyAlertIdentity(parent context.Context, tenant, id, digest string) error {
	_, err := s.readAlertIdentity(parent, tenant, id, digest, false)
	return err
}

// ReadAlertEvidence 只读取研判白名单，不取回原始 EVE、报文或模型无需使用的租户字段。
func (s *Elasticsearch) ReadAlertEvidence(parent context.Context, tenant, id, digest string) (model.Alert, error) {
	return s.readAlertIdentity(parent, tenant, id, digest, true)
}

func (s *Elasticsearch) readAlertIdentity(parent context.Context, tenant, id, digest string, evidence bool) (model.Alert, error) {
	var empty model.Alert
	if !contract.ValidID(tenant) || !contract.ValidID(id) || !assessment.ValidDigest(digest) {
		return empty, assessment.ErrInput
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	fields := []string{"tenant_id", "event_id", "raw_sha256", "event.kind"}
	if evidence {
		fields = append(fields, "@timestamp", "observed_at", "sensor_id", "sensor_registration_id", "source", "destination", "network", "rule", "http", "suricata", "severity", "evidence_status")
	}
	body, _ := json.Marshal(map[string]any{
		"size": 2, "track_total_hits": true, "timeout": "3s", "_source": fields,
		"query": map[string]any{"bool": map[string]any{"filter": []any{map[string]any{"term": map[string]string{"tenant_id": tenant}}, map[string]any{"term": map[string]string{"event_id": id}}}}},
	})
	var result struct {
		TimedOut *bool `json:"timed_out"`
		Shards   struct {
			Failed     *int `json:"failed"`
			Total      *int `json:"total"`
			Successful *int `json:"successful"`
		} `json:"_shards"`
		Hits struct {
			Total struct {
				Value    int64  `json:"value"`
				Relation string `json:"relation"`
			} `json:"total"`
			Items []struct {
				ID     string      `json:"_id"`
				Index  string      `json:"_index"`
				Source model.Alert `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	res, err := s.API.Search(s.API.Search.WithIndex("sb-alerts-"+tenant+"-*"), s.API.Search.WithBody(bytes.NewReader(body)), s.API.Search.WithAllowPartialSearchResults(false), s.API.Search.WithAllowNoIndices(true), s.API.Search.WithContext(ctx))
	if err := response(res, err, &result); err != nil {
		return empty, err
	}
	if result.TimedOut == nil || *result.TimedOut || result.Shards.Failed == nil || *result.Shards.Failed != 0 || result.Shards.Total == nil || *result.Shards.Total < 0 || result.Shards.Successful == nil || *result.Shards.Successful != *result.Shards.Total || result.Hits.Total.Relation != "eq" || result.Hits.Total.Value != int64(len(result.Hits.Items)) {
		return empty, ErrAlertIdentity
	}
	if result.Hits.Total.Value == 0 {
		return empty, pgx.ErrNoRows
	}
	if len(result.Hits.Items) != 1 {
		return empty, ErrAlertIdentity
	}
	hit := result.Hits.Items[0]
	prefix := "sb-alerts-" + tenant + "-"
	date := strings.TrimPrefix(hit.Index, prefix)
	parsed, parseErr := time.Parse("2006.01.02", date)
	index, indexErr := contract.IndexName(tenant, "alerts", parsed.Format("2006-01-02"))
	if parseErr != nil || indexErr != nil || index != hit.Index || hit.ID != id || hit.Source.EventID != id || hit.Source.TenantID != tenant || hit.Source.RawSHA256 != digest || hit.Source.Event.Kind != "alert" || hit.Source.Event.Original != "" {
		return empty, ErrAlertIdentity
	}
	// 分区由平台路由分配，历史重放和延迟上报的事件时间可能早于索引日期。
	// 来源完整性由跨分区唯一事件与原始摘要确认，研判仍要求实际事件及观测时间。
	if evidence && (hit.Source.Timestamp.IsZero() || hit.Source.ObservedAt.IsZero()) {
		return empty, ErrAlertIdentity
	}
	return hit.Source, nil
}
