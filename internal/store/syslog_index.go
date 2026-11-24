package store

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/syslogdata"
)

const logMapping = `{"dynamic":"strict","properties":{
"message_truncated":{"type":"boolean"},"schema_version":{"type":"keyword"},"event_id":{"type":"keyword"},"tenant_id":{"type":"keyword"},"sensor_id":{"type":"keyword"},"sensor_registration_id":{"type":"keyword"},"sequence":{"type":"keyword"},"payload_sha256":{"type":"keyword"},"partition":{"type":"keyword"},"received_at":{"type":"date_nanos"},
"record":{"properties":{"schema_version":{"type":"keyword"},"source_epoch":{"type":"keyword"},"source_sequence":{"type":"keyword"},"observed_at":{"type":"date_nanos"},"raw_base64":{"type":"keyword","index":false,"doc_values":false},"raw_sha256":{"type":"keyword"},
"binding":{"properties":{"source_id":{"type":"keyword"},"source_name":{"type":"keyword","ignore_above":512},"network_domain":{"type":"keyword"},"config_sha256":{"type":"keyword"},"transport":{"type":"keyword"},"format":{"type":"keyword"},"timezone":{"type":"keyword"},"year_policy":{"type":"keyword"}}},
"peer":{"properties":{"ip":{"type":"ip"},"port":{"type":"integer"},"certificate_sha256":{"type":"keyword"}}}}},
"parsed":{"properties":{"parser_version":{"type":"keyword"},"state":{"type":"keyword"},"reason":{"type":"keyword"},"time_quality":{"type":"keyword"},"source_time":{"type":"date"},"priority":{"type":"short"},"facility":{"type":"short"},"severity":{"type":"short"},"hostname":{"type":"keyword","ignore_above":512},"application":{"type":"keyword","ignore_above":512},"process_id":{"type":"keyword","ignore_above":512},"message_id":{"type":"keyword","ignore_above":512},"message":{"type":"text","analyzer":"cjk","fields":{"standard":{"type":"text","analyzer":"standard"}}},"message_utf8":{"type":"boolean"},"structured_data":{"type":"object","enabled":false}}}}}`

func (s *Elasticsearch) BulkLogs(ctx context.Context, index string, items []syslogdata.Document) []error {
	target, _ := contract.ParseEventIndex(index)
	ids := make([]string, len(items))
	docs := make([]json.RawMessage, len(items))
	for i, v := range items {
		ids[i] = v.EventID
		var source any = v
		if target.LogsDB {
			// 普通 LogsDB 索引也要求 @timestamp。Syslog 的索引时间与列表使用同一个接收时刻。
			source = struct {
				syslogdata.Document
				Timestamp time.Time `json:"@timestamp"`
			}{v, v.ReceivedAt}
		}
		raw, err := json.Marshal(source)
		if err != nil {
			out := make([]error, len(items))
			for i := range out {
				out[i] = err
			}
			return out
		}
		docs[i] = raw
	}
	return s.bulkDocuments(ctx, index, ids, docs, func(i int) error {
		var existing struct {
			ID     string `json:"_id"`
			Source struct {
				syslogdata.Document
				Timestamp time.Time `json:"@timestamp"`
			} `json:"_source"`
		}
		res, err := s.API.Get(index, ids[i], s.API.Get.WithContext(ctx))
		if err = response(res, err, &existing); err != nil {
			return err
		}
		actual, want := existing.Source.Document, items[i]
		if target.LogsDB && !existing.Source.Timestamp.Equal(actual.ReceivedAt) {
			return fmt.Errorf("不可变日志接收时间不匹配")
		}
		// received_at 属于首次传输观察；重传可能在新的接收时刻出现，其他存储事实必须相同。
		actual.ReceivedAt = want.ReceivedAt
		if existing.ID != ids[i] || !reflect.DeepEqual(actual, want) {
			return fmt.Errorf("不可变日志发生冲突")
		}
		return nil
	})
}

// verifyIndex 核对同名既有索引具有固定映射、分区起点和生命周期，禁止在未知索引上继续写入。
func (s *Elasticsearch) verifyIndex(ctx context.Context, index string, template sharedTemplate, origin time.Time, days int) error {
	var body map[string]struct {
		Mappings json.RawMessage `json:"mappings"`
		Settings json.RawMessage `json:"settings"`
	}
	res, err := s.API.Indices.Get([]string{index}, s.API.Indices.Get.WithContext(ctx), s.API.Indices.Get.WithFlatSettings(template.sortTime != ""))
	if err = response(res, err, &body); err != nil {
		return err
	}
	v, ok := body[index]
	var actual, want map[string]any
	if !ok || len(body) != 1 || json.Unmarshal(v.Mappings, &actual) != nil || json.Unmarshal([]byte(template.mapping), &want) != nil {
		return fmt.Errorf("既有索引映射无法核对")
	}
	if template.sortTime != "" {
		// 9.5.4 在普通 LogsDB 索引也安装时间戳元字段。已声明的字段类型仍以模板为准。
		want["_data_stream_timestamp"] = map[string]any{"enabled": true}
	}
	if !reflect.DeepEqual(actual, want) {
		return fmt.Errorf("既有索引映射无法核对")
	}
	if template.sortTime != "" {
		var settings map[string]any
		expected := template.settings()
		expected["index.lifecycle.name"] = retentionPolicyName(days)
		expected["index.lifecycle.origination_date"] = fmt.Sprint(origin.UnixMilli())
		if json.Unmarshal(v.Settings, &settings) != nil || !sameIndexSettings(settings, expected, false) {
			return fmt.Errorf("LogsDB 索引静态设置或生命周期无法核对")
		}
	} else {
		var settings struct {
			Index struct {
				Lifecycle struct {
					Name            string      `json:"name"`
					OriginationDate json.Number `json:"origination_date"`
				} `json:"lifecycle"`
			} `json:"index"`
		}
		if json.Unmarshal(v.Settings, &settings) != nil {
			return fmt.Errorf("既有索引生命周期格式无效")
		}
		actualOrigin, originErr := settings.Index.Lifecycle.OriginationDate.Int64()
		if settings.Index.Lifecycle.Name != retentionPolicyName(days) || originErr != nil || actualOrigin != origin.UnixMilli() {
			return fmt.Errorf("既有索引生命周期无法核对")
		}
	}
	ready, err := s.retentionPolicyExists(ctx, days)
	if err != nil {
		return err
	}
	if !ready {
		return fmt.Errorf("既有索引生命周期尚未确认")
	}
	return nil
}
