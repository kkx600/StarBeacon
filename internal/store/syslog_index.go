package store

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/syslogdata"
)

const logMapping = `{"dynamic":"strict","properties":{
"message_truncated":{"type":"boolean"},"schema_version":{"type":"keyword"},"event_id":{"type":"keyword"},"tenant_id":{"type":"keyword"},"sensor_id":{"type":"keyword"},"sensor_registration_id":{"type":"keyword"},"sequence":{"type":"keyword"},"payload_sha256":{"type":"keyword"},"partition":{"type":"keyword"},"received_at":{"type":"date_nanos"},
"record":{"properties":{"schema_version":{"type":"keyword"},"source_epoch":{"type":"keyword"},"source_sequence":{"type":"keyword"},"observed_at":{"type":"date_nanos"},"raw_base64":{"type":"keyword","index":false,"doc_values":false},"raw_sha256":{"type":"keyword"},
"binding":{"properties":{"source_id":{"type":"keyword"},"source_name":{"type":"keyword","ignore_above":512},"network_domain":{"type":"keyword"},"config_sha256":{"type":"keyword"},"transport":{"type":"keyword"},"format":{"type":"keyword"},"timezone":{"type":"keyword"},"year_policy":{"type":"keyword"}}},
"peer":{"properties":{"ip":{"type":"ip"},"port":{"type":"integer"},"certificate_sha256":{"type":"keyword"}}}}},
"parsed":{"properties":{"parser_version":{"type":"keyword"},"state":{"type":"keyword"},"reason":{"type":"keyword"},"time_quality":{"type":"keyword"},"source_time":{"type":"date"},"priority":{"type":"short"},"facility":{"type":"short"},"severity":{"type":"short"},"hostname":{"type":"keyword","ignore_above":512},"application":{"type":"keyword","ignore_above":512},"process_id":{"type":"keyword","ignore_above":512},"message_id":{"type":"keyword","ignore_above":512},"message":{"type":"text","analyzer":"cjk","fields":{"standard":{"type":"text","analyzer":"standard"}}},"message_utf8":{"type":"boolean"},"structured_data":{"type":"object","enabled":false}}}}}`
const logTemplateName = "sb-logs-v1"

func logTemplateBody() string {
	return `{"index_patterns":["sb-logs-*"],"allow_auto_create":false,"priority":152,"version":1,"_meta":{"owner":"starbeacon","schema":1},"template":{"mappings":` + logMapping + `}}`
}
func (s *Elasticsearch) logTemplateExists(ctx context.Context) (bool, error) {
	res, err := s.API.Indices.GetIndexTemplate(s.API.Indices.GetIndexTemplate.WithName(logTemplateName), s.API.Indices.GetIndexTemplate.WithContext(ctx))
	if err != nil {
		return false, err
	}
	if res.StatusCode == 404 {
		res.Body.Close()
		return false, nil
	}
	var out struct {
		Templates []struct {
			Name   string        `json:"name"`
			Config eventTemplate `json:"index_template"`
		} `json:"index_templates"`
	}
	if err = response(res, nil, &out); err != nil {
		return false, err
	}
	if len(out.Templates) != 1 || out.Templates[0].Name != logTemplateName {
		return false, fmt.Errorf("日志索引模板身份无效")
	}
	t := out.Templates[0].Config
	var actual, expected any
	if json.Unmarshal(t.Template.Mappings, &actual) != nil || json.Unmarshal([]byte(logMapping), &expected) != nil || t.Version != 1 || t.Meta.Schema != 1 || t.Meta.Owner != "starbeacon" || t.Priority != 152 || t.AllowAutoCreate == nil || *t.AllowAutoCreate || !reflect.DeepEqual(t.Patterns, []string{"sb-logs-*"}) || !reflect.DeepEqual(actual, expected) {
		return false, fmt.Errorf("日志索引模板契约不一致")
	}
	return true, nil
}
func (s *Elasticsearch) EnsureLogTemplate(ctx context.Context) error {
	_, err, _ := s.indexFlight.Do("log-template", func() (any, error) {
		s.mu.Lock()
		ready := s.logTemplateReady
		s.mu.Unlock()
		if ready {
			return nil, nil
		}
		exists, err := s.logTemplateExists(ctx)
		if err != nil {
			return nil, err
		}
		if !exists {
			res, e := s.API.Indices.PutIndexTemplate(logTemplateName, strings.NewReader(logTemplateBody()), s.API.Indices.PutIndexTemplate.WithCreate(true), s.API.Indices.PutIndexTemplate.WithContext(ctx))
			write := response(res, e, nil)
			if ready, check := s.logTemplateExists(ctx); check != nil {
				return nil, check
			} else if !ready {
				if write != nil {
					return nil, write
				}
				return nil, fmt.Errorf("日志索引模板尚未确认")
			}
		}
		s.mu.Lock()
		s.logTemplateReady = true
		s.mu.Unlock()
		return nil, nil
	})
	return err
}
func (s *Elasticsearch) BulkLogs(ctx context.Context, index string, items []syslogdata.Document) []error {
	ids := make([]string, len(items))
	docs := make([]json.RawMessage, len(items))
	for i, v := range items {
		ids[i] = v.EventID
		raw, err := json.Marshal(v)
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
			ID     string              `json:"_id"`
			Source syslogdata.Document `json:"_source"`
		}
		res, err := s.API.Get(index, ids[i], s.API.Get.WithContext(ctx))
		if err = response(res, err, &existing); err != nil {
			return err
		}
		actual, want := existing.Source, items[i]
		// received_at 属于首次传输观察；重传可能在新的接收时刻出现，其他存储事实必须相同。
		actual.ReceivedAt = want.ReceivedAt
		if existing.ID != ids[i] || !reflect.DeepEqual(actual, want) {
			return fmt.Errorf("不可变日志发生冲突")
		}
		return nil
	})
}

// 同名既有索引必须具有固定映射和有效生命周期，禁止在未知索引上继续写入。
func (s *Elasticsearch) verifyLogIndex(ctx context.Context, index string) error {
	var body map[string]struct {
		Mappings json.RawMessage `json:"mappings"`
		Settings struct {
			Index struct {
				Lifecycle struct {
					Name            string      `json:"name"`
					OriginationDate json.Number `json:"origination_date"`
				} `json:"lifecycle"`
			} `json:"index"`
		} `json:"settings"`
	}
	res, err := s.API.Indices.Get([]string{index}, s.API.Indices.Get.WithContext(ctx))
	if err = response(res, err, &body); err != nil {
		return err
	}
	v, ok := body[index]
	var actual, expected any
	if !ok || len(body) != 1 || json.Unmarshal(v.Mappings, &actual) != nil || json.Unmarshal([]byte(logMapping), &expected) != nil || !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("日志索引映射无法核对")
	}
	name := v.Settings.Index.Lifecycle.Name
	days := 0
	if name == retentionPolicyName(180) {
		days = 180
	} else {
		if _, err := fmt.Sscanf(name, "sb-retention-%dd", &days); err != nil || name != retentionPolicyName(days) {
			return fmt.Errorf("日志生命周期无法核对")
		}
	}
	origin, originErr := v.Settings.Index.Lifecycle.OriginationDate.Int64()
	day, dateErr := time.Parse("2006.01.02", index[len(index)-10:])
	if days < 1 || days > 3650 || originErr != nil || dateErr != nil || origin != day.UnixMilli() {
		return fmt.Errorf("日志生命周期无法核对")
	}
	ready, err := s.retentionPolicyExists(ctx, days)
	if err != nil {
		return err
	}
	if !ready {
		return fmt.Errorf("日志生命周期尚未确认")
	}
	return nil
}
