package store

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

const eventTemplateName = "sb-events-v1"

type eventTemplate struct {
	Patterns        []string `json:"index_patterns"`
	AllowAutoCreate *bool    `json:"allow_auto_create"`
	Priority        int      `json:"priority"`
	Version         int      `json:"version"`
	Meta            struct {
		Owner  string `json:"owner"`
		Schema int    `json:"schema"`
	} `json:"_meta"`
	Template struct {
		Mappings json.RawMessage `json:"mappings"`
	} `json:"template"`
}

func (s *Elasticsearch) eventTemplateExists(ctx context.Context) (bool, error) {
	res, err := s.API.Indices.GetIndexTemplate(s.API.Indices.GetIndexTemplate.WithName(eventTemplateName), s.API.Indices.GetIndexTemplate.WithContext(ctx))
	if err != nil {
		return false, err
	}
	if res.StatusCode == 404 {
		res.Body.Close()
		return false, nil
	}
	var body struct {
		Templates []struct {
			Name   string        `json:"name"`
			Config eventTemplate `json:"index_template"`
		} `json:"index_templates"`
	}
	if err := response(res, nil, &body); err != nil {
		return false, err
	}
	if len(body.Templates) != 1 || body.Templates[0].Name != eventTemplateName {
		return false, fmt.Errorf("索引模板身份不完整")
	}
	t := body.Templates[0].Config
	var actual, expected any
	if json.Unmarshal(t.Template.Mappings, &actual) != nil || json.Unmarshal([]byte(mapping), &expected) != nil {
		return false, fmt.Errorf("索引模板映射不完整")
	}
	if t.Meta.Owner != "starbeacon" || t.Meta.Schema != 1 || t.Version != 1 || t.Priority != 150 || t.AllowAutoCreate == nil || *t.AllowAutoCreate || len(t.Patterns) != 2 || !((t.Patterns[0] == "sb-alerts-*" && t.Patterns[1] == "sb-context-*") || (t.Patterns[1] == "sb-alerts-*" && t.Patterns[0] == "sb-context-*")) || !reflect.DeepEqual(actual, expected) {
		return false, fmt.Errorf("索引模板归属或数据契约不一致；需要管理流程核对")
	}
	return true, nil
}

// 只约束 StarBeacon 的事件索引；当前索引丢失时禁止自动建立无生命周期的动态映射。
func (s *Elasticsearch) EnsureEventTemplate(ctx context.Context) error {
	s.mu.Lock()
	known := s.templateReady
	s.mu.Unlock()
	if known {
		return nil
	}
	_, err, _ := s.indexFlight.Do("event-template", func() (any, error) {
		exists, err := s.eventTemplateExists(ctx)
		if err != nil {
			return nil, err
		}
		if !exists {
			body := fmt.Sprintf(`{"index_patterns":["sb-alerts-*","sb-context-*"],"allow_auto_create":false,"priority":150,"version":1,"_meta":{"owner":"starbeacon","schema":1},"template":{"mappings":%s}}`, mapping)
			res, err := s.API.Indices.PutIndexTemplate(eventTemplateName, strings.NewReader(body), s.API.Indices.PutIndexTemplate.WithCreate(true), s.API.Indices.PutIndexTemplate.WithContext(ctx))
			if err = response(res, err, nil); err != nil {
				if ready, check := s.eventTemplateExists(ctx); check != nil || !ready {
					return nil, err
				}
			}
			if ready, err := s.eventTemplateExists(ctx); err != nil || !ready {
				if err != nil {
					return nil, err
				}
				return nil, fmt.Errorf("索引模板创建结果未确认")
			}
		}
		s.mu.Lock()
		s.templateReady = true
		s.mu.Unlock()
		return nil, nil
	})
	return err
}
