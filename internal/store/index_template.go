package store

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/kkx600/StarBeacon/internal/contract"
)

// 独立模板版本避免旧程序重启时因模板被改写而失去就绪资格。
const eventTemplateName = "sb-events-v2"
const eventTemplatePriority = 151

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
	if t.Meta.Owner != "starbeacon" || t.Priority != eventTemplatePriority || t.AllowAutoCreate == nil || *t.AllowAutoCreate || len(t.Patterns) != 2 || !((t.Patterns[0] == "sb-alerts-*" && t.Patterns[1] == "sb-context-*") || (t.Patterns[1] == "sb-alerts-*" && t.Patterns[0] == "sb-context-*")) {
		return false, fmt.Errorf("索引模板归属或数据契约不一致；需要管理流程核对")
	}
	if t.Meta.Schema == 2 && t.Version == 2 && reflect.DeepEqual(actual, expected) {
		return true, nil
	}
	// 仅接受可证明的原项目 v1 映射，升级范围固定为一个可选字段。
	var legacy map[string]any
	_ = json.Unmarshal([]byte(mapping), &legacy)
	delete(legacy["properties"].(map[string]any), "application")
	if t.Meta.Schema != 1 || t.Version != 1 || !reflect.DeepEqual(actual, legacy) {
		return false, fmt.Errorf("索引模板归属或数据契约不一致；需要管理流程核对")
	}
	res, err = s.API.Indices.PutIndexTemplate(eventTemplateName, strings.NewReader(eventTemplateBody()), s.API.Indices.PutIndexTemplate.WithContext(ctx))
	if err := response(res, err, nil); err != nil {
		return false, err
	}
	// 不信任写入受理结果，随后精确回读 v2 模板；拒绝无限递归升级。
	return s.verifyEventTemplateV2(ctx)
}

func eventTemplateBody() string {
	return fmt.Sprintf(`{"index_patterns":["sb-alerts-*","sb-context-*"],"allow_auto_create":false,"priority":%d,"version":2,"_meta":{"owner":"starbeacon","schema":2},"template":{"mappings":%s}}`, eventTemplatePriority, mapping)
}

func (s *Elasticsearch) verifyEventTemplateV2(ctx context.Context) (bool, error) {
	res, err := s.API.Indices.GetIndexTemplate(s.API.Indices.GetIndexTemplate.WithName(eventTemplateName), s.API.Indices.GetIndexTemplate.WithContext(ctx))
	var body struct {
		Templates []struct {
			Name   string        `json:"name"`
			Config eventTemplate `json:"index_template"`
		} `json:"index_templates"`
	}
	if err := response(res, err, &body); err != nil {
		return false, err
	}
	if len(body.Templates) != 1 || body.Templates[0].Name != eventTemplateName {
		return false, fmt.Errorf("索引模板升级结果不完整")
	}
	t := body.Templates[0].Config
	var actual, expected any
	if json.Unmarshal(t.Template.Mappings, &actual) != nil || json.Unmarshal([]byte(mapping), &expected) != nil || t.Version != 2 || t.Meta.Schema != 2 || t.Meta.Owner != "starbeacon" || t.AllowAutoCreate == nil || *t.AllowAutoCreate || t.Priority != eventTemplatePriority || !reflect.DeepEqual(t.Patterns, []string{"sb-alerts-*", "sb-context-*"}) || !reflect.DeepEqual(actual, expected) {
		return false, fmt.Errorf("索引模板升级尚未确认")
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
			body := eventTemplateBody()
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

// sharedTemplate 约束全部租户共用的事件索引：固定映射，并禁止写入时自动建立缺少生命周期的索引。
type sharedTemplate struct {
	name     string
	patterns []string
	priority int
	mapping  string
}

var sharedEventTemplate = sharedTemplate{"sb-v2-events", []string{"sb-v2-alerts-*", "sb-v2-context-*"}, 161, mapping}
var sharedLogTemplate = sharedTemplate{"sb-v2-logs", []string{"sb-v2-logs-*"}, 162, logMapping}

func (t sharedTemplate) body() string {
	patterns, _ := json.Marshal(t.patterns)
	return fmt.Sprintf(`{"index_patterns":%s,"allow_auto_create":false,"priority":%d,"version":1,"_meta":{"owner":"starbeacon","schema":1},"template":{"mappings":%s}}`, patterns, t.priority, t.mapping)
}

// sharedTemplateExists 只接受本项目的固定契约；内容不一致时拒绝继续写入，不自动覆盖。
func (s *Elasticsearch) sharedTemplateExists(ctx context.Context, t sharedTemplate) (bool, error) {
	res, err := s.API.Indices.GetIndexTemplate(s.API.Indices.GetIndexTemplate.WithName(t.name), s.API.Indices.GetIndexTemplate.WithContext(ctx))
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
	if len(body.Templates) != 1 || body.Templates[0].Name != t.name {
		return false, fmt.Errorf("共享索引模板身份不完整")
	}
	c := body.Templates[0].Config
	var actual, expected any
	if json.Unmarshal(c.Template.Mappings, &actual) != nil || json.Unmarshal([]byte(t.mapping), &expected) != nil || c.Version != 1 || c.Meta.Schema != 1 || c.Meta.Owner != "starbeacon" || c.Priority != t.priority || c.AllowAutoCreate == nil || *c.AllowAutoCreate || !reflect.DeepEqual(c.Patterns, t.patterns) || !reflect.DeepEqual(actual, expected) {
		return false, fmt.Errorf("共享索引模板契约不一致；需要管理流程核对")
	}
	return true, nil
}

func (s *Elasticsearch) ensureSharedTemplate(ctx context.Context, t sharedTemplate) error {
	s.mu.Lock()
	ready := s.templates[t.name]
	s.mu.Unlock()
	if ready {
		return nil
	}
	_, err, _ := s.indexFlight.Do("template/"+t.name, func() (any, error) {
		exists, err := s.sharedTemplateExists(ctx, t)
		if err != nil {
			return nil, err
		}
		if !exists {
			res, e := s.API.Indices.PutIndexTemplate(t.name, strings.NewReader(t.body()), s.API.Indices.PutIndexTemplate.WithCreate(true), s.API.Indices.PutIndexTemplate.WithContext(ctx))
			write := response(res, e, nil)
			// 并发创建时以回读结果为准，不信任单次写入受理。
			if ready, check := s.sharedTemplateExists(ctx, t); check != nil {
				return nil, check
			} else if !ready {
				if write != nil {
					return nil, write
				}
				return nil, fmt.Errorf("共享索引模板尚未确认")
			}
		}
		s.mu.Lock()
		s.templates[t.name] = true
		s.mu.Unlock()
		return nil, nil
	})
	return err
}

func (s *Elasticsearch) ensureIndexTemplate(ctx context.Context, target contract.EventIndex) error {
	switch {
	case target.Legacy && target.Stream == "logs":
		return s.EnsureLogTemplate(ctx)
	case target.Legacy:
		return s.EnsureEventTemplate(ctx)
	case target.Stream == "logs":
		return s.ensureSharedTemplate(ctx, sharedLogTemplate)
	}
	return s.ensureSharedTemplate(ctx, sharedEventTemplate)
}
