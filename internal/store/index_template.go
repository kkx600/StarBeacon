package store

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/kkx600/StarBeacon/internal/contract"
)

// indexTemplate 是 ES 返回的可组合索引模板，用于精确核对本项目的固定契约。
type indexTemplate struct {
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
		Settings map[string]any  `json:"settings"`
	} `json:"template"`
}

// sharedTemplate 约束全部租户共用的事件索引：固定映射，并禁止写入时自动建立缺少生命周期的索引。
type sharedTemplate struct {
	name     string
	patterns []string
	priority int
	mapping  string
	sortTime string
}

var sharedEventTemplate = sharedTemplate{name: "sb-v2-events", patterns: []string{"sb-v2-alerts-*", "sb-v2-context-*"}, priority: 161, mapping: mapping}
var sharedLogTemplate = sharedTemplate{name: "sb-v2-logs", patterns: []string{"sb-v2-logs-*"}, priority: 162, mapping: logMapping}
var contextLogsDBTemplate = sharedTemplate{name: "sb-v2-context-logsdb", patterns: []string{"sb-v2-context-logsdb-*"}, priority: 163, mapping: contextLogsDBMapping, sortTime: "@timestamp"}
var logsLogsDBTemplate = sharedTemplate{name: "sb-v2-logs-logsdb", patterns: []string{"sb-v2-logs-logsdb-*"}, priority: 164, mapping: logsLogsDBMapping, sortTime: "received_at"}

func (t sharedTemplate) body() string {
	patterns, _ := json.Marshal(t.patterns)
	settings := ""
	if t.sortTime != "" {
		raw, _ := json.Marshal(t.settings())
		settings = `,"settings":` + string(raw)
	}
	return fmt.Sprintf(`{"index_patterns":%s,"allow_auto_create":false,"priority":%d,"version":1,"_meta":{"owner":"starbeacon","schema":1},"template":{"mappings":%s%s}}`, patterns, t.priority, t.mapping, settings)
}

// sharedTemplateExists 只接受本项目的固定契约；内容不一致时拒绝继续写入，不自动覆盖。
func (s *Elasticsearch) sharedTemplateExists(ctx context.Context, t sharedTemplate) (bool, error) {
	res, err := s.API.Indices.GetIndexTemplate(s.API.Indices.GetIndexTemplate.WithName(t.name), s.API.Indices.GetIndexTemplate.WithFlatSettings(true), s.API.Indices.GetIndexTemplate.WithContext(ctx))
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
			Config indexTemplate `json:"index_template"`
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
	if !sameIndexSettings(c.Template.Settings, t.settings(), true) {
		return false, fmt.Errorf("共享索引模板静态设置不一致")
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

func templateForIndex(target contract.EventIndex) sharedTemplate {
	if target.LogsDB {
		if target.Stream == "logs" {
			return logsLogsDBTemplate
		}
		return contextLogsDBTemplate
	}
	if target.Stream == "logs" {
		return sharedLogTemplate
	}
	return sharedEventTemplate
}
