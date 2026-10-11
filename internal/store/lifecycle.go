package store

import (
	"context"
	"encoding/json"
	"fmt"
)

func (s *Elasticsearch) retentionPolicyExists(ctx context.Context, days int) (bool, error) {
	name := retentionPolicyName(days)
	res, err := s.API.ILM.GetLifecycle(s.API.ILM.GetLifecycle.WithPolicy(name), s.API.ILM.GetLifecycle.WithContext(ctx))
	if err != nil {
		return false, err
	}
	if res.StatusCode == 404 {
		res.Body.Close()
		return false, nil
	}
	var body map[string]struct {
		Policy struct {
			Phases map[string]struct {
				MinAge  string                     `json:"min_age"`
				Actions map[string]json.RawMessage `json:"actions"`
			} `json:"phases"`
		} `json:"policy"`
	}
	if err := response(res, nil, &body); err != nil {
		return false, err
	}
	policy, ok := body[name]
	if !ok || len(body) != 1 || len(policy.Policy.Phases) != 1 {
		return false, fmt.Errorf("索引生命周期返回不完整或包含其他阶段")
	}
	phase, ok := policy.Policy.Phases["delete"]
	if !ok || phase.MinAge != fmt.Sprintf("%dd", days) || len(phase.Actions) != 1 {
		return false, fmt.Errorf("既有索引生命周期与固定保留期不一致；不会自动覆盖")
	}
	var action map[string]bool
	if json.Unmarshal(phase.Actions["delete"], &action) != nil || action == nil || len(action) > 1 || (len(action) == 1 && !action["delete_searchable_snapshot"]) {
		return false, fmt.Errorf("索引生命周期删除动作不符合当前契约")
	}
	return true, nil
}
