package agent

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/kkx600/StarBeacon/internal/application"
	"github.com/kkx600/StarBeacon/internal/control"
	bolt "go.etcd.io/bbolt"
)

type applicationInstalled struct {
	State   application.State `json:"state"`
	Command control.Command   `json:"command"`
	SHA256  string            `json:"sha256"`
}

type ApplicationService struct {
	wal           *WAL
	mu            sync.RWMutex
	state         application.State
	matcher       *application.Matcher
	commandSHA256 string
}

func NewApplicationService(wal *WAL) (*ApplicationService, error) {
	s := &ApplicationService{wal: wal, state: application.EmptyState()}
	err := wal.DB.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte("local_config")).Get([]byte("application_rules"))
		if len(raw) == 0 {
			return nil
		}
		var installed applicationInstalled
		if json.Unmarshal(raw, &installed) != nil || installed.State.Validate() != nil || installed.Command.Kind != "applications.apply" || control.Validate(installed.Command) != nil || installed.Command.TenantID != wal.TenantID || installed.Command.SensorID != wal.SensorID || installed.Command.RegistrationID != wal.RegistrationID || application.Digest(installed.Command) != installed.SHA256 || installed.State.DeploymentID != installed.Command.ID {
			return errors.New("本地应用规则状态绑定损坏，禁止继续分类")
		}
		p, err := application.ReadPackage(installed.Command.Payload)
		if err != nil || installed.State.RulesSHA256 != p.RulesSHA256 || installed.State.RuleCount != len(p.Versions) || installed.State.InstalledAt.Before(installed.Command.IssuedAt.Add(-time.Minute)) {
			return application.ErrInput
		}
		s.matcher, err = application.Compile(p.Versions)
		if err != nil {
			return err
		}
		s.state = installed.State
		s.commandSHA256 = installed.SHA256
		return nil
	})
	return s, err
}

func (s *ApplicationService) Snapshot() application.State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.state
	if v.InstalledAt != nil {
		at := *v.InstalledAt
		v.InstalledAt = &at
	}
	return v
}

func (s *ApplicationService) Apply(ctx context.Context, c control.Command) (json.RawMessage, string, error) {
	if c.Kind != "applications.apply" || control.Validate(c) != nil || c.TenantID != s.wal.TenantID || c.SensorID != s.wal.SensorID || c.RegistrationID != s.wal.RegistrationID {
		return nil, "invalid_application_package", application.ErrInput
	}
	p, err := application.ReadPackage(c.Payload)
	if err != nil {
		return nil, "invalid_application_package", err
	}
	m, err := application.Compile(p.Versions)
	if err != nil {
		return nil, "invalid_application_package", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, "application_apply_cancelled", err
	}
	if s.state.DeploymentID == c.ID {
		if s.state.RulesSHA256 != p.RulesSHA256 || s.commandSHA256 != application.Digest(c) {
			return nil, "application_state_conflict", application.ErrInput
		}
		raw, err := json.Marshal(s.state)
		return raw, "", err
	}
	if s.state.StateSHA256 != p.ExpectedStateSHA256 {
		return nil, "application_state_conflict", errors.New("采集器应用规则状态已变化")
	}
	now := time.Now().UTC()
	if c.IssuedAt.After(now.Add(time.Minute)) || !c.ExpiresAt.After(now) {
		return nil, "command_expired", control.ErrExpired
	}
	next := application.State{SchemaVersion: application.StateSchema, DeploymentID: c.ID, RulesSHA256: p.RulesSHA256, StateSHA256: application.StateDigest(c.ID, p.RulesSHA256), RuleCount: len(p.Versions), InstalledAt: &now}
	raw, err := json.Marshal(applicationInstalled{State: next, Command: c, SHA256: application.Digest(c)})
	if err != nil {
		return nil, "invalid_application_package", err
	}
	// 同步提交成功后切换唯一快照，读取线程只持有不可变编译对象，不持有 mmap 字节。
	if err = s.wal.DB.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte("local_config")).Put([]byte("application_rules"), raw)
	}); err != nil {
		return nil, "application_storage_unavailable", err
	}
	s.state, s.matcher = next, m
	s.commandSHA256 = application.Digest(c)
	raw, err = json.Marshal(next)
	return raw, "", err
}

func (s *ApplicationService) Attribute(raw []byte, observed time.Time) (json.RawMessage, error) {
	s.mu.RLock()
	m, id := s.matcher, s.state.DeploymentID
	s.mu.RUnlock()
	if m == nil {
		return nil, nil
	}
	a, supported, err := m.Attribute(raw, id, observed)
	if !supported {
		// 原始 EVE 的解析错误由原有隔离路径处理，分类不能阻止基础证据入队。
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(a)
	if err != nil || len(encoded) > application.MaxAttributionBytes {
		return nil, application.ErrInput
	}
	return encoded, nil
}
