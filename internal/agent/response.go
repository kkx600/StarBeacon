package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/response"
	bolt "go.etcd.io/bbolt"
)

type responseRecord struct {
	Action      response.Action  `json:"action"`
	Result      *response.Result `json:"result,omitempty"`
	Status      string           `json:"status"`
	CheckedAt   time.Time        `json:"checked_at"`
	RetainUntil time.Time        `json:"retain_until"`
}
type ResponseService struct {
	WAL          *WAL
	mu           sync.Mutex
	healthMu     sync.RWMutex
	clients      map[string]*response.Client
	health       map[string]response.Health
	retention    int
	management   []string
	addresses    func() ([]net.Addr, error)
	resolve      func(context.Context, string, string) ([]netip.Addr, error)
	configPath   string
	configSHA256 string
}

func NewResponseService(w *WAL, path string, management ...string) (*ResponseService, error) {
	file, err := response.LoadFile(path)
	if err != nil {
		return nil, err
	}
	s := &ResponseService{WAL: w, clients: map[string]*response.Client{}, health: map[string]response.Health{}, retention: file.RetentionDays, management: management, addresses: net.InterfaceAddrs, resolve: net.DefaultResolver.LookupNetIP}
	s.configPath, s.configSHA256 = path, file.SHA256()
	for _, config := range file.Connectors {
		client, err := response.NewClient(config)
		if err != nil {
			s.Close()
			return nil, err
		}
		s.clients[config.ID] = client
		s.health[config.ID] = response.Health{ConnectorID: config.ID, DeviceID: config.DeviceID, Version: config.DeviceVersion, ConfigSHA256: config.SHA256(), Status: "unverified", MaxTTLSeconds: config.MaxTTLSeconds}
	}
	err = w.DB.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucketIfNotExists([]byte("response_leases")); return err })
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
func (s *ResponseService) Close() {
	for _, c := range s.clients {
		c.Close()
	}
}

func (s *ResponseService) CheckConfiguration() response.ConfigCheck {
	out := response.ConfigCheck{SchemaVersion: "response.config-check.v1", State: "not_configured", CheckedAt: time.Now().UTC()}
	if s == nil {
		return out
	}
	out.RunningCount = len(s.clients)
	file, err := response.LoadFile(s.configPath)
	if err != nil {
		out.State = "invalid"
		return out
	}
	out.FileCount = len(file.Connectors)
	out.State = "current"
	if file.SHA256() != s.configSHA256 {
		out.State = "restart_required"
	}
	return out
}
func (s *ResponseService) Health() []response.Health {
	s.healthMu.RLock()
	defer s.healthMu.RUnlock()
	out := make([]response.Health, 0, len(s.health))
	for _, h := range s.health {
		out = append(out, h)
	}
	slices.SortFunc(out, func(a, b response.Health) int {
		if a.ConnectorID < b.ConnectorID {
			return -1
		}
		if a.ConnectorID > b.ConnectorID {
			return 1
		}
		return 0
	})
	return out
}
func (s *ResponseService) check(ctx context.Context, id string) {
	client := s.clients[id]
	s.healthMu.RLock()
	h := s.health[id]
	s.healthMu.RUnlock()
	h.Status = "unavailable"
	if device, err := client.Describe(ctx); err == nil {
		h.Status = "ready"
		h.MaxTTLSeconds = min(client.Config.MaxTTLSeconds, device.MaxTTLSeconds)
	}
	h.ObservedAt = time.Now().UTC()
	s.healthMu.Lock()
	s.health[id] = h
	s.healthMu.Unlock()
}
func (s *ResponseService) Execute(ctx context.Context, c control.Command) (json.RawMessage, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := response.ReadAction(c.Payload)
	if err != nil || a.OwnerSHA256 != response.Owner(c.TenantID, c.SensorID, c.RegistrationID, a.LeaseID) || c.TenantID != s.WAL.TenantID || c.SensorID != s.WAL.SensorID || c.RegistrationID != s.WAL.RegistrationID || c.Kind == "response.block" && a.LeaseID != c.ID {
		return nil, "response_scope_invalid", response.ErrInput
	}
	client := s.clients[a.ConnectorID]
	if client == nil || client.Config.SHA256() != a.ConfigSHA256 {
		return nil, "response_device_unavailable", response.ErrUnavailable
	}
	if c.Kind == "response.block" && !client.Config.Allows(a.TargetIP, int(a.ExpiresAt.Sub(a.RequestedAt)/time.Second)) {
		return nil, "response_scope_invalid", response.ErrInput
	}
	if c.Kind == "response.block" {
		if err := s.protectManagement(ctx, a.TargetIP); err != nil {
			return nil, response.Code(err), err
		}
	}
	var record responseRecord
	err = s.WAL.DB.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("response_leases"))
		if bucket == nil {
			return errors.New("联动租约目录不可用")
		}
		previous := bucket.Get([]byte(a.LeaseID))
		if previous != nil {
			if json.Unmarshal(previous, &record) != nil || s.validRecord(a.LeaseID, record) != nil || record.Action != a {
				return response.ErrInput
			}
			return nil
		}
		if c.Kind != "response.block" {
			return response.ErrUnavailable
		}
		if bucket.Stats().KeyN >= 1024 {
			return errors.New("联动历史容量已满，请核对留存与回读")
		}
		record = responseRecord{Action: a, Status: "pending", RetainUntil: a.RequestedAt.AddDate(0, 0, s.retention)}
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(a.LeaseID), raw)
	})
	if err != nil {
		return nil, "local_storage_unavailable", err
	}
	// 副作用之前的意图已落盘；重启维护只读取状态，不补发历史封禁。
	result, executeErr := client.Execute(ctx, c.Kind, a)
	record.CheckedAt = time.Now().UTC()
	record.Status = "unknown"
	if executeErr == nil {
		record.Status = result.Observation.State
		record.Result = &result
	}
	err = s.WAL.DB.Update(func(tx *bolt.Tx) error {
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		bucket := tx.Bucket([]byte("response_leases"))
		if bucket == nil {
			return errors.New("联动租约目录不可用")
		}
		return bucket.Put([]byte(a.LeaseID), raw)
	})
	if err != nil {
		return nil, "result_unknown", err
	}
	if executeErr != nil {
		return nil, response.Code(executeErr), executeErr
	}
	raw, err := json.Marshal(result)
	return raw, "", err
}
func (s *ResponseService) maintain(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var selected []responseRecord
	now := time.Now().UTC()
	err := s.WAL.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("response_leases"))
		if b == nil {
			return errors.New("联动租约目录不可用")
		}
		cursor := b.Cursor()
		removed := 0
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var r responseRecord
			if json.Unmarshal(v, &r) != nil || s.validRecord(string(k), r) != nil {
				return errors.New("联动租约目录损坏")
			}
			if !r.RetainUntil.After(now) && r.Action.ExpiresAt.Before(now) && removed < 16 {
				if err := cursor.Delete(); err != nil {
					return err
				}
				removed++
				continue
			}
			if r.Status != "revoked" && r.Status != "expired" && now.Sub(r.CheckedAt) >= 10*time.Second {
				selected = append(selected, r)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	// 最久未核对的记录优先，每轮最多两项；不按 key 固定抽样导致后续租约饥饿。
	slices.SortFunc(selected, func(a, b responseRecord) int { return a.CheckedAt.Compare(b.CheckedAt) })
	for _, record := range selected[:min(2, len(selected))] {
		client := s.clients[record.Action.ConnectorID]
		if client == nil || client.Config.SHA256() != record.Action.ConfigSHA256 {
			continue
		}
		call, cancel := context.WithTimeout(ctx, 10*time.Second)
		result, readErr := client.Execute(call, "response.read", record.Action)
		cancel()
		record.CheckedAt = time.Now().UTC()
		record.Status = "unknown"
		if readErr == nil {
			record.Status = result.Observation.State
			record.Result = &result
		}
		if err = s.WAL.DB.Update(func(tx *bolt.Tx) error {
			raw, err := json.Marshal(record)
			if err != nil {
				return err
			}
			bucket := tx.Bucket([]byte("response_leases"))
			if bucket == nil {
				return errors.New("联动租约目录不可用")
			}
			return bucket.Put([]byte(record.Action.LeaseID), raw)
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *ResponseService) validRecord(key string, r responseRecord) error {
	if r.Action.Validate() != nil || key != r.Action.LeaseID || r.Action.OwnerSHA256 != response.Owner(s.WAL.TenantID, s.WAL.SensorID, s.WAL.RegistrationID, key) || !r.RetainUntil.After(r.Action.RequestedAt) {
		return response.ErrInput
	}
	switch r.Status {
	case "pending", "unknown", "active", "expired", "revoked":
	default:
		return response.ErrInput
	}
	return nil
}

// 管理通道和本机地址不参与封禁；地址目录或名称解析失败时停止此动作，不影响采集。
func (s *ResponseService) protectManagement(ctx context.Context, target string) error {
	ip, err := netip.ParseAddr(target)
	if err != nil {
		return response.ErrInput
	}
	addresses, err := s.addresses()
	if err != nil {
		return response.ErrUnavailable
	}
	for _, address := range addresses {
		p, err := netip.ParsePrefix(address.String())
		if err != nil {
			return response.ErrUnavailable
		}
		if p.Addr().Unmap() == ip {
			return response.ErrInput
		}
	}
	seen := map[string]bool{}
	for _, endpoint := range s.management {
		host, _, err := net.SplitHostPort(endpoint)
		if err != nil || host == "" {
			return response.ErrUnavailable
		}
		if seen[host] {
			continue
		}
		seen[host] = true
		if address, err := netip.ParseAddr(host); err == nil {
			if address.Unmap() == ip {
				return response.ErrInput
			}
			continue
		}
		call, cancel := context.WithTimeout(ctx, 2*time.Second)
		resolved, err := s.resolve(call, "ip", host)
		cancel()
		if err != nil || len(resolved) == 0 {
			return response.ErrUnavailable
		}
		for _, address := range resolved {
			if address.Unmap() == ip {
				return response.ErrInput
			}
		}
	}
	return nil
}
func (s *ResponseService) Run(ctx context.Context) error {
	keys := make([]string, 0, len(s.clients))
	for id := range s.clients {
		keys = append(keys, id)
	}
	next := 0
	for ctx.Err() == nil {
		call, cancel := context.WithTimeout(ctx, 10*time.Second)
		s.check(call, keys[next])
		cancel()
		next = (next + 1) % len(keys)
		if err := s.maintain(ctx); err != nil {
			s.WAL.setFailure("response_storage_unavailable", true)
		} else {
			s.WAL.setFailure("response_storage_unavailable", false)
		}
		if !pause(ctx, 3*time.Second) {
			return nil
		}
	}
	return nil
}
