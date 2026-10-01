package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

type localSession struct {
	Principal model.Principal
	Expiry    time.Time
}
type LocalIdentity struct {
	WAL      *WAL
	Hash     []byte
	mu       sync.Mutex
	sessions map[string]localSession
}

func NewLocalIdentity(w *WAL, password string) (*LocalIdentity, error) {
	hash, e := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if e != nil {
		return nil, e
	}
	return &LocalIdentity{WAL: w, Hash: hash, sessions: map[string]localSession{}}, nil
}
func (l *LocalIdentity) Password(ctx context.Context, name string) (model.Principal, string, error) {
	if name != "admin" {
		return model.Principal{}, "", model.ErrUnauthenticated
	}
	return model.Principal{ID: "local_admin", TenantID: l.WAL.TenantID, Username: "admin", Role: "admin"}, string(l.Hash), nil
}
func (l *LocalIdentity) CreateSession(ctx context.Context, u model.Principal) (string, string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, v := range l.sessions {
		if time.Now().After(v.Expiry) {
			delete(l.sessions, k)
		}
	}
	if len(l.sessions) >= 32 {
		return "", "", fmt.Errorf("本地会话数量超限")
	}
	token := store.Token()
	u.CSRF = store.Token()
	l.sessions[store.Hash(token)] = localSession{u, time.Now().Add(8 * time.Hour)}
	return token, u.CSRF, nil
}
func (l *LocalIdentity) Session(ctx context.Context, token string) (model.Principal, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	v, ok := l.sessions[store.Hash(token)]
	if !ok || time.Now().After(v.Expiry) {
		return model.Principal{}, model.ErrUnauthenticated
	}
	return v.Principal, nil
}
func (l *LocalIdentity) DeleteSession(ctx context.Context, token string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.sessions, store.Hash(token))
	return nil
}
func (l *LocalIdentity) LoginAudit(ctx context.Context, u model.Principal, success bool) error {
	return l.WAL.DB.Update(func(tx *bolt.Tx) error {
		return appendAudit(tx, LocalAudit{Username: u.Username, Success: &success, Action: "login", CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().AddDate(0, 0, 180)})
	})
}

type NetworkInterface struct {
	Name      string   `json:"name"`
	Index     int      `json:"index"`
	MAC       string   `json:"mac"`
	MTU       int      `json:"mtu"`
	Up        bool     `json:"up"`
	Loopback  bool     `json:"loopback"`
	Addresses []string `json:"addresses"`
}

func Interfaces() ([]NetworkInterface, error) {
	native, e := net.Interfaces()
	if e != nil {
		return nil, e
	}
	out := make([]NetworkInterface, 0, len(native))
	for _, v := range native {
		row := NetworkInterface{Name: v.Name, Index: v.Index, MAC: v.HardwareAddr.String(), MTU: v.MTU, Up: v.Flags&net.FlagUp != 0, Loopback: v.Flags&net.FlagLoopback != 0, Addresses: []string{}}
		ips, e := v.Addrs()
		if e != nil {
			return nil, e
		}
		for _, ip := range ips {
			row.Addresses = append(row.Addresses, ip.String())
		}
		out = append(out, row)
	}
	return out, nil
}
func LocalHandler(wal *WAL, auth *httpapi.Auth, statePath string) http.Handler {
	m := http.NewServeMux()
	auth.Register(m, "/api/local/v1")
	httpapi.Health(m, func(ctx context.Context) error { _, _, e := wal.Stats(); return e })
	m.HandleFunc("GET /api/local/v1/health", auth.Require(true, func(w http.ResponseWriter, r *http.Request) { httpapi.JSON(w, 200, wal.Health(r.Context(), statePath)) }))
	m.HandleFunc("GET /api/local/v1/network/interfaces", auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		v, e := Interfaces()
		if e != nil {
			httpapi.Fail(w, r, 503, "network_unavailable", "无法读取本机网卡")
			return
		}
		httpapi.JSON(w, 200, map[string]any{"items": v})
	}))
	m.HandleFunc("GET /api/local/v1/capture-config", auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		v, e := wal.LocalConfig()
		if e != nil {
			httpapi.Fail(w, r, 503, "storage_unavailable", "无法读取采集配置")
			return
		}
		httpapi.JSON(w, 200, v)
	}))
	m.HandleFunc("PUT /api/local/v1/capture-config", auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Interfaces []string `json:"interfaces"`
		}
		if e := httpapi.Decode(w, r, &input); e != nil || input.Interfaces == nil || len(input.Interfaces) > 16 {
			httpapi.Fail(w, r, 400, "invalid_config", "采集配置格式无效")
			return
		}
		interfaces, e := Interfaces()
		if e != nil {
			httpapi.Fail(w, r, 503, "network_unavailable", "无法读取本机网卡")
			return
		}
		available := map[string]bool{}
		for _, v := range interfaces {
			available[v.Name] = v.Up && !v.Loopback
		}
		seen := map[string]bool{}
		for _, name := range input.Interfaces {
			if !available[name] || seen[name] {
				httpapi.Fail(w, r, 400, "invalid_interface", "请选择不重复且已启用的非回环网卡")
				return
			}
			seen[name] = true
		}
		v, _ := json.Marshal(map[string]any{"interfaces": input.Interfaces, "status": "not_applied", "updated_at": time.Now().UTC()})
		if e = wal.SaveLocalConfig(v, httpapi.Principal(r).Username, httpapi.RequestID(r)); e != nil {
			httpapi.Fail(w, r, 503, "storage_unavailable", "无法保存采集配置")
			return
		}
		httpapi.JSON(w, 200, json.RawMessage(v))
	}))
	return m
}
