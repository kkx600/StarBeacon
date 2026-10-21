package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/probepki"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/syslogdata"
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
		meta := model.RequestMetadataFrom(ctx)
		return appendAudit(tx, LocalAudit{Username: u.Username, Success: &success, Action: "login", RequestID: meta.RequestID, SourceIP: meta.SourceIP, UserAgent: meta.UserAgent, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().AddDate(0, 0, 180)})
	})
}

type NetworkInterface = model.NetworkInterface

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
func LocalHandler(wal *WAL, auth *httpapi.Auth, statePath string, managers ...*TaskManager) http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /api/local/v1/syslog/sources", auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			httpapi.Fail(w, r, 400, "invalid_query", "来源目录不接受额外查询条件")
			return
		}
		items := []syslogdata.Health{}
		if wal.syslogHealth != nil {
			items = wal.syslogHealth()
		}
		httpapi.JSON(w, 200, map[string]any{"items": items})
	}))
	var capture *CaptureSupervisor
	auth.Register(m, "/api/local/v1")
	if len(managers) > 0 && managers[0] != nil {
		capture = managers[0].Capture
		if managers[0].Replay != nil {
			managers[0].Replay.Register(m, auth)
		}
		m.HandleFunc("GET /api/local/v1/tasks", auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
			items, e := managers[0].List()
			if e != nil {
				httpapi.Fail(w, r, 503, "storage_unavailable", "无法读取执行任务")
				return
			}
			httpapi.JSON(w, 200, map[string]any{"items": items})
		}))
		m.HandleFunc("GET /api/local/v1/tasks/{id}", auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
			if !contract.ValidID(r.PathValue("id")) || r.URL.RawQuery != "" {
				httpapi.Fail(w, r, 400, "invalid_task_request", "任务标识无效，详情查询不接受额外条件")
				return
			}
			item, err := managers[0].Task(r.PathValue("id"))
			if errors.Is(err, ErrLocalTaskNotFound) {
				httpapi.Fail(w, r, 404, "not_found", "本地任务不存在或已过留存期")
			} else if err != nil {
				httpapi.Fail(w, r, 503, "storage_unavailable", "无法读取本地任务，请核对设备存储")
			} else {
				httpapi.JSON(w, 200, item)
			}
		}))
	}
	httpapi.Health(m, func(ctx context.Context) error { _, _, e := wal.Stats(); return e })
	registerLocalPackets(m, wal, auth)
	m.HandleFunc("GET /api/local/v1/identity", auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			httpapi.Fail(w, r, 400, "invalid_identity_request", "证书状态查询不接受额外参数")
			return
		}
		out := probepki.LocalStatus{Mode: "static", SensorID: wal.SensorID, RegistrationID: wal.RegistrationID}
		if wal.certificateStatus != nil {
			out = wal.certificateStatus()
		}
		httpapi.JSON(w, 200, out)
	}))
	m.HandleFunc("GET /api/local/v1/health", auth.Require(true, func(w http.ResponseWriter, r *http.Request) { httpapi.JSON(w, 200, wal.Health(r.Context(), statePath)) }))
	m.HandleFunc("GET /api/local/v1/response-config-check", auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			httpapi.Fail(w, r, 400, "invalid_response_config_check", "本地配置核对不接受文件路径或其他参数")
			return
		}
		var service *ResponseService
		out := service.CheckConfiguration()
		if wal.responseConfigCheck != nil {
			out = wal.responseConfigCheck()
		}
		httpapi.JSON(w, 200, out)
	}))
	m.HandleFunc("GET /api/local/v1/network/interfaces", auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		v, e := Interfaces()
		if e != nil {
			httpapi.Fail(w, r, 503, "network_unavailable", "无法读取本机网卡")
			return
		}
		httpapi.JSON(w, 200, map[string]any{"items": v})
	}))
	m.HandleFunc("GET /api/local/v1/capture-config", auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		if capture != nil {
			httpapi.JSON(w, 200, capture.Snapshot())
			return
		}
		v, e := wal.LocalConfig()
		if e != nil {
			httpapi.Fail(w, r, 503, "storage_unavailable", "无法读取采集配置")
			return
		}
		httpapi.JSON(w, 200, v)
	}))
	m.HandleFunc("PUT /api/local/v1/capture-config", auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		var input CaptureSettings
		if e := httpapi.Decode(w, r, &input); e != nil || input.Interfaces == nil || len(input.Interfaces) > 16 || input.Threads < 0 || input.Threads > 64 || len(input.BPFFilter) > 2048 || strings.ContainsAny(input.BPFFilter, "\x00\r\n") {
			httpapi.Fail(w, r, 400, "invalid_config", "采集配置格式无效")
			return
		}
		if capture != nil {
			call, cancel := context.WithTimeout(r.Context(), 25*time.Second)
			defer cancel()
			value, e := capture.Configure(call, input, httpapi.Principal(r).Username, httpapi.RequestID(r))
			if errors.Is(e, ErrCaptureBusy) {
				httpapi.Fail(w, r, 409, "capture_operation_in_progress", "采集配置正在应用，请稍后刷新状态")
			} else if e != nil {
				httpapi.Fail(w, r, 503, "capture_configuration_failed", "采集配置未保存，请核对网卡与本地存储")
			} else {
				httpapi.JSON(w, 200, value)
			}
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
		v, _ := json.Marshal(map[string]any{"interfaces": input.Interfaces, "threads": input.Threads, "bpf_filter": input.BPFFilter, "promiscuous": input.Promiscuous, "managed": false, "status": "not_applied", "updated_at": time.Now().UTC()})
		if e = wal.SaveLocalConfigWithContext(r.Context(), v, httpapi.Principal(r).Username, httpapi.RequestID(r)); e != nil {
			httpapi.Fail(w, r, 503, "storage_unavailable", "无法保存采集配置")
			return
		}
		httpapi.JSON(w, 200, json.RawMessage(v))
	}))
	return m
}
