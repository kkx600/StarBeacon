// Package responsescript 在隔离进程中解释设备插件，由采集器审核并代理设备请求。
package responsescript

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/privatefile"
)

const (
	maxSource     = 32 * 1024
	maxData       = 16 * 1024
	maxFrame      = 256 * 1024
	maxSteps      = 100_000
	maxCalls      = 96
	maxRequests   = 8
	requestsInMin = 30
	maxStateKeys  = 32
	maxLogBytes   = 512
	maxEvents     = 32
	runTime       = 5 * time.Second
	tokenTTL      = 30 * time.Minute
)

type Code string

const (
	OK          Code = "ok"
	Input       Code = "input"
	Scope       Code = "scope"
	Credential  Code = "credential"
	Steps       Code = "steps"
	Timeout     Code = "timeout"
	Size        Code = "size"
	Concurrency Code = "concurrency"
	Rate        Code = "rate"
	Isolation   Code = "isolation"
	DeviceError Code = "device"
	ScriptError Code = "script"
)

func (c Code) Error() string { return string(c) }

type Event struct {
	Code    Code   `json:"code"`
	Method  string `json:"method,omitempty"`
	Route   string `json:"route,omitempty"`
	Status  int    `json:"status,omitempty"`
	Level   string `json:"level,omitempty"`
	Message string `json:"message,omitempty"`
}

type Result struct {
	Code       Code            `json:"code"`
	Value      json.RawMessage `json:"value,omitempty"`
	Events     []Event         `json:"events,omitempty"`
	DurationMS int64           `json:"duration_ms"`
	Readback   *Readback       `json:"-"`
}

// Readback 来自采集器的实际 HTTPS 响应，不由脚本返回值填写。
type Readback struct {
	Status int
	Fields map[string]json.RawMessage
}

// Config 将不可变源码绑定到采集器本地核准的设备、接口和凭据。
type Config struct {
	Source   string
	Origin   string
	DeviceIP netip.Addr
	Roots    *x509.CertPool
	Routes   []Route
	Login    *Login
	Secrets  map[string]Secret
}

type Route struct {
	Entry  string   `json:"entry"`
	Method string   `json:"method"`
	Path   string   `json:"path"`
	Query  []string `json:"query,omitempty"`
	// 空值允许普通字符串，名称限制为对应凭据引用，token 代表本设备的登录令牌。
	Headers map[string]string `json:"headers,omitempty"`
	// 只把列出的 JSON 对象字段交给脚本。
	Fields []string `json:"fields,omitempty"`
}

type Login struct {
	Path       string            `json:"path"`
	Secrets    map[string]string `json:"secrets"`
	TokenField string            `json:"token_field"`
}

type Secret struct {
	File string `json:"file"`
	// HMAC 专用文件必须包含 32 字节随机密钥，不能作为 HTTP 凭据使用。
	HMAC bool `json:"hmac,omitempty"`
}

type Invocation struct {
	Entry           string
	TaskID          string
	RuleID          string
	Args            []json.RawMessage
	Write           *ApprovedWrite
	ReadbackPath    string
	OwnerSHA256     string
	ExpiresAt       string
	DurationSeconds int
}

// ApprovedWrite 由可信任务端提供，一次调用只允许发出一次完全匹配的变更请求。
type ApprovedWrite struct {
	Method      string
	Path        string
	Body        json.RawMessage
	OwnerSHA256 string
}

type credential struct {
	data string
	hmac bool
}

type stateItem struct {
	value wireValue
	until time.Time
}

type Runtime struct {
	cfg       Config
	binary    string
	client    *http.Client
	secrets   map[string]credential
	active    chan struct{}
	state     map[string]stateItem
	requests  []time.Time
	token     string
	tokenID   uint64
	tokenEnds time.Time
	now       func() time.Time
}

var workerSlots = make(chan struct{}, 4)

func New(cfg Config, workerBinary string) (*Runtime, error) {
	return makeRuntime(cfg, workerBinary, nil)
}

// NewSimulation 只使用调用端提供的样例传输与合成凭据。
func NewSimulation(cfg Config, workerBinary string, replay http.RoundTripper) (*Runtime, error) {
	if replay == nil {
		return nil, Input
	}
	return makeRuntime(cfg, workerBinary, replay)
}

func makeRuntime(cfg Config, workerBinary string, replay http.RoundTripper) (*Runtime, error) {
	if len(cfg.Source) == 0 || len(cfg.Source) > maxSource || len(cfg.Routes) > 32 || len(cfg.Secrets) > 16 {
		return nil, Input
	}
	if workerBinary == "" {
		var err error
		workerBinary, err = os.Executable()
		if err != nil {
			return nil, Isolation
		}
	}
	if !filepath.IsAbs(workerBinary) {
		return nil, Isolation
	}
	policy := outbound.Policy{}
	origin, err := policy.URL(cfg.Origin)
	if err != nil || origin.String() != cfg.Origin || origin.Path != "" || origin.RawQuery != "" || origin.ForceQuery || strings.Contains(cfg.Origin, "#") {
		return nil, Scope
	}
	if literal, err := netip.ParseAddr(origin.Hostname()); err == nil {
		if cfg.DeviceIP.IsValid() && cfg.DeviceIP != literal {
			return nil, Scope
		}
		cfg.DeviceIP = literal
	}
	ip := cfg.DeviceIP
	if !ip.IsValid() || ip.Is4In6() || ip.Zone() != "" {
		return nil, Scope
	}
	policy.PinnedIP = ip
	policy.PrivateNetworks = []netip.Prefix{netip.PrefixFrom(ip, ip.BitLen())}
	if !policy.Allowed(ip) || cfg.Roots == nil && replay == nil {
		return nil, Scope
	}
	var client *http.Client
	if replay == nil {
		policy.Roots = cfg.Roots.Clone()
		client = policy.HTTPClient()
	} else {
		client = &http.Client{Transport: replay, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	r := &Runtime{
		cfg: cfg, binary: workerBinary, client: client,
		secrets: make(map[string]credential, len(cfg.Secrets)), active: make(chan struct{}, 1),
		state: make(map[string]stateItem), now: time.Now,
	}
	for name, spec := range cfg.Secrets {
		var data []byte
		var err error
		if replay == nil {
			data, err = privatefile.Read(spec.File, maxLogBytes)
		} else if spec.HMAC {
			sum := sha256.Sum256([]byte("fixture-signing-" + name))
			data = sum[:]
		} else {
			data = []byte("fixture-secret-" + name)
		}
		if err != nil || !identifier(name) || name == "token" || spec.HMAC && len(data) != 32 || !spec.HMAC && !printable(string(data)) {
			return nil, Credential
		}
		r.secrets[name] = credential{data: string(data), hmac: spec.HMAC}
	}
	if err := r.freezeRoutes(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Runtime) Close() { r.client.CloseIdleConnections() }

func entryKnown(entry string) bool {
	switch entry {
	case "health", "pull_alerts", "verify", "block", "unblock", "isolate", "release":
		return true
	}
	return false
}

func mutation(entry string) bool {
	return entry == "block" || entry == "unblock" || entry == "isolate" || entry == "release"
}

func verbKnown(method string) bool {
	return method == http.MethodGet || method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete
}

func identifier(value string) bool {
	if len(value) == 0 || len(value) > 64 || value == "." || value == ".." {
		return false
	}
	for _, c := range value {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-", c) {
			return false
		}
	}
	return true
}

func routePath(value string) bool {
	if len(value) > 256 || !strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return false
	}
	if value == "/" {
		return true
	}
	for segment := range strings.SplitSeq(value[1:], "/") {
		if !identifier(segment) {
			return false
		}
	}
	return true
}

func printable(s string) bool {
	return len(s) > 0 && len(s) <= maxLogBytes && !strings.ContainsFunc(s, func(c rune) bool { return c < 32 || c == 127 })
}

func (r *Runtime) Run(ctx context.Context, in Invocation) (result Result) {
	started := time.Now()
	defer func() {
		result.DurationMS = time.Since(started).Milliseconds()
		if result.Code != OK {
			result.Events = append(result.Events, Event{Code: result.Code})
		}
		entry := ""
		if entryKnown(in.Entry) {
			entry = in.Entry
		}
		slog.Info("联动脚本执行结束", "entry", entry, "code", result.Code, "duration_ms", result.DurationMS)
	}()
	if !entryKnown(in.Entry) || in.TaskID != "" && !identifier(in.TaskID) || in.RuleID != "" && !identifier(in.RuleID) ||
		len(in.Args) > 4 || in.ReadbackPath != "" && !routePath(in.ReadbackPath) ||
		in.DurationSeconds < 0 || in.DurationSeconds > 3600 || len(in.ExpiresAt) > 40 || !ownerHash(in.OwnerSHA256) {
		return Result{Code: Input}
	}
	select {
	case workerSlots <- struct{}{}:
		defer func() { <-workerSlots }()
	default:
		return Result{Code: Concurrency}
	}
	select {
	case r.active <- struct{}{}:
		defer func() { <-r.active }()
	default:
		return Result{Code: Concurrency}
	}
	call, cancel := context.WithTimeout(ctx, runTime)
	defer cancel()
	now := r.now()
	b := &broker{r: r, in: in, state: make(map[string]stateItem, len(r.state))}
	for key, item := range r.state {
		if now.Before(item.until) {
			b.state[key] = item
		}
	}
	total := 0
	for _, arg := range in.Args {
		total += len(arg)
		if total > maxData {
			return Result{Code: Size}
		}
		if _, code := r.decode(arg); code != OK {
			return Result{Code: code}
		}
	}
	if in.Write != nil {
		grant := *in.Write
		if !mutation(in.Entry) || !verbKnown(grant.Method) || grant.Method == http.MethodGet || !routePath(grant.Path) || !ownerHash(grant.OwnerSHA256) {
			return Result{Code: Scope}
		}
		if len(grant.Body) > 0 {
			value, code := r.decode(grant.Body)
			if code != OK {
				return Result{Code: code}
			}
			grant.Body, _ = json.Marshal(value)
		}
		b.in.Write = &grant
	}
	start := program{Source: r.cfg.Source, Entry: in.Entry, Args: in.Args, Origin: r.cfg.Origin, TaskID: in.TaskID, Now: now.UTC().Format(time.RFC3339Nano),
		OwnerSHA256: in.OwnerSHA256, ExpiresAt: in.ExpiresAt, DurationSeconds: in.DurationSeconds}
	result.Code, result.Value = r.launch(call, start, b)
	result.Events = b.events
	if result.Code == OK {
		r.state = b.state
		result.Readback = b.readback
	}
	return result
}

func ownerHash(s string) bool {
	if s == "" {
		return true
	}
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == s
}

func (r *Runtime) deviceURL(p string, query map[string]string) string {
	values := make(url.Values, len(query))
	for key, value := range query {
		values.Set(key, value)
	}
	result := r.cfg.Origin + p
	if len(values) > 0 {
		result += "?" + values.Encode()
	}
	return result
}

func deviceCode(ctx context.Context, err error) Code {
	if ctx.Err() != nil {
		return Timeout
	}
	if errors.Is(err, outbound.ErrTarget) {
		return Scope
	}
	return DeviceError
}
