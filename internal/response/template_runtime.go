package response

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

type templateRuntime struct {
	definition Template
	sha256     string
	mu         sync.Mutex
	bearer     string
	expires    time.Time
}

// NewTemplateClient 绑定一个已经通过调用方资格检查的不可变模板。平台草稿目录不会调用它。
func NewTemplateClient(c Configuration, definition Template) (*Client, error) {
	if c.Validate() != nil {
		return nil, ErrInput
	}
	raw, err := json.Marshal(definition)
	if err != nil {
		return nil, ErrInput
	}
	var frozen Template
	if json.Unmarshal(raw, &frozen) != nil {
		return nil, ErrInput
	}
	client, err := deviceHTTPClient(c)
	if err != nil {
		return nil, err
	}
	c.AllowedTargets = slices.Clone(c.AllowedTargets)
	c.ProtectedTargets = slices.Clone(c.ProtectedTargets)
	return &Client{Config: c, http: client, template: &templateRuntime{definition: frozen, sha256: frozen.SHA256()}}, nil
}

// 设备回执只在本次调用内解析。身份、租约和状态字段经过独立校验后才会返回。
type templateReply map[string]json.RawMessage

func readTemplateReply(raw []byte) (templateReply, error) {
	fields := templateReply{}
	if len(raw) == 0 {
		return fields, nil
	}
	if json.Unmarshal(raw, &fields) != nil || fields == nil || len(fields) > 64 {
		return nil, ErrUnknown
	}
	allowed := make([]string, 0, len(fields))
	for name := range fields {
		if !templateName.MatchString(name) {
			return nil, ErrUnknown
		}
		allowed = append(allowed, name)
	}
	if contract.JSONFields(string(raw), allowed, 16384) != nil {
		return nil, ErrUnknown
	}
	return fields, nil
}

func (v TemplateCheck) matches(status int, fields templateReply) bool {
	if !slices.Contains(v.Status, status) {
		return false
	}
	if v.Field == "" {
		return true
	}
	actual, valid := templateScalar(fields[v.Field])
	expected, _ := templateScalar(v.Equals)
	return valid && actual == expected
}

func (v TemplateStep) selectFields(fields templateReply) templateReply {
	selected := make(templateReply, len(v.Values)+1)
	for _, field := range v.Values {
		selected[field.Name] = fields[field.Value]
	}
	return selected
}

func (v TemplateStep) renderBody(a Action) map[string]any {
	slots := map[string]any{templateTask: a.LeaseID, "{{target.ip}}": a.TargetIP, "{{owner_sha256}}": a.OwnerSHA256,
		"{{expires_at}}": a.ExpiresAt, "{{duration_seconds}}": max(1, int(time.Until(a.ExpiresAt)/time.Second))}
	values := make(map[string]any, len(v.Body))
	for _, field := range v.Body {
		value, known := slots[field.Value]
		if !known {
			value = field.Value
		}
		values[field.Name] = value
	}
	return values
}

func (t *templateRuntime) token(ctx context.Context, c *Client) (string, error) {
	login := t.definition.Login
	if login == nil {
		return c.fileToken()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.bearer != "" && time.Now().Before(t.expires) {
		return t.bearer, nil
	}
	raw, err := ReadPrivateFile(c.Config.TokenFile, 8192)
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err != nil || contract.JSONFields(string(raw), []string{"username", "password"}, 8192) != nil ||
		json.Unmarshal(raw, &credentials) != nil || !validText(credentials.Username, 512) || !validText(credentials.Password, 1024) {
		return "", ErrUnavailable
	}
	body := map[string]string{login.UsernameField: credentials.Username, login.PasswordField: credentials.Password}
	raw, status, err := c.send(ctx, http.MethodPost, login.Path, body, "", "", false)
	if err != nil || status < 200 || status >= 300 {
		return "", ErrUnavailable
	}
	fields, err := readTemplateReply(raw)
	var token string
	if err != nil || json.Unmarshal(fields[login.TokenField], &token) != nil || !validDeviceToken(token) {
		return "", ErrUnavailable
	}
	t.bearer, t.expires = token, time.Now().Add(time.Duration(login.TTLSeconds)*time.Second)
	return token, nil
}

func (t *templateRuntime) request(ctx context.Context, c *Client, method, path string, body any, owner string) (templateReply, int, error) {
	for attempt := 0; attempt < 2; attempt++ {
		token, err := t.token(ctx, c)
		if err != nil {
			return nil, 0, err
		}
		raw, status, err := c.send(ctx, method, path, body, owner, token, true)
		if t.definition.Login != nil && status == http.StatusUnauthorized {
			t.mu.Lock()
			if t.bearer == token {
				t.bearer = ""
			}
			t.mu.Unlock()
			if method == http.MethodGet && attempt == 0 && ctx.Err() == nil {
				continue
			}
		}
		if err != nil {
			return nil, status, err
		}
		fields, err := readTemplateReply(raw)
		return fields, status, err
	}
	return nil, 0, ErrUnavailable
}

func (t *templateRuntime) describe(ctx context.Context, c *Client) (Device, error) {
	step := t.definition.Health
	fields, status, err := t.request(ctx, c, step.Method, step.Path, nil, "")
	var device Device
	if err != nil || !step.Accept.matches(status, fields) {
		return device, ErrUnavailable
	}
	raw, err := json.Marshal(step.selectFields(fields))
	if err != nil || json.Unmarshal(raw, &device) != nil {
		return device, ErrUnavailable
	}
	device.SchemaVersion = DeviceSchema
	return device, device.Validate(c.Config.DeviceID, c.Config.DeviceVersion, time.Now().UTC())
}

func (t *templateRuntime) read(ctx context.Context, c *Client, a Action) (Lease, bool, error) {
	step := t.definition.Verify
	path := strings.Replace(step.Path, templateTask, a.LeaseID, 1)
	fields, status, err := t.request(ctx, c, step.Method, path, nil, "")
	var lease Lease
	if err != nil {
		return lease, false, ErrUnknown
	}
	if t.definition.Missing.matches(status, fields) {
		return lease, true, nil
	}
	if !step.Accept.matches(status, fields) {
		return lease, false, ErrUnknown
	}
	selected := step.selectFields(fields)
	var ruleID string
	if json.Unmarshal(selected["rule_id"], &ruleID) != nil || !contract.ValidID(ruleID) {
		return lease, false, ErrUnknown
	}
	delete(selected, "rule_id")
	raw, err := json.Marshal(selected)
	if err != nil || json.Unmarshal(raw, &lease) != nil {
		return lease, false, ErrUnknown
	}
	lease.SchemaVersion, lease.DeviceRuleID = LeaseSchema, ruleID
	return lease, false, lease.Validate(a, time.Now().UTC())
}

func (t *templateRuntime) block(ctx context.Context, c *Client, a Action) (string, int, error) {
	step := t.definition.Block
	fields, status, err := t.request(ctx, c, step.Method, step.Path, step.renderBody(a), "")
	if err != nil || status >= 400 {
		return "", status, err
	}
	var ruleID string
	if !step.Accept.matches(status, fields) || json.Unmarshal(fields[step.Values[0].Value], &ruleID) != nil || !contract.ValidID(ruleID) {
		return "", status, ErrUnknown
	}
	return ruleID, status, nil
}

func (t *templateRuntime) unblock(ctx context.Context, c *Client, a Action, lease Lease) (int, error) {
	step := t.definition.Unblock
	path := strings.Replace(step.Path, templateRule, lease.DeviceRuleID, 1)
	fields, status, err := t.request(ctx, c, step.Method, path, nil, a.OwnerSHA256)
	if err == nil && status < 400 && !step.Accept.matches(status, fields) {
		err = ErrUnknown
	}
	return status, err
}
