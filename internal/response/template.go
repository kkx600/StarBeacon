package response

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/kkx600/StarBeacon/internal/contract"
)

const TemplateSchema = "response.template.v1"
const MaxTemplateBytes = 24 * 1024

// Template 描述固定设备接口。写入范围、期限和租约身份仍由现有联动任务控制。
type Template struct {
	SchemaVersion string         `json:"schema_version"`
	Login         *TemplateLogin `json:"login,omitempty"`
	Health        TemplateStep   `json:"health"`
	Block         TemplateStep   `json:"block"`
	Verify        TemplateStep   `json:"verify"`
	Missing       TemplateCheck  `json:"missing"`
	Unblock       TemplateStep   `json:"unblock"`
}

type TemplateLogin struct {
	Path          string `json:"path"`
	UsernameField string `json:"username_field"`
	PasswordField string `json:"password_field"`
	TokenField    string `json:"token_field"`
	TTLSeconds    int    `json:"ttl_seconds"`
}

type TemplateStep struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   []TemplateField `json:"body,omitempty"`
	Accept TemplateCheck   `json:"accept"`
	Values []TemplateField `json:"values,omitempty"`
}

// TemplateField 的 value 为已知请求取值，或所选回执的字段名。
type TemplateField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type TemplateCheck struct {
	Status []int           `json:"status"`
	Field  string          `json:"field,omitempty"`
	Equals json.RawMessage `json:"equals,omitempty"`
}

const templateTask = "{{task_id}}"
const templateRule = "{{lease.rule_id}}"

var templateName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$`)

var templateHealthFields = []string{"device_id", "version", "native_ttl", "separate_leases", "conditional_revoke", "max_ttl_seconds", "observed_at"}
var templateLeaseFields = []string{"device_id", "lease_id", "owner_sha256", "target_ip", "expires_at", "state", "observed_at", "rule_id"}
var templateJSONFields = []string{"schema_version", "login", "username_field", "password_field", "token_field", "ttl_seconds", "health", "block", "verify", "missing", "unblock", "method", "path", "body", "accept", "values", "name", "value", "status", "field", "equals"}

func (v *Template) UnmarshalJSON(raw []byte) error {
	if contract.JSONFields(string(raw), templateJSONFields, MaxTemplateBytes) != nil {
		return ErrInput
	}
	type template Template
	var next template
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&next) != nil || Template(next).Validate() != nil {
		return ErrInput
	}
	for _, check := range []*TemplateCheck{&next.Health.Accept, &next.Block.Accept, &next.Verify.Accept, &next.Missing, &next.Unblock.Accept} {
		if check.Field != "" {
			value, _ := templateScalar(check.Equals)
			check.Equals, _ = json.Marshal(value)
		}
	}
	*v = Template(next)
	return nil
}

func (v Template) Validate() error {
	if v.SchemaVersion != TemplateSchema || v.Login != nil && !v.Login.valid() ||
		!v.Health.valid([]string{http.MethodGet}, "", templateHealthFields, false) ||
		!v.Block.valid([]string{http.MethodPost, http.MethodPut}, "", []string{"rule_id"}, false) ||
		!v.Verify.valid([]string{http.MethodGet}, templateTask, templateLeaseFields, false) ||
		!v.Unblock.valid([]string{http.MethodDelete}, templateRule, nil, true) ||
		!v.Missing.valid(true) || !slices.Equal(v.Missing.Status, []int{404}) || v.Missing.Field == "" {
		return ErrInput
	}
	required := []string{templateTask, "{{target.ip}}", "{{owner_sha256}}", "{{expires_at}}"}
	for _, field := range v.Block.Body {
		if position := slices.Index(required, field.Value); position >= 0 {
			required = slices.Delete(required, position, position+1)
		}
	}
	if len(required) != 0 {
		return ErrInput
	}
	return nil
}

func (v TemplateLogin) valid() bool {
	return validTemplatePath(v.Path, "") && templateName.MatchString(v.UsernameField) && templateName.MatchString(v.PasswordField) &&
		v.UsernameField != v.PasswordField && templateName.MatchString(v.TokenField) && v.TTLSeconds >= 1 && v.TTLSeconds <= 300
}

func validTemplatePath(path, placeholder string) bool {
	if len(path) > 512 || !strings.HasPrefix(path, "/") {
		return false
	}
	count := 0
	for _, part := range strings.Split(path[1:], "/") {
		if placeholder != "" && part == placeholder {
			count++
		} else if !templateName.MatchString(part) {
			return false
		}
	}
	return placeholder == "" || count == 1
}

func (v TemplateStep) valid(methods []string, placeholder string, values []string, allowAbsent bool) bool {
	if !slices.Contains(methods, v.Method) || !validTemplatePath(v.Path, placeholder) || !v.Accept.valid(allowAbsent) ||
		len(v.Values) != len(values) || len(v.Body) > 16 || len(v.Body) != 0 && v.Method != http.MethodPost && v.Method != http.MethodPut {
		return false
	}
	names := map[string]bool{}
	for _, output := range v.Values {
		if !slices.Contains(values, output.Name) || names[output.Name] || !templateName.MatchString(output.Value) {
			return false
		}
		names[output.Name] = true
	}
	names = map[string]bool{}
	for _, input := range v.Body {
		if !templateName.MatchString(input.Name) || names[input.Name] || !validText(input.Value, 256) {
			return false
		}
		if strings.ContainsAny(input.Value, "{}") && !slices.Contains([]string{templateTask, "{{target.ip}}", "{{duration_seconds}}", "{{owner_sha256}}", "{{expires_at}}"}, input.Value) {
			return false
		}
		names[input.Name] = true
	}
	return true
}

func (v TemplateCheck) valid(allowAbsent bool) bool {
	if len(v.Status) < 1 || len(v.Status) > 6 {
		return false
	}
	for i, status := range v.Status {
		if (!(status >= 200 && status < 300) && !(allowAbsent && status == 404)) || slices.Contains(v.Status[:i], status) {
			return false
		}
	}
	if v.Field == "" {
		return len(v.Equals) == 0
	}
	if !templateName.MatchString(v.Field) || len(v.Equals) > 256 {
		return false
	}
	_, valid := templateScalar(v.Equals)
	return valid
}

func (v Template) SHA256() string { return digest(v) }

func templateScalar(raw json.RawMessage) (any, bool) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if !json.Valid(raw) || decoder.Decode(&value) != nil {
		return nil, false
	}
	switch scalar := value.(type) {
	case json.Number:
		number, err := scalar.Int64()
		return number, err == nil
	case string, bool:
		return value, true
	default:
		return nil, false
	}
}
