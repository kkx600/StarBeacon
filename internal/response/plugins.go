package response

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/contract"
)

const MaxPlugins = 64
const MaxPluginVersions = 32
const MaxPluginDraftBytes = 128 * 1024

var ErrPluginQuota = errors.New("联动插件或其历史版本已达上限")

type PluginDraft struct {
	ID              string          `json:"id"`
	ExpectedVersion int             `json:"expected_version"`
	Name            string          `json:"name"`
	Device          string          `json:"device"`
	Template        Template        `json:"template,omitzero"`
	Script          *PluginScript   `json:"script,omitempty"`
	Examples        []PluginExample `json:"examples,omitempty"`
}

type PluginScript struct {
	Source  string   `json:"source"`
	Entries []string `json:"entries"`
}

// 样例正文使用 JSON 字符串，设备字段可自由映射，外层结构仍须严格解码。
type PluginExample struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Query    string `json:"query,omitempty"`
	Request  string `json:"request,omitempty"`
	Status   int    `json:"status"`
	Response string `json:"response,omitempty"`
}

var pluginEntries = []string{"health", "pull_alerts", "block", "verify", "unblock", "isolate", "release"}
var pluginDraftFields = slices.Concat(templateJSONFields, []string{"id", "expected_version", "device", "template", "script", "source", "entries", "examples", "query", "request", "response"})

func (s *PluginScript) Validate() error {
	if s == nil || len(s.Source) == 0 || len(s.Source) > 32*1024 || !utf8.ValidString(s.Source) || bytes.IndexByte([]byte(s.Source), 0) >= 0 || len(s.Entries) == 0 || len(s.Entries) > len(pluginEntries) {
		return ErrInput
	}
	for i, entry := range s.Entries {
		if !slices.Contains(pluginEntries, entry) || slices.Contains(s.Entries[:i], entry) {
			return ErrInput
		}
	}
	has := func(entry string) bool { return slices.Contains(s.Entries, entry) }
	if has("block") != has("unblock") || has("isolate") != has("release") || (has("block") || has("isolate")) && !has("verify") {
		return ErrInput
	}
	return nil
}

func (s *PluginScript) SHA256() string { return digest(s) }

func (e PluginExample) valid() bool {
	switch e.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete:
	default:
		return false
	}
	parsed, err := url.ParseRequestURI(e.Path)
	if err != nil || e.Path == "" || len(e.Path) > 512 || parsed.IsAbs() || parsed.Host != "" || parsed.Path != e.Path || path.Clean(e.Path) != e.Path {
		return false
	}
	for _, raw := range []string{e.Request, e.Response} {
		if len(raw) > 16*1024 || raw != "" && !json.Valid([]byte(raw)) {
			return false
		}
	}
	values, err := url.ParseQuery(e.Query)
	return err == nil && len(e.Query) <= 2048 && values.Encode() == e.Query &&
		e.Status >= 200 && e.Status <= 599 && (e.Status < 300 || e.Status >= 400)
}

func (v *PluginDraft) UnmarshalJSON(raw []byte) error {
	if contract.JSONFields(string(raw), pluginDraftFields, MaxPluginDraftBytes) != nil {
		return ErrInput
	}
	var version struct {
		Expected *int `json:"expected_version"`
	}
	if json.Unmarshal(raw, &version) != nil || version.Expected == nil {
		return ErrInput
	}
	type draft PluginDraft
	var next draft
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&next) != nil || PluginDraft(next).Validate() != nil {
		return ErrInput
	}
	*v = PluginDraft(next)
	return nil
}

func (v PluginDraft) Validate() error {
	if !contract.ValidID(v.ID) || v.ExpectedVersion < 0 || v.ExpectedVersion > MaxPluginVersions ||
		!validText(v.Name, 128) || !validText(v.Device, 128) || len(v.Examples) > 48 {
		return ErrInput
	}
	if v.Script != nil {
		if v.Template.SchemaVersion != "" || v.Script.Validate() != nil {
			return ErrInput
		}
	} else if v.Template.Validate() != nil {
		return ErrInput
	}
	for _, example := range v.Examples {
		if !example.valid() {
			return ErrInput
		}
	}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > MaxPluginDraftBytes {
		return ErrInput
	}
	return nil
}

func (v PluginDraft) SHA256() string { return digest(v) }

// PluginVersion 的内容及摘要一经创建便固定。状态反映这一版本是否仍为当前草稿。
type PluginVersion struct {
	ID             string          `json:"id"`
	Version        int             `json:"version"`
	Name           string          `json:"name"`
	Device         string          `json:"device"`
	Kind           string          `json:"kind"`
	State          string          `json:"state"`
	Template       Template        `json:"template,omitzero"`
	TemplateSHA256 string          `json:"template_sha256,omitempty"`
	Script         *PluginScript   `json:"script,omitempty"`
	ScriptSHA256   string          `json:"script_sha256,omitempty"`
	Examples       []PluginExample `json:"examples,omitempty"`
	CreatedBy      string          `json:"created_by"`
	CreatedAt      time.Time       `json:"created_at"`
}

func (v PluginVersion) Validate() error {
	if v.Version < 1 || v.Version > MaxPluginVersions || v.State != "draft" && v.State != "superseded" ||
		!contract.ValidID(v.CreatedBy) || v.CreatedAt.IsZero() {
		return ErrInput
	}
	if v.Script != nil {
		if v.Kind != "script" || v.ScriptSHA256 != v.Script.SHA256() || v.TemplateSHA256 != "" {
			return ErrInput
		}
	} else if v.Kind != "template" || v.TemplateSHA256 != v.Template.SHA256() || v.ScriptSHA256 != "" {
		return ErrInput
	}
	return v.draft().Validate()
}

func (v PluginVersion) draft() PluginDraft {
	return PluginDraft{ID: v.ID, ExpectedVersion: v.Version - 1, Name: v.Name, Device: v.Device, Template: v.Template, Script: v.Script, Examples: v.Examples}
}

func (v PluginVersion) DefinitionSHA256() string { return v.draft().SHA256() }

func (v PluginVersion) Entries() []string {
	if v.Script != nil {
		return slices.Clone(v.Script.Entries)
	}
	return v.Template.entries()
}

func (v PluginVersion) Supports(entry string) bool { return slices.Contains(v.Entries(), entry) }

func (v PluginVersion) TrialMode() string {
	switch {
	case v.Supports("block") && v.Supports("isolate"):
		return "block_and_isolate"
	case v.Supports("block"):
		return "block"
	case v.Supports("isolate"):
		return "isolate"
	default:
		return "read_only"
	}
}

type PluginPage struct {
	Items       []PluginVersion    `json:"items"`
	NextAfter   string             `json:"next_after"`
	Deployments []PluginDeployment `json:"deployments,omitempty"`
	Executions  []PluginExecution  `json:"executions,omitempty"`
}
