package response

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

const MaxPlugins = 64
const MaxPluginVersions = 32
const MaxPluginDraftBytes = MaxTemplateBytes + 2048

var ErrPluginQuota = errors.New("联动插件或其历史版本已达上限")

type PluginDraft struct {
	ID              string   `json:"id"`
	ExpectedVersion int      `json:"expected_version"`
	Name            string   `json:"name"`
	Device          string   `json:"device"`
	Template        Template `json:"template"`
}

func (v *PluginDraft) UnmarshalJSON(raw []byte) error {
	fields := slices.Concat(templateJSONFields, []string{"id", "expected_version", "device", "template"})
	if contract.JSONFields(string(raw), fields, MaxPluginDraftBytes) != nil {
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
		!validText(v.Name, 128) || !validText(v.Device, 128) || v.Template.Validate() != nil {
		return ErrInput
	}
	return nil
}

func (v PluginDraft) SHA256() string { return digest(v) }

// PluginVersion 的内容及摘要一经创建便固定。状态反映这一版本是否仍为当前草稿。
type PluginVersion struct {
	ID             string    `json:"id"`
	Version        int       `json:"version"`
	Name           string    `json:"name"`
	Device         string    `json:"device"`
	Kind           string    `json:"kind"`
	State          string    `json:"state"`
	Template       Template  `json:"template"`
	TemplateSHA256 string    `json:"template_sha256"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
}

func (v PluginVersion) Validate() error {
	if v.Version < 1 || v.Version > MaxPluginVersions || v.Kind != "template" || v.State != "draft" && v.State != "superseded" ||
		!contract.ValidID(v.CreatedBy) || v.CreatedAt.IsZero() || v.TemplateSHA256 != v.Template.SHA256() {
		return ErrInput
	}
	return (PluginDraft{ID: v.ID, ExpectedVersion: v.Version - 1, Name: v.Name, Device: v.Device, Template: v.Template}).Validate()
}

type PluginPage struct {
	Items     []PluginVersion `json:"items"`
	NextAfter string          `json:"next_after"`
}
