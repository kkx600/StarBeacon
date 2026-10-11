// Package sensormanagement 定义探针管理归类，不改变证书身份、采集配置或执行权限。
package sensormanagement

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/contract"
)

const MaxGroups = 512
const MaxRevision = 1000000

var (
	ErrInput    = errors.New("探针管理参数无效")
	ErrOccupied = errors.New("探针分组仍有成员")
	ErrQuota    = errors.New("探针分组或管理操作数量已达上限")
	ErrInactive = errors.New("探针分组已停用")
)

func validText(v string, max int, required bool) bool {
	return utf8.ValidString(v) && len([]rune(v)) <= max && (!required || strings.TrimSpace(v) != "") && v == strings.TrimSpace(v) && strings.IndexFunc(v, unicode.IsControl) < 0
}

type GroupChange struct {
	ID               string `json:"id"`
	ExpectedRevision int64  `json:"expected_revision"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	Active           *bool  `json:"active"`
}

func (c GroupChange) Validate() error {
	if !contract.ValidID(c.ID) || c.ID == "ungrouped" || c.ExpectedRevision < 0 || c.ExpectedRevision >= MaxRevision || !validText(c.Name, 128, true) || !validText(c.Description, 1000, false) || c.Active == nil || (c.ExpectedRevision == 0 && !*c.Active) {
		return ErrInput
	}
	return nil
}

type Group struct {
	ID          string    `json:"id"`
	Revision    int64     `json:"revision"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Active      bool      `json:"active"`
	MemberCount int64     `json:"member_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (g Group) Validate() error {
	if !contract.ValidID(g.ID) || g.ID == "ungrouped" || g.Revision < 1 || g.Revision > MaxRevision || !validText(g.Name, 128, true) || !validText(g.Description, 1000, false) || g.MemberCount < 0 || g.CreatedAt.IsZero() || g.UpdatedAt.IsZero() {
		return ErrInput
	}
	return nil
}

type GroupPage struct {
	Items      []Group `json:"items"`
	NextCursor string  `json:"next_cursor"`
}

type MetadataChange struct {
	ExpectedRevision int64  `json:"expected_revision"`
	RegistrationID   string `json:"registration_id"`
	Name             string `json:"name"`
	GroupID          string `json:"group_id"`
	Site             string `json:"site"`
	Description      string `json:"description"`
}

func (c MetadataChange) Validate() error {
	if c.ExpectedRevision < 1 || c.ExpectedRevision >= MaxRevision || !contract.ValidID(c.RegistrationID) || !validText(c.Name, 128, true) || (c.GroupID != "" && !contract.ValidID(c.GroupID)) || !validText(c.Site, 128, false) || !validText(c.Description, 1000, false) {
		return ErrInput
	}
	return nil
}

type Metadata struct {
	ID             string    `json:"id"`
	Revision       int64     `json:"revision"`
	RegistrationID string    `json:"registration_id"`
	Name           string    `json:"name"`
	GroupID        string    `json:"group_id"`
	Site           string    `json:"site"`
	Description    string    `json:"description"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func (m Metadata) Validate() error {
	if !contract.ValidID(m.ID) || m.UpdatedAt.IsZero() {
		return ErrInput
	}
	// 回执可达到最大修订；该值不能再次作为可写输入。
	if m.Revision < 1 || m.Revision > MaxRevision {
		return ErrInput
	}
	c := MetadataChange{ExpectedRevision: 1, RegistrationID: m.RegistrationID, Name: m.Name, GroupID: m.GroupID, Site: m.Site, Description: m.Description}
	return c.Validate()
}

type Query struct {
	Cursor  string
	Keyword string
	Active  string
	GroupID string
	Status  string
	Limit   int
}

func (q Query) Validate(groups bool) error {
	if q.Limit < 1 || q.Limit > 100 || (q.Cursor != "" && !contract.ValidID(q.Cursor)) || !validText(q.Keyword, 128, false) || (q.Active != "" && q.Active != "true" && q.Active != "false") {
		return ErrInput
	}
	if groups && (q.GroupID != "" || q.Status != "") {
		return ErrInput
	}
	if !groups && (q.Active != "" || q.GroupID != "" && q.GroupID != "ungrouped" && !contract.ValidID(q.GroupID) || q.Status != "" && q.Status != "online" && q.Status != "offline" && q.Status != "disabled") {
		return ErrInput
	}
	return nil
}

// 摘要同时绑定对象和输入，原请求键不能变更目标、注册代次或期望修订。
func InputHash(id string, input any) string {
	raw, _ := json.Marshal(struct {
		ID    string `json:"id"`
		Input any    `json:"input"`
	}{id, input})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
