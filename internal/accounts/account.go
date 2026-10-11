// Package accounts 定义租户内用户权限维护，不向调用方返回密码或凭据摘要。
package accounts

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/contract"
)

var ErrInput = errors.New("用户管理参数无效")
var ErrProtected = errors.New("不能停用或降低当前登录账号的权限")
var ErrUnavailable = errors.New("当前账号不具备用户管理权限")
var ErrQuota = errors.New("用户或今日变更额度已用尽")
var ErrExpired = errors.New("用户管理请求已到保留期限")
var ErrPassword = errors.New("当前密码验证失败")
var ErrPasswordRate = errors.New("密码操作过于频繁")

const MaxRevision int64 = 1000000

func ValidUsername(value string) bool {
	return utf8.ValidString(value) && len(value) >= 3 && len(value) <= 64 && strings.TrimSpace(value) == value && strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) < 0
}
func ValidRole(value string) bool { return value == "admin" || value == "viewer" }

func ValidPassword(value string) bool {
	return utf8.ValidString(value) && len(value) >= 12 && len(value) <= 72 && strings.IndexFunc(value, unicode.IsControl) < 0
}

type PasswordChange struct {
	ExpectedRevision int64  `json:"expected_revision"`
	CurrentPassword  string `json:"current_password"`
	NewPassword      string `json:"new_password"`
}

func (c PasswordChange) Validate() error {
	if c.ExpectedRevision < 1 || c.ExpectedRevision >= MaxRevision || !ValidPassword(c.NewPassword) || !utf8.ValidString(c.CurrentPassword) || len(c.CurrentPassword) == 0 || len(c.CurrentPassword) > 72 || strings.IndexFunc(c.CurrentPassword, unicode.IsControl) >= 0 || c.CurrentPassword == c.NewPassword {
		return ErrInput
	}
	return nil
}

type Create struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
	Active   *bool  `json:"active"`
}

func (c Create) Validate() error {
	if !ValidUsername(c.Username) || !ValidRole(c.Role) || c.Active == nil || !utf8.ValidString(c.Password) || len(c.Password) < 12 || len(c.Password) > 72 || strings.IndexFunc(c.Password, unicode.IsControl) >= 0 {
		return ErrInput
	}
	return nil
}

// 幂等材料仅包含公开配置；原密码通过既有 bcrypt 摘要比较，不保存可快速穷举的密码指纹。
func (c Create) PublicInput() []byte {
	raw, _ := json.Marshal(struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		Active   *bool  `json:"active"`
	}{c.Username, c.Role, c.Active})
	return raw
}

type Change struct {
	ExpectedRevision int64  `json:"expected_revision"`
	Role             string `json:"role"`
	Active           *bool  `json:"active"`
}

func (c Change) Validate() error {
	if c.ExpectedRevision < 1 || c.ExpectedRevision >= MaxRevision || !ValidRole(c.Role) || c.Active == nil {
		return ErrInput
	}
	return nil
}

type Record struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	Active    bool      `json:"active"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (r Record) Validate() error {
	if !contract.ValidID(r.ID) || !ValidUsername(r.Username) || !ValidRole(r.Role) || r.Revision < 1 || r.Revision > MaxRevision || r.CreatedAt.IsZero() || r.UpdatedAt.Before(r.CreatedAt) {
		return ErrInput
	}
	return nil
}

type Query struct {
	Role   string
	Active string
	Before string
}

func (q Query) Validate() error {
	if q.Role != "" && !ValidRole(q.Role) || q.Active != "" && q.Active != "true" && q.Active != "false" || q.Before != "" && !contract.ValidID(q.Before) {
		return ErrInput
	}
	return nil
}

type Page struct {
	Items []Record `json:"items"`
	Next  string   `json:"next_cursor"`
}
