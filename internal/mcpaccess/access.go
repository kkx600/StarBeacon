// Package mcpaccess 定义服务身份的显式租户授权，不接受调用方指定租户或继承管理员权限。
package mcpaccess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
)

var ErrDenied = errors.New("MCP 服务身份未获授权或已失效")
var ErrConflict = errors.New("MCP 身份绑定已存在或修订发生变化")
var ErrQuota = errors.New("MCP 调用超出当前窗口预算")

var Scopes = []string{"alerts:read", "assets:read", "sensors:read", "traffic:read"}

type Binding struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Issuer            string    `json:"issuer"`
	Subject           string    `json:"subject"`
	OAuthClientID     string    `json:"oauth_client_id"`
	Scopes            []string  `json:"scopes"`
	Enabled           bool      `json:"enabled"`
	ExpiresAt         time.Time `json:"expires_at"`
	RequestsPerMinute int       `json:"requests_per_minute"`
	OwnerID           string    `json:"owner_id"`
	Revision          int64     `json:"revision"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type Change struct {
	ID                string    `json:"id"`
	ExpectedRevision  int64     `json:"expected_revision"`
	Name              string    `json:"name"`
	Subject           string    `json:"subject"`
	OAuthClientID     string    `json:"oauth_client_id"`
	Scopes            []string  `json:"scopes"`
	Enabled           bool      `json:"enabled"`
	ExpiresAt         time.Time `json:"expires_at"`
	RequestsPerMinute int       `json:"requests_per_minute"`
}

type Identity struct {
	Principal     model.Principal
	Binding       Binding
	GrantedScopes []string
}

func ValidText(value string, max int) bool {
	if value == "" || !utf8.ValidString(value) || len(value) > max || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return false
		}
	}
	return true
}

func (c *Change) Validate(now time.Time) error {
	if !contract.ValidID(c.ID) || c.ExpectedRevision < 0 || !ValidText(c.Name, 240) || !ValidText(c.Subject, 512) || !ValidText(c.OAuthClientID, 512) || c.RequestsPerMinute < 1 || c.RequestsPerMinute > 120 || !c.ExpiresAt.After(now) || c.ExpiresAt.After(now.Add(3650*24*time.Hour)) || len(c.Scopes) < 1 || len(c.Scopes) > len(Scopes) {
		return errors.New("身份、有效期或调用预算无效；有效期最多 3650 天，预算为每分钟 1–120 次")
	}
	seen := map[string]bool{}
	for _, scope := range c.Scopes {
		if !slices.Contains(Scopes, scope) || seen[scope] {
			return errors.New("服务身份权限范围无效或重复")
		}
		seen[scope] = true
	}
	c.ExpiresAt = c.ExpiresAt.UTC()
	slices.Sort(c.Scopes)
	return nil
}

// TupleHash 对 issuer、sub 与 OAuth 客户端共同绑定，防止同一用户的其他应用继承权限。
func TupleHash(issuer, subject, clientID string) string {
	encoded, _ := json.Marshal([]string{issuer, subject, clientID})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func Intersect(granted, allowed []string) []string {
	result := []string{}
	for _, scope := range allowed {
		if slices.Contains(granted, scope) && !slices.Contains(result, scope) {
			result = append(result, scope)
		}
	}
	return result
}
