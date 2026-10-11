package accounts

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAccountInputsUseUTF8BytesAndExplicitState(t *testing.T) {
	active := true
	for _, name := range []string{"值班员", "user_01", strings.Repeat("a", 64)} {
		if !ValidUsername(name) {
			t.Fatalf("合法账号被拒绝：%q", name)
		}
	}
	for _, name := range []string{"", "ab", " user", "user ", "a\x00bc", "a\u200dbc", string([]byte{0xff}), strings.Repeat("中", 22)} {
		if ValidUsername(name) {
			t.Fatalf("非法账号被接受：%q", name)
		}
	}
	c := Create{Username: "值班员", Password: "owned-pass-123456", Role: "viewer", Active: &active}
	if c.Validate() != nil {
		t.Fatal("合法创建失败")
	}
	var public map[string]any
	if json.Unmarshal(c.PublicInput(), &public) != nil || len(public) != 3 || bytes.Contains(c.PublicInput(), []byte(c.Password)) {
		t.Fatal("公开材料包含密码或遗漏配置")
	}
	for _, field := range []string{"username", "role", "active", "short_password", "long_password", "control_password", "invalid_utf8"} {
		v := c
		switch field {
		case "username":
			v.Username = "ab"
		case "role":
			v.Role = "owner"
		case "active":
			v.Active = nil
		case "short_password":
			v.Password = "short"
		case "long_password":
			v.Password = strings.Repeat("中", 25)
		case "control_password":
			v.Password = "owned-pass\n1234"
		case "invalid_utf8":
			v.Password = string([]byte{0xff}) + strings.Repeat("x", 12)
		}
		if v.Validate() != ErrInput {
			t.Fatalf("非法字段通过：%s", field)
		}
	}
	for _, password := range []string{strings.Repeat("a", 12), strings.Repeat("中", 24)} {
		v := c
		v.Password = password
		if v.Validate() != nil {
			t.Fatal("密码合法字节边界失败")
		}
	}
	change := Change{ExpectedRevision: 1, Role: "admin", Active: &active}
	if change.Validate() != nil {
		t.Fatal("合法变更失败")
	}
	for _, revision := range []int64{0, MaxRevision, -1} {
		v := change
		v.ExpectedRevision = revision
		if v.Validate() != ErrInput {
			t.Fatal("非法修订通过")
		}
	}
	change.ExpectedRevision = MaxRevision - 1
	if change.Validate() != nil {
		t.Fatal("最大可变更修订失败")
	}
	change.Role = "owner"
	if change.Validate() != ErrInput {
		t.Fatal("非法角色通过")
	}
	change.Role = "viewer"
	change.Active = nil
	if change.Validate() != ErrInput {
		t.Fatal("缺失状态通过")
	}
}

func TestAccountPublicRecordAndQueryBoundaries(t *testing.T) {
	now := time.Now().UTC()
	r := Record{ID: "user_owned", Username: "值班员", Role: "admin", Active: true, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if r.Validate() != nil {
		t.Fatal("合法记录失败")
	}
	for _, field := range []string{"id", "name", "role", "zero_revision", "large_revision", "created", "updated"} {
		v := r
		switch field {
		case "id":
			v.ID = "bad/id"
		case "name":
			v.Username = "ab"
		case "role":
			v.Role = "owner"
		case "zero_revision":
			v.Revision = 0
		case "large_revision":
			v.Revision = MaxRevision + 1
		case "created":
			v.CreatedAt = time.Time{}
		case "updated":
			v.UpdatedAt = now.Add(-time.Second)
		}
		if v.Validate() != ErrInput {
			t.Fatalf("异常记录通过：%s", field)
		}
	}
	for _, q := range []Query{{}, {Role: "admin", Active: "true", Before: "user_owned"}, {Role: "viewer", Active: "false"}} {
		if q.Validate() != nil {
			t.Fatal("合法筛选失败")
		}
	}
	for _, q := range []Query{{Role: "owner"}, {Active: "yes"}, {Before: "bad/id"}} {
		if q.Validate() != ErrInput {
			t.Fatal("非法筛选通过")
		}
	}
}
