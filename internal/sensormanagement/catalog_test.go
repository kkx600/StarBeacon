package sensormanagement

import (
	"strings"
	"testing"
	"time"
)

func TestManagementInputsPreserveIdentityAndTextBoundaries(t *testing.T) {
	active := true
	group := GroupChange{ID: "sg_owned", Name: "办公站点", Description: "镜像口探针", Active: &active}
	if group.Validate() != nil {
		t.Fatal("合法分组被拒绝")
	}
	for _, change := range []func(*GroupChange){func(c *GroupChange) { c.ID = "ungrouped" }, func(c *GroupChange) { c.ID = "foreign/id" }, func(c *GroupChange) { c.Name = " " }, func(c *GroupChange) { c.Name = " 办公" }, func(c *GroupChange) { c.Name = strings.Repeat("中", 129) }, func(c *GroupChange) { c.Description = strings.Repeat("中", 1001) }, func(c *GroupChange) { c.Description = "a\x00b" }, func(c *GroupChange) { c.Description = string([]byte{255}) }, func(c *GroupChange) { c.Active = nil }, func(c *GroupChange) { f := false; c.Active = &f }, func(c *GroupChange) { c.ExpectedRevision = -1 }, func(c *GroupChange) { c.ExpectedRevision = MaxRevision }} {
		bad := group
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("非法分组输入被接受")
		}
	}
	metadata := MetadataChange{ExpectedRevision: 1, RegistrationID: "reg_owned", Name: "边界探针", GroupID: "sg_owned", Site: "机房 A", Description: "旁路镜像"}
	if metadata.Validate() != nil {
		t.Fatal("合法管理信息被拒绝")
	}
	for _, change := range []func(*MetadataChange){func(c *MetadataChange) { c.ExpectedRevision = 0 }, func(c *MetadataChange) { c.ExpectedRevision = MaxRevision }, func(c *MetadataChange) { c.RegistrationID = "" }, func(c *MetadataChange) { c.Name = "\tprobe" }, func(c *MetadataChange) { c.GroupID = "a/b" }, func(c *MetadataChange) { c.Site = strings.Repeat("中", 129) }, func(c *MetadataChange) { c.Description = "a\nb" }} {
		bad := metadata
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("非法元数据输入被接受")
		}
	}
	metadata.GroupID = ""
	metadata.Site = ""
	metadata.Description = ""
	if metadata.Validate() != nil {
		t.Fatal("无法清除可选信息")
	}
	if InputHash("probe_a", metadata) == InputHash("probe_b", metadata) {
		t.Fatal("摘要没有绑定对象")
	}
	changed := metadata
	changed.RegistrationID = "reg_changed"
	if InputHash("probe_a", metadata) == InputHash("probe_a", changed) {
		t.Fatal("摘要没有绑定注册代次")
	}
}

func TestDirectoryQueriesAreBoundedAndTyped(t *testing.T) {
	for _, groups := range []bool{false, true} {
		base := Query{Limit: 20}
		if base.Validate(groups) != nil {
			t.Fatal("默认查询被拒绝")
		}
		for _, bad := range []Query{{Limit: 0}, {Limit: 101}, {Limit: 20, Cursor: "a/b"}, {Limit: 20, Keyword: strings.Repeat("中", 129)}, {Limit: 20, Keyword: "a\nb"}, {Limit: 20, Active: "yes"}} {
			if bad.Validate(groups) == nil {
				t.Fatal("非法查询被接受")
			}
		}
	}
	for _, q := range []Query{{Limit: 1, Status: "online", GroupID: "ungrouped"}, {Limit: 100, Status: "offline", GroupID: "sg_owned"}, {Limit: 20, Status: "disabled"}} {
		if q.Validate(false) != nil {
			t.Fatal("合法状态被拒绝")
		}
		if q.Validate(true) == nil {
			t.Fatal("分组接收了探针筛选")
		}
	}
	for _, q := range []Query{{Limit: 20, Status: "active"}, {Limit: 20, GroupID: "a/b"}, {Limit: 20, Active: "true"}} {
		if q.Validate(false) == nil {
			t.Fatal("探针接收非法类型筛选")
		}
	}
	if (Query{Limit: 20, Active: "false"}).Validate(true) != nil {
		t.Fatal("无法检索停用分组")
	}
}

func TestReceiptsHavePublicIdentityRevisionAndTime(t *testing.T) {
	now := time.Now().UTC()
	g := Group{ID: "sg_owned", Revision: 1, Name: "办公", CreatedAt: now, UpdatedAt: now}
	if g.Validate() != nil {
		t.Fatal("合法分组回执被拒绝")
	}
	for _, change := range []func(*Group){func(v *Group) { v.ID = "" }, func(v *Group) { v.Revision = 0 }, func(v *Group) { v.Revision = MaxRevision + 1 }, func(v *Group) { v.Name = "" }, func(v *Group) { v.Description = "a\nb" }, func(v *Group) { v.MemberCount = -1 }, func(v *Group) { v.CreatedAt = time.Time{} }, func(v *Group) { v.UpdatedAt = time.Time{} }} {
		bad := g
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("损坏分组回执被接受")
		}
	}
	m := Metadata{ID: "probe_owned", RegistrationID: "reg_owned", Revision: MaxRevision, Name: "探针", UpdatedAt: now}
	if m.Validate() != nil {
		t.Fatal("最大修订合法回执被拒绝")
	}
	for _, change := range []func(*Metadata){func(v *Metadata) { v.ID = "" }, func(v *Metadata) { v.Revision = 0 }, func(v *Metadata) { v.Revision = MaxRevision + 1 }, func(v *Metadata) { v.UpdatedAt = time.Time{} }, func(v *Metadata) { v.RegistrationID = "" }} {
		bad := m
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("损坏管理信息回执被接受")
		}
	}
}
