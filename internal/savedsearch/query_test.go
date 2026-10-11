package savedsearch

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func definition() Definition {
	return Definition{SchemaVersion: Schema, ParserVersion: "1.0", Dataset: "alerts", Mode: "visual", Window: Window{Mode: "relative", Hours: 24}, Terms: Terms{SourceIP: "192.0.2.1", Protocol: "http", Method: "GET", Path: "/api/", Severity: "high"}}
}

func change() Change {
	active := true
	return Change{ID: "query_owned", Name: "业务入口检查", Description: "检查指定入口", Visibility: "personal", Active: &active, Definition: definition()}
}

func TestQueryWindowsDatasetsAndExactFlowIdentity(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 3, 2, 123, time.FixedZone("test", 8*3600))
	for _, hours := range []int{24, 168, 720} {
		d := definition()
		d.Window.Hours = hours
		q, err := d.Query(now)
		if err != nil || q.Start.Location() != time.UTC || q.End.Location() != time.UTC || q.End.Sub(q.Start) != time.Duration(hours)*time.Hour || !q.End.Equal(now) || q.SourceIP != d.Terms.SourceIP || q.Page != 1 || q.PageSize != 20 {
			t.Fatal("相对查询没有在应用时解析固定窗口", err)
		}
	}
	start, end := now.Add(-time.Hour), now
	d := definition()
	d.Window = Window{Mode: "absolute", Start: &start, End: &end}
	q, err := d.Query(now.Add(24 * time.Hour))
	if err != nil || !q.Start.Equal(start) || !q.End.Equal(end) {
		t.Fatal("固定窗口被换成当前时间")
	}
	d.Dataset, d.Mode, d.Terms = "context", "advanced", Terms{EventKind: "tls", SensorID: "sensor_1", RegistrationID: "reg_1", GenerationID: "generation_1", FlowID: "18446744073709551615", Filter: `tls.sni contains "example"`}
	q, err = d.Query(now)
	if err != nil || q.EventKind != "tls" || q.SensorID != d.Terms.SensorID || q.RegistrationID != d.Terms.RegistrationID || q.GenerationID != d.Terms.GenerationID || q.FlowID != d.Terms.FlowID || q.Filter != d.Terms.Filter {
		t.Fatal("来源代次或大整数流标识被丢失或舍入", err)
	}
	for _, mutate := range []func(*Definition){
		func(d *Definition) { d.SchemaVersion = "unknown" }, func(d *Definition) { d.Dataset = "packets" }, func(d *Definition) { d.Mode = "script" }, func(d *Definition) { d.ParserVersion = "" }, func(d *Definition) { d.Mode = "visual"; d.Terms.Filter = "ip.addr" },
		func(d *Definition) { d.Terms.SensorID = "sensor_1" }, func(d *Definition) { d.Mode = "advanced" }, func(d *Definition) { d.Dataset = "context"; d.Terms.Keyword = "rule" }, func(d *Definition) { d.Dataset = "context" },
	} {
		bad := definition()
		mutate(&bad)
		if _, err := bad.Query(now); !errors.Is(err, ErrInput) {
			t.Fatal("不一致的数据集、模式或字段被接受", bad)
		}
	}
	d = definition()
	d.ParserVersion = "2.0"
	if _, err := d.Query(now); !errors.Is(err, ErrVersion) {
		t.Fatal("未知解析器静默执行")
	}
	for _, window := range []Window{{Mode: "unknown"}, {Mode: "relative", Hours: 1}, {Mode: "relative", Hours: 24, Start: &start}, {Mode: "relative", Hours: 24, End: &end}, {Mode: "absolute", Start: &start}, {Mode: "absolute", End: &end}, {Mode: "absolute", Start: &end, End: &start}, {Mode: "absolute", Hours: 24, Start: &start, End: &end}} {
		if _, _, err := window.Bounds(now); err == nil {
			t.Fatal("无效窗口被接受", window)
		}
	}
	for _, invalidNow := range []time.Time{{}, time.Date(1, 1, 1, 1, 0, 0, 0, time.UTC), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if _, _, err := (Window{Mode: "relative", Hours: 24}).Bounds(invalidNow); err == nil {
			t.Fatal("相对窗口越过日期边界")
		}
	}
	far := now.Add(32 * 24 * time.Hour)
	zero := time.Time{}
	tooLate := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, window := range []Window{{Mode: "absolute", Start: &start, End: &far}, {Mode: "absolute", Start: &zero, End: &end}, {Mode: "absolute", Start: &start, End: &tooLate}} {
		if _, _, err := window.Bounds(now); err == nil {
			t.Fatal("固定窗口越界")
		}
	}
}

func TestChangesReceiptsAndRequestBinding(t *testing.T) {
	c := change()
	if c.Validate() != nil || InputHash(c) != InputHash(c) || len(InputHash(c)) != 64 {
		t.Fatal("合法创建或摘要不稳定")
	}
	for _, mutate := range []func(*Change){func(c *Change) { c.ID = "bad/id" }, func(c *Change) { c.ExpectedRevision = -1 }, func(c *Change) { c.ExpectedRevision = MaxRevision }, func(c *Change) { c.Name = " " }, func(c *Change) { c.Name = " 尾部 " }, func(c *Change) { c.Name = strings.Repeat("中", 129) }, func(c *Change) { c.Description = "a\nb" }, func(c *Change) { c.Description = strings.Repeat("中", 1001) }, func(c *Change) { c.Visibility = "public" }, func(c *Change) { c.Active = nil }, func(c *Change) { v := false; c.Active = &v }, func(c *Change) { c.ExpectedGenerationID = "generation_1" }, func(c *Change) { c.ExpectedRevision = 1 }} {
		bad := change()
		mutate(&bad)
		if bad.Validate() == nil || InputHash(bad) == InputHash(c) {
			t.Fatal("无效变更或改变后的原请求摘要被接受")
		}
	}
	c.ExpectedRevision, c.ExpectedGenerationID = 1, "generation_1"
	if c.Validate() != nil {
		t.Fatal("合法编辑被拒绝")
	}
	now := time.Now().UTC()
	r := Record{TenantID: "tenant_1", ID: c.ID, GenerationID: c.ExpectedGenerationID, OwnerID: "user_1", Revision: MaxRevision, Name: c.Name, Description: c.Description, Visibility: c.Visibility, Active: true, Definition: c.Definition, CreatedAt: now, UpdatedAt: now}
	if r.Validate() != nil {
		t.Fatal("最大修订回执被拒绝")
	}
	r.Definition.ParserVersion = "2.0"
	if r.Validate() != nil {
		t.Fatal("未知解析器的记录无法展示兼容性问题")
	}
	r.Definition = c.Definition
	expiry := now.AddDate(0, 0, 180)
	for _, mutate := range []func(*Record){func(r *Record) { r.ID = "bad/id" }, func(r *Record) { r.OwnerID = "" }, func(r *Record) { r.GenerationID = "" }, func(r *Record) { r.Revision = 0 }, func(r *Record) { r.Revision++ }, func(r *Record) { r.CreatedAt = time.Time{} }, func(r *Record) { r.UpdatedAt = now.Add(-time.Second) }, func(r *Record) { r.Active = false }, func(r *Record) { r.ExpiresAt = &expiry }, func(r *Record) { r.Definition.Dataset = "unknown" }} {
		bad := r
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("损坏的回执被接受")
		}
	}
	r.Active, r.ExpiresAt = false, &expiry
	if r.Validate() != nil {
		t.Fatal("停用回执缺少保留期限")
	}
	r.ExpiresAt = &now
	if r.Validate() == nil {
		t.Fatal("停用回执期限没有覆盖更新时间")
	}
}

func TestStrictJSONAndListLimits(t *testing.T) {
	raw, err := json.Marshal(change())
	if err != nil {
		t.Fatal(err)
	}
	var c Change
	if json.Unmarshal(raw, &c) != nil || c.Validate() != nil {
		t.Fatal("合法唯一字段 JSON 无法读取")
	}
	for _, bad := range []string{"null", "[]", `{"id":"a","ID":"b"}`, `{"id":"a","id":"b"}`, `{"id":"a","definition":{"terms":{"protocol":"http","protocol":"tcp"}}}`, `{"id":"a","definition":{"terms":{"tenant_id":"foreign"}}}`, `{"id":false}`, `{"id":"a","definition":{"hours":24}}`, `{"id":"` + strings.Repeat("a", 32768) + `"}`, "{\"id\":\"" + string([]byte{0xff}) + "\"}"} {
		if json.Unmarshal([]byte(bad), &c) == nil {
			t.Fatal("重复字段、无效编码或额外内容进入查询", bad[:min(len(bad), 100)])
		}
	}
	q := ListQuery{Dataset: "alerts", Visibility: "personal", Active: "true", Limit: 20, Keyword: "入口", Cursor: "query_1"}
	if q.Validate() != nil {
		t.Fatal("合法目录请求被拒绝")
	}
	for _, mutate := range []func(*ListQuery){func(q *ListQuery) { q.Limit = 0 }, func(q *ListQuery) { q.Limit = 101 }, func(q *ListQuery) { q.Dataset = "packets" }, func(q *ListQuery) { q.Visibility = "everyone" }, func(q *ListQuery) { q.Active = "yes" }, func(q *ListQuery) { q.Cursor = "bad/id" }, func(q *ListQuery) { q.Keyword = "\n" }, func(q *ListQuery) { q.Keyword = strings.Repeat("中", 129) }} {
		bad := q
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("目录参数越过预算或对象边界")
		}
	}
}
