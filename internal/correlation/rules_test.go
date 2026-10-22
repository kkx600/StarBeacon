package correlation

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRuleAndRequestRejectUnsupportedSemanticsAndInvalidRanges(t *testing.T) {
	r, q, now := fixture()
	for _, mutate := range []func(*Definition){
		func(d *Definition) { d.SchemaVersion = "future" }, func(d *Definition) { d.Dataset = "logs" }, func(d *Definition) { d.Filter = "not a filter" }, func(d *Definition) { d.Filter = "\n" }, func(d *Definition) { d.GroupBy = "asset.id" }, func(d *Definition) { d.Metric = "sequence" }, func(d *Definition) { d.DistinctField = "source.ip" }, func(d *Definition) { d.WindowSeconds = 14 }, func(d *Definition) { d.WindowSeconds = 3601 }, func(d *Definition) { d.Threshold = 1 }, func(d *Definition) { d.Threshold = MaxFacts + 1 }, func(d *Definition) { d.Metric = "distinct"; d.DistinctField = "" }, func(d *Definition) { d.Metric = "distinct"; d.DistinctField = d.GroupBy },
	} {
		d := r.Definition
		mutate(&d)
		if !errors.Is(d.Validate(), ErrInput) {
			t.Fatalf("允许不支持的规则：%+v", d)
		}
	}
	for _, mutate := range []func(*Request){func(q *Request) { q.ExpectedRevision = 0 }, func(q *Request) { q.ExpectedRevision = MaxRevision + 1 }, func(q *Request) { q.Start = time.Time{} }, func(q *Request) { q.End = q.Start }, func(q *Request) { q.Start = q.End.Add(-time.Hour - time.Second) }, func(q *Request) { q.End = now.Add(time.Second) }, func(q *Request) { q.Start = q.Start.Add(time.Nanosecond) }, func(q *Request) { q.End = q.End.Add(-time.Nanosecond) }} {
		v := q
		mutate(&v)
		if !errors.Is(v.Validate(now), ErrInput) {
			t.Fatalf("允许无效范围：%+v", v)
		}
	}
	active := true
	c := Change{ID: r.ID, Name: r.Name, Description: "说明", Active: &active, Definition: r.Definition}
	if c.Validate() != nil || r.Validate() != nil || q.Validate(now) != nil {
		t.Fatal("合法规则被拒绝")
	}
	for _, mutate := range []func(*Change){func(v *Change) { v.ID = "" }, func(v *Change) { v.ExpectedRevision = -1 }, func(v *Change) { v.ExpectedRevision = MaxRevision }, func(v *Change) { v.Name = " " }, func(v *Change) { v.Description = strings.Repeat("字", 1001) }, func(v *Change) { v.Active = nil }, func(v *Change) { v.Definition.Dataset = "unknown" }} {
		v := c
		mutate(&v)
		if v.Validate() == nil {
			t.Fatal("允许无效变更", v)
		}
	}
	for _, mutate := range []func(*Record){func(v *Record) { v.TenantID = "" }, func(v *Record) { v.CreatedBy = "" }, func(v *Record) { v.ID = "" }, func(v *Record) { v.Revision = 0 }, func(v *Record) { v.Revision = MaxRevision + 1 }, func(v *Record) { v.Name = "" }, func(v *Record) { v.Description = "\n" }, func(v *Record) { v.DefinitionSHA256 = "" }, func(v *Record) { v.CreatedAt = time.Time{} }, func(v *Record) { v.ExpiresAt = v.CreatedAt }, func(v *Record) { v.Definition.GroupBy = "invalid"; v.DefinitionSHA256 = Digest(v.Definition) }} {
		v := r
		mutate(&v)
		if !errors.Is(v.Validate(), ErrSource) {
			t.Fatal("允许无效修订", v)
		}
	}
	if Text("\xff", 10, false) || Text(" x", 10, true) || Text("字字", 1, true) || Text("", 10, true) {
		t.Fatal("文本边界无效")
	}
}

func TestRulePaginationBindsTenantFiltersAndLimit(t *testing.T) {
	q := Query{Keyword: "同源", Active: "true", Limit: 20}
	if p, e := q.Position("tenant_test"); e != nil || p != "" {
		t.Fatal(p, e)
	}
	q.Cursor = q.Next("tenant_test", "rule_last")
	if p, e := q.Position("tenant_test"); e != nil || p != "rule_last" {
		t.Fatal(p, e)
	}
	if _, e := q.Position("other_tenant"); !errors.Is(e, ErrInput) {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Query){func(v *Query) { v.Keyword = "other" }, func(v *Query) { v.Active = "false" }, func(v *Query) { v.Limit = 21 }, func(v *Query) { v.Cursor = "bad" }, func(v *Query) { v.Cursor += "=" }, func(v *Query) { v.Cursor = strings.Repeat("a", 2049) }, func(v *Query) { v.Keyword = "\n" }, func(v *Query) { v.Active = "yes" }, func(v *Query) { v.Limit = 0 }, func(v *Query) { v.Limit = 101 }} {
		v := q
		mutate(&v)
		if _, e := v.Position("tenant_test"); !errors.Is(e, ErrInput) {
			t.Fatal("允许无效游标", v, e)
		}
	}
	q.Cursor = q.Next("tenant_test", "bad/id")
	if _, e := q.Position("tenant_test"); !errors.Is(e, ErrInput) {
		t.Fatal(e)
	}
	if _, e := (Query{Limit: 20}).Position("bad/id"); !errors.Is(e, ErrInput) {
		t.Fatal(e)
	}
}
