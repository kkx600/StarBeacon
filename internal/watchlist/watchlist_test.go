package watchlist

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fixture() Definition {
	at := time.Date(2026, 10, 22, 1, 0, 0, 0, time.UTC)
	return Definition{SchemaVersion: Schema, Kind: "protect", MatchType: "ip", Values: []string{"192.0.2.1"}, Sensors: []Sensor{{"probe_owned", "registration_owned"}}, ValidFrom: at, ValidUntil: at.Add(180 * 24 * time.Hour)}
}
func copyDefinition(d Definition) Definition {
	raw, _ := json.Marshal(d)
	var out Definition
	_ = json.Unmarshal(raw, &out)
	return out
}
func TestWatchlistCanonicalValuesAndUnsupportedSemantics(t *testing.T) {
	for _, c := range []struct {
		kind, value string
		valid       bool
	}{
		{"ip", "192.0.2.1", true}, {"ip", "2001:db8::1", true}, {"ip", "::ffff:192.0.2.1", false}, {"ip", "fe80::1%eth0", false}, {"ip", "0.0.0.0", false}, {"ip", "224.0.0.1", false}, {"ip", "2001:0db8::1", false}, {"ip", "192.0.2.01", false}, {"ip", "192.0.2.1 ", false},
		{"cidr", "192.0.2.0/24", true}, {"cidr", "2001:db8::/120", true}, {"cidr", "192.0.2.1/24", false}, {"cidr", "::ffff:192.0.2.0/120", false}, {"cidr", "bad", false},
		{"domain", "example.com", true}, {"domain", "a.example.com", true}, {"domain", "xn--fiqs8s.example", true}, {"domain", "Example.com", false}, {"domain", "example.com.", false}, {"domain", "*.example.com", false}, {"domain", "http://example.com", false}, {"domain", "user@example.com", false}, {"domain", "192.0.2.1", false}, {"domain", "com", false}, {"domain", "co.uk", false}, {"domain", "-a.example", false}, {"domain", "a-.example", false}, {"domain", "a..example", false}, {"domain", strings.Repeat("a", 64) + ".example", false}, {"domain", "中.example", false}, {"domain", "a_.example", false}, {"domain", "a\x00.example", false}, {"regex", ".*", false},
	} {
		if actual := ValidValue(c.kind, c.value); actual != c.valid {
			t.Fatalf("%s %q = %v", c.kind, c.value, actual)
		}
	}
}
func TestWatchlistDefinitionRejectsInvalidScopeAndTime(t *testing.T) {
	good := fixture()
	if good.Validate() != nil {
		t.Fatal("有效范围被拒绝")
	}
	mutations := []func(*Definition){
		func(d *Definition) { d.SchemaVersion = "other" }, func(d *Definition) { d.Kind = "allow" }, func(d *Definition) { d.MatchType = "substring" }, func(d *Definition) { d.Values = nil }, func(d *Definition) { d.Values = make([]string, 65) }, func(d *Definition) { d.Values = []string{"192.0.2.1", "192.0.2.1"} }, func(d *Definition) { d.Sensors = nil }, func(d *Definition) { d.Sensors = make([]Sensor, 33) }, func(d *Definition) { d.Sensors = []Sensor{{"/", "reg"}} }, func(d *Definition) { d.Sensors = []Sensor{{"probe", "/"}} }, func(d *Definition) { d.Sensors = append(d.Sensors, Sensor{"probe_owned", "different_registration"}) },
		func(d *Definition) { d.ValidFrom = time.Time{} }, func(d *Definition) { d.ValidUntil = d.ValidFrom }, func(d *Definition) { d.ValidUntil = d.ValidFrom.Add(3650*24*time.Hour + time.Second) }, func(d *Definition) { d.ValidFrom = d.ValidFrom.Add(time.Nanosecond) }, func(d *Definition) { d.ValidUntil = d.ValidUntil.Add(time.Nanosecond) }, func(d *Definition) { d.ValidFrom = d.ValidFrom.In(time.FixedZone("local", 3600)) }, func(d *Definition) { d.ValidUntil = d.ValidUntil.In(time.FixedZone("local", 3600)) },
	}
	for i, mutate := range mutations {
		d := copyDefinition(good)
		mutate(&d)
		if d.Validate() == nil {
			t.Fatal("无效定义通过", i)
		}
	}
	for _, s := range []string{"", " value", "value ", "a\nb", string([]byte{0xff}), strings.Repeat("文", 129)} {
		if Text(s, 128, true) {
			t.Fatal("非法文本", s)
		}
	}
	if !Text("", 128, false) || !Text("说明", 128, true) {
		t.Fatal("合法文本")
	}
}
func TestWatchlistBroadPrefixesCannotBeEffectiveForPreview(t *testing.T) {
	for _, c := range []struct {
		value string
		broad bool
	}{{"192.0.2.0/24", false}, {"192.0.0.0/16", true}, {"0.0.0.0/0", true}, {"2001:db8::/120", false}, {"2001:db8::/64", true}, {"::/0", true}, {"bad", true}} {
		d := fixture()
		d.MatchType = "cidr"
		d.Values = []string{c.value}
		if d.Broad() != c.broad {
			t.Fatal(c.value)
		}
		if c.value != "bad" {
			active := true
			p, e := (PreviewRequest{d, &active, []Target{}}).Evaluate(d.ValidFrom)
			if e != nil || p.Admissible == c.broad || p.Effective == c.broad || p.ExecutionAuthorized || p.FactDeletionAllowed {
				t.Fatal(c, p, e)
			}
		}
	}
}
func TestWatchlistMatchesExactIdentityTypeAndLabelBoundaries(t *testing.T) {
	d := fixture()
	tgt := Target{"probe_owned", "registration_owned", "ip", "192.0.2.1"}
	if !d.Matches(tgt) {
		t.Fatal("精确地址未命中")
	}
	for _, mutate := range []func(*Target){func(t *Target) { t.SensorID = "foreign_probe" }, func(t *Target) { t.RegistrationID = "new_registration" }, func(t *Target) { t.Value = "192.0.2.2" }, func(t *Target) { t.Type = "domain"; t.Value = "example.com" }, func(t *Target) { t.Type = "regex" }} {
		c := tgt
		mutate(&c)
		if d.Matches(c) {
			t.Fatal("越域或不同类型命中", c)
		}
	}
	d.MatchType = "cidr"
	d.Values = []string{"192.0.2.0/24"}
	if !d.Matches(tgt) {
		t.Fatal("网段未命中")
	}
	tgt.Value = "192.0.3.1"
	if d.Matches(tgt) {
		t.Fatal("网段越界")
	}
	d.MatchType = "domain"
	d.Values = []string{"example.com"}
	tgt.Type = "domain"
	tgt.Value = "example.com"
	if !d.Matches(tgt) {
		t.Fatal("域名未命中")
	}
	for _, v := range []string{"other.example.com", "evilexample.com", "example.com.attacker.test"} {
		tgt.Value = v
		if d.Matches(tgt) {
			t.Fatal("域名被扩展为子串或后缀", v)
		}
	}
	tgt.Type = "ip"
	tgt.Value = "192.0.2.1"
	if d.Matches(tgt) {
		t.Fatal("域名推断成IP")
	}
	d.SchemaVersion = "bad"
	if d.Matches(tgt) {
		t.Fatal("坏范围命中")
	}
}
func TestWatchlistValidityAndMaterialPreviewStaySeparate(t *testing.T) {
	d := fixture()
	active := false
	input := PreviewRequest{d, &active, []Target{{"probe_owned", "registration_owned", "ip", "192.0.2.1"}, {"foreign_probe", "registration_owned", "ip", "192.0.2.1"}}}
	p, e := input.Evaluate(d.ValidFrom)
	if e != nil || !p.Admissible || p.Effective || len(p.Matches) != 2 || !p.Matches[0].Matched || p.Matches[1].Matched || len(p.Reasons) != 1 || p.Reasons[0] != "inactive" {
		t.Fatal(p, e)
	}
	active = true
	for _, c := range []struct {
		at                    time.Time
		effective, admissible bool
		reason                string
	}{{d.ValidFrom.Add(-time.Second), false, true, "not_yet_valid"}, {d.ValidFrom, true, true, ""}, {d.ValidUntil.Add(-time.Nanosecond), true, true, ""}, {d.ValidUntil, false, false, "expired"}} {
		p, e = input.Evaluate(c.at)
		if e != nil || p.Effective != c.effective || p.Admissible != c.admissible || p.DefinitionSHA256 != Digest(d) || p.ScopeSensorCount != 1 || p.ValueCount != 1 || p.ExecutionAuthorized || p.FactDeletionAllowed {
			t.Fatal(c, p, e)
		}
		if c.reason != "" && (len(p.Reasons) != 1 || p.Reasons[0] != c.reason) {
			t.Fatal(p)
		}
	}
	if _, e = input.Evaluate(time.Time{}); e == nil {
		t.Fatal("缺少核对时间")
	}
	for _, mutate := range []func(*PreviewRequest){func(p *PreviewRequest) { p.Active = nil }, func(p *PreviewRequest) { p.Targets = nil }, func(p *PreviewRequest) { p.Targets = make([]Target, 129) }, func(p *PreviewRequest) {
		p.Targets = []Target{{SensorID: "bad", RegistrationID: "reg", Type: "ip", Value: "bad"}}
	}, func(p *PreviewRequest) { p.Definition.SchemaVersion = "bad" }} {
		q := input
		mutate(&q)
		if q.Validate() == nil {
			t.Fatal("无效预览通过")
		}
		if _, e = q.Evaluate(d.ValidFrom); e == nil {
			t.Fatal("无效预览执行")
		}
	}
}
func TestWatchlistRevisionAndChangeAreBoundToCanonicalDefinition(t *testing.T) {
	d := fixture()
	active := true
	c := Change{"list_owned", 0, "保护管理链路", "业务依据", &active, d}
	if c.Validate() != nil {
		t.Fatal("合法变更")
	}
	for _, mutate := range []func(*Change){func(c *Change) { c.ID = "/" }, func(c *Change) { c.ExpectedRevision = -1 }, func(c *Change) { c.ExpectedRevision = MaxRevision }, func(c *Change) { c.Name = "" }, func(c *Change) { c.Description = "" }, func(c *Change) { c.Active = nil }, func(c *Change) { c.Definition.SchemaVersion = "bad" }} {
		v := c
		mutate(&v)
		if v.Validate() == nil {
			t.Fatal("无效变更通过")
		}
	}
	r := Record{"tenant_owned", c.ID, 1, c.Name, c.Description, true, d, Digest(d), "user_owned", d.ValidFrom, d.ValidFrom.Add(180 * 24 * time.Hour)}
	if r.Validate() != nil {
		t.Fatal("合法修订")
	}
	for _, mutate := range []func(*Record){func(r *Record) { r.TenantID = "/" }, func(r *Record) { r.ID = "/" }, func(r *Record) { r.CreatedBy = "/" }, func(r *Record) { r.Revision = 0 }, func(r *Record) { r.Revision = MaxRevision + 1 }, func(r *Record) { r.Name = "" }, func(r *Record) { r.Description = "" }, func(r *Record) { r.DefinitionSHA256 = "bad" }, func(r *Record) { r.CreatedAt = time.Time{} }, func(r *Record) { r.ExpiresAt = r.CreatedAt }, func(r *Record) {
		r.Definition = copyDefinition(r.Definition)
		r.Definition.SchemaVersion = "bad"
		r.DefinitionSHA256 = Digest(r.Definition)
	}, func(r *Record) {
		r.Definition = copyDefinition(r.Definition)
		r.Definition.MatchType = "cidr"
		r.Definition.Values = []string{"0.0.0.0/0"}
		r.DefinitionSHA256 = Digest(r.Definition)
	}} {
		v := r
		mutate(&v)
		if v.Validate() == nil {
			t.Fatal("无效修订通过")
		}
	}
}
func TestWatchlistCursorBindsTenantAndAllFilters(t *testing.T) {
	q := Query{Limit: 20, Keyword: "保护", Active: "true", Kind: "protect"}
	q.Cursor = q.Next("tenant_owned", "list_001")
	if id, e := q.Position("tenant_owned"); e != nil || id != "list_001" {
		t.Fatal(id, e)
	}
	if _, e := q.Position("tenant_other"); e == nil {
		t.Fatal("游标跨租户")
	}
	for _, mutate := range []func(*Query){func(q *Query) { q.Keyword = "other" }, func(q *Query) { q.Active = "false" }, func(q *Query) { q.Kind = "observe" }, func(q *Query) { q.Limit = 21 }, func(q *Query) { q.Cursor = "invalid" }, func(q *Query) {
		q.Cursor = base64.RawURLEncoding.EncodeToString([]byte(`{"after":"list_001","scope":"bad","scope":"bad"}`))
	}, func(q *Query) { q.Cursor = base64.RawURLEncoding.EncodeToString([]byte(`{"after":"/","scope":"bad"}`)) }} {
		v := q
		mutate(&v)
		if _, e := v.Position("tenant_owned"); e == nil {
			t.Fatal("失配游标通过", v)
		}
	}
	for _, mutate := range []func(*Query){func(q *Query) { q.Limit = 0 }, func(q *Query) { q.Limit = 101 }, func(q *Query) { q.Keyword = " " }, func(q *Query) { q.Active = "yes" }, func(q *Query) { q.Kind = "allow" }, func(q *Query) { q.Cursor = strings.Repeat("a", 2049) }} {
		v := Query{Limit: 20}
		mutate(&v)
		if v.Validate() == nil {
			t.Fatal("无效查询通过")
		}
	}
	q = Query{Limit: 20}
	if v, e := q.Position("tenant_owned"); e != nil || v != "" {
		t.Fatal(v, e)
	}
	if _, e := q.Position("/"); e == nil {
		t.Fatal("非法租户")
	}
}
