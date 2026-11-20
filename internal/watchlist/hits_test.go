package watchlist

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/model"
)

const testTenant = "tenant_owned"

func observeFixture() Definition {
	d := fixture()
	d.Kind = "observe"
	return d
}

// hitRecord 构造一份当前修订的观察名单；创建时间固定早于告警接收时间。
func hitRecord(d Definition) Record {
	r := Record{TenantID: testTenant, ID: "list_owned", Revision: 3, Name: "出口可疑地址", Description: "关注出口地址", Active: true, Definition: d, CreatedBy: "user_owned", CreatedAt: d.ValidFrom}
	r.DefinitionSHA256 = Digest(d)
	r.ExpiresAt = r.CreatedAt.Add(180 * 24 * time.Hour)
	return r
}

// alertFixture 构造一条命中名单首个值的告警，观测时间处于业务有效期内。
func alertFixture(d Definition) model.Alert {
	at := d.ValidFrom.Add(time.Hour)
	var a model.Alert
	a.TenantID = testTenant
	a.EventID = "alert_owned"
	a.RawSHA256 = strings.Repeat("a", 64)
	a.SensorID = d.Sensors[0].SensorID
	a.RegistrationID = d.Sensors[0].RegistrationID
	a.Timestamp, a.ObservedAt, a.ReceivedAt = at, at, at
	a.Event.Kind = "alert"
	a.Source.IP = "192.0.2.1"
	a.Destination.IP = "198.51.100.7"
	a.Severity = "high"
	a.Rule.ID = "rule_owned"
	a.Rule.Name = "出口异常连接"
	return a
}

func TestCanonicalHostNormalizesAndRejectsNonDomains(t *testing.T) {
	for _, c := range []struct {
		in, out string
		ok      bool
	}{
		{"example.com", "example.com", true},
		{"EXAMPLE.com", "example.com", true},
		{"example.com.", "example.com", true},
		{"Service.Example.COM.", "service.example.com", true},
		{"xn--fiqs8s.example", "xn--fiqs8s.example", true},
		{"中.example", "xn--fiq.example", true},
		{"", "", false},
		{".", "", false},
		{"192.0.2.1", "", false},
		{"2001:db8::1", "", false},
		{"*.example.com", "", false},
		{"http://example.com", "", false},
		{"example.com/path", "", false},
		{"user@example.com", "", false},
		{"com", "", false},
		{"co.uk", "", false},
		{"-a.example", "", false},
		{"a-.example", "", false},
		{"a..example", "", false},
		{"example.com:443", "", false},
		{strings.Repeat("a", 254), "", false},
		{strings.Repeat("a", 64) + ".example", "", false},
	} {
		host, ok := CanonicalHost(c.in)
		if ok != c.ok || host != c.out {
			t.Fatalf("CanonicalHost(%q) = %q,%v，期望 %q,%v", c.in, host, ok, c.out, c.ok)
		}
	}
}

func TestAlertTargetsExtractsOnlyRequestedFieldsWithoutDNSExpansion(t *testing.T) {
	d := observeFixture()
	a := alertFixture(d)
	a.HTTP.Hostname = "Service.Example.COM"
	a.Event.Original = `{"tls":{"sni":"tls.example.com"},"dns":{"version":3,"queries":[{"rrname":"q1.example.com","rrtype":"A"},{"rrname":"q1.example.com","rrtype":"AAAA"},{"rrname":"192.0.2.1","rrtype":"A"}]}}`

	plain := AlertTargets(a, false)
	if len(plain) != 2 || plain[0] != (Observed{FieldSourceIP, "192.0.2.1"}) || plain[1] != (Observed{FieldDestinationIP, "198.51.100.7"}) {
		t.Fatalf("未要求域名时应只提取两个 IP，实际 %+v", plain)
	}

	full := AlertTargets(a, true)
	expected := []Observed{
		{FieldSourceIP, "192.0.2.1"},
		{FieldDestinationIP, "198.51.100.7"},
		{FieldHTTPHost, "service.example.com"},
		{FieldTLSSNI, "tls.example.com"},
		{FieldDNSName, "q1.example.com"},
	}
	if len(full) != len(expected) {
		t.Fatalf("域名提取结果数量不符：%+v", full)
	}
	for i, want := range expected {
		if full[i] != want {
			t.Fatalf("第 %d 项为 %+v，期望 %+v", i, full[i], want)
		}
	}
}

func TestAlertTargetsSkipsMissingAndInvalidValues(t *testing.T) {
	d := observeFixture()
	a := alertFixture(d)
	a.Source.IP = ""
	a.Destination.IP = "not-an-ip"
	a.HTTP.Hostname = "*.example.com"
	a.Event.Original = `{"tls":{"sni":"192.0.2.1"}}`
	if got := AlertTargets(a, true); len(got) != 0 {
		t.Fatalf("无效值不应进入候选：%+v", got)
	}

	// flow 时间戳非法时 Parse 返回 unavailable，TLS 与 DNS 不可用，但 HTTP 主机名仍来自结构化字段。
	broken := alertFixture(d)
	broken.HTTP.Hostname = "service.example.com"
	broken.Event.Original = `{"flow":{"start":"not-a-time"},"tls":{"sni":"tls.example.com"}}`
	got := AlertTargets(broken, true)
	for _, o := range got {
		if o.Field == FieldTLSSNI {
			t.Fatal("原始载荷不可解析时不应产出 TLS SNI")
		}
	}
	if len(got) != 3 || got[2] != (Observed{FieldHTTPHost, "service.example.com"}) {
		t.Fatalf("结构化主机名应保留：%+v", got)
	}
}

func TestRecordAlertMatchesRequiresCurrentRevisionAndScope(t *testing.T) {
	d := observeFixture()
	base := hitRecord(d)
	alert := alertFixture(d)
	targets := AlertTargets(alert, false)

	if got := base.AlertMatches(alert, targets); len(got) != 1 || got[0] != (Observed{FieldSourceIP, "192.0.2.1"}) {
		t.Fatalf("有效名单应命中源 IP：%+v", got)
	}

	for _, c := range []struct {
		name  string
		mutge func(*Record, *model.Alert)
	}{
		{"保护名单不参与命中", func(r *Record, _ *model.Alert) { r.Definition.Kind = "protect" }},
		{"停用名单不命中", func(r *Record, _ *model.Alert) { r.Active = false }},
		{"观测时间早于生效起点", func(r *Record, a *model.Alert) { a.ObservedAt = r.Definition.ValidFrom.Add(-time.Second) }},
		{"观测时间到达终点", func(r *Record, a *model.Alert) { a.ObservedAt = r.Definition.ValidUntil }},
		{"接收时间早于修订创建", func(r *Record, a *model.Alert) { a.ReceivedAt = r.CreatedAt.Add(-time.Second) }},
		{"探针不在范围", func(_ *Record, a *model.Alert) { a.SensorID = "probe_other" }},
		{"注册代次不在范围", func(_ *Record, a *model.Alert) { a.RegistrationID = "registration_other" }},
	} {
		r, a := base, alertFixture(d)
		r.Definition = copyDefinition(base.Definition)
		c.mutge(&r, &a)
		if got := r.AlertMatches(a, AlertTargets(a, false)); len(got) != 0 {
			t.Fatalf("%s：仍返回命中 %+v", c.name, got)
		}
	}

	// 接收时间与修订创建时间相同属于"不早于"，应当登记。
	same := base
	equal := alertFixture(d)
	equal.ReceivedAt = base.CreatedAt
	if got := same.AlertMatches(equal, AlertTargets(equal, false)); len(got) != 1 {
		t.Fatalf("接收时间等于修订创建时间应登记：%+v", got)
	}
}

func TestRecordAlertMatchesReportsEveryMatchedField(t *testing.T) {
	d := observeFixture()
	d.Values = []string{"192.0.2.1", "198.51.100.7"}
	r := hitRecord(d)
	a := alertFixture(d)
	got := r.AlertMatches(a, AlertTargets(a, false))
	if len(got) != 2 || got[0].Field != FieldSourceIP || got[1].Field != FieldDestinationIP {
		t.Fatalf("源与目的同时命中时应返回两项：%+v", got)
	}
}

func TestHitIDIsStableAndBoundToIdentity(t *testing.T) {
	first := HitID(testTenant, "list_owned", 3, "alert_owned", strings.Repeat("a", 64))
	if first != HitID(testTenant, "list_owned", 3, "alert_owned", strings.Repeat("a", 64)) {
		t.Fatal("相同身份的命中标识应稳定")
	}
	if !strings.HasPrefix(first, "whit_") || len(first) != 61 {
		t.Fatalf("命中标识格式不符：%q", first)
	}
	for _, other := range []string{
		HitID("tenant_other", "list_owned", 3, "alert_owned", strings.Repeat("a", 64)),
		HitID(testTenant, "list_other", 3, "alert_owned", strings.Repeat("a", 64)),
		HitID(testTenant, "list_owned", 4, "alert_owned", strings.Repeat("a", 64)),
		HitID(testTenant, "list_owned", 3, "alert_other", strings.Repeat("a", 64)),
		HitID(testTenant, "list_owned", 3, "alert_owned", strings.Repeat("b", 64)),
	} {
		if other == first {
			t.Fatal("不同身份不应产生相同命中标识")
		}
	}
}

func TestValidDigestAcceptsOnlyLowercaseHex(t *testing.T) {
	for _, c := range []struct {
		in string
		ok bool
	}{
		{strings.Repeat("a", 64), true},
		{strings.Repeat("0", 64), true},
		{"0123456789abcdef" + strings.Repeat("0", 48), true},
		{strings.Repeat("A", 64), false},
		{strings.Repeat("a", 63), false},
		{strings.Repeat("a", 65), false},
		{strings.Repeat("g", 64), false},
		{"", false},
	} {
		if ValidDigest(c.in) != c.ok {
			t.Fatalf("ValidDigest(%q) 判定错误", c.in)
		}
	}
}

func TestNewHitFreezesSummaryAndDropsUnusableRuleText(t *testing.T) {
	d := observeFixture()
	r := hitRecord(d)
	a := alertFixture(d)
	matches := r.AlertMatches(a, AlertTargets(a, false))

	hit := NewHit(testTenant, r, a, matches)
	if hit.SchemaVersion != HitSchema || hit.ListID != r.ID || hit.ListRevision != r.Revision || hit.DefinitionSHA256 != r.DefinitionSHA256 {
		t.Fatalf("命中未绑定当时修订：%+v", hit)
	}
	if hit.RuleName != "出口异常连接" || hit.RuleID != "rule_owned" || hit.Severity != "high" {
		t.Fatalf("告警摘要未冻结：%+v", hit)
	}
	if hit.Validate(testTenant) != nil {
		t.Fatal("构造的命中应通过自校验")
	}

	// 超长或含控制字符的规则名记为空，不截断成另一条规则名。
	long := alertFixture(d)
	long.Rule.Name = strings.Repeat("字", maxRuleNameLen+1)
	long.Rule.ID = strings.Repeat("x", 65)
	trimmed := NewHit(testTenant, r, long, matches)
	if trimmed.RuleName != "" || trimmed.RuleID != "" {
		t.Fatalf("不可用的规则文本应记为空：%q %q", trimmed.RuleName, trimmed.RuleID)
	}
	if trimmed.Validate(testTenant) != nil {
		t.Fatal("规则文本为空的命中仍应有效")
	}
}

func TestHitValidateRejectsBrokenMaterials(t *testing.T) {
	d := observeFixture()
	r := hitRecord(d)
	a := alertFixture(d)
	good := NewHit(testTenant, r, a, r.AlertMatches(a, AlertTargets(a, false)))

	for _, c := range []struct {
		name   string
		mutate func(*Hit)
	}{
		{"架构版本不符", func(h *Hit) { h.SchemaVersion = "watchlist-hit.v2" }},
		{"标识与身份不符", func(h *Hit) { h.ID = "whit_" + strings.Repeat("0", 56) }},
		{"名单标识非法", func(h *Hit) { h.ListID = "List_Owned" }},
		{"修订为零", func(h *Hit) { h.ListRevision = 0 }},
		{"修订越界", func(h *Hit) { h.ListRevision = MaxRevision + 1 }},
		{"定义摘要非法", func(h *Hit) { h.DefinitionSHA256 = "short" }},
		{"事件标识非法", func(h *Hit) { h.EventID = "Alert_Owned" }},
		{"原始摘要非法", func(h *Hit) { h.RawSHA256 = strings.Repeat("A", 64) }},
		{"探针身份非法", func(h *Hit) { h.SensorID = "" }},
		{"严重级别非法", func(h *Hit) { h.Severity = "critical" }},
		{"匹配项为空", func(h *Hit) { h.Matches = nil }},
		{"匹配项重复", func(h *Hit) {
			h.Matches = []Observed{{FieldSourceIP, "192.0.2.1"}, {FieldSourceIP, "192.0.2.1"}}
		}},
		{"匹配字段未登记", func(h *Hit) { h.Matches = []Observed{{"source.port", "443"}} }},
		{"匹配值与字段类型不符", func(h *Hit) { h.Matches = []Observed{{FieldSourceIP, "example.com"}} }},
		{"观测时间缺失", func(h *Hit) { h.ObservedAt = time.Time{} }},
		{"接收时间缺失", func(h *Hit) { h.ReceivedAt = time.Time{} }},
		{"到期早于创建", func(h *Hit) {
			h.CreatedAt = a.ReceivedAt
			h.ExpiresAt = a.ReceivedAt.Add(-time.Second)
		}},
	} {
		broken := good
		broken.Matches = append([]Observed(nil), good.Matches...)
		c.mutate(&broken)
		if broken.Validate(testTenant) == nil {
			t.Fatalf("%s：仍通过校验", c.name)
		}
	}

	if good.Validate("tenant_other") == nil {
		t.Fatal("命中标识绑定租户，换租户应拒绝")
	}
	if len(good.Matches) != 1 {
		t.Fatal("原始命中被测试修改")
	}
}

func TestHitQueryValidateBoundsWindowAndPageSize(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	base := HitQuery{ListID: "list_owned", Start: now.Add(-24 * time.Hour), End: now, Limit: 20}
	if base.Validate(now) != nil {
		t.Fatal("合法查询被拒绝")
	}
	for _, c := range []struct {
		name   string
		mutate func(*HitQuery)
	}{
		{"名单标识非法", func(q *HitQuery) { q.ListID = "List" }},
		{"起点缺失", func(q *HitQuery) { q.Start = time.Time{} }},
		{"终点缺失", func(q *HitQuery) { q.End = time.Time{} }},
		{"窗口为零", func(q *HitQuery) { q.Start = q.End }},
		{"窗口反向", func(q *HitQuery) { q.Start, q.End = q.End, q.Start }},
		{"窗口超过上限", func(q *HitQuery) { q.Start = q.End.Add(-MaxHitWindow - time.Second) }},
		{"终点超过当前时间", func(q *HitQuery) { q.End = now.Add(time.Hour) }},
		{"页大小为零", func(q *HitQuery) { q.Limit = 0 }},
		{"页大小越界", func(q *HitQuery) { q.Limit = 101 }},
		{"游标过长", func(q *HitQuery) { q.Cursor = strings.Repeat("x", 513) }},
	} {
		q := base
		c.mutate(&q)
		if q.Validate(now) == nil {
			t.Fatalf("%s：仍通过校验", c.name)
		}
	}
	// 终点允许少量时钟偏移，避免客户端与服务端时间微差导致整页失败。
	skew := base
	skew.End = now.Add(20 * time.Second)
	if skew.Validate(now) != nil {
		t.Fatal("终点在允许偏移内应接受")
	}
}

func TestHitQueryCursorBindsScopeAndRejectsTampering(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	q := HitQuery{ListID: "list_owned", Start: now.Add(-24 * time.Hour), End: now, Limit: 20}
	last := Hit{ID: "whit_" + strings.Repeat("a", 56), ObservedAt: now.Add(-time.Hour)}

	cursor := q.Next(testTenant, last)
	next := q
	next.Cursor = cursor
	at, id, err := next.Position(testTenant)
	if err != nil || id != last.ID || !at.Equal(last.ObservedAt) {
		t.Fatalf("续读位置不符：%v %q %v", at, id, err)
	}

	// 首次读取从窗口终点开始，不含终点。
	at, id, err = q.Position(testTenant)
	if err != nil || id != "" || !at.Equal(q.End) {
		t.Fatalf("首页位置应为窗口终点：%v %q %v", at, id, err)
	}

	for _, c := range []struct {
		name   string
		tenant string
		mutate func(*HitQuery)
	}{
		{"换租户", "tenant_other", func(_ *HitQuery) {}},
		{"换名单", testTenant, func(q *HitQuery) { q.ListID = "list_other" }},
		{"换窗口起点", testTenant, func(q *HitQuery) { q.Start = q.Start.Add(time.Minute) }},
		{"换窗口终点", testTenant, func(q *HitQuery) { q.End = q.End.Add(-time.Minute) }},
		{"换页大小", testTenant, func(q *HitQuery) { q.Limit = 50 }},
	} {
		other := q
		other.Cursor = cursor
		c.mutate(&other)
		if _, _, e := other.Position(c.tenant); e == nil {
			t.Fatalf("%s：游标仍被接受", c.name)
		}
	}

	for _, c := range []struct {
		name, cursor string
	}{
		{"非 base64", "!!!"},
		{"带填充", base64.StdEncoding.EncodeToString([]byte(`{"time":"2026-11-06T11:00:00Z","id":"whit_x","scope":"x"}`))},
		{"非 JSON", base64.RawURLEncoding.EncodeToString([]byte("plain"))},
		{"字段缺失", base64.RawURLEncoding.EncodeToString([]byte(`{"time":"2026-11-06T11:00:00Z"}`))},
		{"多余字段", base64.RawURLEncoding.EncodeToString([]byte(`{"time":"2026-11-06T11:00:00Z","id":"whit_a","scope":"x","extra":1}`))},
	} {
		other := q
		other.Cursor = c.cursor
		if _, _, e := other.Position(testTenant); e == nil {
			t.Fatalf("%s：游标仍被接受", c.name)
		}
	}

	// 位置必须落在窗口内，否则可借游标越过窗口读取。
	for _, at := range []time.Time{q.Start.Add(-time.Second), q.End, q.End.Add(time.Hour)} {
		raw, _ := json.Marshal(hitCursor{Time: at, ID: last.ID, Scope: q.scope(testTenant)})
		other := q
		other.Cursor = base64.RawURLEncoding.EncodeToString(raw)
		if _, _, e := other.Position(testTenant); e == nil {
			t.Fatalf("窗口外位置 %v 仍被接受", at)
		}
	}

	if _, _, e := q.Position("Tenant"); e == nil {
		t.Fatal("非法租户应被拒绝")
	}
}
