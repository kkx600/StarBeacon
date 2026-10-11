package application

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func testDefinition() Definition {
	return Definition{SchemaVersion: Schema, ProductID: "owned_files", ProductName: "业务文件服务", CategoryID: "cloud_storage", Protocols: []string{"http", "tls"}, Any: []Condition{{Field: "http.host", Op: "domain_suffix", Value: "files.example"}, {Field: "tls.sni", Op: "eq", Value: "files.example"}}, All: []Condition{}, Exclude: []Condition{}}
}
func testObservation() Observation {
	return Observation{SchemaVersion: ObservationSchema, Protocol: "http", HTTPHost: "files.example", HTTPMethod: "GET", HTTPPath: "/documents/1", TLSALPN: []string{}, DNSNames: []string{}}
}
func testVersion() Version {
	return Version{ID: "app_files", Revision: 1, Definition: testDefinition()}
}
func copyDefinition(d Definition) Definition {
	raw, _ := json.Marshal(d)
	var result Definition
	_ = json.Unmarshal(raw, &result)
	return result
}

func TestVisibleNamesCannotConfirmProductsOrMatchDeceptiveSuffixes(t *testing.T) {
	now := time.Now()
	version := testVersion()
	observation := testObservation()
	for _, item := range []struct{ host, status string }{{"files.example", "candidate"}, {"API.FILES.EXAMPLE.:443", "candidate"}, {"api.files.example", "candidate"}, {"files.example.attacker.example", "unknown"}, {"myfiles.example", "unknown"}, {"example", "invalid"}, {"files.example:00443", "invalid"}, {"files.example:65536", "invalid"}, {"files.example:http", "invalid"}, {"https://files.example", "invalid"}, {"files.example@attacker.example", "invalid"}, {"198.51.100.5", "invalid"}, {"[2001:db8::1]:443", "invalid"}} {
		t.Run(item.host, func(t *testing.T) {
			observation.HTTPHost = item.host
			result, err := Evaluate([]Version{version}, observation, now)
			if item.status == "invalid" {
				if err == nil {
					t.Fatal("无效名称作为产品证据")
				}
				return
			}
			if err != nil || result.Status != item.status || result.Origin != "user_supplied_metadata" || result.ObservationSHA256 != Digest(observation) || result.RulesSHA256 != Digest([]Version{version}) {
				t.Fatalf("候选或来源不一致：%+v %v", result, err)
			}
		})
	}
	version.Definition.Any = []Condition{{Field: "http.host", Op: "eq", Value: "bücher.example"}}
	observation.HTTPHost = "XN--BCHER-KVA.EXAMPLE."
	result, err := Evaluate([]Version{version}, observation, now)
	if err != nil || result.Status != "candidate" {
		t.Fatal("IDNA 名称不一致", err)
	}
	for _, name := range []string{"com", "co.uk", "*.files.example", "-bad.files.example", "bad-.files.example", "a..example", "bad_.example", strings.Repeat("x", 64) + ".example", "name\n.example", strings.Repeat("a.", 128) + "example", "files.example/", "\xff.example"} {
		if _, err := domain(name); err == nil {
			t.Fatal("不安全域名被接受", name)
		}
	}
}

func TestConjunctionExclusionsAndMissingMetadataDoNotInventEvidence(t *testing.T) {
	version := testVersion()
	version.Definition.All = []Condition{{Field: "http.method", Op: "eq", Value: "GET"}, {Field: "http.path", Op: "prefix", Value: "/documents/"}, {Field: "http.user_agent", Op: "contains", Value: "OwnedClient"}}
	version.Definition.Exclude = []Condition{{Field: "http.path", Op: "eq", Value: "/documents/public"}}
	o := testObservation()
	o.HTTPUserAgent = "OwnedClient/1.0"
	now := time.Now()
	result, err := Evaluate([]Version{version}, o, now)
	if err != nil || result.Status != "candidate" || len(result.Matches[0].Evidence) != 4 {
		t.Fatal("正向组合未命中", err)
	}
	for _, change := range []func(*Observation){func(o *Observation) { o.HTTPMethod = "POST" }, func(o *Observation) { o.HTTPPath = "/other" }, func(o *Observation) { o.HTTPUserAgent = "Browser" }, func(o *Observation) { o.HTTPHost = "" }, func(o *Observation) { o.HTTPPath = "/documents/public" }} {
		input := o
		change(&input)
		result, err := Evaluate([]Version{version}, input, now)
		if err != nil || result.Status != "unknown" || result.MatchedRuleCount != 0 {
			t.Fatal("排除或缺测仍识别", err)
		}
	}
	o = Observation{SchemaVersion: ObservationSchema, Protocol: "tls", TLSALPN: []string{}, DNSNames: []string{}}
	result, err = Evaluate([]Version{testVersion()}, o, now)
	if err != nil || result.Status != "unknown" || result.Reason != "metadata_unavailable" {
		t.Fatal("加密缺测没有保留未知", err)
	}
	o.TLSSNI = "files.example"
	o.TLSALPN = []string{"h2"}
	version = testVersion()
	version.Definition.All = []Condition{{Field: "tls.alpn", Op: "eq", Value: "h2"}}
	result, err = Evaluate([]Version{version}, o, now)
	if err != nil || result.Status != "candidate" {
		t.Fatal("可见 SNI/ALPN 不一致", err)
	}
	o.Protocol = "quic"
	version.Definition.Protocols = []string{"quic"}
	version.Definition.Any = []Condition{{Field: "tls.sni", Op: "domain_suffix", Value: "files.example"}}
	result, err = Evaluate([]Version{version}, o, now)
	if err != nil || result.Status != "candidate" {
		t.Fatal("QUIC 可见名称测试失败", err)
	}
	version.Definition.Protocols = []string{"tls"}
	result, err = Evaluate([]Version{version}, o, now)
	if err != nil || result.Status != "unknown" {
		t.Fatal("跨协议匹配", err)
	}
}

func TestConflictsAndOutputLimitsKeepAllMatchingProductsInDecision(t *testing.T) {
	versions := []Version{}
	for i := 0; i < 20; i++ {
		v := testVersion()
		v.ID = fmt.Sprintf("app_%02d", i)
		v.Definition.ProductID = fmt.Sprintf("product_%02d", i)
		versions = append(versions, v)
	}
	result, err := Evaluate(versions, testObservation(), time.Now())
	if err != nil || result.Status != "conflict" || result.MatchedRuleCount != 20 || len(result.Matches) != 16 || !result.Limited {
		t.Fatal("输出截断掩盖了冲突", err)
	}
	for i := range versions {
		versions[i].Definition.ProductID = "same_product"
	}
	result, err = Evaluate(versions, testObservation(), time.Now())
	if err != nil || result.Status != "candidate" || result.MatchedRuleCount != 20 {
		t.Fatal("同一产品多证据产生假冲突", err)
	}
	for i, j := 0, len(versions)-1; i < j; i, j = i+1, j-1 {
		versions[i], versions[j] = versions[j], versions[i]
	}
	reordered, err := Evaluate(versions, testObservation(), time.Now())
	if err != nil || reordered.RulesSHA256 != result.RulesSHA256 || reordered.Matches[0].RuleID != result.Matches[0].RuleID {
		t.Fatal("快照摘要依赖查询顺序", err)
	}
	v := testVersion()
	// 多个不同域名条件同时可由 DNS 数组命中，但不成为传输会话或字节归因。
	v.Definition.Protocols = []string{"dns"}
	v.Definition.All = []Condition{}
	v.Definition.Any = []Condition{}
	names := []string{}
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("%d.files.example", i)
		v.Definition.Any = append(v.Definition.Any, Condition{Field: "dns.name", Op: "eq", Value: name})
		names = append(names, name)
	}
	o := Observation{SchemaVersion: ObservationSchema, Protocol: "dns", TLSALPN: []string{}, DNSNames: names}
	result, err = Evaluate([]Version{v}, o, time.Now())
	if err != nil || result.Status != "candidate" || len(result.Matches[0].Evidence) != 8 || !result.Matches[0].EvidenceLimited {
		t.Fatal("DNS 证据或展示上限丢失", err)
	}
}

func TestRuleAndObservationResourceBoundaries(t *testing.T) {
	oversized := testDefinition()
	oversized.Any = []Condition{}
	oversized.All = []Condition{}
	largeName := strings.Repeat("一", 50) + "." + strings.Repeat("二", 50) + "." + strings.Repeat("三", 50) + ".example"
	for i := 0; i < 16; i++ {
		oversized.Any = append(oversized.Any, Condition{Field: "http.host", Op: "domain_suffix", Value: fmt.Sprintf("%d.%s", i, largeName)})
		oversized.All = append(oversized.All, Condition{Field: "http.host", Op: "eq", Value: fmt.Sprintf("%d.%s", i, largeName)})
	}
	if oversized.Validate() == nil {
		t.Fatal("超大 Unicode 规则定义未受字节预算约束")
	}
	for _, change := range []func(*Definition){
		func(d *Definition) { d.SchemaVersion = "wrong" }, func(d *Definition) { d.ProductID = "a/b" }, func(d *Definition) { d.ProductName = " " }, func(d *Definition) { d.CategoryID = "tcp" }, func(d *Definition) { d.Protocols = nil }, func(d *Definition) { d.Protocols = []string{"http", "http"} }, func(d *Definition) { d.Protocols = []string{"udp"} }, func(d *Definition) { d.Any = nil }, func(d *Definition) { d.All = nil }, func(d *Definition) { d.Exclude = nil }, func(d *Definition) { d.Any = []Condition{{Field: "http.user_agent", Op: "contains", Value: "Browser"}} }, func(d *Definition) { d.Any[0].Op = "regex" }, func(d *Definition) { d.All = []Condition{{Field: "http.method", Op: "eq", Value: "get"}} }, func(d *Definition) { d.All = []Condition{{Field: "http.path", Op: "regex", Value: ".*"}} }, func(d *Definition) { d.All = []Condition{{Field: "http.path", Op: "eq", Value: "relative"}} }, func(d *Definition) { d.All = []Condition{{Field: "http.user_agent", Op: "prefix", Value: "Browser"}} }, func(d *Definition) { d.All = []Condition{{Field: "tls.alpn", Op: "contains", Value: "h2"}} }, func(d *Definition) { d.All = []Condition{{Field: "ip.dst", Op: "eq", Value: "198.51.100.5"}} }, func(d *Definition) { d.Any = append(d.Any, d.Any[0]) }, func(d *Definition) { d.Protocols = []string{"dns"} }, func(d *Definition) { d.Any = make([]Condition, 17) }, func(d *Definition) { d.Exclude = make([]Condition, 32) },
	} {
		d := copyDefinition(testDefinition())
		change(&d)
		if d.Validate() == nil {
			t.Fatalf("无效规则被接受：%+v", d)
		}
	}
	for _, change := range []func(*Observation){
		func(o *Observation) { o.SchemaVersion = "wrong" }, func(o *Observation) { o.Protocol = "udp" }, func(o *Observation) { o.TLSALPN = nil }, func(o *Observation) { o.DNSNames = nil }, func(o *Observation) { o.HTTPMethod = "INVALID" }, func(o *Observation) { o.HTTPPath = "relative" }, func(o *Observation) { o.HTTPPath = "/" + strings.Repeat("x", 4096) }, func(o *Observation) { o.HTTPUserAgent = "a\nb" }, func(o *Observation) { o.TLSSNI = "files.example" }, func(o *Observation) { o.TLSALPN = []string{"h2"} }, func(o *Observation) { o.DNSNames = []string{"files.example"} }, func(o *Observation) { o.Protocol = "tls" }, func(o *Observation) { o.Protocol = "dns" },
	} {
		o := testObservation()
		change(&o)
		if _, err := Evaluate([]Version{testVersion()}, o, time.Now()); err == nil {
			t.Fatalf("无效材料被接受：%+v", o)
		}
	}
	for _, o := range []Observation{{SchemaVersion: ObservationSchema, Protocol: "dns", DNSNames: []string{"com"}, TLSALPN: []string{}}, {SchemaVersion: ObservationSchema, Protocol: "dns", DNSNames: make([]string, 33), TLSALPN: []string{}}, {SchemaVersion: ObservationSchema, Protocol: "tls", DNSNames: []string{}, TLSALPN: []string{"bad\n"}}, {SchemaVersion: ObservationSchema, Protocol: "tls", DNSNames: []string{}, TLSALPN: make([]string, 9)}} {
		if _, err := Evaluate(nil, o, time.Now()); err == nil {
			t.Fatal("超限或非法 DNS/ALPN 被接受")
		}
	}
	for _, versions := range [][]Version{make([]Version, MaxRules+1), {{ID: "invalid/", Revision: 1, Definition: testDefinition()}}, {{ID: "rule", Revision: 0, Definition: testDefinition()}}, {testVersion(), testVersion()}} {
		if _, err := Evaluate(versions, testObservation(), time.Now()); err == nil {
			t.Fatal("非法规则快照被接受")
		}
	}
	if _, err := Evaluate(nil, testObservation(), time.Time{}); err == nil {
		t.Fatal("缺失评测时间被接受")
	}
	for _, c := range []Condition{{Field: "http.path", Op: "eq", Value: "/x"}, {Field: "http.user_agent", Op: "eq", Value: "Owned"}} {
		if c.Validate() != nil || !matches(c, map[string][]string{c.Field: {c.Value}}) {
			t.Fatal("精确匹配失败")
		}
	}
	if matches(Condition{Field: "http.host", Op: "invalid", Value: "files.example"}, map[string][]string{"http.host": {"files.example"}}) {
		t.Fatal("未知操作符匹配")
	}
}

func TestChangesRecordsAndPageQueriesRejectUnboundValues(t *testing.T) {
	active := true
	c := Change{ID: "rule_owned", Name: "业务产品域名", Active: &active, Definition: testDefinition()}
	if c.Validate() != nil {
		t.Fatal("合法创建无效")
	}
	for _, change := range []func(*Change){func(c *Change) { c.ID = "/" }, func(c *Change) { c.ExpectedRevision = -1 }, func(c *Change) { c.ExpectedRevision = MaxRevision }, func(c *Change) { c.Name = " " }, func(c *Change) { c.Description = "a\nb" }, func(c *Change) { c.Active = nil }, func(c *Change) { v := false; c.Active = &v }} {
		bad := c
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("无效变更被接受")
		}
	}
	r := Record{TenantID: "tenant", ID: c.ID, Revision: 1, Name: c.Name, Active: true, Definition: c.Definition, DefinitionSHA256: Digest(c.Definition), CreatedBy: "owner", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(180 * 24 * time.Hour)}
	if r.Validate() != nil {
		t.Fatal("合法记录无效")
	}
	for _, change := range []func(*Record){func(r *Record) { r.TenantID = "/" }, func(r *Record) { r.ID = "/" }, func(r *Record) { r.CreatedBy = "/" }, func(r *Record) { r.Revision = 0 }, func(r *Record) { r.Name = " " }, func(r *Record) { r.Description = "a\nb" }, func(r *Record) { r.CreatedAt = time.Time{} }, func(r *Record) { r.ExpiresAt = r.CreatedAt }, func(r *Record) { r.DefinitionSHA256 = strings.Repeat("0", 64) }} {
		bad := r
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("损坏修订被接受")
		}
	}
	for _, q := range []ListQuery{{Limit: 0}, {Limit: 101}, {Limit: 20, Cursor: "/"}, {Limit: 20, Keyword: " a"}, {Limit: 20, Active: "yes"}} {
		if q.Validate() == nil {
			t.Fatal("非法目录范围被接受")
		}
	}
	if (ListQuery{Limit: 20, Cursor: "rule_owned", Keyword: "业务", Active: "false"}).Validate() != nil {
		t.Fatal("合法目录范围被拒绝")
	}
}
