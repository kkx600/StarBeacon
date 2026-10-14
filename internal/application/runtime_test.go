package application

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCompiledMatcherPreservesRuleSemanticsAndSnapshotIsolation(t *testing.T) {
	now := time.Now().UTC()
	versions := []Version{testVersion()}
	versions[0].Definition.All = []Condition{{Field: "http.method", Op: "eq", Value: "GET"}, {Field: "http.path", Op: "prefix", Value: "/documents/"}}
	versions[0].Definition.Exclude = []Condition{{Field: "http.path", Op: "eq", Value: "/documents/public"}}
	m, err := Compile(versions)
	if err != nil || m.SHA256() != Digest(versions) {
		t.Fatal("编译快照不一致", err)
	}
	for _, host := range []string{"files.example", "API.FILES.EXAMPLE.:443", "myfiles.example", "files.example.attacker.example", ""} {
		for _, path := range []string{"/documents/1", "/documents/public", "/other"} {
			o := testObservation()
			o.HTTPHost, o.HTTPPath = host, path
			expected, err := Evaluate(versions, o, now)
			if err != nil {
				t.Fatal(err)
			}
			expected.Origin = "suricata_visible_metadata"
			actual, err := m.Evaluate(o, now)
			if err != nil || !reflect.DeepEqual(expected, actual) {
				t.Fatalf("编译匹配语义改变：%s %s %+v %+v %v", host, path, expected, actual, err)
			}
		}
	}
	versions[0].Definition.Any[0].Value = "other.example"
	if r, err := m.Evaluate(testObservation(), now); err != nil || r.Status != "candidate" {
		t.Fatal("调用者修改了已编译快照", err)
	}
	if _, err := m.Evaluate(testObservation(), time.Time{}); err == nil {
		t.Fatal("缺失时间被接受")
	}
	bad := testObservation()
	bad.HTTPHost = "https://files.example"
	if _, err := m.Evaluate(bad, now); err == nil {
		t.Fatal("无效材料被接受")
	}
	for _, versions := range [][]Version{nil, make([]Version, MaxRules+1), {testVersion(), testVersion()}, {{ID: "bad/", Revision: 1, Definition: testDefinition()}}, {{ID: "rule", Revision: 0, Definition: testDefinition()}}} {
		if _, err := Compile(versions); err == nil {
			t.Fatal("无效编译目录被接受")
		}
	}
	v := testVersion()
	v.ID, v.Definition.ProductName = "rule_other", "冲突的产品名称"
	if _, err := Compile([]Version{testVersion(), v}); err == nil {
		t.Fatal("同一产品标识出现不一致描述")
	}
}

func TestCompiledConflictsLimitsIDNAAndProtocolBuckets(t *testing.T) {
	versions := []Version{}
	for i := range 20 {
		v := testVersion()
		v.ID, v.Definition.ProductID = fmt.Sprintf("app_%02d", i), fmt.Sprintf("product_%02d", i)
		versions = append(versions, v)
	}
	m, err := Compile(versions)
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.Evaluate(testObservation(), time.Now())
	if err != nil || r.Status != "conflict" || r.MatchedRuleCount != 20 || len(r.Matches) != 16 || !r.Limited {
		t.Fatal("冲突被展示截断掩盖", err)
	}
	v := testVersion()
	v.Definition.Any = []Condition{{Field: "http.host", Op: "eq", Value: "bücher.example"}}
	m, err = Compile([]Version{v})
	if err != nil {
		t.Fatal(err)
	}
	o := testObservation()
	o.HTTPHost = "XN--BCHER-KVA.EXAMPLE."
	if r, err := m.Evaluate(o, time.Now()); err != nil || r.Status != "candidate" {
		t.Fatal("IDNA 编译失效", err)
	}
	o = emptyRuntimeObservation("tls")
	o.TLSSNI = "bücher.example"
	if r, err := m.Evaluate(o, time.Now()); err != nil || r.Status != "unknown" {
		t.Fatal("HTTP 名称跨协议归因", err)
	}
	v.Definition = testDefinition()
	v.Definition.Protocols, v.Definition.Any = []string{"dns"}, []Condition{}
	for i := range 10 {
		v.Definition.Any = append(v.Definition.Any, Condition{Field: "dns.name", Op: "eq", Value: fmt.Sprintf("%d.files.example", i)})
	}
	m, err = Compile([]Version{v})
	if err != nil {
		t.Fatal(err)
	}
	o = emptyRuntimeObservation("dns")
	for i := range 10 {
		o.DNSNames = append(o.DNSNames, fmt.Sprintf("%d.files.example", i))
	}
	if r, err := m.Evaluate(o, time.Now()); err != nil || r.Status != "candidate" || len(r.Matches[0].Evidence) != 8 || !r.Matches[0].EvidenceLimited {
		t.Fatal("DNS 输出额度未保留", err)
	}
}

func emptyRuntimeObservation(protocol string) Observation {
	return Observation{SchemaVersion: ObservationSchema, Protocol: protocol, TLSALPN: []string{}, DNSNames: []string{}}
}

func TestRuntimeEVEFieldsAndMissingEncryptedMetadata(t *testing.T) {
	now := time.Now().UTC()
	versions := []Version{testVersion()}
	versions[0].Definition.Protocols = []string{"http", "tls", "quic", "dns"}
	versions[0].Definition.Any = append(versions[0].Definition.Any, Condition{Field: "dns.name", Op: "eq", Value: "files.example"})
	m, err := Compile(versions)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ raw, status, reason string }{
		{`{"event_type":"http","http":{"hostname":"files.example","http_method":"GET","url":"/documents"}}`, "candidate", "visible_name_rule"},
		{`{"event_type":"tls","tls":{"sni":"files.example","client_alpns":["h2"],"server_alpns":["h2"]}}`, "candidate", "visible_name_rule"},
		{`{"event_type":"tls","tls":{"client_alpns":["h2"]}}`, "unknown", "no_matching_rule"},
		{`{"event_type":"tls","tls":{}}`, "unknown", "metadata_unavailable"},
		{`{"event_type":"quic","quic":{"sni":"files.example","extensions":[{"type":16,"values":["h3","h3"]},{"type":0,"values":["other.example"]}]}}`, "candidate", "visible_name_rule"},
		{`{"event_type":"dns","dns":{"version":3,"queries":[{"rrname":"files.example"}]}}`, "candidate", "visible_name_rule"},
		{`{"event_type":"dns","dns":{"version":2,"type":"query","rrname":"files.example"}}`, "candidate", "visible_name_rule"},
		{`{"event_type":"dns","dns":{"version":2,"type":"answer","rrname":"files.example"}}`, "unknown", "metadata_unavailable"},
		{`{"event_type":"alert","app_proto":"http","http":{"hostname":"files.example"},"tx_guessed":true}`, "unknown", "transaction_unbound"},
		{`{"event_type":"alert","app_proto":"http","http":{"hostname":"files.example","url":"relative"}}`, "unknown", "metadata_invalid"},
		{`{"event_type":"http","http":{"hostname":"files.example.attacker.example"}}`, "unknown", "no_matching_rule"},
	} {
		a, supported, err := m.Attribute([]byte(tc.raw), "deployment_owned", now)
		if err != nil || !supported || a.Result.Status != tc.status || a.Result.Reason != tc.reason {
			t.Fatalf("实际字段或缺测语义不一致：%s %+v %v", tc.raw, a, err)
		}
		encoded, _ := json.Marshal(a)
		parsed, err := ReadAttribution(encoded)
		if err != nil || m.Verify(parsed, []byte(tc.raw), "deployment_owned", now) != nil {
			t.Fatal("原材料复算失效", err)
		}
		parsed.ProductID = "forged_product"
		if m.Verify(parsed, []byte(tc.raw), "deployment_owned", now) == nil {
			t.Fatal("伪造产品被接受")
		}
	}
	for _, raw := range []string{`{`, `{"event_type":"flow","app_proto":"http"}`, `{"event_type":"ssh"}`} {
		if _, supported, _ := m.Attribute([]byte(raw), "deployment_owned", now); supported {
			t.Fatal("非协议事务被分类")
		}
	}
	if _, _, err := m.Attribute([]byte(`{}`), "bad/", now); err == nil {
		t.Fatal("非法部署身份")
	}
	if _, _, err := m.Attribute([]byte(`{}`), "owned", time.Time{}); err == nil {
		t.Fatal("缺少观测时间")
	}
	o, supported, err := EVEObservation([]byte(`{"event_type":"tls","tls":{"sni":"files.example","client_alpns":["h2"],"server_alpns":["h2","http/1.1"]}}`))
	if err != nil || !supported || !reflect.DeepEqual(o.TLSALPN, []string{"h2", "http/1.1"}) {
		t.Fatal("ALPN 字段或去重错误", err)
	}
}

func TestApplicationPackageStateAndAttributionBoundaries(t *testing.T) {
	s := EmptyState()
	if s.Validate() != nil {
		t.Fatal("初始状态无效")
	}
	versions := []Version{testVersion()}
	p := Package{SchemaVersion: PackageSchema, DeploymentInput: DeploymentInput{ExpectedRegistrationID: "reg_owned", ExpectedStateSHA256: s.StateSHA256, RulesSHA256: Digest(versions)}, Versions: versions}
	raw, _ := json.Marshal(p)
	if _, err := ReadPackage(raw); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{}`, `null`, string(raw) + `{}`, strings.Replace(string(raw), `"schema_version":`, `"Schema_version":`, 1), strings.Replace(string(raw), `"rules_sha256":`, `"rules_sha256":"duplicate","rules_sha256":`, 1), strings.Replace(string(raw), `"versions":[`, `"versions":null,"unknown":[`, 1), strings.Repeat(" ", MaxPackageBytes) + string(raw)} {
		if _, err := ReadPackage([]byte(raw)); err == nil {
			t.Fatal("非法规则包通过")
		}
	}
	for _, change := range []func(*State){func(s *State) { s.SchemaVersion = "bad" }, func(s *State) { s.RulesSHA256 = "" }, func(s *State) { s.StateSHA256 = "" }, func(s *State) { s.RuleCount = 129 }, func(s *State) { s.DeploymentID = "bad/" }, func(s *State) { s.RuleCount = 1 }} {
		bad := s
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("无效状态通过")
		}
	}
	now := time.Now().UTC()
	s = State{SchemaVersion: StateSchema, DeploymentID: "owned", RulesSHA256: Digest(versions), StateSHA256: StateDigest("owned", Digest(versions)), RuleCount: 1, InstalledAt: &now}
	if s.Validate() != nil {
		t.Fatal("有效部署状态失效")
	}
	s.InstalledAt = nil
	if s.Validate() == nil {
		t.Fatal("缺失安装时间")
	}
	for _, digest := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		if ValidSHA256(digest) {
			t.Fatal("无效摘要被接受")
		}
	}
	for _, input := range []DeploymentInput{{}, {ExpectedStateSHA256: EmptyState().StateSHA256}} {
		if input.Validate() == nil {
			t.Fatal("未绑定提交通过")
		}
	}
	m, _ := Compile(versions)
	a, _, _ := m.Attribute([]byte(`{"event_type":"http","http":{"hostname":"files.example"}}`), "owned", now)
	raw, _ = json.Marshal(a)
	for _, v := range []string{`null`, `{}`, string(raw) + `[]`, strings.Replace(string(raw), `"result":`, `"unknown":`, 1), strings.Replace(string(raw), `"matches":[`, `"matches":null,"duplicate":[`, 1), strings.Replace(string(raw), `"origin":"suricata_visible_metadata"`, `"origin":"user_supplied_metadata"`, 1), strings.Repeat(" ", MaxAttributionBytes) + string(raw)} {
		if _, err := ReadAttribution([]byte(v)); err == nil {
			t.Fatal("非法分类数据通过")
		}
	}
	if m.Verify(a, []byte(`{"event_type":"tls"}`), "owned", now) == nil || m.Verify(a, []byte(`{}`), "owned", now) == nil {
		t.Fatal("跨材料证明通过")
	}
}

func TestLargeValidRuleEvidenceCannotOverflowTheEventAttachment(t *testing.T) {
	versions := []Version{}
	path := "/" + strings.Repeat("界", 255)
	for i := range 16 {
		v := testVersion()
		v.ID = fmt.Sprintf("rule_%02d", i)
		for n := range 7 {
			v.Definition.All = append(v.Definition.All, Condition{Field: "http.path", Op: "prefix", Value: path[:len(path)-n*3]})
		}
		versions = append(versions, v)
	}
	m, err := Compile(versions)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"event_type": "http", "http": map[string]string{"hostname": "files.example", "url": path}})
	a, supported, err := m.Attribute(raw, "deployment_large", time.Now().UTC())
	if err != nil || !supported || a.Result.MatchedRuleCount != 16 || a.Result.Status != "candidate" {
		t.Fatal("有效大条件没有保持全部命中", err)
	}
	encoded, err := json.Marshal(a)
	if err != nil || len(encoded) > MaxAttributionBytes {
		t.Fatal("有效配置造成分类越过传输预算", len(encoded), err)
	}
	for _, match := range a.Result.Matches {
		if len(match.Evidence) < 1 || !match.EvidenceLimited || match.Evidence[0].Field != "http.host" {
			t.Fatal("压缩展示丢失正向域名依据或截断声明")
		}
	}
	if _, err := ReadAttribution(encoded); err != nil {
		t.Fatal("有界分类无法读取", err)
	}
}
