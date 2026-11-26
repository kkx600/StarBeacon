package gatewayblock

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testFlow(source, destination string, transport string) Flow {
	return Flow{netip.MustParseAddr(source), 45678, netip.MustParseAddr(destination), 8080, transport}
}

func testLocal() LocalConfig {
	return LocalConfig{Enabled: true, Scope: Scope{
		Sources:      []netip.Prefix{netip.MustParsePrefix("10.203.35.0/24"), netip.MustParsePrefix("fd12:35::/64")},
		Destinations: []netip.Prefix{netip.MustParsePrefix("10.203.36.0/24"), netip.MustParsePrefix("fd12:36::/64")},
	}}
}

func TestGatewayFlowAndPolicyRequireBoundEndpointsAndShortLease(t *testing.T) {
	valid := testFlow("10.203.35.3", "10.203.36.3", "tcp")
	reverse := Flow{valid.DestinationIP, valid.DestinationPort, valid.SourceIP, valid.SourcePort, valid.Transport}
	if !valid.Valid() || !testLocal().Scope.Allows(valid) || testLocal().Scope.Allows(reverse) || valid.Key() != reverse.Key() {
		t.Fatal("连接身份归一化与授权方向不一致")
	}
	for _, f := range []Flow{
		testFlow("127.0.0.1", "10.203.36.3", "tcp"),
		testFlow("::ffff:10.203.35.3", "::ffff:10.203.36.3", "tcp"),
		testFlow("fd12:35::3%eth0", "fd12:36::3", "udp"),
		testFlow("10.203.35.3", "fd12:36::3", "udp"),
		testFlow("10.203.35.3", "10.203.35.3", "tcp"),
		testFlow("10.203.35.3", "10.203.36.3", "icmp"),
		{SourceIP: valid.SourceIP, DestinationIP: valid.DestinationIP, Transport: "tcp"},
	} {
		if f.Valid() {
			t.Fatal("不完整、混合、非单播或未支持的连接被授权", f)
		}
	}
	now := time.Now().UTC()
	d := Definition{Name: "试验接入", Enabled: true, Trigger: Rule, SensorID: "sensor_nft", RegistrationID: "reg_nft",
		RuleID: "1000001", RuleRevision: "1", Scope: testLocal().Scope, LeaseSeconds: 8, ValidUntil: now.Add(time.Hour)}
	if !(PolicyChange{0, d}).Valid(now) || !(SettingsChange{0, true, 3}).Valid() ||
		!(ReviewRequest{"policy", 1, 5, strings.Repeat("a", 64)}).Valid() {
		t.Fatal("可授权输入不受支持")
	}
	for _, change := range []func(*Definition){
		func(d *Definition) { d.RuleID = "010" },
		func(d *Definition) { d.RuleRevision = "0" },
		func(d *Definition) { d.Trigger = "arbitrary" },
		func(d *Definition) { d.SensorID = "invalid/" },
		func(d *Definition) { d.LeaseSeconds = 61 },
		func(d *Definition) { d.ValidUntil = now.Add(25 * time.Hour) },
		func(d *Definition) { d.ValidUntil = now },
		func(d *Definition) { d.Name = "坏\n名称" },
		func(d *Definition) { d.Scope.Sources = nil },
		func(d *Definition) { d.Scope.Destinations = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/7")} },
		func(d *Definition) { d.Scope.Sources = []netip.Prefix{netip.MustParsePrefix("10.203.35.3/24")} },
		func(d *Definition) { d.Scope.Sources = []netip.Prefix{d.Scope.Sources[0], d.Scope.Sources[0]} },
	} {
		candidate := d
		change(&candidate)
		if (PolicyChange{0, candidate}).Valid(now) {
			t.Fatal("越界策略取得授权", candidate)
		}
	}
	if (SettingsChange{0, true, 61}).Valid() || (ReviewRequest{"policy", 1, 5, strings.Repeat("A", 64)}).Valid() {
		t.Fatal("接受越界限额或非规范摘要")
	}
	d.Enabled, d.ValidUntil = false, now.Add(-time.Hour)
	if !(PolicyChange{1, d}).Valid(now) {
		t.Fatal("已过期的旧策略无法明确停用")
	}
}

func TestGatewayActionAndIndependentReceiptUseExactFlowAndDeadline(t *testing.T) {
	now := time.Now().UTC()
	a := Action{RequestID: "gateway_plan", EventID: strings.Repeat("a", 64), ConfigSHA256: testLocal().Binding().ConfigSHA256,
		PolicyID: "policy", Revision: 1, Trigger: Review, Flow: testFlow("10.203.35.3", "10.203.36.3", "tcp"), LeaseUntil: now.Add(12 * time.Second)}
	raw, _ := json.Marshal(a)
	if parsed, err := ReadAction(raw, now, now.Add(DispatchWindow)); err != nil || parsed != a {
		t.Fatal("签名参数解析失配", err)
	}
	duplicate := strings.Replace(string(raw), `"policy_id":"policy"`, `"policy_id":"policy","policy_id":"alternate"`, 1)
	for _, invalid := range []struct {
		json    string
		expires time.Time
	}{{duplicate, now.Add(DispatchWindow)}, {string(raw), now.Add(DispatchWindow + time.Second)},
		{strings.Replace(string(raw), "10.203.36.3", "127.0.0.1", 1), now.Add(DispatchWindow)}} {
		if _, err := ReadAction([]byte(invalid.json), now, invalid.expires); !errors.Is(err, ErrInput) {
			t.Fatal("无效命令通过", err)
		}
	}
	result := Result{a.RequestID, a.ConfigSHA256, a.Flow, a.LeaseUntil, now.Add(time.Second)}
	body, _ := json.Marshal(result)
	if err := VerifyResult(body, a, now, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	result.Flow.DestinationPort++
	body, _ = json.Marshal(result)
	if err := VerifyResult(body, a, now, now.Add(2*time.Second)); !errors.Is(err, ErrUnknown) {
		t.Fatal("另一连接回执通过", err)
	}
}

func chainFixture(f Flow) []byte {
	ip := "ip"
	if f.SourceIP.Is6() {
		ip = "ip6"
	}
	chain := map[string]any{"family": "inet", "table": table, "name": "forwarding", "type": "filter", "hook": "forward"}
	results := []map[string]any{{"chain": chain}}
	for _, fields := range [][4]string{{"saddr", "sport", "daddr", "dport"}, {"daddr", "dport", "saddr", "sport"}} {
		concat := []map[string]any{}
		for i, name := range fields {
			protocol := ip
			if i%2 == 1 {
				protocol = f.Transport
			}
			concat = append(concat, map[string]any{"payload": map[string]string{"protocol": protocol, "field": name}})
		}
		match := map[string]any{"op": "==", "right": "@" + f.setName(), "left": map[string]any{"concat": concat}}
		rule := map[string]any{"family": "inet", "table": table, "chain": "forwarding",
			"expr": []map[string]any{{"match": match}, {"counter": map[string]int{"packets": 0}}, {"drop": nil}}}
		results = append(results, map[string]any{"rule": rule})
	}
	raw, _ := json.Marshal(map[string]any{"nftables": results})
	return raw
}

func elementFixture(f Flow, owner string, expires int) []byte {
	entry := map[string]any{"comment": owner, "timeout": 10, "expires": expires,
		"val": map[string]any{"concat": []any{f.SourceIP, f.SourcePort, f.DestinationIP, f.DestinationPort}}}
	set := map[string]any{"family": "inet", "table": table, "name": f.setName(), "flags": []string{"timeout"},
		"elem": []map[string]any{{"elem": map[string]any{"comment": "retained_other_entry"}}, {"elem": entry}}}
	raw, _ := json.Marshal(map[string]any{"nftables": []map[string]any{{"metainfo": map[string]int{"json_schema_version": 1}}, {"set": set}}})
	return raw
}

func TestGatewayNFTOnlyCreatesOneTimedElementAndChecksExactReadback(t *testing.T) {
	config := testLocal()
	path := filepath.Join(t.TempDir(), "gateway.json")
	configRaw, _ := json.Marshal(config)
	if err := os.WriteFile(path, configRaw, 0600); err != nil {
		t.Fatal(err)
	}
	flow := testFlow("fd12:35::3", "fd12:36::3", "udp")
	currentChain := chainFixture(flow)
	currentSet := elementFixture(flow, "task_gateway", 6)
	var writes [][]string
	s := &Service{path: path, nft: func(_ context.Context, args ...string) ([]byte, error) {
		switch strings.Join(args[:4], " ") {
		case "-j -n list chain":
			return currentChain, nil
		case "-j -n list set":
			return currentSet, nil
		case "create element inet starbeacon_gateway":
			writes = append(writes, args)
			// 模拟提交确认丢失。独立读取允许认领原始条目。
			return nil, errors.New("确认丢失")
		default:
			t.Fatal("出现预期之外的防火墙操作", args)
			return nil, nil
		}
	}}
	health := s.Health(t.Context())
	if health == nil || *health != config.Binding() {
		t.Fatal("没有发布当前本地配置摘要")
	}
	a := Action{RequestID: "gateway_plan", ConfigSHA256: health.ConfigSHA256, Flow: flow, LeaseUntil: time.Now().Add(12 * time.Second)}
	r, code, err := s.Apply(t.Context(), "task_gateway", a, time.Now().Add(4*time.Second))
	if err != nil || code != "" || r.Flow != flow || !r.LeaseUntil.Equal(a.LeaseUntil) || len(writes) != 1 {
		t.Fatal("已存在的原始限时条目未被核验", r, code, err)
	}
	if writes[0][4] != "udp6" || writes[0][6] != "fd12:35::3 . 45678 . fd12:36::3 . 8080" ||
		writes[0][7] != "timeout" || writes[0][10] != `"task_gateway"` {
		t.Fatal("网关写入超过单条连接", writes[0])
	}
	for _, set := range [][]byte{elementFixture(flow, "different_owner", 6), elementFixture(flow, "task_gateway", 999),
		elementFixture(testFlow("fd12:35::9", "fd12:36::3", "udp"), "task_gateway", 6), []byte("{")} {
		currentSet = set
		before := len(writes)
		_, code, err := s.Apply(t.Context(), "task_gateway", a, time.Now().Add(4*time.Second))
		if !errors.Is(err, ErrUnknown) || code != "result_unknown" || len(writes) != before+1 {
			t.Fatal("未知调用未保留原状态或重复写入", code, err)
		}
	}
	outOfScope := a
	outOfScope.Flow = testFlow("fd12:35::3", "fd12:37::3", "udp")
	before := len(writes)
	if _, _, err := s.Apply(t.Context(), "task_gateway", outOfScope, time.Now().Add(4*time.Second)); !errors.Is(err, ErrIneligible) || len(writes) != before {
		t.Fatal("越出本地范围的请求改变了防火墙", err)
	}
	if _, _, err := s.Apply(t.Context(), "task_gateway", a, time.Now().Add(-time.Second)); !errors.Is(err, ErrIneligible) || len(writes) != before {
		t.Fatal("过期授权写入防火墙", err)
	}
	currentChain = []byte(strings.ReplaceAll(string(currentChain), `"drop":null`, `"accept":null`))
	if _, _, err := s.Apply(t.Context(), "task_gateway", a, time.Now().Add(4*time.Second)); !errors.Is(err, ErrUnavailable) || len(writes) != before {
		t.Fatal("转发链缺少准确丢弃动作仍然写入", err)
	}
	var buffer boundedBuffer
	if _, err := buffer.Write(make([]byte, 64*1024)); err != nil {
		t.Fatal(err)
	}
	if _, err := buffer.Write([]byte{1}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("命令输出超限未受约束", err)
	}
}

func TestLocalGatewaySwitchRejectsUntrustedFileWithoutFirewallCalls(t *testing.T) {
	if NewService("") != nil {
		t.Fatal("未提供路径却创建可执行服务")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.json")
	s := &Service{path: path, nft: func(context.Context, ...string) ([]byte, error) {
		t.Fatal("无本地许可时访问防火墙")
		return nil, nil
	}}
	var disabled *Service
	if disabled.Health(t.Context()) != nil {
		t.Fatal("默认开启网关能力")
	}
	if _, _, err := disabled.Apply(t.Context(), "", Action{}, time.Time{}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("默认关闭的服务接受了命令", err)
	}
	for _, body := range []string{strings.Repeat("x", configLimit+1), `{"enabled":true,"enabled":false}`,
		`{"enabled":false}`, `{"enabled":true,"scope":{"sources":[],"destinations":[]}}`} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if s.Health(t.Context()) != nil {
			t.Fatal("无有效本地许可仍公布网关能力")
		}
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if s.Health(t.Context()) != nil {
		t.Fatal("组或其他用户可以写入配置")
	}
	s.path = filepath.Join(dir, "link.json")
	if err := os.Symlink(path, s.path); err != nil {
		t.Fatal(err)
	}
	if s.Health(t.Context()) != nil {
		t.Fatal("跟随了本地网关设置链接")
	}
}

func TestGatewayFailsClosedWhenForwardingOrLocalConfigIsUnavailable(t *testing.T) {
	config := testLocal()
	path := filepath.Join(t.TempDir(), "gateway.json")
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" {
		s := NewService(path)
		if s == nil || s.path != path {
			t.Fatal("受控网关本地服务未接入已配置的入口")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := s.nft(ctx, "--version"); err == nil {
			t.Fatal("取消的只读命令仍然启动本地进程")
		}
	}
	f := testFlow("10.203.35.3", "10.203.36.3", "tcp")
	match := string(chainFixture(f))
	cases := []struct {
		name, chain string
		expectsLive bool
	}{
		{"缺少转发钩子", strings.Replace(match, `"hook":"forward"`, `"hook":"input"`, 1), false},
		{"不合法的规则文档", "{", false},
		{"五元组集合不对应", strings.ReplaceAll(match, `"@tcp4"`, `"@udp4"`), true},
		{"端口协议不对应", strings.ReplaceAll(match, `"protocol":"tcp"`, `"protocol":"udp"`), true},
		{"地址字段不对应", strings.ReplaceAll(match, `"field":"saddr"`, `"field":"nonmatching"`), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{path: path, nft: func(_ context.Context, args ...string) ([]byte, error) {
				if args[2] != "list" || args[3] != "chain" {
					t.Fatal("链结构不符时仍操作限时集合", args)
				}
				return []byte(tc.chain), nil
			}}
			if (s.Health(t.Context()) != nil) != tc.expectsLive {
				t.Fatal("转发链备妥状态错误")
			}
			a := Action{RequestID: "gateway_plan", ConfigSHA256: config.Binding().ConfigSHA256, Flow: f, LeaseUntil: time.Now().Add(12 * time.Second)}
			if _, code, err := s.Apply(t.Context(), "task_gateway", a, time.Now().Add(4*time.Second)); code != "gateway_unavailable" || !errors.Is(err, ErrUnavailable) {
				t.Fatal("不符合结构的防火墙得到可信回执", code, err)
			}
		})
	}
	s := &Service{path: filepath.Join(t.TempDir(), "missing.json")}
	if _, code, err := s.Apply(t.Context(), "task_gateway", Action{}, time.Now().Add(time.Second)); code != "gateway_unavailable" || !errors.Is(err, ErrUnavailable) {
		t.Fatal("本地配置文件缺失时产生执行回执", code, err)
	}
}
