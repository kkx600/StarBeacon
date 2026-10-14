package searchfilter

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func jsonQuery(t *testing.T, source string) string {
	t.Helper()
	v, err := Compile(source)
	if err != nil {
		t.Fatalf("%s: %v", source, err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestComparisonsAndProtocolGuards(t *testing.T) {
	cases := []struct {
		source    string
		fragments []string
	}{
		{`http.request.method == "get" and http.request.uri contains "/admin?x=*"`, []string{`"http.method":"GET"`, `"network.protocol":"http"`, `*`}},
		{`tcp.port in {80 443 8000..8080} && not ip.addr == 192.0.2.1`, []string{`"network.transport":"tcp"`, `"gte":8000`, `"lte":8080`, `"must_not"`, `"minimum_should_match":1`}},
		{`(udp.dstport ge 0x35 or dns) and eth.src == "AA-BB-CC-DD-EE-FF"`, []string{`"gte":53`, `"source.mac":"aa:bb:cc:dd:ee:ff"`, `"network.protocol":"dns"`}},
		{`ipv6.addr in {2001:db8::/32}`, []string{`"source.ip":"0.0.0.0/0"`, `"must_not"`, `"destination.ip":"2001:db8::/32"`}},
		{`frame.time >= "2026-10-01T12:00:00+08:00"`, []string{`"gte":"2026-10-01T04:00:00Z"`}},
		{`suricata.flow_id == 18446744073709551615`, []string{`"suricata.flow_id":"18446744073709551615"`}},
		{`network.transport == TCP && http.host contains "example"`, []string{`"network.transport":"tcp"`, `*example*`}},
		{`source.ip`, []string{`"exists":{"field":"source.ip"}`}},
		{`!!tls`, []string{`"network.protocol":"tls"`}},
		{`ip and eth`, []string{`"source.ip":"0.0.0.0/0"`, `"destination.ip":"0.0.0.0/0"`, `"exists":{"field":"source.mac"}`}},
		{`ipv6 && not ip`, []string{`"source.ip":"0.0.0.0/0"`, `"exists":{"field":"source.ip"}`, `"must_not"`}},
		{`ip.src > 192.0.2.0 and ipv6.dst le 2001:db8::ffff`, []string{`"gt":"192.0.2.0"`, `"source.ip":"0.0.0.0/0"`, `"lte":"2001:db8::ffff"`, `"destination.ip":"0.0.0.0/0"`, `"must_not"`}},
		{`http.path contains r"\admin\files"`, []string{`\\\\admin\\\\files`}},
	}
	for _, tc := range cases {
		t.Run(tc.source, func(t *testing.T) {
			result := jsonQuery(t, tc.source)
			for _, fragment := range tc.fragments {
				if !strings.Contains(result, fragment) {
					t.Fatalf("缺少 %s: %s", fragment, result)
				}
			}
		})
	}
}

func TestNotEqualAllValuesAndMissingFields(t *testing.T) {
	v, err := Compile(`ip.addr != 192.0.2.1`)
	if err != nil {
		t.Fatal(err)
	}
	f := v.(map[string]any)["bool"].(map[string]any)["filter"].([]any)
	if len(f) != 2 {
		t.Fatal("需要存在性和所有值不等两项")
	}
	negative := f[1].(map[string]any)["bool"].(map[string]any)["must_not"].([]any)
	if len(negative) != 1 {
		t.Fatal("否定必须保留 bool 层")
	}
	s := jsonQuery(t, `!http`)
	if !strings.Contains(s, `"must_not":[{"term":{"network.protocol":"http"}}]`) {
		t.Fatal(s)
	}
	if jsonQuery(t, `source.port ne 443`) != jsonQuery(t, `source.port != 443`) {
		t.Fatal("英文和符号运算不一致")
	}
}

func TestInvalidFiltersFailWithPosition(t *testing.T) {
	cases := []string{
		`tenant_id == "tenant_other"`, `tcp.flags.syn == 1`, `http.host matches "x.*"`, `script == "return true"`,
		`tcp.port == 65536`, `tcp.port == -1`, `tcp.port contains "80"`, `tcp.port in {80..12}`, `tcp.port in {x..12}`,
		`tcp.port in {1..2..3}`, `tcp.port in {}`, `tcp.port in 80`, `tcp.port == {80}`, `tcp.port == "08"`,
		`source.ip == nope`, `source.ip == 192.0.2.1/90`, `source.ip == fe80::1%eth0`, `source.mac == 01:02:03`,
		`source.mac == 00:11:22:33:44:55:66:77`, `rule.id == 18446744073709551616`, `rule.id == x`,
		`frame.time < "2026-10-01"`, `http contains "x"`, `http.method contains ""`, `http.path == "a\nb"`,
		`http.path == "a\u0000b"`, `http.path == "` + strings.Repeat("x", 1025) + `"`,
		`ip == true`, `ipv6 contains "x"`, `eth == true`, `source.ip > 192.0.2.0/24`, `http.path == r"unfinished`,
		`http &&`, `http | tls`, `(`, `http)`, `http.path == "unfinished`, `http.request.uri[0:2] == "xx"`,
		strings.Repeat("(", 17) + "http" + strings.Repeat(")", 17), strings.Repeat("http or ", 128) + "tls",
		`tcp.port in {` + strings.Repeat("80 ", 65) + `}`, strings.Repeat("x", 4097), string([]byte{0xff}),
	}
	for _, source := range cases {
		t.Run(source[:min(len(source), 80)], func(t *testing.T) {
			_, err := Compile(source)
			var detail *Error
			if !errors.As(err, &detail) || detail.Line < 1 || detail.Column < 1 || detail.Error() == "" {
				t.Fatalf("必须返回可定位的拒绝原因: %v", err)
			}
		})
	}
}

func TestCatalogCapabilitiesAndIsolation(t *testing.T) {
	first := Catalog()
	if len(first) != len(fields)+len(protocols)+3 {
		t.Fatal("字段目录不完整")
	}
	seen := map[string]bool{}
	for _, f := range first {
		if seen[f.Name] || f.Name == "tenant_id" || len(f.Operators) == 0 {
			t.Fatalf("非法字段目录: %+v", f)
		}
		seen[f.Name] = true
		if _, err := Compile(f.Name); err != nil {
			t.Fatalf("目录字段无法解析: %s: %v", f.Name, err)
		}
	}
	first[0].Aliases[0] = "unsafe"
	first[0].Operators[0] = "script"
	if Catalog()[0].Aliases[0] == "unsafe" || Catalog()[0].Operators[0] == "script" {
		t.Fatal("调用者修改了共享目录")
	}
	for _, source := range []string{"", " \t\n"} {
		v, err := Compile(source)
		if v != nil || err != nil {
			t.Fatal(v, err)
		}
	}
}

func FuzzCompile(f *testing.F) {
	for _, source := range []string{`tcp.port in {80 443}`, `not (http or tls)`, `ip.addr != 192.0.2.1`, `http.path contains "\""`, `ipv6.src == ::1`, "("} {
		f.Add(source)
	}
	f.Fuzz(func(t *testing.T, source string) {
		v, err := Compile(source)
		if err == nil {
			if _, e := json.Marshal(v); e != nil {
				t.Fatal(e)
			}
		}
	})
}

func BenchmarkCompile(b *testing.B) {
	for b.Loop() {
		_, err := Compile(`(tcp.port in {80 443 8000..8080} or dns) && not ip.addr in {192.0.2.0/24 198.51.100.0/24} && http.path contains "/api"`)
		if err != nil {
			b.Fatal(err)
		}
	}
}
