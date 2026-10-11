package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func raw(t *testing.T, value any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func TestAssetInterfacesAndNetworkCanonicalization(t *testing.T) {
	asset := Asset{Name: "业务服务器", Owner: "安全运营", GroupID: "group_prod", NetworkDomain: "office", Criticality: "high", Active: true, Interfaces: []Interface{{Name: "eth0", MAC: "AA-BB-CC-DD-EE-FF", IPs: []string{"192.0.2.1", "2001:0db8:0:0::1"}}}}
	value, err := Validate("assets", raw(t, asset))
	if err != nil {
		t.Fatal(err)
	}
	var normalized Asset
	if err := json.Unmarshal(value.Data, &normalized); err != nil {
		t.Fatal(err)
	}
	if normalized.Interfaces[0].MAC != "aa:bb:cc:dd:ee:ff" || normalized.Interfaces[0].IPs[1] != "2001:db8::1" || value.GroupID != asset.GroupID || !value.Active {
		t.Fatal("资产标识标准化不一致")
	}
	for _, prefix := range []string{"192.0.2.100/24", "2001:db8::abcd/32"} {
		v, err := Validate("networks", raw(t, Network{Name: "业务网段", Prefix: prefix, NetworkDomain: "office", Purpose: "internal", Active: true}))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(v.Data), "192.0.2.100") || strings.Contains(string(v.Data), "::abcd") {
			t.Fatal("未清除 CIDR 主机位")
		}
	}
	for _, purpose := range []string{"internal", "external", "excluded"} {
		if _, err := Validate("networks", raw(t, Network{Name: "范围", Prefix: "0.0.0.0/0", NetworkDomain: "default", Purpose: purpose})); err != nil {
			t.Fatal(err)
		}
	}
	for _, criticality := range []string{"critical", "high", "normal", "low"} {
		asset.Criticality = criticality
		asset.Interfaces = nil
		if _, err := Validate("assets", raw(t, asset)); err != nil {
			t.Fatal(err)
		}
	}
	if v, err := Validate("groups", raw(t, Group{Name: "生产资产", Owner: "运维", Description: "业务责任范围", Active: true})); err != nil || v.Name != "生产资产" || v.GroupID != "" {
		t.Fatal(v, err)
	}
	for _, kind := range []string{"assets", "groups", "networks"} {
		if !ValidKind(kind) {
			t.Fatal(kind)
		}
	}
	if ValidKind("users") {
		t.Fatal("目录越界")
	}
}
func TestInvalidInventoryRecords(t *testing.T) {
	for _, kind := range []string{"assets", "groups", "networks", "other"} {
		for _, data := range []json.RawMessage{nil, []byte("null"), []byte("{"), []byte("[]"), []byte(`{"unknown":true}`), []byte(`{"name":"a"} {}`), []byte(`{"name":"` + strings.Repeat("x", 32769) + `"}`), []byte{'"', 0xff, '"'}} {
			if _, err := Validate(kind, data); err == nil {
				t.Fatal("接受无效对象", kind, string(data[:min(len(data), 60)]))
			}
		}
	}
	for _, group := range []Group{{Name: ""}, {Name: " name"}, {Name: "a\n"}, {Name: strings.Repeat("名", 129)}, {Name: "a", Owner: strings.Repeat("x", 129)}, {Name: "a", Description: strings.Repeat("x", 1025)}} {
		if _, err := Validate("groups", raw(t, group)); err == nil {
			t.Fatal("接受无效资产组")
		}
	}
	base := Asset{Name: "资产", NetworkDomain: "default", Criticality: "normal", Interfaces: []Interface{{Name: "eth0"}}}
	mutations := []func(*Asset){func(a *Asset) { a.Name = "" }, func(a *Asset) { a.Owner = "\x00" }, func(a *Asset) { a.NetworkDomain = "" }, func(a *Asset) { a.Description = strings.Repeat("x", 1025) }, func(a *Asset) { a.Criticality = "undefined" }, func(a *Asset) { a.Interfaces = make([]Interface, 33) }, func(a *Asset) { a.Interfaces = []Interface{{Name: "eth0"}, {Name: "eth0"}} }, func(a *Asset) { a.Interfaces = []Interface{{Name: ""}} }, func(a *Asset) { a.Interfaces = []Interface{{Name: "eth0", IPs: make([]string, 33)}} }, func(a *Asset) { a.Interfaces[0].MAC = "invalid" }, func(a *Asset) { a.Interfaces[0].MAC = "00:11:22:33:44:55:66:77" }, func(a *Asset) { a.Interfaces[0].IPs = []string{"wrong"} }, func(a *Asset) { a.Interfaces[0].IPs = []string{"fe80::1%eth0"} }, func(a *Asset) { a.Interfaces[0].IPs = []string{"192.0.2.1", "::ffff:192.0.2.1"} }}
	for i, mutate := range mutations {
		a := base
		a.Interfaces = append([]Interface{}, base.Interfaces...)
		mutate(&a)
		if _, err := Validate("assets", raw(t, a)); err == nil {
			t.Fatal("接受无效资产", i)
		}
	}
	for _, network := range []Network{{Name: "", Prefix: "192.0.2.0/24", NetworkDomain: "x", Purpose: "internal"}, {Name: "n", Prefix: "wrong", NetworkDomain: "x", Purpose: "internal"}, {Name: "n", Prefix: "::ffff:192.0.2.1/128", NetworkDomain: "x", Purpose: "internal"}, {Name: "n", Prefix: "192.0.2.0/24", NetworkDomain: "x", Purpose: "unknown"}, {Name: "n", Prefix: "192.0.2.0/24", Purpose: "internal"}} {
		if _, err := Validate("networks", raw(t, network)); err == nil {
			t.Fatal("接受无效网段")
		}
	}
	if _, err := Validate("unknown", []byte(`{}`)); err == nil {
		t.Fatal("接受未声明对象")
	}
}
