package searchfilter

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestDatasetCatalogAndCompilerShareTheAllowedFields(t *testing.T) {
	for _, dataset := range []string{"alerts", "context"} {
		catalog, err := CatalogForDataset(dataset)
		if err != nil || len(catalog) == 0 {
			t.Fatal(dataset, err)
		}
		for _, field := range catalog {
			for _, name := range append([]string{field.Name}, field.Aliases...) {
				actual, err := CompileForDataset(name, dataset)
				if err != nil {
					t.Fatal("目录中存在不可使用的字段", dataset, name, err)
				}
				expected, err := Compile(name)
				if err != nil || !reflect.DeepEqual(actual, expected) {
					t.Fatal("同一字段在数据集中的语义变化", dataset, name, err)
				}
			}
		}
	}
	for _, expression := range []string{"rule.id", "suricata.sid == 1", "not (tcp or severity == high)", "evidence_status", "suricata.action"} {
		if _, err := CompileForDataset(expression, "alerts"); err != nil {
			t.Fatal("告警合法字段被拒绝", expression, err)
		}
		if _, err := CompileForDataset(expression, "context"); err == nil {
			t.Fatal("协议校验接受了告警字段或别名", expression)
		}
	}
	for _, dataset := range []string{"", "tenant_foreign", "context*"} {
		if _, err := CatalogForDataset(dataset); err == nil {
			t.Fatal("接受了未知数据集", dataset)
		}
		if _, err := CompileForDataset("", dataset); err == nil {
			t.Fatal("空表达式绕过数据集校验", dataset)
		}
	}
	catalog, _ := CatalogForDataset("context")
	catalog[0].Aliases[0] = "private_alias"
	catalog[0].Paths[0] = "tenant_id"
	catalog[0].Operators[0] = "script"
	query, err := Compile("ip.src == 192.0.2.1")
	encoded, _ := json.Marshal(query)
	if err != nil || strings.Contains(string(encoded), "tenant_id") || !strings.Contains(string(encoded), "source.ip") {
		t.Fatal("调用方目录修改污染了编译器", string(encoded), err)
	}
}
