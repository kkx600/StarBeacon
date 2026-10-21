package retention

import "testing"

func TestDefaultCatalogAndPublicationScope(t *testing.T) {
	if DefaultDays != 180 || len(Catalog()) != 12 {
		t.Fatal("默认期限或类别缺失")
	}
	for _, category := range Catalog() {
		if _, ok := Lookup(category.ID); !ok {
			t.Fatal("类别不可查询")
		}
		candidate := Candidate{Category: category.ID, Days: 180, ExpectedRevision: 1, ApplyMode: "future"}
		if err := candidate.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	candidate := Candidate{Category: "reports", Days: 3650, ExpectedRevision: 1, ApplyMode: "future"}
	if candidate.Validate() != nil {
		t.Fatal("合法长期策略被拒绝")
	}
	for _, invalid := range []Candidate{{Category: "unknown", Days: 180, ExpectedRevision: 1, ApplyMode: "future"}, {Category: "pcap", Days: 0, ExpectedRevision: 1, ApplyMode: "future"}, {Category: "pcap", Days: 3651, ExpectedRevision: 1, ApplyMode: "future"}, {Category: "pcap", Days: 180, ExpectedRevision: 0, ApplyMode: "future"}, {Category: "pcap", Days: 180, ExpectedRevision: 1, ApplyMode: "recompute"}} {
		if invalid.Validate() == nil {
			t.Fatal("无效策略被接受")
		}
	}
	copy := Catalog()
	copy[0].ID = "changed"
	if _, ok := Lookup("alerts"); !ok {
		t.Fatal("外部修改污染分类目录")
	}
}
