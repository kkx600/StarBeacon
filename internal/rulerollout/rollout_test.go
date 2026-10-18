package rulerollout

import (
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/rulesync"
)

func valid() Create {
	return Create{ID: "rollout_test", Spec: Spec{Name: "办公探针规则发布", Plans: []Selection{{"sync_a", 1}, {"sync_b", 2}, {"sync_c", 1}, {"sync_d", 1}}, CanaryCount: 1, BatchSize: 2, ObservationSeconds: 30, TimeoutSeconds: 300}}
}
func TestFrozenSelectionAndBounds(t *testing.T) {
	c := valid()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for i, want := range []int{0, 1, 1, 2} {
		if c.Spec.Batch(i) != want {
			t.Fatal("批次边界错误", i)
		}
	}
	if c.Spec.Batch(-1) != -1 || c.Spec.Batch(4) != -1 {
		t.Fatal("越界目标被编入批次")
	}
	for _, change := range []func(*Create){
		func(c *Create) { c.ID = "bad/id" }, func(c *Create) { c.Spec.Name = "" }, func(c *Create) { c.Spec.Name = " 空白" }, func(c *Create) { c.Spec.Name = "非法\n名称" }, func(c *Create) { c.Spec.Name = string([]byte{0xff}) }, func(c *Create) { c.Spec.Name = strings.Repeat("名", 129) },
		func(c *Create) { c.Spec.Plans = nil }, func(c *Create) { c.Spec.Plans = c.Spec.Plans[:1] }, func(c *Create) { c.Spec.Plans = make([]Selection, 201) }, func(c *Create) { c.Spec.Plans[1] = c.Spec.Plans[0] }, func(c *Create) { c.Spec.Plans[0].PlanID = "bad/id" }, func(c *Create) { c.Spec.Plans[0].Revision = 0 }, func(c *Create) { c.Spec.Plans[0].Revision = rulesync.MaxRevision }, func(c *Create) { c.Spec.Plans[0].Revision = rulesync.MaxRevision - 1 },
		func(c *Create) { c.Spec.CanaryCount = 0 }, func(c *Create) { c.Spec.CanaryCount = 21 }, func(c *Create) { c.Spec.CanaryCount = 4 }, func(c *Create) { c.Spec.BatchSize = 0 }, func(c *Create) { c.Spec.BatchSize = 21 }, func(c *Create) { c.Spec.ObservationSeconds = 29 }, func(c *Create) { c.Spec.ObservationSeconds = 3601 }, func(c *Create) { c.Spec.TimeoutSeconds = 299 }, func(c *Create) { c.Spec.TimeoutSeconds = 86401 }, func(c *Create) { c.Spec.TimeoutSeconds = 300; c.Spec.ObservationSeconds = 300 },
	} {
		bad := valid()
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("非法范围被接受", bad)
		}
	}
	c.Spec.BatchSize = 0
	if c.Spec.Batch(1) != -1 {
		t.Fatal("非法批次大小未拒绝")
	}
	for _, reason := range []string{"", " 需要停止", "停止\n发布", strings.Repeat("停", 513), string([]byte{0xff})} {
		if (Stop{reason}).Validate() == nil {
			t.Fatal("停止原因未校验")
		}
	}
	if (Stop{"现场维护，停止后续发布"}).Validate() != nil {
		t.Fatal("有效原因未接受")
	}
	for _, s := range []string{"succeeded", "stopped", "blocked"} {
		if !Terminal(s) {
			t.Fatal(s)
		}
	}
	if Terminal("stopping") {
		t.Fatal("等待在途回执被误报终止")
	}
	for _, c := range [][3]string{{"succeeded", "observing", "observed"}, {"succeeded", "observed", "observed"}, {"observing", "observing", "observing"}, {"blocked", "target_failed", "target_failed"}} {
		if RecordCode(c[0], c[1]) != c[2] {
			t.Fatal("终态与原因码矛盾", c)
		}
	}
	a := rulesync.Spec{PackageID: "p", PackageRevision: 1, PositiveSampleID: "hit", NegativeSampleID: "miss"}
	b := a
	b.SensorID = "other"
	if !SameRelease(a, b) {
		t.Fatal("设备不同被误认为规则不同")
	}
	b.PackageRevision = 2
	if SameRelease(a, b) {
		t.Fatal("混合修订被接受")
	}
}
