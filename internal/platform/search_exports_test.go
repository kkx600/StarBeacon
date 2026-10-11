package platform

import (
	"context"
	"errors"
	"testing"
)

func TestExportLocalBudgetBoundsConcurrencyAndReleasesTenant(t *testing.T) {
	a := &API{}
	releaseA, err := a.exportSlot(context.Background(), "tenant_a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.exportSlot(context.Background(), "tenant_a"); !errors.Is(err, errExportBusy) {
		t.Fatal("相同租户重复取得导出额度", err)
	}
	releaseB, err := a.exportSlot(context.Background(), "tenant_b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.exportSlot(context.Background(), "tenant_c"); !errors.Is(err, errExportBusy) {
		t.Fatal("实例并发额度没有生效", err)
	}
	releaseA()
	releaseC, err := a.exportSlot(context.Background(), "tenant_c")
	if err != nil {
		t.Fatal("结束任务未释放额度", err)
	}
	releaseB()
	releaseC()
	if len(a.exportActive) != 0 {
		t.Fatal("额度索引残留")
	}
}
