package assistant

import (
	"testing"
	"time"
)

func TestReportPlanCalendarPeriodsAndPersistentSlots(t *testing.T) {
	for _, item := range []struct {
		kind, now, next, period, start, end string
	}{
		{"daily", "2026-10-03T00:00:00Z", "2026-10-03T01:00:00Z", "2026-10-02", "2026-10-01T16:00:00Z", "2026-10-02T16:00:00Z"},
		{"weekly", "2026-10-04T12:00:00Z", "2026-10-05T01:00:00Z", "2026-09-28", "2026-09-27T16:00:00Z", "2026-10-04T16:00:00Z"},
		{"monthly", "2026-10-31T12:00:00Z", "2026-11-01T01:00:00Z", "2026-10-01", "2026-09-30T16:00:00Z", "2026-10-31T16:00:00Z"},
	} {
		t.Run(item.kind, func(t *testing.T) {
			spec := PlanSpec{Name: "周期报告", Kind: item.kind, Timezone: "Asia/Shanghai", At: "09:00", Enabled: true}
			now, _ := time.Parse(time.RFC3339, item.now)
			next, err := spec.Next(now)
			if err != nil || next.Format(time.RFC3339) != item.next {
				t.Fatal("自然周期调度不一致", next, err)
			}
			r, err := spec.RequestAt(next)
			if err != nil || r.Period != item.period || r.Window.Start.Format(time.RFC3339) != item.start || r.Window.End.Format(time.RFC3339) != item.end {
				t.Fatal("报告覆盖的不是前一完整周期", r, err)
			}
			latest, err := spec.Latest(next)
			if err != nil || !latest.Equal(next) {
				t.Fatal("精确槽位不应回到更早周期", latest, err)
			}
			following, err := spec.Next(next)
			if err != nil || !following.After(next) {
				t.Fatal("下一槽位重复", following, err)
			}
		})
	}
}

func TestReportPlanDSTAmbiguitySkippedMinutesAndMonthLength(t *testing.T) {
	for _, item := range []struct {
		at, now, next string
	}{
		{"02:30", "2026-03-08T05:00:00Z", "2026-03-08T07:00:00Z"},
		{"01:30", "2026-11-01T04:00:00Z", "2026-11-01T05:30:00Z"},
	} {
		spec := PlanSpec{Name: "日历验证", Kind: "daily", Timezone: "America/New_York", At: item.at}
		now, _ := time.Parse(time.RFC3339, item.now)
		next, err := spec.Next(now)
		if err != nil || next.Format(time.RFC3339) != item.next {
			t.Fatal("夏令时槽位不确定", next, err)
		}
		if _, err := spec.RequestAt(next.Add(time.Minute)); err == nil {
			t.Fatal("非槽位时刻得到执行许可")
		}
	}
	monthly := PlanSpec{Name: "月报", Kind: "monthly", Timezone: "America/New_York", At: "09:00"}
	due, _ := time.Parse(time.RFC3339, "2026-12-01T14:00:00Z")
	request, err := monthly.RequestAt(due)
	if err != nil || request.Window.End.Sub(request.Window.Start) != 30*24*time.Hour+time.Hour {
		t.Fatal("月报丢失夏令时小时", request, err)
	}
	latest, err := monthly.Latest(due.Add(-time.Minute))
	if err != nil || latest.Format(time.RFC3339) != "2026-11-01T14:00:00Z" {
		t.Fatal("月初未到执行时刻应回读上一槽位", latest, err)
	}
	spec := PlanSpec{Name: "日历换日", Kind: "daily", Timezone: "Pacific/Apia", At: "09:00"}
	now, _ := time.Parse(time.RFC3339, "2011-12-29T20:00:00Z")
	next, err := spec.Next(now)
	if err != nil || next.Format(time.RFC3339) != "2011-12-30T19:00:00Z" {
		t.Fatal("缺失自然日不得伪装为可执行槽位", next, err)
	}
}

func TestReportPlanRejectsInvalidClockContextIdentityAndCalendar(t *testing.T) {
	valid := PlanSpec{Name: "安全日报", Kind: "daily", Timezone: "Asia/Shanghai", At: "09:00"}
	invalid := []PlanSpec{valid}
	invalid[0].Name = ""
	for _, mutate := range []func(*PlanSpec){
		func(s *PlanSpec) { s.Kind = "chat" }, func(s *PlanSpec) { s.Timezone = "Local" }, func(s *PlanSpec) { s.Timezone = "../etc" }, func(s *PlanSpec) { s.Timezone = "invalid/zone" }, func(s *PlanSpec) { s.At = "9:00" }, func(s *PlanSpec) { s.At = "24:00" }, func(s *PlanSpec) { s.AllowContext = true }, func(s *PlanSpec) { s.ProviderRevision = 1 }, func(s *PlanSpec) { s.ProviderID = "bad/id"; s.ProviderRevision = 1; s.AllowContext = true }, func(s *PlanSpec) { s.ProviderID = "provider_owned"; s.ProviderRevision = 1 }, func(s *PlanSpec) {
			s.ProviderID = "provider_owned"
			s.ProviderRevision = 1 << 53
			s.AllowContext = true
		},
	} {
		spec := valid
		mutate(&spec)
		invalid = append(invalid, spec)
	}
	for _, spec := range invalid {
		if spec.Validate() == nil {
			t.Fatal("无效计划得到许可", spec)
		}
		if _, err := spec.Next(time.Now()); err == nil {
			t.Fatal("无效计划取得槽位")
		}
		if _, err := spec.Latest(time.Now()); err == nil {
			t.Fatal("无效计划取得历史槽位")
		}
		if _, err := spec.RequestAt(time.Now()); err == nil {
			t.Fatal("无效计划取得报告范围")
		}
	}
	for _, operation := range []func(time.Time) (time.Time, error){valid.Next, valid.Latest} {
		if _, err := operation(time.Time{}); err == nil {
			t.Fatal("零时间得到许可")
		}
	}
	if _, err := valid.RequestAt(time.Time{}); err == nil {
		t.Fatal("零时间生成报告")
	}
	args := PlanArgs{TenantID: "tenant_owned", PlanID: "plan_owned", Revision: 1, DueAt: time.Now()}
	if args.Validate() != nil || args.Kind() != "starbeacon.report_plan" {
		t.Fatal("计划队列参数不一致")
	}
	for _, mutate := range []func(*PlanArgs){func(a *PlanArgs) { a.TenantID = "" }, func(a *PlanArgs) { a.PlanID = "../plan" }, func(a *PlanArgs) { a.Revision = 0 }, func(a *PlanArgs) { a.Revision = 1 << 53 }, func(a *PlanArgs) { a.DueAt = time.Time{} }} {
		bad := args
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("无效队列参数得到许可")
		}
	}
}
