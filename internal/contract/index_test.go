package contract

import "testing"

func TestSharedIndexNamesUseFrozenRetentionAndPeriodStart(t *testing.T) {
	for _, tc := range []struct {
		stream string
		days   int
		period IndexPeriod
		day    string
		want   string
	}{
		{"alerts", 180, PeriodWeek, "2026-11-05", "sb-v2-alerts-r180-w2026.11.02"},
		{"alerts", 180, PeriodWeek, "2026-11-02", "sb-v2-alerts-r180-w2026.11.02"},
		{"alerts", 180, PeriodWeek, "2026-11-08", "sb-v2-alerts-r180-w2026.11.02"},
		{"alerts", 180, PeriodWeek, "2027-01-01", "sb-v2-alerts-r180-w2026.12.28"},
		{"context", 30, PeriodDay, "2026-11-05", "sb-v2-context-r30-d2026.11.05"},
		{"logs", 3650, PeriodMonth, "2026-02-28", "sb-v2-logs-r3650-m2026.02.01"},
	} {
		got, err := EventIndexName(tc.stream, tc.days, tc.period, tc.day)
		if err != nil || got != tc.want {
			t.Fatalf("%v：得到 %q，%v", tc, got, err)
		}
		parsed, err := ParseEventIndex(got)
		if err != nil || parsed.Name != got || parsed.Stream != tc.stream || parsed.Days != tc.days || parsed.Period != tc.period || !parsed.Covers(tc.day) {
			t.Fatalf("共享索引无法还原：%+v，%v", parsed, err)
		}
	}
	week, _ := ParseEventIndex("sb-v2-alerts-r180-w2026.11.02")
	if week.Covers("2026-11-01") || week.Covers("2026-11-09") || !week.Covers("2026-11-08") || week.Covers("bad") {
		t.Fatal("周分区覆盖范围错误")
	}
	day, _ := ParseEventIndex("sb-v2-context-r30-d2026.11.05")
	if !day.Covers("2026-11-05") || day.Covers("2026-11-04") || day.Covers("2026-11-06") {
		t.Fatal("日分区覆盖范围错误")
	}
	month, _ := ParseEventIndex("sb-v2-logs-r3650-m2026.02.01")
	if !month.Covers("2026-02-01") || !month.Covers("2026-02-28") || month.Covers("2026-01-31") || month.Covers("2026-03-01") {
		t.Fatal("月分区覆盖范围错误")
	}
	for _, args := range []struct {
		stream string
		days   int
		period IndexPeriod
		day    string
	}{{"files", 180, PeriodDay, "2026-11-05"}, {"alerts", 0, PeriodDay, "2026-11-05"}, {"alerts", 3651, PeriodDay, "2026-11-05"}, {"alerts", 180, "year", "2026-11-05"}, {"alerts", 180, PeriodDay, "2026-11-31"}} {
		if _, err := EventIndexName(args.stream, args.days, args.period, args.day); err == nil {
			t.Fatalf("无效共享索引身份被接受：%v", args)
		}
	}
}

func TestEventIndexParsingRejectsForeignAndNonCanonicalNames(t *testing.T) {
	// 旧版租户日索引已不属于事件数据流，与其他非规范名称一样拒绝。
	for _, name := range []string{"", "sb-alerts-tenant_a-2026.10.03", "sb-context-tenant-a-b-2026.10.03", "sb-logs-tenant_a-2026.10.03", "sb-v2-alerts-r180-w2026.11.03", "sb-v2-alerts-r180-m2026.11.02", "sb-v2-alerts-r0-d2026.11.02", "sb-v2-alerts-r3651-d2026.11.02", "sb-v2-alerts-r0180-d2026.11.02", "sb-v2-files-r180-d2026.11.02", "sb-v2-alerts-r180-d2026.02.30", "sb-v2-alerts-r180-d2026.11.02-alias", "sb-alerts-tenant_a-2026.10.03-alias", "sb-alerts-tenant_a-2026.02.30", "sb-alerts--2026.10.03", "other-tenant_a-2026.10.03"} {
		if _, err := ParseEventIndex(name); err == nil {
			t.Fatalf("旧版或非规范索引被接受：%q", name)
		}
	}
	for _, tc := range []struct {
		index, stream string
		want          bool
	}{
		{"sb-v2-alerts-r180-w2026.11.02", "alerts", true},
		{"sb-v2-context-r30-d2026.11.05", "context", true},
		{"sb-v2-logs-r3650-m2026.02.01", "logs", true},
		{"sb-v2-alerts-r180-w2026.11.02", "context", false},
		{"sb-v2-logs-r3650-m2026.02.01", "alerts", false},
		{"sb-v2-alerts-r180-w2026.11.03", "alerts", false},
		{"sb-v2-alerts-r180-w2026.11.02-alias", "alerts", false},
		{"sb-alerts-tenant_a-2026.10.03", "alerts", false},
		{"sb-alerts-tenant_a-b-2026.10.03", "alerts", false},
	} {
		if got := IndexServes(tc.index, tc.stream); got != tc.want {
			t.Fatalf("%+v：得到 %v", tc, got)
		}
	}
	for _, stream := range []string{"alerts", "context", "logs"} {
		if got := SearchIndex(stream); got != "sb-v2-"+stream+"-*" {
			t.Fatalf("检索表达式错误：%v", got)
		}
	}
}

func TestIndexLayoutDefaultsOverridesAndBounds(t *testing.T) {
	zero := IndexLayout{}
	if zero.For("alerts") != (StreamLayout{PeriodWeek, 1}) || zero.For("context") != (StreamLayout{PeriodDay, 1}) || zero.For("logs") != (StreamLayout{PeriodWeek, 1}) {
		t.Fatal("零值布局未使用默认值")
	}
	layout, err := ParseIndexLayout("context=week, logs=month", "context=4", 2)
	if err != nil || layout.For("alerts") != (StreamLayout{PeriodWeek, 1}) || layout.For("context") != (StreamLayout{PeriodWeek, 4}) || layout.For("logs") != (StreamLayout{PeriodMonth, 1}) || layout.Replicas != 2 {
		t.Fatalf("分项配置未生效：%+v，%v", layout, err)
	}
	all, err := ParseIndexLayout("day", "3", 0)
	if err != nil || all.For("alerts") != (StreamLayout{PeriodDay, 3}) || all.For("logs") != (StreamLayout{PeriodDay, 3}) || all.Replicas != 0 {
		t.Fatalf("统一配置未生效：%+v，%v", all, err)
	}
	for _, args := range [][3]any{{"year", "", 1}, {"alerts=day,alerts=week", "", 1}, {"files=day", "", 1}, {"alerts", "", 1}, {"", "0", 1}, {"", "65", 1}, {"", "context=x", 1}, {"", "", -1}, {"", "", 6}} {
		if _, err := ParseIndexLayout(args[0].(string), args[1].(string), args[2].(int)); err == nil {
			t.Fatalf("无效布局被接受：%v", args)
		}
	}
	if PeriodDay.SpanDays() != 1 || PeriodWeek.SpanDays() != 7 || PeriodMonth.SpanDays() != 31 {
		t.Fatal("生命周期跨度错误")
	}
}
