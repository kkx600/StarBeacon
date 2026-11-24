package contract

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SharedIndexPrefix 标识全部租户共享的事件索引。
const SharedIndexPrefix = "sb-v2-"

// IndexPeriod 是共享索引的时间粒度。索引名称在路由创建时冻结，修改粒度只影响新路由。
type IndexPeriod string

const (
	PeriodDay   IndexPeriod = "day"
	PeriodWeek  IndexPeriod = "week"
	PeriodMonth IndexPeriod = "month"
)

var periodCodes = map[IndexPeriod]string{PeriodDay: "d", PeriodWeek: "w", PeriodMonth: "m"}

func ParseIndexPeriod(value string) (IndexPeriod, error) {
	period := IndexPeriod(value)
	if _, ok := periodCodes[period]; !ok {
		return "", fmt.Errorf("索引时间粒度仅支持 day、week 或 month")
	}
	return period, nil
}

// SpanDays 是分区可覆盖的最长天数；生命周期从分区起点计算，额外等待这一跨度，使分区内每条记录至少保留设定天数。
func (p IndexPeriod) SpanDays() int {
	switch p {
	case PeriodWeek:
		return 7
	case PeriodMonth:
		return 31
	}
	return 1
}

// StreamLayout 是单个数据流的新建索引布局。
type StreamLayout struct {
	Period IndexPeriod
	Shards int
}

// IndexLayout 只影响此后新建的共享索引；既有索引沿用创建时的分片与副本。
type IndexLayout struct {
	Alerts, Context, Logs StreamLayout
	Replicas              int
}

// DefaultIndexLayout 让低量告警与日志按周分区、高量协议记录按日分区，单分片起步，副本数由部署配置。
func DefaultIndexLayout() IndexLayout {
	return IndexLayout{Alerts: StreamLayout{PeriodWeek, 1}, Context: StreamLayout{PeriodDay, 1}, Logs: StreamLayout{PeriodWeek, 1}, Replicas: 1}
}

// For 返回数据流的布局，未设置的字段使用默认值。
func (l IndexLayout) For(stream string) StreamLayout {
	defaults := DefaultIndexLayout()
	v, fallback := StreamLayout{}, StreamLayout{}
	switch stream {
	case "alerts":
		v, fallback = l.Alerts, defaults.Alerts
	case "context":
		v, fallback = l.Context, defaults.Context
	case "logs":
		v, fallback = l.Logs, defaults.Logs
	}
	if _, ok := periodCodes[v.Period]; !ok {
		v.Period = fallback.Period
	}
	if v.Shards < 1 {
		v.Shards = fallback.Shards
	}
	return v
}

// ParseIndexLayout 读取 “数据流=取值” 列表或作用于全部数据流的单个取值，例如 alerts=week,context=day,logs=week。
func ParseIndexLayout(periods, shards string, replicas int) (IndexLayout, error) {
	layout := DefaultIndexLayout()
	if replicas < 0 || replicas > 5 {
		return layout, fmt.Errorf("索引副本数必须为 0–5")
	}
	layout.Replicas = replicas
	targets := map[string]*StreamLayout{"alerts": &layout.Alerts, "context": &layout.Context, "logs": &layout.Logs}
	apply := func(spec, name string, set func(*StreamLayout, string) error) error {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			return nil
		}
		if !strings.Contains(spec, "=") {
			for _, target := range targets {
				if err := set(target, spec); err != nil {
					return err
				}
			}
			return nil
		}
		seen := map[string]bool{}
		for _, part := range strings.Split(spec, ",") {
			key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			target, known := targets[strings.TrimSpace(key)]
			if !ok || !known || seen[key] {
				return fmt.Errorf("%s 只接受 alerts、context、logs 各一次", name)
			}
			seen[key] = true
			if err := set(target, strings.TrimSpace(value)); err != nil {
				return err
			}
		}
		return nil
	}
	if err := apply(periods, "索引时间粒度", func(t *StreamLayout, value string) error {
		period, err := ParseIndexPeriod(value)
		t.Period = period
		return err
	}); err != nil {
		return layout, err
	}
	err := apply(shards, "索引主分片数", func(t *StreamLayout, value string) error {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 64 {
			return fmt.Errorf("索引主分片数必须为 1–64")
		}
		t.Shards = n
		return nil
	})
	return layout, err
}

func periodStart(period IndexPeriod, day time.Time) time.Time {
	day = time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC)
	switch period {
	case PeriodWeek:
		return day.AddDate(0, 0, -((int(day.Weekday()) + 6) % 7))
	case PeriodMonth:
		return time.Date(day.Year(), day.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
	return day
}

func periodEnd(period IndexPeriod, start time.Time) time.Time {
	switch period {
	case PeriodWeek:
		return start.AddDate(0, 0, 7)
	case PeriodMonth:
		return start.AddDate(0, 1, 0)
	}
	return start.AddDate(0, 0, 1)
}

// EventIndexName 返回路由日所在的共享索引：同一数据流、保留期和时间分区的全部租户写入同一索引。
// 协议记录和日志的新分区在数据流后带 logsdb，既有冻结路由沿用原索引名。
func EventIndexName(stream string, days int, period IndexPeriod, day string) (string, error) {
	code, ok := periodCodes[period]
	if !ValidStream(stream) || days < 1 || days > 3650 || !ok {
		return "", fmt.Errorf("共享索引身份不合法")
	}
	parsed, err := time.Parse("2006-01-02", day)
	if err != nil {
		return "", err
	}
	name := SharedIndexPrefix + stream
	if stream != "alerts" {
		name += "-logsdb"
	}
	return name + "-r" + strconv.Itoa(days) + "-" + code + periodStart(period, parsed).Format("2006.01.02"), nil
}

// EventIndex 是解析后的共享索引身份；索引同时承载多个租户，隔离依赖文档 tenant_id。
type EventIndex struct {
	Name, Stream string
	LogsDB       bool
	Days         int
	Period       IndexPeriod
	Start, End   time.Time
}

// Covers 判断路由日是否位于索引的时间分区内。
func (v EventIndex) Covers(day string) bool {
	parsed, err := time.Parse("2006-01-02", day)
	return err == nil && !parsed.Before(v.Start) && parsed.Before(v.End)
}

var sharedIndex = regexp.MustCompile(`^sb-v2-(alerts|context|logs)(-logsdb)?-r([1-9][0-9]{0,3})-([dwm])([0-9]{4}\.[0-9]{2}\.[0-9]{2})$`)

func ParseEventIndex(name string) (EventIndex, error) {
	if match := sharedIndex.FindStringSubmatch(name); match != nil {
		logsDB := match[2] != ""
		days, _ := strconv.Atoi(match[3])
		var period IndexPeriod
		for candidate, code := range periodCodes {
			if code == match[4] {
				period = candidate
			}
		}
		start, err := time.Parse("2006.01.02", match[5])
		if err != nil || days > 3650 || logsDB && match[1] == "alerts" || !periodStart(period, start).Equal(start) {
			return EventIndex{}, fmt.Errorf("共享索引分区无效")
		}
		return EventIndex{Name: name, Stream: match[1], LogsDB: logsDB, Days: days, Period: period, Start: start, End: periodEnd(period, start)}, nil
	}
	return EventIndex{}, fmt.Errorf("索引名称不属于事件数据流")
}

// IndexServes 判断检索命中的物理索引是否属于该数据流的共享索引；租户隔离由文档 tenant_id 过滤与回读核对。
func IndexServes(name, stream string) bool {
	v, err := ParseEventIndex(name)
	return err == nil && v.Stream == stream
}

// SearchIndex 返回数据流的检索表达式。表达式本身不构成隔离，调用方必须同时在查询中强制过滤 tenant_id。
func SearchIndex(stream string) string {
	return SharedIndexPrefix + stream + "-*"
}
