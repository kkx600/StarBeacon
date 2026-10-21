package syslogdata

import (
	"bytes"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	syslog "github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/leodido/go-syslog/v4/rfc5424"
)

type Parsed struct {
	ParserVersion string                       `json:"parser_version"`
	State         string                       `json:"state"`
	Reason        string                       `json:"reason"`
	TimeQuality   string                       `json:"time_quality"`
	SourceTime    *time.Time                   `json:"source_time"`
	Priority      *uint8                       `json:"priority"`
	Facility      *uint8                       `json:"facility"`
	Severity      *uint8                       `json:"severity"`
	Hostname      string                       `json:"hostname"`
	Application   string                       `json:"application"`
	ProcessID     string                       `json:"process_id"`
	MessageID     string                       `json:"message_id"`
	Message       string                       `json:"message"`
	MessageUTF8   bool                         `json:"message_utf8"`
	Structured    map[string]map[string]string `json:"structured_data"`
}

func value(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// Parse 每次以接收时间和冻结策略解析；不使用解析库的当前年份默认值。
func Parse(record Record, raw []byte) Parsed {
	out := Parsed{ParserVersion: ParserVersion, State: "quarantined", Reason: "invalid_syslog", TimeQuality: "unavailable", Structured: map[string]map[string]string{}}
	var base syslog.Base
	switch record.Binding.Format {
	case "rfc5424":
		m, err := rfc5424.NewParser().Parse(raw)
		v, ok := m.(*rfc5424.SyslogMessage)
		if err != nil || !ok || v == nil || v.Priority == nil || v.Version != 1 {
			return out
		}
		base = v.Base
		if v.StructuredData != nil {
			out.Structured = *v.StructuredData
		}
		out.TimeQuality = "source_timezone"
	case "rfc3164":
		location, err := time.LoadLocation(record.Binding.Timezone)
		if err != nil || record.Binding.YearPolicy != "nearest_received_year" {
			return out
		}
		m, parseErr := rfc3164.NewParser(rfc3164.WithYear(rfc3164.Year{YYYY: record.ObservedAt.In(location).Year()}), rfc3164.WithEmbeddedNewlines()).Parse(raw)
		parsed, ok := m.(*rfc3164.SyslogMessage)
		if parseErr != nil || !ok || parsed == nil || parsed.Priority == nil || parsed.Timestamp == nil || parsed.Hostname == nil || parsed.Message == nil {
			return out
		}
		base = parsed.Base
		end := bytes.IndexByte(raw, '>')
		if end < 0 || len(raw) < end+16 {
			return out
		}
		stamp := string(raw[end+1 : end+16])
		// 库负责协议语法；年份与本地时区按冻结接收时刻显式解析，避免年零时区偏移影响历史时钟。
		var chosen *time.Time
		best := time.Duration(1<<63 - 1)
		ambiguous := false
		for year := record.ObservedAt.In(location).Year() - 1; year <= record.ObservedAt.In(location).Year()+1; year++ {
			candidate, e := time.ParseInLocation("2006 Jan _2 15:04:05", strconv.Itoa(year)+" "+stamp, location)
			if e != nil {
				continue
			}
			d := record.ObservedAt.Sub(candidate)
			if d < 0 {
				d = -d
			}
			if d == best {
				ambiguous = true
			}
			if d < best {
				chosen, best, ambiguous = &candidate, d, false
			}
		}
		base.Timestamp = chosen
		out.TimeQuality = "inferred_year_timezone"
		if chosen == nil || best > 183*24*time.Hour || ambiguous {
			base.Timestamp = nil
			out.TimeQuality = "ambiguous_year"
		}
		if base.Timestamp != nil && ambiguousLocalTime(raw, *base.Timestamp, location) {
			base.Timestamp = nil
			out.TimeQuality = "ambiguous_local_time"
		}

	default:
		return out
	}
	out.State, out.Reason = "parsed", ""
	out.Priority, out.Facility, out.Severity = base.Priority, base.Facility, base.Severity
	out.Hostname, out.Application, out.ProcessID, out.MessageID = value(base.Hostname), value(base.Appname), value(base.ProcID), value(base.MsgID)
	out.MessageUTF8 = utf8.ValidString(value(base.Message))
	out.Message = strings.ToValidUTF8(value(base.Message), "�")
	if base.Timestamp == nil {
		if out.TimeQuality == "source_timezone" {
			out.TimeQuality = "missing_source_time"
		}
	} else {
		t := base.Timestamp.UTC()
		if t.Year() < 2000 || t.Year() > 9999 {
			out.TimeQuality = "source_time_out_of_range"
		} else {
			out.SourceTime = &t
			if t.After(record.ObservedAt.Add(5 * time.Minute)) {
				out.TimeQuality = "future_source_time"
			}
		}
	}
	return out
}

func ambiguousLocalTime(raw []byte, candidate time.Time, location *time.Location) bool {
	end := bytes.IndexByte(raw, '>')
	if end < 0 || len(raw) < end+16 {
		return true
	}
	stamp := string(raw[end+1 : end+16])
	// 标准 Stamp 固定 15 字节；库若规范化了不存在的本地时间，仍保留未知状态。
	local := candidate.In(location)
	if local.Format(time.Stamp) != stamp {
		return true
	}
	seen := map[int]bool{}
	matches := 0
	for _, delta := range []time.Duration{-48 * time.Hour, -24 * time.Hour, 0, 24 * time.Hour, 48 * time.Hour} {
		_, offset := candidate.Add(delta).In(location).Zone()
		if seen[offset] {
			continue
		}
		seen[offset] = true
		wall := time.Date(local.Year(), local.Month(), local.Day(), local.Hour(), local.Minute(), local.Second(), 0, time.UTC).Add(-time.Duration(offset) * time.Second)
		if wall.In(location).Format("2006 Jan _2 15:04:05") == strconv.Itoa(local.Year())+" "+stamp {
			matches++
		}
	}
	return matches != 1
}
