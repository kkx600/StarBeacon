package normalize

import (
	"errors"
	"strconv"
	"time"
)

// 原生 EVE 的时区为 +HHMM，API 样本可使用 RFC3339 的 +HH:MM；两者均保留纳秒精度。
func ParseTimestamp(value string) (time.Time, error) {
	if len(value) < 20 || len(value) > 40 {
		return time.Time{}, errors.New("EVE 时间格式无效")
	}
	if len(value) >= 25 {
		zone := value[len(value)-6:]
		if (zone[0] == '+' || zone[0] == '-') && zone[3] == ':' {
			hour, hourError := strconv.Atoi(zone[1:3])
			minute, minuteError := strconv.Atoi(zone[4:6])
			if hourError != nil || minuteError != nil || hour > 23 || minute > 59 || hour < 0 || minute < 0 {
				return time.Time{}, errors.New("EVE 时区超出范围")
			}
		}
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, nil
	}
	zone := value[len(value)-5:]
	if zone[0] != '+' && zone[0] != '-' {
		return time.Time{}, errors.New("EVE 时间缺少合法时区")
	}
	hour, hourError := strconv.Atoi(zone[1:3])
	minute, minuteError := strconv.Atoi(zone[3:5])
	if hourError != nil || minuteError != nil || hour > 23 || minute > 59 || hour < 0 || minute < 0 {
		return time.Time{}, errors.New("EVE 时区超出范围")
	}
	return time.Parse("2006-01-02T15:04:05.999999999-0700", value)
}
