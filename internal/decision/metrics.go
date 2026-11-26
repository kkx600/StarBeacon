package decision

import (
	"time"
	_ "time/tzdata"
)

type PlanMetrics struct {
	TimeZone     string    `json:"timezone"`
	Start        time.Time `json:"start"`
	End          time.Time `json:"end"`
	TriageCount  int64     `json:"triage_count"`
	TriageMeanMS *int64    `json:"triage_mean_ms"`
	Pending      int64     `json:"pending"`
	Executed     int64     `json:"executed"`
	Automatic    int64     `json:"automatic"`
	Rejected     int64     `json:"rejected"`
	Protected    int64     `json:"protected"`
}

func PlanMetricsDay(now time.Time, zone string) (PlanMetrics, error) {
	if zone == "" {
		zone = "UTC"
	}
	if len(zone) > 128 || zone == "Local" || now.IsZero() {
		return PlanMetrics{}, ErrInput
	}
	location, err := time.LoadLocation(zone)
	if err != nil {
		return PlanMetrics{}, ErrInput
	}
	local := now.In(location)
	date := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, time.UTC)
	return PlanMetrics{
		TimeZone: zone,
		Start:    planDayBoundary(date, location).UTC(),
		End:      planDayBoundary(date.AddDate(0, 0, 1), location).UTC(),
	}, nil
}

func planDayBoundary(date time.Time, location *time.Location) time.Time {
	midnight := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, location)
	_, offset := midnight.Zone()
	wallTime := midnight.Add(time.Duration(offset) * time.Second)
	start, end := midnight.ZoneBounds()
	// 午夜落在拨快的空隙里时，用时钟切换时刻作为日界。
	if wallTime.Before(date) {
		return end
	}
	if wallTime.After(date) {
		return start
	}
	// 午夜出现两次时取第一次，避免漏计当天的首段记录。
	if !start.IsZero() {
		_, previousOffset := start.Add(-time.Nanosecond).Zone()
		earlier := date.Add(-time.Duration(previousOffset) * time.Second)
		_, earlierOffset := earlier.In(location).Zone()
		if earlier.Before(start) && earlierOffset == previousOffset {
			return earlier
		}
	}
	return midnight
}
