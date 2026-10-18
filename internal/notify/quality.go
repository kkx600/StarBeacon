package notify

import (
	"encoding/hex"
	"slices"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/qualityevent"
)

// 只外发区间事件摘要；计数详情、原始 EVE、载荷和配置摘要不进入办公渠道。
type QualitySummary struct {
	ID        string    `json:"id"`
	SensorID  string    `json:"sensor_id"`
	Timestamp time.Time `json:"timestamp"`
	Kind      string    `json:"kind"`
	Title     string    `json:"title"`
	Reminder  bool      `json:"reminder"`
}

func QualityFrom(e qualityevent.Event) QualitySummary {
	return QualitySummary{e.ID, e.SensorID, e.CreatedAt, e.Signal.Kind, qualityevent.Title(e.Signal.Kind), e.Signal.Reminder}
}
func ValidateQuality(tenant, batch string, items []QualitySummary) error {
	if !contract.ValidID(tenant) || !contract.ValidID(batch) || len(items) != 1 || batch != "quality_"+items[0].ID[:min(56, len(items[0].ID))] {
		return ErrBatch
	}
	for _, s := range items {
		b, err := hex.DecodeString(s.ID)
		if err != nil || len(b) != 32 || hex.EncodeToString(b) != s.ID || !contract.ValidID(s.SensorID) || s.Timestamp.Year() < 2000 || s.Timestamp.Year() > 2100 || !slices.Contains([]string{"limitation", "policy", "uncertain", "interval_clear", "observation_resumed"}, s.Kind) || s.Title != qualityevent.Title(s.Kind) || (s.Reminder && (s.Kind == "interval_clear" || s.Kind == "observation_resumed")) {
			return ErrBatch
		}
	}
	return nil
}
func validQuality(c Config, m Message) bool {
	if len(m.Quality) == 0 {
		return true
	}
	return c.Accepts("quality") && !m.Test && len(m.Alerts) == 0 && len(m.Logs) == 0 && ValidateQuality(m.TenantID, m.BatchID, m.Quality) == nil
}
