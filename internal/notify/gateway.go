package notify

import (
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

// GatewaySummary 只向操作通知渠道输出记录引用和观察状态。
type GatewaySummary struct {
	RequestID   string    `json:"request_id"`
	SensorID    string    `json:"sensor_id"`
	ObservedAt  time.Time `json:"observed_at"`
	Reconnected bool      `json:"reconnected"`
}

func (v GatewaySummary) Valid() bool {
	return contract.ValidID(v.RequestID) && contract.ValidID(v.SensorID) &&
		v.ObservedAt.Year() >= 2000 && v.ObservedAt.Year() <= 2100
}

func validGatewayMessage(c Config, m Message) bool {
	if m.Gateway == nil {
		return true
	}
	return !m.Test && c.Accepts("quality") && len(m.Alerts) == 0 && len(m.Logs) == 0 && len(m.Quality) == 0 &&
		contract.ValidID(m.TenantID) && m.Gateway.Valid() && m.BatchID == m.Gateway.RequestID
}
