package notify

import (
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

// 通知只携带方案编号和确认截止时刻，研判材料留在平台权限范围内。
type DecisionTimeout struct {
	PlanID    string    `json:"plan_id"`
	ExpiredAt time.Time `json:"expired_at"`
}

func validDecisionTimeout(c Config, m Message) bool {
	timeout := m.DecisionTimeout
	return timeout == nil || !m.Test && c.Accepts("quality") && len(m.Alerts) == 0 && len(m.Logs) == 0 && len(m.Quality) == 0 && m.Gateway == nil &&
		contract.ValidID(m.TenantID) && contract.ValidID(timeout.PlanID) && m.BatchID == timeout.PlanID &&
		timeout.ExpiredAt.Year() >= 2000 && timeout.ExpiredAt.Year() <= 2100
}
