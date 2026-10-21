package response

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

// ConnectorQuery 检索当前登记设备；分页不承诺跨心跳的状态快照。
type ConnectorQuery struct {
	SensorID string `json:"sensor_id"`
	DeviceID string `json:"device_id"`
	Status   string `json:"status"`
	Cursor   string `json:"cursor"`
	Limit    int    `json:"limit"`
}

type connectorCursor struct {
	SensorID    string `json:"sensor_id"`
	ConnectorID string `json:"connector_id"`
	Query       string `json:"query"`
}

func (q ConnectorQuery) fingerprint() string { q.Cursor = ""; return digest(q) }

func (q ConnectorQuery) Validate() error {
	if q.Limit < 1 || q.Limit > 100 || q.SensorID != "" && !contract.ValidID(q.SensorID) || q.DeviceID != "" && !contract.ValidID(q.DeviceID) {
		return ErrInput
	}
	switch q.Status {
	case "", "ready", "unverified", "unavailable":
	default:
		return ErrInput
	}
	_, _, err := q.Position()
	return err
}

func (q ConnectorQuery) Position() (string, string, error) {
	if q.Cursor == "" {
		return "", "", nil
	}
	if len(q.Cursor) > 512 {
		return "", "", ErrInput
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(q.Cursor)
	var c connectorCursor
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != q.Cursor || contract.JSONFields(string(raw), []string{"sensor_id", "connector_id", "query"}, 384) != nil || json.Unmarshal(raw, &c) != nil || !contract.ValidID(c.SensorID) || !contract.ValidID(c.ConnectorID) || c.Query != q.fingerprint() {
		return "", "", ErrInput
	}
	return c.SensorID, c.ConnectorID, nil
}

func (q ConnectorQuery) Next(sensor, connector string) string {
	raw, _ := json.Marshal(connectorCursor{sensor, connector, q.fingerprint()})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (h Health) Valid() bool {
	return contract.ValidID(h.ConnectorID) && contract.ValidID(h.DeviceID) && validText(h.Version, 64) && validHash(h.ConfigSHA256) && h.MaxTTLSeconds >= 30 && h.MaxTTLSeconds <= MaxTTLSeconds && (h.Status == "ready" || h.Status == "unavailable" || h.Status == "unverified") && (h.Status == "unverified" || !h.ObservedAt.IsZero())
}

// ConfigCheck 只核对固定本地文件的结构和运行绑定，不发起设备请求。
type ConfigCheck struct {
	SchemaVersion string    `json:"schema_version"`
	State         string    `json:"state"`
	RunningCount  int       `json:"running_count"`
	FileCount     int       `json:"file_count"`
	CheckedAt     time.Time `json:"checked_at"`
}

func (v File) SHA256() string { return digest(v) }
