package response

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

// CatalogQuery 按任务创建时间检索；状态仍是读取时的执行状态，不是历史状态重放。
type CatalogQuery struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	SensorID string    `json:"sensor_id"`
	Kind     string    `json:"kind"`
	State    string    `json:"state"`
	TargetIP string    `json:"target_ip"`
	DeviceID string    `json:"device_id"`
	Cursor   string    `json:"cursor"`
	Limit    int       `json:"limit"`
}

type catalogCursor struct {
	Time  time.Time `json:"time"`
	ID    string    `json:"id"`
	Query string    `json:"query"`
}

func (q CatalogQuery) fingerprint() string {
	q.Cursor = ""
	q.Start, q.End = q.Start.UTC(), q.End.UTC()
	return digest(q)
}

func (q CatalogQuery) Validate() error {
	if q.Start.IsZero() || q.End.IsZero() || !q.Start.Before(q.End) || q.End.Sub(q.Start) > 31*24*time.Hour || q.End.After(time.Now().Add(30*time.Second)) || q.Limit < 1 || q.Limit > 100 || q.SensorID != "" && !contract.ValidID(q.SensorID) || q.DeviceID != "" && !contract.ValidID(q.DeviceID) || q.TargetIP != "" && !ValidTarget(q.TargetIP) {
		return ErrInput
	}
	if q.Kind != "" && q.Kind != "response.block" && q.Kind != "response.read" && q.Kind != "response.revoke" {
		return ErrInput
	}
	switch q.State {
	case "", "queued", "delivered", "running", "succeeded", "failed", "unknown", "expired", "cancelled":
	default:
		return ErrInput
	}
	_, _, err := q.Position()
	return err
}

// 游标绑定完整筛选条件，不能将其他窗口或页大小的续页误作当前结果。
func (q CatalogQuery) Position() (time.Time, string, error) {
	if q.Cursor == "" {
		return q.End, "", nil
	}
	if len(q.Cursor) > 512 {
		return time.Time{}, "", ErrInput
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(q.Cursor)
	var c catalogCursor
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != q.Cursor || contract.JSONFields(string(raw), []string{"time", "id", "query"}, 384) != nil || json.Unmarshal(raw, &c) != nil || !contract.ValidID(c.ID) || c.Query != q.fingerprint() || c.Time.Before(q.Start) || !c.Time.Before(q.End) {
		return time.Time{}, "", ErrInput
	}
	return c.Time.UTC(), c.ID, nil
}

func (q CatalogQuery) Next(created time.Time, id string) string {
	raw, _ := json.Marshal(catalogCursor{Time: created.UTC(), ID: id, Query: q.fingerprint()})
	return base64.RawURLEncoding.EncodeToString(raw)
}
