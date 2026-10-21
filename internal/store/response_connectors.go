package store

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
)

type ResponseConnector struct {
	responseapi.Health
	SensorID       string     `json:"sensor_id"`
	SensorName     string     `json:"sensor_name"`
	RegistrationID string     `json:"registration_id"`
	SensorStatus   string     `json:"sensor_status"`
	LastSeen       *time.Time `json:"last_seen"`
	HostObservedAt time.Time  `json:"host_observed_at"`
	Observation    string     `json:"observation"`
	TaskSupported  bool       `json:"task_supported"`
}

type ResponseConnectorPage struct {
	Items      []ResponseConnector        `json:"items"`
	NextCursor string                     `json:"next_cursor"`
	Query      responseapi.ConnectorQuery `json:"query"`
	ObservedAt time.Time                  `json:"observed_at"`
}

func connectorObservation(h responseapi.Health, now time.Time) string {
	if h.ObservedAt.IsZero() {
		return "pending"
	}
	if now.Sub(h.ObservedAt) > 35*time.Second || h.ObservedAt.After(now.Add(30*time.Second)) {
		return "stale"
	}
	return "fresh"
}

func (p *Postgres) ResponseConnectors(ctx context.Context, u model.Principal, q responseapi.ConnectorQuery) (ResponseConnectorPage, error) {
	out := ResponseConnectorPage{Items: []ResponseConnector{}, Query: q}
	if q.Validate() != nil {
		return out, responseapi.ErrInput
	}
	position, connector, _ := q.Position()
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := responseTaskActor(ctx, tx, u); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&out.ObservedAt); err != nil {
			return err
		}
		args := []any{u.TenantID}
		where := `s.tenant_id=$1 AND s.health ? 'response_connectors'`
		if q.SensorID != "" {
			args = append(args, q.SensorID)
			where += fmt.Sprintf(" AND s.id=$%d", len(args))
		}
		// 损坏的设备数组作为错误哨兵保留，不能被展开成空列表。
		query := `WITH source AS (SELECT s.id,s.name,s.registration_id,s.active,s.last_seen,s.health FROM sensors s WHERE ` + where + `), expanded AS (
		 SELECT s.*,c.value,COALESCE(c.value->>'connector_id','') AS connector_id
		 FROM source s CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(s.health->'response_connectors')='array' THEN CASE WHEN jsonb_array_length(s.health->'response_connectors')<=8 THEN s.health->'response_connectors' ELSE '[null]'::jsonb END ELSE '[null]'::jsonb END) c(value))
		 SELECT id,name,registration_id,active,last_seen,health,connector_id FROM expanded WHERE true`
		if q.DeviceID != "" {
			args = append(args, q.DeviceID)
			query += fmt.Sprintf(" AND (connector_id='' OR value->>'device_id'=$%d)", len(args))
		}
		if q.Status != "" {
			args = append(args, q.Status)
			query += fmt.Sprintf(" AND (connector_id='' OR value->>'status'=$%d)", len(args))
		}
		if position != "" {
			args = append(args, position, connector)
			query += fmt.Sprintf(" AND (id COLLATE \"C\",connector_id COLLATE \"C\")>($%d,$%d)", len(args)-1, len(args))
		}
		args = append(args, q.Limit+1)
		query += fmt.Sprintf(" ORDER BY id COLLATE \"C\",connector_id COLLATE \"C\" LIMIT $%d", len(args))
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v ResponseConnector
			var raw []byte
			var active bool
			var id string
			if err := rows.Scan(&v.SensorID, &v.SensorName, &v.RegistrationID, &active, &v.LastSeen, &raw, &id); err != nil {
				return err
			}
			var health model.HostHealth
			if !contract.ValidID(v.SensorID) || !contract.ValidID(v.RegistrationID) || json.Unmarshal(raw, &health) != nil || len(health.ResponseConnectors) > 8 {
				return fmt.Errorf("联动设备来源无效")
			}
			seen, devices := map[string]bool{}, map[string]bool{}
			found := false
			for _, h := range health.ResponseConnectors {
				if !h.Valid() || seen[h.ConnectorID] || devices[h.DeviceID] {
					return fmt.Errorf("联动设备来源无效")
				}
				seen[h.ConnectorID], devices[h.DeviceID] = true, true
				if h.ConnectorID == id {
					v.Health = h
					found = true
				}
			}
			if !found {
				return fmt.Errorf("联动设备来源不完整")
			}
			v.SensorStatus = "offline"
			if !active {
				v.SensorStatus = "disabled"
			} else if v.LastSeen != nil && out.ObservedAt.Sub(*v.LastSeen) <= 35*time.Second && !v.LastSeen.After(out.ObservedAt.Add(30*time.Second)) && !health.ObservedAt.IsZero() && out.ObservedAt.Sub(health.ObservedAt) <= 35*time.Second && !health.ObservedAt.After(out.ObservedAt.Add(30*time.Second)) {
				v.SensorStatus = "online"
			}
			v.HostObservedAt = health.ObservedAt
			v.Observation = connectorObservation(v.Health, out.ObservedAt)
			v.TaskSupported = slices.Contains(health.TaskCapabilities, "response.block") && slices.Contains(health.TaskCapabilities, "response.read") && slices.Contains(health.TaskCapabilities, "response.revoke")
			out.Items = append(out.Items, v)
		}
		return rows.Err()
	})
	if err != nil {
		return ResponseConnectorPage{}, err
	}
	if len(out.Items) > q.Limit {
		out.Items = out.Items[:q.Limit]
		last := out.Items[len(out.Items)-1]
		out.NextCursor = q.Next(last.SensorID, last.ConnectorID)
	}
	return out, nil
}
