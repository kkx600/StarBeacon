package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/syslogdata"
)

type SyslogSource struct {
	syslogdata.Health
	SensorID       string     `json:"sensor_id"`
	SensorName     string     `json:"sensor_name"`
	RegistrationID string     `json:"registration_id"`
	SensorStatus   string     `json:"sensor_status"`
	Observation    string     `json:"observation"`
	LastSeen       *time.Time `json:"last_seen"`
}
type SyslogSourcePage struct {
	Items      []SyslogSource         `json:"items"`
	Query      syslogdata.SourceQuery `json:"query"`
	NextCursor string                 `json:"next_cursor"`
	ObservedAt time.Time              `json:"observed_at"`
}

func (p *Postgres) SyslogSources(ctx context.Context, u model.Principal, q syslogdata.SourceQuery) (SyslogSourcePage, error) {
	out := SyslogSourcePage{Items: []SyslogSource{}, Query: q}
	if q.Validate() != nil {
		return out, syslogdata.ErrInput
	}
	sensor, source, _ := q.Position()
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := responseTaskActor(ctx, tx, u); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&out.ObservedAt); err != nil {
			return err
		}
		args := []any{u.TenantID}
		where := `s.tenant_id=$1 AND s.health ? 'syslog_sources'`
		if q.SensorID != "" {
			args = append(args, q.SensorID)
			where += fmt.Sprintf(" AND s.id=$%d", len(args))
		}
		query := `WITH source AS(SELECT s.id,s.name,s.registration_id,s.active,s.last_seen,s.health FROM sensors s WHERE ` + where + `), expanded AS(
   SELECT s.*,v.value,COALESCE(v.value->>'source_id','') source_id FROM source s CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(s.health->'syslog_sources')='array' THEN CASE WHEN jsonb_array_length(s.health->'syslog_sources')<=16 THEN s.health->'syslog_sources' ELSE '[null]'::jsonb END ELSE '[null]'::jsonb END) v(value)) SELECT id,name,registration_id,active,last_seen,health,source_id FROM expanded WHERE true`
		if q.SourceID != "" {
			args = append(args, q.SourceID)
			query += fmt.Sprintf(" AND (source_id='' OR source_id=$%d)", len(args))
		}
		if sensor != "" {
			args = append(args, sensor, source)
			query += fmt.Sprintf(` AND (id COLLATE "C",source_id COLLATE "C")>($%d,$%d)`, len(args)-1, len(args))
		}
		args = append(args, q.Limit+1)
		query += fmt.Sprintf(` ORDER BY id COLLATE "C",source_id COLLATE "C" LIMIT $%d`, len(args))
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v SyslogSource
			var raw []byte
			var active bool
			var id string
			if err := rows.Scan(&v.SensorID, &v.SensorName, &v.RegistrationID, &active, &v.LastSeen, &raw, &id); err != nil {
				return err
			}
			var host model.HostHealth
			if !syslogdata.ValidID(v.SensorID) || !syslogdata.ValidID(v.RegistrationID) || json.Unmarshal(raw, &host) != nil || len(host.SyslogSources) > syslogdata.MaxSources {
				return syslogdata.ErrInput
			}
			found := false
			seen := map[string]bool{}
			for _, h := range host.SyslogSources {
				if !h.Valid() || seen[h.SourceID] {
					return syslogdata.ErrInput
				}
				seen[h.SourceID] = true
				if h.SourceID == id {
					v.Health = h
					found = true
				}
			}
			if !found {
				return syslogdata.ErrInput
			}
			v.SensorStatus = "offline"
			if !active {
				v.SensorStatus = "disabled"
			} else if freshSyslogTime(out.ObservedAt, v.LastSeen) && freshSyslogTime(out.ObservedAt, &host.ObservedAt) {
				v.SensorStatus = "online"
			}
			v.Observation = "stale"
			if freshSyslogTime(out.ObservedAt, &v.ObservedAt) {
				v.Observation = "fresh"
			}
			out.Items = append(out.Items, v)
		}
		return rows.Err()
	})
	if err != nil {
		return SyslogSourcePage{}, err
	}
	if len(out.Items) > q.Limit {
		out.Items = out.Items[:q.Limit]
		v := out.Items[len(out.Items)-1]
		out.NextCursor = q.Next(v.SensorID, v.SourceID)
	}
	return out, nil
}
func freshSyslogTime(now time.Time, t *time.Time) bool {
	return t != nil && !t.IsZero() && now.Sub(*t) <= 35*time.Second && !t.After(now.Add(30*time.Second))
}

// ES 原文读取后再次核对数据库中的账号状态；只对成功的原文查看登记审计。
func (p *Postgres) AuthorizeSyslog(ctx context.Context, u model.Principal, event, request string) error {
	return p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := responseTaskActor(ctx, tx, u); err != nil {
			return err
		}
		if event != "" {
			return insertOperationAudit(ctx, tx, u, "syslog.raw.read", event, request)
		}
		return nil
	})
}
