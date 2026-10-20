package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
)

type ResponseActionPage struct {
	Items      []SensorTask             `json:"items"`
	NextCursor string                   `json:"next_cursor"`
	Query      responseapi.CatalogQuery `json:"query"`
	ObservedAt time.Time                `json:"observed_at"`
}

const responseCatalogState = `CASE WHEN state='queued' AND delivery_count=0 AND expires_at<=transaction_timestamp() THEN 'expired' ELSE state END`

// 检索只计算尚未投递任务的到期显示，不修改任务或原始回执。
func responseCatalogColumns() string {
	return strings.Replace(taskColumns, "kind,state,", "kind,"+responseCatalogState+",", 1)
}

func (p *Postgres) ResponseActions(ctx context.Context, u model.Principal, q responseapi.CatalogQuery) (ResponseActionPage, error) {
	out := ResponseActionPage{Items: []SensorTask{}, Query: q}
	if q.Validate() != nil {
		return out, responseapi.ErrInput
	}
	position, id, _ := q.Position()
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := responseTaskActor(ctx, tx, u); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='4s'`); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&out.ObservedAt); err != nil {
			return err
		}
		args := []any{u.TenantID, q.Start, q.End}
		where := `tenant_id=$1 AND kind LIKE 'response.%' AND retain_until>transaction_timestamp() AND created_at>=$2 AND created_at<$3`
		add := func(expression string, value any) {
			args = append(args, value)
			where += " AND " + expression + fmt.Sprintf("=$%d", len(args))
		}
		if q.SensorID != "" {
			add("sensor_id", q.SensorID)
		}
		if q.Kind != "" {
			add("kind", q.Kind)
		}
		if q.State != "" {
			add("("+responseCatalogState+")", q.State)
		}
		// 联动任务有租户日预算，时间窗口另限制 31 天；不扫描无关规则载荷。
		if q.TargetIP != "" {
			add("(convert_from(command,'UTF8')::jsonb->'payload'->>'target_ip')", q.TargetIP)
		}
		if q.DeviceID != "" {
			add("(convert_from(command,'UTF8')::jsonb->'payload'->>'device_id')", q.DeviceID)
		}
		if id != "" {
			args = append(args, position, id)
			where += fmt.Sprintf(" AND (created_at,id)<($%d,$%d)", len(args)-1, len(args))
		}
		args = append(args, q.Limit+1)
		rows, err := tx.Query(ctx, "SELECT "+responseCatalogColumns()+" FROM sensor_tasks WHERE "+where+fmt.Sprintf(" ORDER BY created_at DESC,id DESC LIMIT $%d", len(args)), args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			value, err := scanSensorTask(rows, u.TenantID)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, value)
		}
		return rows.Err()
	})
	if err != nil {
		return ResponseActionPage{}, err
	}
	if len(out.Items) > q.Limit {
		out.Items = out.Items[:q.Limit]
		last := out.Items[len(out.Items)-1]
		out.NextCursor = q.Next(last.CreatedAt, last.ID)
	}
	return out, nil
}

func (p *Postgres) ResponseAction(ctx context.Context, u model.Principal, id string) (SensorTask, error) {
	var out SensorTask
	if !contract.ValidID(id) {
		return out, responseapi.ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := responseTaskActor(ctx, tx, u); err != nil {
			return err
		}
		var err error
		out, err = scanSensorTask(tx.QueryRow(ctx, "SELECT "+responseCatalogColumns()+" FROM sensor_tasks WHERE tenant_id=$1 AND id=$2 AND kind LIKE 'response.%' AND retain_until>transaction_timestamp()", u.TenantID, id), u.TenantID)
		return err
	})
	return out, err
}
