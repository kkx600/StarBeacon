package store

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/model"
)

type AuditQuery struct {
	Start, End       time.Time
	Cursor           string
	Limit            int
	Action, Username string
	Success          *bool
}
type AuditRecord struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id,omitempty"`
	Username  string    `json:"username"`
	Action    string    `json:"action"`
	ObjectID  string    `json:"object_id,omitempty"`
	RequestID string    `json:"request_id"`
	SourceIP  string    `json:"source_ip"`
	UserAgent string    `json:"user_agent"`
	Success   *bool     `json:"success,omitempty"`
	Phase     string    `json:"phase,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
type AuditResult struct {
	Items      []AuditRecord `json:"items"`
	NextCursor string        `json:"next_cursor"`
}

func (q AuditQuery) Validate() error {
	if q.Start.IsZero() || !q.End.After(q.Start) || q.End.Sub(q.Start) > 31*24*time.Hour || q.Limit < 1 || q.Limit > 100 || len(q.Action) > 128 || len(q.Username) > 64 {
		return fmt.Errorf("单次日志检索范围最多 31 天，每页最多 100 条")
	}
	if q.Cursor != "" {
		v, e := strconv.ParseInt(q.Cursor, 10, 64)
		if e != nil || v < 1 {
			return fmt.Errorf("日志游标无效")
		}
	}
	return nil
}
func insertOperationAudit(ctx context.Context, tx pgx.Tx, u model.Principal, action, object, request string) error {
	meta := model.RequestMetadataFrom(ctx)
	_, e := tx.Exec(ctx, `INSERT INTO operation_audits(tenant_id,user_id,action,object_id,request_id,source_ip,user_agent,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180)))`, u.TenantID, u.ID, action, object, request, meta.SourceIP, meta.UserAgent)
	return e
}
func (p *Postgres) Audits(ctx context.Context, tenant, category string, q AuditQuery) (AuditResult, error) {
	out := AuditResult{Items: []AuditRecord{}}
	if e := q.Validate(); e != nil {
		return out, e
	}
	if category != "operations" && category != "logins" {
		return out, fmt.Errorf("日志类别无效")
	}
	cursor := int64(0)
	if q.Cursor != "" {
		cursor, _ = strconv.ParseInt(q.Cursor, 10, 64)
	}
	e := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var rows pgx.Rows
		var e error
		if category == "operations" {
			rows, e = tx.Query(ctx, `SELECT a.id,a.user_id,COALESCE(u.username,a.user_id),a.action,a.object_id,a.request_id,a.source_ip,a.user_agent,a.created_at FROM operation_audits a LEFT JOIN users u ON u.id=a.user_id AND u.tenant_id=a.tenant_id WHERE a.tenant_id=$1 AND a.created_at>=$2 AND a.created_at<$3 AND a.expires_at>now() AND ($4=0 OR a.id<$4) AND ($5='' OR a.action=$5) AND ($6='' OR u.username=$6) ORDER BY a.id DESC LIMIT $7`, tenant, q.Start, q.End, cursor, q.Action, q.Username, q.Limit+1)
		} else {
			rows, e = tx.Query(ctx, `SELECT id,username,success,request_id,source_ip,user_agent,phase,created_at FROM login_audits WHERE tenant_id=$1 AND created_at>=$2 AND created_at<$3 AND expires_at>now() AND ($4=0 OR id<$4) AND ($5='' OR username=$5) AND ($6::boolean IS NULL OR success=$6) ORDER BY id DESC LIMIT $7`, tenant, q.Start, q.End, cursor, q.Username, q.Success, q.Limit+1)
		}
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var row AuditRecord
			var id int64
			if category == "operations" {
				e = rows.Scan(&id, &row.UserID, &row.Username, &row.Action, &row.ObjectID, &row.RequestID, &row.SourceIP, &row.UserAgent, &row.CreatedAt)
			} else {
				e = rows.Scan(&id, &row.Username, &row.Success, &row.RequestID, &row.SourceIP, &row.UserAgent, &row.Phase, &row.CreatedAt)
				row.Action = "auth.password_verification"
			}
			if e != nil {
				return e
			}
			row.ID = strconv.FormatInt(id, 10)
			out.Items = append(out.Items, row)
		}
		return rows.Err()
	})
	if e == nil && len(out.Items) > q.Limit {
		out.Items = out.Items[:q.Limit]
		out.NextCursor = out.Items[len(out.Items)-1].ID
	}
	return out, e
}
