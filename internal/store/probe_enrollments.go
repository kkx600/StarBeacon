package store

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/probepki"
)

func (p *Postgres) ProbeEnrollments(ctx context.Context, u model.Principal, cursor string) ([]probepki.Enrollment, string, error) {
	out := []probepki.Enrollment{}
	next := ""
	if cursor != "" && !contract.ValidID(cursor) {
		return out, next, probepki.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := sensorManager(ctx, tx, u); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT e.id,e.sensor_id,e.registration_id,e.created_at,e.expires_at,e.revoked,CASE WHEN e.revoked THEN 'revoked' WHEN c.state IS NOT NULL THEN c.state WHEN e.expires_at<=now() THEN 'expired' ELSE 'unused' END,COALESCE(c.id,''),COALESCE(c.csr_sha256,'') FROM probe_enrollments e LEFT JOIN probe_certificates c ON c.tenant_id=e.tenant_id AND c.kind='enroll' AND c.credential_id=e.id WHERE e.tenant_id=$1 AND e.id>$2 AND e.retain_until>now() ORDER BY e.id LIMIT 21`, u.TenantID, cursor)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item probepki.Enrollment
			if err := rows.Scan(&item.ID, &item.SensorID, &item.RegistrationID, &item.CreatedAt, &item.ExpiresAt, &item.Revoked, &item.State, &item.JobID, &item.CSRSHA256); err != nil {
				return err
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	if len(out) > 20 {
		out = out[:20]
		next = out[19].ID
	}
	return out, next, err
}
