package store

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/probepki"
	"github.com/kkx600/StarBeacon/internal/transport"
)

func probeLock(ctx context.Context, tx pgx.Tx, id transport.SensorIdentity) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, id.TenantID+"/probe-certificates/"+id.SensorID); err != nil {
		return err
	}
	var ok bool
	err := tx.QueryRow(ctx, `SELECT true FROM sensors s JOIN tenants t ON t.id=s.tenant_id WHERE s.tenant_id=$1 AND s.id=$2 AND s.registration_id=$3 AND s.active AND s.certificate_managed AND t.active FOR SHARE OF s`, id.TenantID, id.SensorID, id.RegistrationID).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return probepki.ErrDenied
	}
	return err
}
func (p *Postgres) CreateProbeEnrollment(ctx context.Context, u model.Principal, input probepki.EnrollmentInput) (probepki.Enrollment, error) {
	var out probepki.Enrollment
	if input.Validate() != nil || u.Role != "admin" {
		return out, probepki.ErrInput
	}
	c, _ := probepki.ParseCredential(input.Token)
	if c.Identity.TenantID != u.TenantID {
		return out, probepki.ErrDenied
	}
	raw, _ := json.Marshal(input)
	hash := probepki.Digest(raw)
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := sensorManager(ctx, tx, u); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/probe-enrollments"); err != nil {
			return err
		}
		var prior, owner string
		err := tx.QueryRow(ctx, `SELECT id,sensor_id,registration_id,created_at,expires_at,revoked,input_hash,created_by FROM probe_enrollments WHERE tenant_id=$1 AND id=$2`, u.TenantID, c.ID).Scan(&out.ID, &out.SensorID, &out.RegistrationID, &out.CreatedAt, &out.ExpiresAt, &out.Revoked, &prior, &owner)
		if err == nil {
			if prior != hash || owner != u.ID {
				return ErrConflict
			}
			out.State = "created"
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM probe_enrollments WHERE tenant_id=$1 AND created_at>now()-interval '24 hours'`, u.TenantID).Scan(&count); err != nil {
			return err
		}
		if count >= 10000 {
			return probepki.ErrQuota
		}
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM probe_enrollments WHERE tenant_id=$1 AND sensor_id=$2 AND NOT revoked AND expires_at>now()`, u.TenantID, c.Identity.SensorID).Scan(&count); err != nil {
			return err
		}
		if count >= 4 {
			return probepki.ErrQuota
		}
		if _, err = tx.Exec(ctx, `SELECT public.register_managed_probe($1,$2,$3,$4,$5)`, u.TenantID, u.ID, c.Identity.SensorID, c.Identity.RegistrationID, input.Name); err != nil {
			var databaseError *pgconn.PgError
			if errors.As(err, &databaseError) && databaseError.Code == "40001" {
				return ErrConflict
			}
			return sensorWriteError(err)
		}
		err = tx.QueryRow(ctx, `INSERT INTO probe_enrollments(tenant_id,id,sensor_id,registration_id,token_hash,input_hash,created_by,expires_at,retain_until) VALUES($1,$2,$3,$4,$5,$6,$7,now()+make_interval(secs=>$8),now()+make_interval(secs=>$8)+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180))) RETURNING id,sensor_id,registration_id,created_at,expires_at,revoked`, u.TenantID, c.ID, c.Identity.SensorID, c.Identity.RegistrationID, Hash(input.Token), hash, u.ID, input.TTLSeconds).Scan(&out.ID, &out.SensorID, &out.RegistrationID, &out.CreatedAt, &out.ExpiresAt, &out.Revoked)
		if err != nil {
			return err
		}
		out.State = "created"
		return insertOperationAudit(ctx, tx, u, "sensor.enrollment.create", c.ID, model.RequestMetadataFrom(ctx).RequestID)
	})
	return out, err
}
func certificateJob(ctx context.Context, tx pgx.Tx, id transport.SensorIdentity, kind, credential, csr string) (probepki.Job, bool, error) {
	j := probepki.Job{Identity: id, CSR: csr}
	var oldHash string
	var before, after pgtype.Timestamptz
	err := tx.QueryRow(ctx, `SELECT id,state,csr_sha256,chain_pem,COALESCE(fingerprint,''),serial,not_before,not_after,revoked_at,ca_revocation FROM probe_certificates WHERE tenant_id=$1 AND kind=$2 AND credential_id=$3`, id.TenantID, kind, credential).Scan(&j.ID, &j.State, &oldHash, &j.Certificate.Chain, &j.Certificate.Fingerprint, &j.Certificate.Serial, &before, &after, &j.Certificate.RevokedAt, &j.Certificate.CARevocation)
	if err == nil {
		j.Certificate.NotBefore = before.Time
		j.Certificate.NotAfter = after.Time
		if oldHash != probepki.Digest([]byte(csr)) || j.Certificate.RevokedAt != nil {
			return j, false, probepki.ErrConflict
		}
		j.Certificate.ID = j.ID
		j.Certificate.State = j.State
		j.Certificate.CSRSHA256 = oldHash
		j.Certificate.SensorID = id.SensorID
		j.Certificate.RegistrationID = id.RegistrationID
		if j.State != "issued" {
			return j, false, probepki.ErrConflict
		}
		return j, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return j, false, err
	}
	j.ID = RandomID("cert_")
	j.State = "signing"
	_, err = tx.Exec(ctx, `INSERT INTO probe_certificates(tenant_id,id,sensor_id,registration_id,kind,credential_id,csr_pem,csr_sha256,state,retain_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'signing',now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180)))`, id.TenantID, j.ID, id.SensorID, id.RegistrationID, kind, credential, csr, probepki.Digest([]byte(csr)))
	return j, err == nil, err
}

func (p *Postgres) BeginProbeEnrollment(ctx context.Context, input probepki.Exchange) (probepki.Job, bool, error) {
	var j probepki.Job
	var send bool
	c, err := probepki.ParseCredential(input.Token)
	if err != nil {
		return j, false, err
	}
	if _, err := probepki.ParseCSR(input.CSR, c.Identity); err != nil {
		return j, false, err
	}
	err = p.TenantTx(ctx, c.Identity.TenantID, func(tx pgx.Tx) error {
		if err := probeLock(ctx, tx, c.Identity); err != nil {
			return err
		}
		var hash, user string
		var allowed bool
		err := tx.QueryRow(ctx, `SELECT e.token_hash,e.created_by,(NOT e.revoked AND e.expires_at>now() AND e.sensor_id=$3 AND e.registration_id=$4 AND u.active AND u.role='admin') FROM probe_enrollments e JOIN users u ON u.tenant_id=e.tenant_id AND u.id=e.created_by WHERE e.tenant_id=$1 AND e.id=$2`, c.Identity.TenantID, c.ID, c.Identity.SensorID, c.Identity.RegistrationID).Scan(&hash, &user, &allowed)
		if errors.Is(err, pgx.ErrNoRows) {
			return probepki.ErrDenied
		}
		if err != nil {
			return err
		}
		if !allowed || subtle.ConstantTimeCompare([]byte(hash), []byte(Hash(input.Token))) != 1 {
			return probepki.ErrDenied
		}
		j, send, err = certificateJob(ctx, tx, c.Identity, "enroll", c.ID, input.CSR)
		if err != nil {
			return err
		}
		if send {
			return insertOperationAudit(ctx, tx, model.Principal{ID: user, TenantID: c.Identity.TenantID, Role: "admin"}, "sensor.certificate.request", j.ID, model.RequestMetadataFrom(ctx).RequestID)
		}
		return nil
	})
	return j, send, err
}
func (p *Postgres) BeginProbeRenewal(ctx context.Context, id transport.SensorIdentity, fingerprint, csr string) (probepki.Job, bool, error) {
	var j probepki.Job
	var send bool
	if _, err := probepki.ParseCSR(csr, id); err != nil {
		return j, false, err
	}
	err := p.TenantTx(ctx, id.TenantID, func(tx pgx.Tx) error {
		if err := probeLock(ctx, tx, id); err != nil {
			return err
		}
		var before, after time.Time
		var revoked *time.Time
		err := tx.QueryRow(ctx, `SELECT not_before,not_after,revoked_at FROM probe_certificates WHERE tenant_id=$1 AND sensor_id=$2 AND registration_id=$3 AND fingerprint=$4 AND state='issued'`, id.TenantID, id.SensorID, id.RegistrationID, fingerprint).Scan(&before, &after, &revoked)
		if errors.Is(err, pgx.ErrNoRows) {
			return probepki.ErrDenied
		}
		if err != nil {
			return err
		}
		if revoked != nil || !after.After(time.Now()) {
			return probepki.ErrDenied
		}
		if time.Until(after) > after.Sub(before)/3 {
			return probepki.ErrNotDue
		}
		j, send, err = certificateJob(ctx, tx, id, "renew", fingerprint, csr)
		return err
	})
	return j, send, err
}
func (p *Postgres) FinishProbeCertificate(ctx context.Context, j probepki.Job, c probepki.Certificate, signErr error) (probepki.Certificate, error) {
	err := p.TenantTx(ctx, j.Identity.TenantID, func(tx pgx.Tx) error {
		// 授权锁先于探针锁，与账号变更和凭据撤销保持顺序；不在 CA 网络请求期间持锁。
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, j.Identity.TenantID+"/users"); err != nil {
			return err
		}
		if err := probeLock(ctx, tx, j.Identity); err != nil {
			return err
		}
		// 签发期间停用、撤销注册令牌或撤销父证书，均不得把 CA 结果登记为可用身份。
		var allowed bool
		if err := tx.QueryRow(ctx, `SELECT CASE WHEN p.kind='enroll' THEN EXISTS(SELECT 1 FROM probe_enrollments e JOIN users u ON u.tenant_id=e.tenant_id AND u.id=e.created_by WHERE e.tenant_id=p.tenant_id AND e.id=p.credential_id AND NOT e.revoked AND e.expires_at>now() AND u.active AND u.role='admin') ELSE EXISTS(SELECT 1 FROM probe_certificates old WHERE old.tenant_id=p.tenant_id AND old.fingerprint=p.credential_id AND old.revoked_at IS NULL AND old.not_after>now() AND old.state='issued') END FROM probe_certificates p WHERE p.tenant_id=$1 AND p.id=$2 AND p.state='signing'`, j.Identity.TenantID, j.ID).Scan(&allowed); err != nil {
			return err
		}
		if signErr != nil || !allowed {
			_, err := tx.Exec(ctx, `UPDATE probe_certificates SET state='unknown' WHERE tenant_id=$1 AND id=$2 AND state='signing'`, j.Identity.TenantID, j.ID)
			return err
		}
		if c.ID != j.ID || c.SensorID != j.Identity.SensorID || c.RegistrationID != j.Identity.RegistrationID || len(c.Fingerprint) != 64 || c.Chain == "" || !c.NotAfter.After(time.Now()) {
			return probepki.ErrInput
		}
		tag, err := tx.Exec(ctx, `UPDATE probe_certificates SET state='issued',chain_pem=$3,fingerprint=$4,serial=$5,not_before=$6,not_after=$7,retain_until=greatest(retain_until,$7::timestamptz+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180))) WHERE tenant_id=$1 AND id=$2 AND state='signing'`, j.Identity.TenantID, j.ID, c.Chain, c.Fingerprint, c.Serial, c.NotBefore, c.NotAfter)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return probepki.ErrConflict
		}
		return nil
	})
	if err != nil {
		return probepki.Certificate{}, err
	}
	if signErr != nil {
		return probepki.Certificate{}, probepki.ErrConflict
	}
	// 回读保证只返回实际持久登记且仍可使用的证书。
	if err = p.SensorCertificateActive(ctx, j.Identity, c.Fingerprint, c.NotAfter); err != nil {
		return probepki.Certificate{}, err
	}
	return c, nil
}
func (p *Postgres) SensorCertificateActive(ctx context.Context, id transport.SensorIdentity, fingerprint string, notAfter time.Time) error {
	if !notAfter.After(time.Now()) {
		return ErrSensorInactive
	}
	return p.TenantTx(ctx, id.TenantID, func(tx pgx.Tx) error {
		var ok bool
		err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sensors s JOIN tenants t ON t.id=s.tenant_id WHERE s.tenant_id=$1 AND s.id=$2 AND s.registration_id=$3 AND s.active AND t.active AND (NOT s.certificate_managed OR EXISTS(SELECT 1 FROM probe_certificates c WHERE c.tenant_id=s.tenant_id AND c.sensor_id=s.id AND c.registration_id=s.registration_id AND c.fingerprint=$4 AND c.state='issued' AND c.revoked_at IS NULL AND c.not_before<=now() AND c.not_after>now())))`, id.TenantID, id.SensorID, id.RegistrationID, fingerprint).Scan(&ok)
		if err != nil {
			return err
		}
		if !ok {
			return ErrSensorInactive
		}
		return nil
	})
}
func (p *Postgres) ProbeCertificates(ctx context.Context, u model.Principal, sensor, cursor string) ([]probepki.Certificate, string, error) {
	out := []probepki.Certificate{}
	next := ""
	if !contract.ValidID(sensor) || cursor != "" && !contract.ValidID(cursor) {
		return out, next, probepki.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := sensorManager(ctx, tx, u); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id,sensor_id,registration_id,COALESCE(fingerprint,''),serial,not_before,not_after,revoked_at,ca_revocation,state,csr_sha256 FROM probe_certificates WHERE tenant_id=$1 AND sensor_id=$2 AND id>$3 AND retain_until>now() ORDER BY id LIMIT 21`, u.TenantID, sensor, cursor)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c probepki.Certificate
			var before, after pgtype.Timestamptz
			if err := rows.Scan(&c.ID, &c.SensorID, &c.RegistrationID, &c.Fingerprint, &c.Serial, &before, &after, &c.RevokedAt, &c.CARevocation, &c.State, &c.CSRSHA256); err != nil {
				return err
			}
			c.NotBefore = before.Time
			c.NotAfter = after.Time
			out = append(out, c)
		}
		return rows.Err()
	})
	if len(out) > 20 {
		out = out[:20]
		next = out[19].ID
	}
	return out, next, err
}
func (p *Postgres) RevokeProbeCertificate(ctx context.Context, u model.Principal, id string) (probepki.Certificate, error) {
	var c probepki.Certificate
	if !contract.ValidID(id) {
		return c, probepki.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := sensorManager(ctx, tx, u); err != nil {
			return err
		}
		// 与签发收尾保持相同锁顺序，避免证书行锁和探针锁互相等待。
		var sensor, registration string
		if err := tx.QueryRow(ctx, `SELECT sensor_id,registration_id FROM probe_certificates WHERE tenant_id=$1 AND id=$2 AND state='issued'`, u.TenantID, id).Scan(&sensor, &registration); err != nil {
			return err
		}
		if err := probeLock(ctx, tx, transport.SensorIdentity{TenantID: u.TenantID, SensorID: sensor, RegistrationID: registration}); err != nil && !errors.Is(err, probepki.ErrDenied) {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT id,sensor_id,registration_id,fingerprint,serial,not_before,not_after,revoked_at,ca_revocation FROM probe_certificates WHERE tenant_id=$1 AND id=$2 AND state='issued' FOR UPDATE`, u.TenantID, id).Scan(&c.ID, &c.SensorID, &c.RegistrationID, &c.Fingerprint, &c.Serial, &c.NotBefore, &c.NotAfter, &c.RevokedAt, &c.CARevocation); err != nil {
			return err
		}
		if c.RevokedAt != nil {
			c.State = "issued"
			return nil
		}
		if err := tx.QueryRow(ctx, `UPDATE probe_certificates SET revoked_at=now(),ca_revocation='pending' WHERE tenant_id=$1 AND id=$2 RETURNING revoked_at,ca_revocation`, u.TenantID, id).Scan(&c.RevokedAt, &c.CARevocation); err != nil {
			return err
		}
		c.State = "issued"
		return insertOperationAudit(ctx, tx, u, "sensor.certificate.revoke", id, model.RequestMetadataFrom(ctx).RequestID)
	})
	return c, err
}
func (p *Postgres) SetProbeCARevocation(ctx context.Context, tenant, id string, confirmed bool) error {
	return p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		state := "unknown"
		if confirmed {
			state = "confirmed"
		}
		_, err := tx.Exec(ctx, `UPDATE probe_certificates SET ca_revocation=$3 WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NOT NULL AND ca_revocation<>'confirmed'`, tenant, id, state)
		return err
	})
}
func (p *Postgres) RevokeProbeEnrollment(ctx context.Context, u model.Principal, id string) error {
	if !contract.ValidID(id) {
		return probepki.ErrInput
	}
	return p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := sensorManager(ctx, tx, u); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE probe_enrollments SET revoked=true WHERE tenant_id=$1 AND id=$2 AND NOT revoked`, u.TenantID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var exists bool
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM probe_enrollments WHERE tenant_id=$1 AND id=$2)`, u.TenantID, id).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return pgx.ErrNoRows
			}
			return nil
		}
		return insertOperationAudit(ctx, tx, u, "sensor.enrollment.revoke", id, model.RequestMetadataFrom(ctx).RequestID)
	})
}
