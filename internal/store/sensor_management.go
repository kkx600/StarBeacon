package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/sensormanagement"
)

type SensorPage struct {
	Items      []model.Sensor `json:"items"`
	NextCursor string         `json:"next_cursor"`
}

// 任务目标通过租户与设备主键读取，不受目录分页或工具结果上限影响。
func (p *Postgres) Sensor(ctx context.Context, tenant, id string) (model.Sensor, error) {
	var s model.Sensor
	if !contract.ValidID(id) {
		return s, pgx.ErrNoRows
	}
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT s.id,s.name,s.registration_id,s.active,s.created_at,s.last_seen,s.health,s.metadata_revision,COALESCE(s.group_id,''),COALESCE(g.name,''),s.site,s.description,s.metadata_updated_at,
 CASE WHEN NOT s.active THEN 'disabled' WHEN s.last_seen>now()-interval '35 seconds' THEN 'online' ELSE 'offline' END
 FROM sensors s LEFT JOIN sensor_groups g ON g.tenant_id=s.tenant_id AND g.id=s.group_id WHERE s.tenant_id=$1 AND s.id=$2`, tenant, id).Scan(&s.ID, &s.Name, &s.RegistrationID, &s.Active, &s.CreatedAt, &s.LastSeen, &s.Health, &s.MetadataRevision, &s.GroupID, &s.GroupName, &s.Site, &s.Description, &s.MetadataUpdatedAt, &s.Status)
	})
	return s, err
}

func sensorManager(ctx context.Context, tx pgx.Tx, u model.Principal) error {
	if u.Role != "admin" || !contract.ValidID(u.ID) || !contract.ValidID(u.TenantID) {
		return sensormanagement.ErrInput
	}
	var active, tenantActive bool
	var role string
	// 用户权限、密码和离线恢复共用此事务锁；运行角色仅需用户表读取权限。
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/users"); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT u.active,u.role,t.active FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.tenant_id=$1 AND u.id=$2`, u.TenantID, u.ID).Scan(&active, &role, &tenantActive); err != nil {
		return err
	}
	if !active || !tenantActive || role != "admin" {
		return pgx.ErrNoRows
	}
	return nil
}

func sensorWriteError(err error) error {
	var e *pgconn.PgError
	if errors.As(err, &e) && e.Code == "23505" {
		return ErrConflict
	}
	return err
}

// 管理操作按租户串行，配额、分组停用和成员迁移在同一事务中核对；心跳不取得此锁。
func sensorChange(ctx context.Context, tx pgx.Tx, u model.Principal, key, operation, id, hash string, result interface{ Validate() error }, apply func() error) error {
	if !contract.ValidID(key) || !contract.ValidID(id) {
		return sensormanagement.ErrInput
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/sensor-management"); err != nil {
		return err
	}
	if err := sensorManager(ctx, tx, u); err != nil {
		return err
	}
	var priorOperation, priorID, priorHash string
	var raw json.RawMessage
	var expires time.Time
	err := tx.QueryRow(ctx, `SELECT operation,object_id,input_hash,record,expires_at FROM sensor_management_requests WHERE tenant_id=$1 AND created_by=$2 AND key_hash=$3`, u.TenantID, u.ID, Hash(key)).Scan(&priorOperation, &priorID, &priorHash, &raw, &expires)
	if err == nil {
		if priorOperation != operation || priorID != id || priorHash != hash || !expires.After(time.Now()) {
			return ErrConflict
		}
		if err := json.Unmarshal(raw, result); err != nil {
			return err
		}
		if result.Validate() != nil {
			return errors.New("探针管理原提交回执不完整")
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM sensor_management_requests WHERE tenant_id=$1 AND created_at>now()-interval '24 hours'`, u.TenantID).Scan(&count); err != nil {
		return err
	}
	if count >= 10000 {
		return sensormanagement.ErrQuota
	}
	if err := apply(); err != nil {
		return err
	}
	if result.Validate() != nil {
		return errors.New("探针管理回执不完整")
	}
	if err := insertOperationAudit(ctx, tx, u, "sensor."+operation, id, model.RequestMetadataFrom(ctx).RequestID); err != nil {
		return err
	}
	raw, err = json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO sensor_management_requests(tenant_id,created_by,key_hash,operation,object_id,input_hash,record,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180)))`, u.TenantID, u.ID, Hash(key), operation, id, hash, raw)
	return err
}

func (p *Postgres) SensorDirectory(ctx context.Context, tenant string, q sensormanagement.Query) (SensorPage, error) {
	page := SensorPage{Items: []model.Sensor{}}
	if q.Validate(false) != nil {
		return page, sensormanagement.ErrInput
	}
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		pattern := "%" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(q.Keyword) + "%"
		rows, err := tx.Query(ctx, `SELECT s.id,s.name,s.registration_id,s.active,s.created_at,s.last_seen,s.health,s.metadata_revision,COALESCE(s.group_id,''),COALESCE(g.name,''),s.site,s.description,s.metadata_updated_at,
 CASE WHEN NOT s.active THEN 'disabled' WHEN s.last_seen>now()-interval '35 seconds' THEN 'online' ELSE 'offline' END AS status
 FROM sensors s LEFT JOIN sensor_groups g ON g.tenant_id=s.tenant_id AND g.id=s.group_id
 WHERE s.tenant_id=$1 AND s.id>$2 AND (s.name ILIKE $3 ESCAPE '!' OR s.id ILIKE $3 ESCAPE '!' OR s.site ILIKE $3 ESCAPE '!')
 AND ($4='' OR ($4='ungrouped' AND s.group_id IS NULL) OR s.group_id=$4)
 AND ($5='' OR ($5='disabled' AND NOT s.active) OR ($5='online' AND s.active AND s.last_seen>now()-interval '35 seconds') OR ($5='offline' AND s.active AND (s.last_seen IS NULL OR s.last_seen<=now()-interval '35 seconds')))
 ORDER BY s.id LIMIT $6`, tenant, q.Cursor, pattern, q.GroupID, q.Status, q.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s model.Sensor
			if err := rows.Scan(&s.ID, &s.Name, &s.RegistrationID, &s.Active, &s.CreatedAt, &s.LastSeen, &s.Health, &s.MetadataRevision, &s.GroupID, &s.GroupName, &s.Site, &s.Description, &s.MetadataUpdatedAt, &s.Status); err != nil {
				return err
			}
			page.Items = append(page.Items, s)
		}
		return rows.Err()
	})
	if len(page.Items) > q.Limit {
		page.NextCursor = page.Items[q.Limit-1].ID
		page.Items = page.Items[:q.Limit]
	}
	return page, err
}

func (p *Postgres) SensorGroups(ctx context.Context, tenant string, q sensormanagement.Query) (sensormanagement.GroupPage, error) {
	page := sensormanagement.GroupPage{Items: []sensormanagement.Group{}}
	if q.Validate(true) != nil {
		return page, sensormanagement.ErrInput
	}
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		pattern := "%" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(q.Keyword) + "%"
		rows, err := tx.Query(ctx, `SELECT g.id,g.revision,g.name,g.description,g.active,(SELECT count(*) FROM sensors s WHERE s.tenant_id=g.tenant_id AND s.group_id=g.id),g.created_at,g.updated_at FROM sensor_groups g WHERE g.tenant_id=$1 AND g.id>$2 AND g.name ILIKE $3 ESCAPE '!' AND ($4='' OR g.active=($4='true')) ORDER BY g.id LIMIT $5`, tenant, q.Cursor, pattern, q.Active, q.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var g sensormanagement.Group
			if err := rows.Scan(&g.ID, &g.Revision, &g.Name, &g.Description, &g.Active, &g.MemberCount, &g.CreatedAt, &g.UpdatedAt); err != nil {
				return err
			}
			page.Items = append(page.Items, g)
		}
		return rows.Err()
	})
	if len(page.Items) > q.Limit {
		page.NextCursor = page.Items[q.Limit-1].ID
		page.Items = page.Items[:q.Limit]
	}
	return page, err
}

func (p *Postgres) SaveSensorGroup(ctx context.Context, u model.Principal, key string, c sensormanagement.GroupChange) (sensormanagement.Group, error) {
	var result sensormanagement.Group
	if c.Validate() != nil || c.ID == "ungrouped" {
		return result, sensormanagement.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		return sensorChange(ctx, tx, u, key, "group", c.ID, sensormanagement.InputHash(c.ID, c), &result, func() error {
			var current sensormanagement.Group
			err := tx.QueryRow(ctx, `SELECT id,revision,name,description,active,(SELECT count(*) FROM sensors s WHERE s.tenant_id=$1 AND s.group_id=$2),created_at,updated_at FROM sensor_groups WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, u.TenantID, c.ID).Scan(&current.ID, &current.Revision, &current.Name, &current.Description, &current.Active, &current.MemberCount, &current.CreatedAt, &current.UpdatedAt)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if errors.Is(err, pgx.ErrNoRows) && c.ExpectedRevision > 0 {
				return pgx.ErrNoRows
			}
			if current.Revision != c.ExpectedRevision {
				return ErrConflict
			}
			if current.Revision > 0 && current.Name == c.Name && current.Description == c.Description && current.Active == *c.Active {
				return sensormanagement.ErrInput
			}
			if !*c.Active && current.MemberCount > 0 {
				return sensormanagement.ErrOccupied
			}
			if current.Revision == 0 {
				var count int
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM sensor_groups WHERE tenant_id=$1`, u.TenantID).Scan(&count); err != nil {
					return err
				}
				if count >= sensormanagement.MaxGroups {
					return sensormanagement.ErrQuota
				}
			}
			result.MemberCount = current.MemberCount
			return tx.QueryRow(ctx, `INSERT INTO sensor_groups(tenant_id,id,name,description,revision,active) VALUES($1,$2,$3,$4,1,$5) ON CONFLICT(tenant_id,id) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,active=EXCLUDED.active,revision=sensor_groups.revision+1,updated_at=now() RETURNING id,revision,name,description,active,created_at,updated_at`, u.TenantID, c.ID, c.Name, c.Description, *c.Active).Scan(&result.ID, &result.Revision, &result.Name, &result.Description, &result.Active, &result.CreatedAt, &result.UpdatedAt)
		})
	})
	if err == nil && (result.ID != c.ID || result.Revision != c.ExpectedRevision+1 || result.Name != c.Name || result.Description != c.Description || result.Active != *c.Active) {
		err = errors.New("探针分组原提交回执与输入不一致")
	}
	return result, sensorWriteError(err)
}

func (p *Postgres) SaveSensorMetadata(ctx context.Context, u model.Principal, id, key string, c sensormanagement.MetadataChange) (sensormanagement.Metadata, error) {
	var result sensormanagement.Metadata
	if !contract.ValidID(id) || c.Validate() != nil {
		return result, sensormanagement.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		return sensorChange(ctx, tx, u, key, "metadata", id, sensormanagement.InputHash(id, c), &result, func() error {
			var current sensormanagement.Metadata
			if err := tx.QueryRow(ctx, `SELECT id,metadata_revision,registration_id,name,COALESCE(group_id,''),site,description,metadata_updated_at FROM sensors WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, u.TenantID, id).Scan(&current.ID, &current.Revision, &current.RegistrationID, &current.Name, &current.GroupID, &current.Site, &current.Description, &current.UpdatedAt); err != nil {
				return err
			}
			if current.Revision != c.ExpectedRevision || current.RegistrationID != c.RegistrationID {
				return ErrConflict
			}
			if current.Name == c.Name && current.GroupID == c.GroupID && current.Site == c.Site && current.Description == c.Description {
				return sensormanagement.ErrInput
			}
			if c.GroupID != "" {
				var active bool
				if err := tx.QueryRow(ctx, `SELECT active FROM sensor_groups WHERE tenant_id=$1 AND id=$2 FOR SHARE`, u.TenantID, c.GroupID).Scan(&active); err != nil {
					return err
				}
				if !active {
					return sensormanagement.ErrInactive
				}
			}
			return tx.QueryRow(ctx, `UPDATE sensors SET name=$3,group_id=NULLIF($4,''),site=$5,description=$6,metadata_revision=metadata_revision+1,metadata_updated_at=now() WHERE tenant_id=$1 AND id=$2 RETURNING id,metadata_revision,registration_id,name,COALESCE(group_id,''),site,description,metadata_updated_at`, u.TenantID, id, c.Name, c.GroupID, c.Site, c.Description).Scan(&result.ID, &result.Revision, &result.RegistrationID, &result.Name, &result.GroupID, &result.Site, &result.Description, &result.UpdatedAt)
		})
	})
	if err == nil && (result.ID != id || result.Revision != c.ExpectedRevision+1 || result.RegistrationID != c.RegistrationID || result.Name != c.Name || result.GroupID != c.GroupID || result.Site != c.Site || result.Description != c.Description) {
		err = errors.New("探针管理信息原提交回执与输入不一致")
	}
	return result, sensorWriteError(err)
}
