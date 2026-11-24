package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/telemetry"
	"github.com/kkx600/StarBeacon/internal/transport"
)

var ErrPacketBusy = errors.New("原包归档正在由其他传输处理")

type PacketArchive struct {
	ID             string                    `json:"id"`
	State          string                    `json:"state"`
	Manifest       packetarchive.Manifest    `json:"manifest"`
	Index          packetarchive.IndexRecord `json:"-"`
	ManifestSHA256 string                    `json:"manifest_sha256"`
	ObjectKey      string                    `json:"-"`
	ObjectVersion  string                    `json:"object_version"`
	LeaseToken     string                    `json:"-"`
	CreatedAt      time.Time                 `json:"created_at"`
	ExpiresAt      time.Time                 `json:"expires_at"`
}

func (v PacketArchive) Acknowledgement() packetarchive.Acknowledgement {
	return packetarchive.Acknowledgement{ID: v.ID, ManifestSHA256: v.ManifestSHA256, RawSHA256: v.Manifest.Encoding.RawSHA256, StoredSHA256: v.Manifest.Encoding.StoredSHA256, StoredBytes: v.Manifest.Encoding.StoredBytes, ObjectVersion: v.ObjectVersion, ExpiresAt: v.ExpiresAt}
}

const packetArchiveColumns = `id,state,manifest,manifest_sha256,object_key,object_version,lease_token,created_at,expires_at`

func scanPacketArchive(row pgx.Row) (v PacketArchive, err error) {
	var raw []byte
	err = row.Scan(&v.ID, &v.State, &raw, &v.ManifestSHA256, &v.ObjectKey, &v.ObjectVersion, &v.LeaseToken, &v.CreatedAt, &v.ExpiresAt)
	if err != nil {
		return v, err
	}
	v.Manifest, err = packetarchive.ParseManifest(raw)
	if err != nil {
		return v, err
	}
	_, digest, err := v.Manifest.JSON()
	if err != nil || digest != v.ManifestSHA256 || v.ID != v.Manifest.Capture.ID || v.ObjectKey != packetarchive.ObjectKey(v.Manifest) {
		return v, packetarchive.ErrIntegrity
	}
	return v, nil
}
func packetSensor(ctx context.Context, tx pgx.Tx, id transport.SensorIdentity) error {
	var sensor string
	err := tx.QueryRow(ctx, `SELECT public.lock_packet_sensor($1,$2) WHERE current_setting('starbeacon.tenant_id',true)=$3`, id.SensorID, id.RegistrationID, id.TenantID).Scan(&sensor)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSensorInactive
	}
	return err
}

// BeginPacketArchive 登记原包上传。存储容量由全部租户共享，不按租户预占额度；空间由准入检查与全局回收维持。
func (p *Postgres) BeginPacketArchive(ctx context.Context, id transport.SensorIdentity, m packetarchive.Manifest) (v PacketArchive, acquired bool, err error) {
	raw, digest, err := m.JSON()
	if err != nil || m.Capture.TenantID != id.TenantID || m.Capture.SensorID != id.SensorID || m.Capture.RegistrationID != id.RegistrationID || m.Capture.EndedAt.After(time.Now().Add(5*time.Minute)) {
		return v, false, packetarchive.ErrIntegrity
	}
	err = p.TenantTx(ctx, id.TenantID, func(tx pgx.Tx) error {
		if e := packetSensor(ctx, tx, id); e != nil {
			return e
		}
		existing, e := scanPacketArchive(tx.QueryRow(ctx, `SELECT `+packetArchiveColumns+` FROM packet_archives WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, id.TenantID, m.Capture.ID))
		lease := RandomID("packetlease_")
		if e == nil {
			if existing.ManifestSHA256 != digest {
				return ErrConflict
			}
			if !existing.ExpiresAt.After(time.Now()) || existing.State == "deleting" {
				return pgx.ErrNoRows
			}
			if existing.State == "ready" {
				v = existing
				return nil
			}
			tag, e := tx.Exec(ctx, `UPDATE packet_archives SET lease_token=$3,lease_until=now()+interval '3 minutes' WHERE tenant_id=$1 AND id=$2 AND lease_until<=now()`, id.TenantID, m.Capture.ID, lease)
			if e != nil {
				return e
			}
			if tag.RowsAffected() != 1 {
				return ErrPacketBusy
			}
		} else {
			if !errors.Is(e, pgx.ErrNoRows) {
				return e
			}
			// 同一原包的并发首次登记只有一方成功，另一方按传输进行中返回并稍后重试。
			tag, e := tx.Exec(ctx, `INSERT INTO packet_archives(tenant_id,id,sensor_id,registration_id,manifest,manifest_sha256,object_key,stored_bytes,state,lease_token,lease_until,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'uploading',$9,now()+interval '3 minutes',now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='pcap'),180))) ON CONFLICT(tenant_id,id) DO NOTHING`, id.TenantID, m.Capture.ID, id.SensorID, id.RegistrationID, raw, digest, packetarchive.ObjectKey(m), m.Encoding.StoredBytes, lease)
			if e != nil {
				return e
			}
			if tag.RowsAffected() != 1 {
				return ErrPacketBusy
			}
		}
		v, e = scanPacketArchive(tx.QueryRow(ctx, `SELECT `+packetArchiveColumns+` FROM packet_archives WHERE tenant_id=$1 AND id=$2`, id.TenantID, m.Capture.ID))
		acquired = e == nil
		return e
	})
	return v, acquired, err
}
func (p *Postgres) RegisterPacketObject(ctx context.Context, id transport.SensorIdentity, row PacketArchive, version string) error {
	if !packetarchive.ValidObjectVersion(version) {
		return packetarchive.ErrIntegrity
	}
	return p.TenantTx(ctx, id.TenantID, func(tx pgx.Tx) error {
		if err := packetSensor(ctx, tx, id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE packet_archives SET state='stored',object_version=$6 WHERE tenant_id=$1 AND id=$2 AND sensor_id=$3 AND registration_id=$4 AND lease_token=$5 AND lease_until>now() AND expires_at>now() AND state IN('uploading','stored') AND (object_version='' OR object_version=$6)`, id.TenantID, row.ID, id.SensorID, id.RegistrationID, row.LeaseToken, version)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrConflict
		}
		return nil
	})
}
func (p *Postgres) CompletePacketArchive(ctx context.Context, id transport.SensorIdentity, row PacketArchive, index ...packetarchive.IndexRecord) (v PacketArchive, err error) {
	if len(index) > 1 || (row.Manifest.Encoding.Schema == packetarchive.PackedSchema) != (len(index) == 1) {
		return v, packetarchive.ErrIntegrity
	}
	err = p.TenantTx(ctx, id.TenantID, func(tx pgx.Tx) error {
		if e := packetSensor(ctx, tx, id); e != nil {
			return e
		}
		tag, e := tx.Exec(ctx, `UPDATE packet_archives SET state='ready',lease_until=now() WHERE tenant_id=$1 AND id=$2 AND sensor_id=$3 AND registration_id=$4 AND lease_token=$5 AND lease_until>now() AND expires_at>now() AND state='stored' AND object_version<>''`, id.TenantID, row.ID, id.SensorID, id.RegistrationID, row.LeaseToken)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return ErrConflict
		}
		v, e = scanPacketArchive(tx.QueryRow(ctx, `SELECT `+packetArchiveColumns+` FROM packet_archives WHERE tenant_id=$1 AND id=$2`, id.TenantID, row.ID))
		if e == nil && len(index) == 1 {
			e = setPacketFlowIndex(ctx, tx, v, index[0])
		}
		return e
	})
	return v, err
}
func (p *Postgres) ReleasePacketLease(ctx context.Context, id transport.SensorIdentity, row PacketArchive) error {
	return p.TenantTx(ctx, id.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE packet_archives SET lease_until=now() WHERE tenant_id=$1 AND id=$2 AND sensor_id=$3 AND registration_id=$4 AND lease_token=$5 AND state IN('uploading','stored')`, id.TenantID, row.ID, id.SensorID, id.RegistrationID, row.LeaseToken)
		return err
	})
}

func (p *Postgres) PacketArchive(ctx context.Context, u model.Principal, id string) (v PacketArchive, err error) {
	if u.Role != "admin" || !contract.ValidID(id) {
		return v, pgx.ErrNoRows
	}
	err = p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if e := activePlanOwner(ctx, tx, u.TenantID, u.ID); e != nil {
			return e
		}
		var e error
		v, e = scanPacketArchive(tx.QueryRow(ctx, `SELECT `+packetArchiveColumns+` FROM packet_archives WHERE tenant_id=$1 AND id=$2 AND state='ready' AND expires_at>now()`, u.TenantID, id))
		return e
	})
	return v, err
}

type PacketArchiveSummary struct {
	ID             string                `json:"id"`
	State          string                `json:"state"`
	Capture        packetarchive.Capture `json:"capture"`
	Codec          string                `json:"codec"`
	RawBytes       int64                 `json:"raw_bytes"`
	StoredBytes    int64                 `json:"stored_bytes"`
	ManifestSHA256 string                `json:"manifest_sha256"`
	CreatedAt      time.Time             `json:"created_at"`
	ExpiresAt      time.Time             `json:"expires_at"`
}
type packetCursor struct {
	Time time.Time `json:"time"`
	ID   string    `json:"id"`
}

func (p *Postgres) PacketArchives(ctx context.Context, u model.Principal, sensor, cursor string, limit int) (out []PacketArchiveSummary, next string, err error) {
	out = []PacketArchiveSummary{}
	var after packetCursor
	if !contract.ValidListLimit(limit) || u.Role != "admin" || sensor != "" && !contract.ValidID(sensor) || len(cursor) > 1024 {
		return out, "", packetarchive.ErrIntegrity
	}
	if cursor != "" {
		raw, e := base64.RawURLEncoding.DecodeString(cursor)
		if e != nil || json.Unmarshal(raw, &after) != nil || after.Time.IsZero() || !contract.ValidID(after.ID) {
			return out, "", packetarchive.ErrIntegrity
		}
	}
	err = p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if e := activePlanOwner(ctx, tx, u.TenantID, u.ID); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT id,state,manifest->'capture',manifest->'encoding'->>'codec',(manifest->'encoding'->>'raw_bytes')::bigint,stored_bytes,manifest_sha256,created_at,expires_at FROM packet_archives WHERE tenant_id=$1 AND ($2='' OR sensor_id=$2) AND expires_at>now() AND ($3::timestamptz IS NULL OR (created_at,id)<($3,$4)) ORDER BY created_at DESC,id DESC LIMIT $5`, u.TenantID, sensor, nullableTime(after.Time), after.ID, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var v PacketArchiveSummary
			var capture []byte
			if e = rows.Scan(&v.ID, &v.State, &capture, &v.Codec, &v.RawBytes, &v.StoredBytes, &v.ManifestSHA256, &v.CreatedAt, &v.ExpiresAt); e != nil {
				return e
			}
			if json.Unmarshal(capture, &v.Capture) != nil || v.Capture.Validate() != nil || v.Capture.TenantID != u.TenantID || v.ID != v.Capture.ID {
				return packetarchive.ErrIntegrity
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err == nil && len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		raw, _ := json.Marshal(packetCursor{last.CreatedAt, last.ID})
		next = base64.RawURLEncoding.EncodeToString(raw)
	}
	return out, next, err
}
func nullableTime(v time.Time) any {
	if v.IsZero() {
		return nil
	}
	return v
}

func (p *Postgres) AuditPacketDownload(ctx context.Context, u model.Principal, id, request string) error {
	return p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := activePlanOwner(ctx, tx, u.TenantID, u.ID); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "pcap.download.request", id, request)
	})
}

func (p *Postgres) AuditPacketInspection(ctx context.Context, u model.Principal, id, request string) error {
	return p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := activePlanOwner(ctx, tx, u.TenantID, u.ID); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "pcap.inspect.request", id, request)
	})
}

// 读取事务按固定 ID 顺序锁住有界原包集合，应用清理器须等副本验证完毕后才能标记删除。
// 外部对象生命周期不受 PG 锁保护；读取器仍须使用指定版本和完整摘要验证。
func (p *Postgres) WithPacketArchives(ctx context.Context, u model.Principal, ids []string, read func([]PacketArchive) error) error {
	if read == nil {
		return packetarchive.ErrIntegrity
	}
	return p.withPacketArchives(ctx, u, ids, func(_ pgx.Tx, rows []PacketArchive) error { return read(rows) })
}

func setPacketFlowIndex(ctx context.Context, tx pgx.Tx, row PacketArchive, index packetarchive.IndexRecord) error {
	if _, err := index.Decode(row.Manifest); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO packet_archive_flow_indexes(tenant_id,archive_id,object_version,manifest_sha256,index_sha256,data)
		VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,archive_id) DO UPDATE
		SET object_version=excluded.object_version,manifest_sha256=excluded.manifest_sha256,index_sha256=excluded.index_sha256,data=excluded.data`,
		row.Manifest.Capture.TenantID, row.ID, row.ObjectVersion, row.ManifestSHA256, index.SHA256, index.Data)
	return err
}

// WithPacketFlowIndexes 共享归档读取租约。派生索引单独写入，重建不需要升级原包行锁。
func (p *Postgres) WithPacketFlowIndexes(ctx context.Context, u model.Principal, ids []string, read func([]PacketArchive, func(string, packetarchive.IndexRecord) error) error) error {
	if read == nil {
		return packetarchive.ErrIntegrity
	}
	return p.withPacketArchives(ctx, u, ids, func(tx pgx.Tx, rows []PacketArchive) error {
		for i := range rows {
			row := &rows[i]
			if row.Manifest.Encoding.Schema != packetarchive.PackedSchema {
				continue
			}
			err := tx.QueryRow(ctx, `SELECT data,index_sha256 FROM packet_archive_flow_indexes
				WHERE tenant_id=$1 AND archive_id=$2 AND object_version=$3 AND manifest_sha256=$4`, u.TenantID,
				row.ID, row.ObjectVersion, row.ManifestSHA256).Scan(&row.Index.Data, &row.Index.SHA256)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		return read(rows, func(id string, index packetarchive.IndexRecord) error {
			for _, row := range rows {
				if row.ID == id {
					return setPacketFlowIndex(ctx, tx, row, index)
				}
			}
			return packetarchive.ErrIntegrity
		})
	})
}
func (p *Postgres) withPacketArchives(ctx context.Context, u model.Principal, ids []string, read func(pgx.Tx, []PacketArchive) error) error {
	if u.Role != "admin" || len(ids) < 1 || len(ids) > packetarchive.MaxSessionInputs || read == nil {
		return packetarchive.ErrIntegrity
	}
	ordered := slices.Clone(ids)
	slices.Sort(ordered)
	for i, id := range ordered {
		if !contract.ValidID(id) || i > 0 && ordered[i-1] == id {
			return packetarchive.ErrIntegrity
		}
	}
	return p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := activePlanOwner(ctx, tx, u.TenantID, u.ID); err != nil {
			return err
		}
		rows := make([]PacketArchive, 0, len(ordered))
		for _, id := range ordered {
			row, err := scanPacketArchive(tx.QueryRow(ctx, `SELECT `+packetArchiveColumns+` FROM packet_archives WHERE tenant_id=$1 AND id=$2 AND state='ready' AND expires_at>clock_timestamp() FOR SHARE`, u.TenantID, id))
			if err != nil {
				return err
			}
			rows = append(rows, row)
		}
		if err := read(tx, rows); err != nil {
			return err
		}
		// 事务内 now() 固定于开始时；长读取必须按实际时间复核留存和当前账号。
		for _, row := range rows {
			if !row.ExpiresAt.After(time.Now()) {
				return pgx.ErrNoRows
			}
		}
		return activePlanOwner(ctx, tx, u.TenantID, u.ID)
	})
}
func (p *Postgres) AuditPacketSessionExport(ctx context.Context, u model.Principal, ids []string, mode, request string) error {
	if mode != "full_session" && mode != "snapshot" {
		return packetarchive.ErrIntegrity
	}
	return p.withPacketArchives(ctx, u, ids, func(tx pgx.Tx, rows []PacketArchive) error {
		// 独立提交请求审计，使后续严格校验失败或对象读取失败仍留下访问记录。
		return insertOperationAudit(ctx, tx, u, "pcap.session.export."+mode+".request", rows[0].ID, request)
	})
}

// SweepPacketArchives 先按共享存储容量把全局最早的原包提前到期，再删除全部到期原包。
// 删除先持久标记，再删除指定版本，最终提交目录；失败保留目录并在后续轮次重试。
func (p *Postgres) SweepPacketArchives(ctx context.Context, objects packetarchive.ObjectStorage, pool packetarchive.Pool) (PacketSweep, error) {
	var result PacketSweep
	if objects == nil {
		return result, packetarchive.ErrIntegrity
	}
	if !p.packetSweepMu.TryLock() {
		return result, ErrPacketBusy
	}
	defer p.packetSweepMu.Unlock()
	tenants, err := p.packetTenants(ctx)
	if err != nil {
		return result, err
	}
	var all error
	result.Evicted, result.EvictedBytes, result.More, err = p.reclaimPacketStorage(ctx, tenants, objects, pool)
	if err != nil {
		all = errors.Join(all, err)
	}
	// 从上轮结束的租户之后继续，期限截止时各租户轮流获得删除机会。
	start := 0
	for i, tenant := range tenants {
		if tenant > p.packetSweepAfter {
			start = i
			break
		}
	}
	for _, tenant := range slices.Concat(tenants[start:], tenants[:start]) {
		if ctx.Err() != nil {
			result.More = true
			break
		}
		var after packetCursor
		attempts := 0
		for ; attempts < packetSweepBatch && ctx.Err() == nil; attempts++ {
			var row PacketArchive
			err = p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
				var e error
				row, e = scanPacketArchive(tx.QueryRow(ctx, `SELECT `+packetArchiveColumns+` FROM packet_archives WHERE tenant_id=$1 AND expires_at<=now() AND lease_until<=now() AND ($2::timestamptz IS NULL OR (expires_at,id)>($2,$3)) ORDER BY expires_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, tenant, nullableTime(after.Time), after.ID))
				if e != nil {
					return e
				}
				_, e = tx.Exec(ctx, `UPDATE packet_archives SET state='deleting' WHERE tenant_id=$1 AND id=$2`, tenant, row.ID)
				return e
			})
			if errors.Is(err, pgx.ErrNoRows) {
				break
			}
			if err != nil {
				all = errors.Join(all, err)
				break
			}
			after = packetCursor{row.ExpiresAt, row.ID}
			version := row.ObjectVersion
			if version == "" {
				var exists bool
				version, exists, err = objects.Locate(ctx, row.ObjectKey, row.Manifest.Encoding.StoredBytes, row.Manifest.Encoding.StoredSHA256)
				if err != nil {
					all = errors.Join(all, err)
					continue
				}
				if exists {
					// 只在标记已提交且传输租约到期后恢复这个冻结键的确切版本，随后按版本删除。
					err = p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
						tag, e := tx.Exec(ctx, `UPDATE packet_archives SET object_version=$3 WHERE tenant_id=$1 AND id=$2 AND state='deleting' AND object_version='' AND expires_at<=now() AND lease_until<=now()`, tenant, row.ID, version)
						if e != nil {
							return e
						}
						if tag.RowsAffected() != 1 {
							return ErrConflict
						}
						return nil
					})
					if err != nil {
						all = errors.Join(all, err)
						continue
					}
					row.ObjectVersion = version
				}
			}
			if version != "" {
				err = objects.Remove(ctx, row.ObjectKey, version)
			} else {
				err = nil
			}
			if err != nil {
				all = errors.Join(all, err)
				continue
			}
			err = p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
				tag, e := tx.Exec(ctx, `DELETE FROM packet_archives WHERE tenant_id=$1 AND id=$2 AND state='deleting' AND expires_at<=now() AND lease_until<=now() AND object_version=$3`, tenant, row.ID, row.ObjectVersion)
				if e != nil {
					return e
				}
				if tag.RowsAffected() != 1 {
					return ErrConflict
				}
				return nil
			})
			if err != nil {
				all = errors.Join(all, err)
				break
			}
			result.Deleted++
			result.DeletedBytes += row.Manifest.Encoding.StoredBytes
			telemetry.PacketDeleted.Inc()
		}
		if attempts == packetSweepBatch {
			result.More = true
		}
		p.packetSweepAfter = tenant
	}
	if ctx.Err() != nil {
		return result, errors.Join(all, ctx.Err())
	}
	return result, all
}
