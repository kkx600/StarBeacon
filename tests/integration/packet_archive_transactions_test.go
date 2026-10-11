//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
)

func TestPacketArchiveDirectoryTransactionsNeverConfirmPartialWrites(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant := store.RandomID("it_packet_fault_")
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "原包事务验收", tenant, store.Token(), "admin"))
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	id := transport.SensorIdentity{TenantID: tenant, SensorID: "sensor_owned", RegistrationID: "registration_owned"}
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id) VALUES($1,$2,'专属原包探针',$3)`, tenant, id.SensorID, id.RegistrationID)
	require(t, err)
	m, _, stored := packetMaterial(t, id, "packet_fault_seed")
	objects, err := packetarchive.NewLocalObjects(filepath.Join(t.TempDir(), "objects"))
	require(t, err)
	version, err := objects.Put(ctx, packetarchive.ObjectKey(m), bytes.NewReader(stored), int64(len(stored)), packetarchive.Digest(stored))
	require(t, err)
	row, _, err := f.Runtime.BeginPacketArchive(ctx, id, m, 100<<20)
	require(t, err)
	require(t, f.Runtime.RegisterPacketObject(ctx, id, row, version))
	row, err = f.Runtime.CompletePacketArchive(ctx, id, row)
	require(t, err)
	newManifest := m
	newManifest.Capture.ID = "packet_create_fault"
	snapshot := func() string {
		state := map[string]json.RawMessage{}
		require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
			for _, table := range []string{"packet_archives", "packet_archive_capacity", "operation_audits"} {
				var raw []byte
				if e := tx.QueryRow(ctx, "SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY to_jsonb(v)::text),'[]'::jsonb) FROM (SELECT * FROM "+pgx.Identifier{table}.Sanitize()+" WHERE tenant_id=$1) v", tenant).Scan(&raw); e != nil {
					return e
				}
				state[table] = raw
			}
			return nil
		}))
		b, e := json.Marshal(state)
		require(t, e)
		return string(b)
	}
	type op struct {
		name     string
		prefixes []string
		run      func(*store.Postgres) error
	}
	ops := []op{
		{"create", []string{"SELECT public.lock_packet_sensor", "INSERT INTO packet_archive_capacity", "SELECT reserved_bytes", "SELECT id,state,manifest", "INSERT INTO packet_archives(", "UPDATE packet_archive_capacity SET reserved_bytes=reserved_bytes+$2"}, func(db *store.Postgres) error {
			_, _, e := db.BeginPacketArchive(ctx, id, newManifest, 100<<20)
			return e
		}},
		{"read", []string{"SELECT id,state,manifest"}, func(db *store.Postgres) error { _, e := db.PacketArchive(ctx, u, row.ID); return e }},
		{"directory", []string{"SELECT id,state,manifest->'capture'"}, func(db *store.Postgres) error { _, _, e := db.PacketArchives(ctx, u, "", ""); return e }},
		{"version", []string{"SELECT public.lock_packet_sensor", "UPDATE packet_archives SET state='stored'"}, func(db *store.Postgres) error { return db.RegisterPacketObject(ctx, id, row, version) }},
		{"completion", []string{"UPDATE packet_archives SET state='ready'"}, func(db *store.Postgres) error { _, e := db.CompletePacketArchive(ctx, id, row); return e }},
		{"release", []string{"UPDATE packet_archives SET lease_until=now()"}, func(db *store.Postgres) error { return db.ReleasePacketLease(ctx, id, row) }},
		{"download_audit", []string{"INSERT INTO operation_audits"}, func(db *store.Postgres) error { return db.AuditPacketDownload(ctx, u, row.ID, "fault") }},
		{"session_audit", []string{"SELECT id,state,manifest", "INSERT INTO operation_audits"}, func(db *store.Postgres) error {
			return db.AuditPacketSessionExport(ctx, u, []string{row.ID}, "full_session", "fault")
		}},
	}
	for _, operation := range ops {
		for i, prefix := range operation.prefixes {
			t.Run(fmt.Sprintf("%s/%02d", operation.name, i), func(t *testing.T) {
				before := snapshot()
				db, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
				if e := operation.run(db); e == nil || !tracer.fired.Load() {
					t.Fatalf("故障未执行或返回持久确认：%v", e)
				}
				if snapshot() != before {
					t.Fatal("失败事务改变原包目录、容量或审计")
				}
			})
		}
	}
	if _, _, e := f.Runtime.BeginPacketArchive(ctx, id, newManifest, 1); !errors.Is(e, packetarchive.ErrQuota) {
		t.Fatal("目录容量不足仍接受传输", e)
	}
	if _, e := f.Runtime.PacketArchive(ctx, u, "bad/id"); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("非法原包身份可读", e)
	}
	if e := f.Runtime.WithPacketArchives(ctx, u, []string{row.ID}, nil); !errors.Is(e, packetarchive.ErrIntegrity) {
		t.Fatal("缺少读取约束仍取得共享锁", e)
	}
	if e := f.Runtime.WithPacketArchives(ctx, u, []string{row.ID, row.ID}, func([]store.PacketArchive) error { return nil }); !errors.Is(e, packetarchive.ErrIntegrity) {
		t.Fatal("重复源对象被当成独立证据", e)
	}
	if e := f.Runtime.AuditPacketSessionExport(ctx, u, []string{row.ID}, "unknown", "fault"); !errors.Is(e, packetarchive.ErrIntegrity) {
		t.Fatal("未知导出模式写入审计", e)
	}
	if e := f.Runtime.SweepPacketArchives(ctx, nil); !errors.Is(e, packetarchive.ErrIntegrity) {
		t.Fatal("无存储回收资格返回成功", e)
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE packet_archives SET manifest='{}' WHERE tenant_id=$1 AND id=$2`, tenant, row.ID)
	require(t, err)
	if _, e := f.Runtime.PacketArchive(ctx, u, row.ID); e == nil {
		t.Fatal("损坏原包目录返回有效材料")
	}
	if _, _, e := f.Runtime.PacketArchives(ctx, u, "", ""); e == nil {
		t.Fatal("损坏捕获概要可以列出")
	}
}
