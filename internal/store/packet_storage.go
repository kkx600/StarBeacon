package store

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/telemetry"
)

// packetSweepBatch 是单轮每个租户最多处理的到期原包数；达到上限时立即安排下一轮。
const packetSweepBatch = 64

// maxPacketTenants 限制单轮遍历的租户数，私有化与集团部署通常远低于该值。
const maxPacketTenants = 10000

// PacketSweep 记录一轮原包回收结果；More 表示仍有待处理的到期或回收工作。
type PacketSweep struct {
	Evicted, Deleted           int
	EvictedBytes, DeletedBytes int64
	More                       bool
}

func (p *Postgres) packetTenants(ctx context.Context) ([]string, error) {
	rows, err := p.Pool.Query(ctx, `SELECT id FROM tenants ORDER BY id LIMIT $1`, maxPacketTenants)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

type packetTotals struct {
	Archives, StoredBytes, ExpiredBytes int64
	Oldest                              *time.Time
}

// tenantPacketTotals 在租户自己的 RLS 事务内汇总目录；跨租户合计只在平台进程内计算，不向租户返回其他租户数据。
func (p *Postgres) tenantPacketTotals(ctx context.Context, tenant string) (packetTotals, error) {
	var v packetTotals
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE state='ready' AND expires_at>now()),COALESCE(sum(stored_bytes),0),COALESCE(sum(stored_bytes) FILTER(WHERE expires_at<=now()),0),min(created_at) FILTER(WHERE state='ready' AND expires_at>now()) FROM packet_archives WHERE tenant_id=$1`, tenant).Scan(&v.Archives, &v.StoredBytes, &v.ExpiredBytes, &v.Oldest)
	})
	return v, err
}

type packetCandidate struct {
	tenant, id string
	bytes      int64
	created    time.Time
}

// reclaimPacketStorage 在共享存储低于剩余空间阈值或超过目录上限时，把全部租户中最早的已归档原包提前到期，
// 随后由同一轮删除流程按指定版本删除。正在传输或被会话导出读取锁定的原包跳过，不影响进行中的取证。
func (p *Postgres) reclaimPacketStorage(ctx context.Context, tenants []string, objects packetarchive.ObjectStorage, pool packetarchive.Pool) (int, int64, bool, error) {
	usage := packetarchive.Usage{}
	if measurer, ok := objects.(packetarchive.Measurer); ok {
		var err error
		if usage, err = measurer.Usage(); err != nil {
			return 0, 0, false, err
		}
		telemetry.PacketStorageFree.Set(float64(usage.Free))
	}
	if !usage.Measured && pool.LimitBytes == 0 {
		return 0, 0, false, nil
	}
	var cataloged, pending int64
	for _, tenant := range tenants {
		totals, err := p.tenantPacketTotals(ctx, tenant)
		if err != nil {
			return 0, 0, false, err
		}
		cataloged += totals.StoredBytes
		pending += totals.ExpiredBytes
	}
	need := pool.Reclaim(usage, cataloged, pending)
	evicted, freed, exhausted := 0, int64(0), false
	for round := 0; round < 8 && freed < need && ctx.Err() == nil; round++ {
		candidates := []packetCandidate{}
		for _, tenant := range tenants {
			err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
				rows, err := tx.Query(ctx, `SELECT id,stored_bytes,created_at FROM packet_archives WHERE tenant_id=$1 AND state='ready' AND expires_at>now() AND lease_until<=now() ORDER BY created_at,id LIMIT $2`, tenant, packetSweepBatch)
				if err != nil {
					return err
				}
				defer rows.Close()
				for rows.Next() {
					c := packetCandidate{tenant: tenant}
					if err := rows.Scan(&c.id, &c.bytes, &c.created); err != nil {
						return err
					}
					candidates = append(candidates, c)
				}
				return rows.Err()
			})
			if err != nil {
				return evicted, freed, false, err
			}
		}
		if len(candidates) == 0 {
			exhausted = true
			break
		}
		slices.SortFunc(candidates, func(a, b packetCandidate) int {
			return cmp.Or(a.created.Compare(b.created), strings.Compare(a.tenant, b.tenant), strings.Compare(a.id, b.id))
		})
		chosen, planned := map[string][]string{}, int64(0)
		for _, c := range candidates {
			if freed+planned >= need {
				break
			}
			chosen[c.tenant] = append(chosen[c.tenant], c.id)
			planned += c.bytes
		}
		marked := 0
		for tenant, ids := range chosen {
			err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
				rows, err := tx.Query(ctx, `UPDATE packet_archives SET expires_at=now() WHERE tenant_id=$1 AND id IN(SELECT id FROM packet_archives WHERE tenant_id=$1 AND id=ANY($2) AND state='ready' AND expires_at>now() AND lease_until<=now() FOR UPDATE SKIP LOCKED) RETURNING stored_bytes`, tenant, ids)
				if err != nil {
					return err
				}
				defer rows.Close()
				for rows.Next() {
					var bytes int64
					if err := rows.Scan(&bytes); err != nil {
						return err
					}
					marked++
					freed += bytes
				}
				return rows.Err()
			})
			if err != nil {
				telemetry.PacketEvicted.Add(float64(evicted + marked))
				return evicted + marked, freed, false, err
			}
		}
		evicted += marked
		if marked == 0 {
			// 候选均被传输或导出锁定，下一轮再试。
			break
		}
	}
	telemetry.PacketEvicted.Add(float64(evicted))
	telemetry.PacketEvictedBytes.Add(float64(freed))
	if freed < need && exhausted {
		return evicted, freed, false, errors.New("原包存储低于回收阈值，但已没有可回收的已归档原包；请扩容存储或检查其他占用")
	}
	return evicted, freed, freed < need && ctx.Err() == nil, ctx.Err()
}

// PacketStorageStatus 说明共享原包存储与当前租户的实际可回溯范围。容量数字属于部署存储，
// 原包数量、容量与最早时间只统计当前租户，不暴露其他租户的数据量。
type PacketStorageStatus struct {
	Backend       string     `json:"backend"`
	Measured      bool       `json:"measured"`
	FreeBytes     string     `json:"free_bytes"`
	TotalBytes    string     `json:"total_bytes"`
	FloorBytes    string     `json:"floor_bytes"`
	LimitBytes    string     `json:"limit_bytes"`
	Archives      string     `json:"archives"`
	StoredBytes   string     `json:"stored_bytes"`
	Oldest        *time.Time `json:"oldest_created_at"`
	RetentionDays int        `json:"retention_days"`
}

func (p *Postgres) PacketStorageStatus(ctx context.Context, u model.Principal, backend string, objects packetarchive.ObjectStorage, pool packetarchive.Pool) (PacketStorageStatus, error) {
	status := PacketStorageStatus{Backend: backend, FreeBytes: "0", TotalBytes: "0", FloorBytes: "0", LimitBytes: strconv.FormatInt(pool.LimitBytes, 10)}
	if measurer, ok := objects.(packetarchive.Measurer); ok {
		usage, err := measurer.Usage()
		if err != nil {
			return status, err
		}
		status.Measured = usage.Measured
		status.FreeBytes, status.TotalBytes = strconv.FormatUint(usage.Free, 10), strconv.FormatUint(usage.Total, 10)
		status.FloorBytes = strconv.FormatUint(pool.Floor(usage.Total), 10)
	}
	totals, err := p.tenantPacketTotals(ctx, u.TenantID)
	if err != nil {
		return status, err
	}
	status.Archives, status.StoredBytes, status.Oldest = strconv.FormatInt(totals.Archives, 10), strconv.FormatInt(totals.StoredBytes-totals.ExpiredBytes, 10), totals.Oldest
	err = p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='pcap'),180)`, u.TenantID).Scan(&status.RetentionDays)
	})
	return status, err
}
