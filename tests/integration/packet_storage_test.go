//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
)

// measuredObjects 以固定容量代替真实磁盘读数，避免开发机剩余空间影响回收结论。
type measuredObjects struct {
	packetarchive.ObjectStorage
	usage packetarchive.Usage
}

func (m *measuredObjects) Usage() (packetarchive.Usage, error) { return m.usage, nil }

// unmeasuredObjects 模拟无法读取剩余空间的对象存储。
type unmeasuredObjects struct{ packetarchive.ObjectStorage }

func TestPacketStorageReclaimsGloballyOldestAcrossTenants(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	objects, err := packetarchive.NewLocalObjects(filepath.Join(t.TempDir(), "objects"))
	require(t, err)
	identities := map[string]transport.SensorIdentity{}
	password := store.Token()
	for _, tenant := range []string{"pool_a", "pool_b"} {
		require(t, admin.Bootstrap(ctx, f.Owner, tenant, "共享原包存储验收", tenant+"_admin", password, "admin"))
		id := transport.SensorIdentity{TenantID: tenant, SensorID: "sensor_pool", RegistrationID: "registration_" + tenant}
		_, err := f.Owner.Pool.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id) VALUES($1,$2,'共享存储探针',$3)`, tenant, id.SensorID, id.RegistrationID)
		require(t, err)
		identities[tenant] = id
	}
	// 创建时间依次为 A1 最早、B1 其次、A2 最新；回收必须跨租户按全局时间顺序进行，而不是按租户平均分配。
	sizes := map[string]int64{}
	for _, item := range []struct {
		tenant, name string
		age          time.Duration
	}{{"pool_a", "pool_a_first", 3 * time.Hour}, {"pool_b", "pool_b_first", 2 * time.Hour}, {"pool_a", "pool_a_second", time.Hour}} {
		id := identities[item.tenant]
		m, _, stored := packetMaterial(t, id, item.name)
		row, acquired, err := f.Runtime.BeginPacketArchive(ctx, id, m)
		require(t, err)
		if !acquired {
			t.Fatal("新原包未取得传输租约")
		}
		version, err := objects.Put(ctx, row.ObjectKey, bytes.NewReader(stored), int64(len(stored)), m.Encoding.StoredSHA256)
		require(t, err)
		require(t, f.Runtime.RegisterPacketObject(ctx, id, row, version))
		_, err = f.Runtime.CompletePacketArchive(ctx, id, row)
		require(t, err)
		_, err = f.Owner.Pool.Exec(ctx, `UPDATE packet_archives SET created_at=now()-$3::interval WHERE tenant_id=$1 AND id=$2`, item.tenant, item.name, fmt.Sprintf("%d seconds", int(item.age.Seconds())))
		require(t, err)
		sizes[item.name] = m.Encoding.StoredBytes
	}
	exists := func(tenant, name string) bool {
		var n int
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM packet_archives WHERE tenant_id=$1 AND id=$2`, tenant, name).Scan(&n))
		return n == 1
	}
	total := uint64(1 << 40)
	pool := packetarchive.Pool{FreePercent: 5}
	plenty := &measuredObjects{ObjectStorage: objects, usage: packetarchive.Usage{Measured: true, Total: total, Free: total / 2}}
	result, err := f.Runtime.SweepPacketArchives(ctx, plenty, pool)
	require(t, err)
	if result.Evicted != 0 || result.Deleted != 0 || !exists("pool_a", "pool_a_first") {
		t.Fatal("空间充足时提前删除了未到期原包", result)
	}
	// 剩余空间只比阈值少 1 字节：只回收全局最早的一个原包。
	low := &measuredObjects{ObjectStorage: objects, usage: packetarchive.Usage{Measured: true, Total: total, Free: pool.Floor(total) - 1}}
	result, err = f.Runtime.SweepPacketArchives(ctx, low, pool)
	require(t, err)
	if result.Evicted != 1 || result.Deleted != 1 || exists("pool_a", "pool_a_first") || !exists("pool_b", "pool_b_first") || !exists("pool_a", "pool_a_second") {
		t.Fatal("空间不足时未按全局最早优先回收", result)
	}
	// 对象存储无法测量剩余空间时，按目录总量上限回收；保留一个原包即回收其他租户的次早原包。
	result, err = f.Runtime.SweepPacketArchives(ctx, unmeasuredObjects{objects}, packetarchive.Pool{LimitBytes: sizes["pool_a_second"]})
	require(t, err)
	if result.Evicted != 1 || exists("pool_b", "pool_b_first") || !exists("pool_a", "pool_a_second") {
		t.Fatal("目录上限未按全局最早优先回收", result)
	}
	// 正在被会话导出读取的原包不提前删除；读取结束后才回收。
	u, _, err := f.Runtime.Password(ctx, "pool_a_admin")
	require(t, err)
	require(t, f.Runtime.WithPacketArchives(ctx, u, []string{"pool_a_second"}, func([]store.PacketArchive) error {
		locked, err := f.Runtime.SweepPacketArchives(ctx, low, pool)
		if err != nil {
			return err
		}
		if locked.Evicted != 0 || !locked.More || !exists("pool_a", "pool_a_second") {
			t.Error("读取中的原包被提前回收", locked)
		}
		return nil
	}))
	status, err := f.Runtime.PacketStorageStatus(ctx, u, "filesystem", plenty, pool)
	require(t, err)
	if status.Archives != "1" || status.StoredBytes != fmt.Sprint(sizes["pool_a_second"]) || status.Oldest == nil || status.RetentionDays != 180 || !status.Measured || status.FloorBytes != fmt.Sprint(pool.Floor(total)) {
		t.Fatal("存储状态未只统计当前租户或缺少容量阈值", status)
	}
	other, _, err := f.Runtime.Password(ctx, "pool_b_admin")
	require(t, err)
	if status, err = f.Runtime.PacketStorageStatus(ctx, other, "filesystem", plenty, pool); err != nil || status.Archives != "0" || status.Oldest != nil {
		t.Fatal("其他租户看到了不属于自己的原包统计", status, err)
	}
	result, err = f.Runtime.SweepPacketArchives(ctx, low, pool)
	require(t, err)
	if result.Evicted != 1 || exists("pool_a", "pool_a_second") {
		t.Fatal("读取结束后仍未回收", result)
	}
	if _, err = f.Runtime.SweepPacketArchives(ctx, low, pool); err == nil {
		t.Fatal("空间不足且无可回收原包时没有报告")
	}
}
