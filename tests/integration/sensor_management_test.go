//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/sensormanagement"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
)

func TestSensorManagementHTTPGroupingPaginationIsolationAndIdempotency(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, b, password := accountFixture(t, ctx)
	var receiptUpdate, groupDelete, userUpdate, sensorInsert bool
	require(t, f.Runtime.Pool.QueryRow(ctx, `SELECT has_table_privilege(current_user,'sensor_management_requests','UPDATE'),has_table_privilege(current_user,'sensor_groups','DELETE'),has_table_privilege(current_user,'users','UPDATE'),has_table_privilege(current_user,'sensors','INSERT')`).Scan(&receiptUpdate, &groupDelete, &userUpdate, &sensorInsert))
	if receiptUpdate || groupDelete || userUpdate || sensorInsert {
		t.Fatal("探针管理赋予了不必要的运行权限")
	}
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Signer: signer}, u.Username, password)
	other := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Signer: signer}, b.Username, password)
	active := true
	viewerPass := store.Token()
	viewerRecord, err := f.Runtime.CreateUser(ctx, u, "sensor_viewer_create", accounts.Create{Username: "sensor_directory_viewer", Password: viewerPass, Role: "viewer", Active: &active})
	require(t, err)
	viewer := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, viewerRecord.Username, viewerPass)
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id,active,last_seen) SELECT $1,'probe_'||lpad(i::text,4,'0'),'边界探针 '||i,$1||'_reg_'||i,i%3<>0,CASE WHEN i%3=1 THEN now() ELSE NULL END FROM generate_series(1,501) AS i`, u.TenantID)
	require(t, err)
	group := sensormanagement.GroupChange{ID: "sg_owned", Name: "办公站点", Description: "办公镜像区", Active: &active}
	var created, retry sensormanagement.Group
	a.request("POST", "/sensor-groups", "sensor_group_create", group, &created, 200)
	a.request("POST", "/sensor-groups", "sensor_group_create", group, &retry, 200)
	if created.Revision != 1 || created.ID != retry.ID || !created.CreatedAt.Equal(retry.CreatedAt) {
		t.Fatal("分组创建或原提交回执不稳定")
	}
	viewer.request("POST", "/sensor-groups", "sensor_viewer_denied", group, nil, 403)
	noCSRF := *a
	noCSRF.csrf = ""
	noCSRF.request("POST", "/sensor-groups", "sensor_csrf_denied", group, nil, 403)
	a.request("POST", "/sensor-groups", "", group, nil, 400)
	changed := group
	changed.Name = "changed"
	a.request("POST", "/sensor-groups", "sensor_group_create", changed, nil, 409)
	changed = group
	changed.ID = "sg_duplicate_name"
	a.request("POST", "/sensor-groups", "sensor_name_duplicate", changed, nil, 409)
	changed = group
	changed.ID = "sg_foreign"
	changed.Name = "其他站点"
	other.request("POST", "/sensor-groups", "sensor_foreign_group", changed, nil, 200)
	var groups sensormanagement.GroupPage
	viewer.request("GET", "/sensor-groups?active=true", "", nil, &groups, 200)
	if len(groups.Items) != 1 || groups.Items[0].ID != created.ID {
		t.Fatal("只读目录泄漏其他租户或缺少分组")
	}
	var directory store.SensorPage
	seen := map[string]bool{}
	cursor := ""
	for round := 0; round < 6; round++ {
		a.request("GET", "/sensors?limit=100&cursor="+cursor, "", nil, &directory, 200)
		for _, s := range directory.Items {
			if seen[s.ID] || s.MetadataRevision != 1 || s.GroupID != "" {
				t.Fatal("分页重复、遗漏管理修订或初始归类异常")
			}
			seen[s.ID] = true
		}
		cursor = directory.NextCursor
		if cursor == "" {
			break
		}
	}
	if len(seen) != 501 || cursor != "" {
		t.Fatal("超过 500 台的目录无法完整浏览", len(seen))
	}
	// 最早登记的目标位于旧工具目录上限之外，任务必须直接读取目标身份。
	health, err := json.Marshal(model.HostHealth{ObservedAt: time.Now().UTC(), TaskCapabilities: []string{"diagnostics"}, CommandSignerSHA256: control.Digest(public)})
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE sensors SET active=true,created_at='2000-01-01T00:00:00Z',last_seen=now(),health=$3 WHERE tenant_id=$1 AND id=$2`, u.TenantID, "probe_0501", health)
	require(t, err)
	limited, err := f.Runtime.Sensors(ctx, u.TenantID)
	require(t, err)
	if len(limited) != 500 {
		t.Fatal("有界工具目录未按约束返回")
	}
	for _, s := range limited {
		if s.ID == "probe_0501" {
			t.Fatal("测试目标未处于旧目录边界之外")
		}
	}
	var accepted, confirmed map[string]string
	a.request("POST", "/sensors/probe_0501/tasks", "sensor_tail_diagnostics", map[string]string{"kind": "diagnostics"}, &accepted, 202)
	a.request("POST", "/sensors/probe_0501/tasks", "sensor_tail_diagnostics", map[string]string{"kind": "diagnostics"}, &confirmed, 202)
	if accepted["id"] == "" || accepted["id"] != confirmed["id"] {
		t.Fatal("边界外目标任务没有稳定受理")
	}
	identity := transport.SensorIdentity{TenantID: u.TenantID, SensorID: "probe_0501", RegistrationID: u.TenantID + "_reg_501"}
	delivery, err := f.Runtime.NextTask(ctx, identity)
	require(t, err)
	if delivery == nil || delivery.ID != accepted["id"] {
		t.Fatal("边界外探针没有取得自己的持久任务")
	}
	command, err := control.Decode(delivery.Command, delivery.Signature, public, identity.TenantID, identity.SensorID, identity.RegistrationID, time.Now().UTC())
	require(t, err)
	if command.Kind != "diagnostics" || command.SensorID != identity.SensorID {
		t.Fatal("下发目标或签名命令不匹配")
	}
	other.request("POST", "/sensors/probe_0501/tasks", "sensor_tail_foreign", map[string]string{"kind": "diagnostics"}, nil, 404)
	a.request("POST", "/sensors/probe_0003/tasks", "sensor_disabled_task", map[string]string{"kind": "diagnostics"}, nil, 404)
	a.request("POST", "/sensors/missing_probe/tasks", "sensor_missing_task", map[string]string{"kind": "diagnostics"}, nil, 404)
	a.request("POST", "/sensors/bad!id/tasks", "sensor_invalid_target", map[string]string{"kind": "diagnostics"}, nil, 404)
	other.request("GET", "/sensors", "", nil, &directory, 200)
	if len(directory.Items) != 0 {
		t.Fatal("探针目录跨租户")
	}
	for _, status := range []string{"online", "offline", "disabled"} {
		a.request("GET", "/sensors?limit=100&status="+status, "", nil, &directory, 200)
		for _, s := range directory.Items {
			if s.Status != status {
				t.Fatal("连接状态过滤不一致")
			}
		}
	}
	input := sensormanagement.MetadataChange{ExpectedRevision: 1, RegistrationID: u.TenantID + "_reg_1", Name: "办公出口", GroupID: created.ID, Site: "机房 A", Description: "旁路镜像"}
	var metadata sensormanagement.Metadata
	path := "/sensors/probe_0001/metadata"
	a.request("PUT", path, "sensor_metadata_update", input, &metadata, 200)
	if metadata.Revision != 2 || metadata.Name != input.Name || metadata.GroupID != created.ID || metadata.RegistrationID != input.RegistrationID {
		t.Fatal("管理信息没有准确生效")
	}
	a.request("PUT", path, "sensor_metadata_update", input, &metadata, 200)
	a.request("PUT", path, "sensor_metadata_stale", input, nil, 409)
	a.request("PUT", path, "sensor_group_create", input, nil, 409)
	other.request("PUT", path, "sensor_metadata_foreign", input, nil, 404)
	viewer.request("PUT", path, "sensor_metadata_viewer", input, nil, 403)
	input.ExpectedRevision = 2
	input.GroupID = "sg_foreign"
	a.request("PUT", path, "sensor_group_foreign_reference", input, nil, 404)
	input.GroupID = created.ID
	input.RegistrationID = "reg_obsolete"
	a.request("PUT", path, "sensor_registration_obsolete", input, nil, 409)
	input.RegistrationID = u.TenantID + "_reg_1"
	a.request("PUT", path, "sensor_no_change", input, nil, 400)
	a.request("GET", "/sensors?group_id="+created.ID+"&keyword=%E6%9C%BA%E6%88%BF", "", nil, &directory, 200)
	if len(directory.Items) != 1 || directory.Items[0].Name != "办公出口" || directory.Items[0].GroupName != "办公站点" {
		t.Fatal("分组、站点检索或详情缺失")
	}
	single, err := f.Runtime.Sensor(ctx, u.TenantID, "probe_0001")
	require(t, err)
	if single.GroupName != "办公站点" || single.MetadataRevision != 2 {
		t.Fatal("按主键读取缺少管理归属")
	}
	a.request("GET", "/sensors?keyword=%25", "", nil, &directory, 200)
	if len(directory.Items) != 0 {
		t.Fatal("关键字被解释为 SQL 通配符")
	}
	a.request("GET", "/sensors?group_id=ungrouped&limit=100", "", nil, &directory, 200)
	for _, s := range directory.Items {
		if s.GroupID != "" {
			t.Fatal("未分组过滤错误")
		}
	}
	active = false
	group.ExpectedRevision = 1
	group.Active = &active
	a.request("POST", "/sensor-groups", "sensor_group_occupied", group, nil, 409)
	input.GroupID = ""
	input.Site = ""
	input.Description = ""
	a.request("PUT", path, "sensor_remove_group", input, &metadata, 200)
	a.request("POST", "/sensor-groups", "sensor_group_disable", group, &retry, 200)
	if retry.Active || retry.Revision != 2 {
		t.Fatal("空分组停用未生效")
	}
	input.ExpectedRevision = 3
	input.GroupID = created.ID
	a.request("PUT", path, "sensor_inactive_reference", input, nil, 409)
	a.request("GET", "/sensor-groups?active=false", "", nil, &groups, 200)
	if len(groups.Items) != 1 || groups.Items[0].MemberCount != 0 {
		t.Fatal("停用分组或成员数量错误")
	}
	var audits, receipts int
	var minDays, maxDays float64
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action IN('sensor.group','sensor.metadata')`, u.TenantID).Scan(&audits); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*),min(extract(epoch FROM expires_at-created_at)/86400),max(extract(epoch FROM expires_at-created_at)/86400) FROM sensor_management_requests WHERE tenant_id=$1`, u.TenantID).Scan(&receipts, &minDays, &maxDays)
	}))
	if audits != 4 || receipts != 4 || minDays < 179.99 || maxDays > 180.01 {
		t.Fatal("重试产生重复审计或默认留存错误", audits, receipts)
	}
}

func TestSensorManagementTransactionsConcurrencyQuotaAndRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, _, _ := accountFixture(t, ctx)
	active := true
	group := sensormanagement.GroupChange{ID: "sg_cas", Name: "并发站点", Active: &active}
	_, err := f.Runtime.SaveSensorGroup(ctx, u, "sensor_cas_create", group)
	require(t, err)
	group.ExpectedRevision = 1
	errorsCh := make(chan error, 2)
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			c := group
			c.Name = fmt.Sprintf("站点 %d", n)
			_, err := f.Runtime.SaveSensorGroup(ctx, u, fmt.Sprintf("sensor_cas_%d", n), c)
			errorsCh <- err
		}(i)
	}
	wg.Wait()
	close(errorsCh)
	success, conflicts := 0, 0
	for err := range errorsCh {
		if err == nil {
			success++
		} else if errors.Is(err, store.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatal("CAS 并发覆盖", success, conflicts)
	}
	viewer := u
	viewer.Role = "viewer"
	if _, err := f.Runtime.SaveSensorGroup(ctx, viewer, "sensor_bad_role", group); !errors.Is(err, sensormanagement.ErrInput) {
		t.Fatal("直接存储调用绕过角色")
	}
	for _, cut := range []string{"SELECT pg_advisory_xact_lock", "SELECT u.active,u.role", "SELECT operation,object_id", "SELECT count(*) FROM sensor_management_requests", "SELECT id,revision,name", "INSERT INTO sensor_groups", "INSERT INTO operation_audits", "INSERT INTO sensor_management_requests"} {
		broken, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, cut)
		candidate := sensormanagement.GroupChange{ID: store.RandomID("sg_fault_"), Name: store.RandomID("断线_"), Active: &active}
		_, err := broken.SaveSensorGroup(ctx, u, store.RandomID("sensor_fault_"), candidate)
		broken.Close()
		if err == nil || !tracer.fired.Load() {
			t.Fatal("断线未影响指定事务步骤", cut)
		}
		var exists bool
		require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sensor_groups WHERE tenant_id=$1 AND id=$2)`, u.TenantID, candidate.ID).Scan(&exists)
		}))
		if exists {
			t.Fatal("断线留下半个分组", cut)
		}
	}
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id) VALUES($1,'probe_fault','原管理信息','reg_fault')`, u.TenantID)
	require(t, err)
	metadata := sensormanagement.MetadataChange{ExpectedRevision: 1, RegistrationID: "reg_fault", Name: "变更管理信息", GroupID: group.ID, Site: "机房", Description: "旁路"}
	for _, cut := range []string{"SELECT id,metadata_revision", "SELECT active FROM sensor_groups", "UPDATE sensors SET name", "INSERT INTO operation_audits", "INSERT INTO sensor_management_requests"} {
		broken, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, cut)
		_, err := broken.SaveSensorMetadata(ctx, u, "probe_fault", store.RandomID("metadata_fault_"), metadata)
		broken.Close()
		if err == nil || !tracer.fired.Load() {
			t.Fatal("管理信息断线注入没有生效", cut)
		}
		var revision int64
		var name string
		require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT metadata_revision,name FROM sensors WHERE tenant_id=$1 AND id='probe_fault'`, u.TenantID).Scan(&revision, &name)
		}))
		if revision != 1 || name != "原管理信息" {
			t.Fatal("断线留下管理信息或修订半提交", cut)
		}
	}
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO sensor_groups(tenant_id,id,name,description,revision,active) SELECT $1,'sg_limit_'||i,'额度站点 '||i,'',1,true FROM generate_series(1,$2) AS i`, u.TenantID, sensormanagement.MaxGroups-1)
		return err
	}))
	if _, err := f.Runtime.SaveSensorGroup(ctx, u, "sensor_group_overquota", sensormanagement.GroupChange{ID: "sg_limit_extra", Name: "超额站点", Active: &active}); !errors.Is(err, sensormanagement.ErrQuota) {
		t.Fatal("分组额度没有生效", err)
	}
	// 既有回执到期后不得再把旧键解释为新的变更。
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sensor_management_requests SET expires_at=now()-interval '1 second' WHERE tenant_id=$1`, u.TenantID)
		return err
	}))
	group.ExpectedRevision = 0
	group.Name = "并发站点"
	if _, err := f.Runtime.SaveSensorGroup(ctx, u, "sensor_cas_create", group); !errors.Is(err, store.ErrConflict) {
		t.Fatal("到期请求键被重用", err)
	}
	group.ExpectedRevision = 2
	group.Name = "额度下编辑"
	_, err = f.Runtime.SaveSensorGroup(ctx, u, "sensor_group_edit_at_quota", group)
	require(t, err)
	result, err := f.Runtime.SweepHistory(ctx)
	require(t, err)
	if result.ByTable["sensor_management_requests"] != 2 {
		t.Fatal("到期管理回执没有按独立类别清理", result.ByTable)
	}
	page, err := f.Runtime.SensorGroups(ctx, u.TenantID, sensormanagement.Query{Limit: 100})
	require(t, err)
	if len(page.Items) != 100 || page.NextCursor == "" {
		t.Fatal("分组分页不完整")
	}
	// 自定义期限只作用于此后首次提交的管理回执。
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE retention_policies SET days=7 WHERE tenant_id=$1 AND category='operations'`, u.TenantID)
		return err
	}))
	group.ExpectedRevision = 3
	group.Name = "自定义留存"
	_, err = f.Runtime.SaveSensorGroup(ctx, u, "sensor_group_retention", group)
	require(t, err)
	var days float64
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT extract(epoch FROM expires_at-created_at)/86400 FROM sensor_management_requests WHERE tenant_id=$1 AND key_hash=$2`, u.TenantID, store.Hash("sensor_group_retention")).Scan(&days)
	}))
	if days < 6.99 || days > 7.01 {
		t.Fatal("自定义管理留存没有生效")
	}
}
