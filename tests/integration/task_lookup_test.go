//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestTaskDetailReadsRetainedHistoryOutsideListWithoutLiveDevice(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	f, u, signer, input, password := responseTaskFixture(t, ctx)
	id, err := f.Runtime.CreateResponseTask(ctx, u, "sensor_response", "task_history_response", input, signer)
	require(t, err)
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		// 历史夹具保留真实授权命令；模拟任务已结束及设备随后离线、停用。
		if _, err := tx.Exec(ctx, `UPDATE sensor_tasks SET state='succeeded',delivery_count=1,created_at=now()-interval '1 day' WHERE tenant_id=$1 AND id=$2`, u.TenantID, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE sensors SET active=false,last_seen=NULL WHERE tenant_id=$1 AND id='sensor_response'`, u.TenantID); err != nil {
			return err
		}
		for i := 0; i < 201; i++ {
			key := store.RandomID("task_")
			now := time.Now().UTC()
			c := control.Command{ID: key, TenantID: u.TenantID, SensorID: "sensor_response", RegistrationID: "registration_response", Kind: "diagnostics", IssuedAt: now, ExpiresAt: now.Add(30 * time.Minute), Payload: json.RawMessage(`{}`)}
			raw, signature, err := control.Encode(c, signer)
			if err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `INSERT INTO sensor_tasks(tenant_id,id,sensor_id,registration_id,kind,state,idempotency_key,request_sha256,command,signature,command_sha256,created_by,expires_at) VALUES($1,$2,'sensor_response','registration_response','diagnostics','succeeded',$2,$3,$4,$5,$3,$6,$7)`, u.TenantID, key, control.Digest(raw), raw, signature, u.ID, c.ExpiresAt); err != nil {
				return err
			}
		}
		return nil
	}))
	api := &platform.API{DB: f.Runtime} // 档案读取不需要在线设备、ES 或当前签名密钥。
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, api, u.Username, password)
	var listed struct {
		Items []store.SensorTask `json:"items"`
	}
	client.request("GET", "/tasks", "", nil, &listed, 200)
	if len(listed.Items) != 200 {
		t.Fatal("列表预算发生变化", len(listed.Items))
	}
	for _, row := range listed.Items {
		if row.ID == id {
			t.Fatal("历史任务未超出列表预算")
		}
	}
	var detail store.SensorTask
	client.request("GET", "/tasks/"+id, "", nil, &detail, 200)
	if detail.ID != id || detail.State != "succeeded" || detail.ResponseAction == nil || detail.ResponseAction.TargetIP != input.TargetIP || !detail.RetainUntil.After(time.Now().Add(179*24*time.Hour)) || detail.ResponseAction.OwnerSHA256 == "" {
		t.Fatal("未读取原始授权和独立留存期限", detail)
	}
	// 来源摘要损坏不能伪装成可执行的历史授权。
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sensor_tasks SET command_sha256=$3 WHERE tenant_id=$1 AND id=$2`, u.TenantID, id, control.Digest([]byte("different")))
		return err
	}))
	client.request("GET", "/tasks/"+id, "", nil, nil, 503)
}

func TestTaskDetailTenantPermissionRetentionAndExecutionExpiry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	f, u, signer, _, password := responseTaskFixture(t, ctx)
	id, err := f.Runtime.CreateTask(ctx, u, "sensor_response", "diagnostics", "task_history_diagnostic", json.RawMessage(`{}`), signer)
	require(t, err)
	api := &platform.API{DB: f.Runtime}
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, api, u.Username, password)
	client.request("GET", "/tasks/"+id, "", nil, nil, 200)
	client.request("GET", "/tasks/task_missing", "", nil, nil, 404)
	client.request("GET", "/tasks/"+id+"?sensor_id=sensor_response", "", nil, nil, 400)
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sensor_tasks SET expires_at=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, u.TenantID, id)
		return err
	}))
	var detail store.SensorTask
	client.request("GET", "/tasks/"+id, "", nil, &detail, 200)
	if detail.State != "expired" || !detail.RetainUntil.After(time.Now()) {
		t.Fatal("执行到期误删除历史记录")
	}
	other, otherPassword := store.RandomID("it_task_other_"), store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, other, "隔离任务验收", other, otherPassword, "admin"))
	otherClient := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, other, otherPassword)
	otherClient.request("GET", "/tasks/"+id, "", nil, nil, 404)
	if _, err := f.Runtime.Task(ctx, other, id); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("运行身份 RLS 或租户谓词失效", err)
	}
	viewerPassword := store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, u.TenantID, "本租户", "task_viewer", viewerPassword, "viewer"))
	viewer := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, "task_viewer", viewerPassword)
	viewer.request("GET", "/tasks/"+id, "", nil, nil, 403)
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sensor_tasks SET retain_until=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, u.TenantID, id)
		return err
	}))
	client.request("GET", "/tasks/"+id, "", nil, nil, 404)
	var listed struct {
		Items []store.SensorTask `json:"items"`
	}
	client.request("GET", "/tasks", "", nil, &listed, 200)
	if len(listed.Items) != 0 {
		t.Fatal("已过留存期任务仍在列表中泄漏")
	}
	broken, err := store.Open(ctx, f.RuntimeDSN)
	require(t, err)
	broken.Close()
	brokenClient := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: broken}, u.Username, password)
	brokenClient.request("GET", "/tasks/"+id, "", nil, nil, 503)
	// 已撤销的账号会话不能继续读取档案。
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET active=false WHERE tenant_id=$1 AND id=$2`, u.TenantID, u.ID)
		return err
	}))
	client.request("GET", "/tasks/"+id, "", nil, nil, 401)
}

func TestTaskHistoryIndexesSupportTenantAndSensorOrdering(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	for _, name := range []string{"sensor_tasks_recent_tenant", "sensor_tasks_recent_sensor"} {
		var definition string
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT indexdef FROM pg_indexes WHERE schemaname='public' AND indexname=$1`, name).Scan(&definition))
		if !strings.Contains(definition, "tenant_id") || !strings.Contains(definition, "created_at DESC, id DESC") || name == "sensor_tasks_recent_sensor" && !strings.Contains(definition, "sensor_id") {
			t.Fatal("任务列表排序缺少匹配索引", definition)
		}
	}
}
