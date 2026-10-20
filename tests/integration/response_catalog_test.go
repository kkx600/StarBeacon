//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/platform"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/store"
)

func catalogPath(q responseapi.CatalogQuery) string {
	return "/response-actions?" + url.Values{"start": {q.Start.Format(time.RFC3339Nano)}, "end": {q.End.Format(time.RFC3339Nano)}, "limit": {fmt.Sprint(q.Limit)}, "cursor": {q.Cursor}, "sensor_id": {q.SensorID}, "device_id": {q.DeviceID}, "target_ip": {q.TargetIP}, "kind": {q.Kind}, "state": {q.State}}.Encode()
}

func TestResponseCatalogCursorFiltersAndImmutableReads(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, signer, input, password := responseTaskFixture(t, ctx)
	original, err := f.Runtime.CreateResponseTask(ctx, u, "sensor_response", "catalog_original", input, signer)
	require(t, err)
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE sensor_tasks SET state='failed',delivery_count=1 WHERE tenant_id=$1 AND id=$2`, u.TenantID, original); err != nil {
			return err
		}
		for i := 0; i < 205; i++ {
			id := fmt.Sprintf("task_catalog_%03d", i)
			kind := []string{"response.block", "response.read", "response.revoke"}[i%3]
			action := responseapi.Action{SchemaVersion: responseapi.ActionSchema, ConnectorID: input.ConnectorID, ConfigSHA256: input.ConfigSHA256, DeviceID: "device_protocol", LeaseID: id, OwnerSHA256: responseapi.Owner(u.TenantID, "sensor_response", "registration_response", id), TargetIP: input.TargetIP, RequestedAt: base, ExpiresAt: base.Add(time.Minute), Reason: "隔离目录读取夹具"}
			if i%2 == 1 {
				action.TargetIP = "2001:db8::10"
			}
			payload, _ := json.Marshal(action)
			c := control.Command{ID: id, TenantID: u.TenantID, SensorID: "sensor_response", RegistrationID: "registration_response", Kind: kind, IssuedAt: base, ExpiresAt: base.Add(30 * time.Second), Payload: payload}
			raw, signature, err := control.Encode(c, signer)
			if err != nil {
				return err
			}
			state, delivered := "failed", 1
			if i%3 == 1 {
				state = "succeeded"
			}
			if i%3 == 2 {
				state = "unknown"
			}
			if i == 204 {
				state, delivered = "queued", 0
			}
			if _, err = tx.Exec(ctx, `INSERT INTO sensor_tasks(tenant_id,id,sensor_id,registration_id,kind,state,idempotency_key,request_sha256,command,signature,command_sha256,created_by,created_at,expires_at,delivery_count) VALUES($1,$2,'sensor_response','registration_response',$3,$4,$2,$5,$6,$7,$5,$8,$9,$10,$11)`, u.TenantID, id, kind, state, control.Digest(raw), raw, signature, u.ID, base, c.ExpiresAt, delivered); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `UPDATE sensors SET active=false,last_seen=NULL WHERE tenant_id=$1 AND id='sensor_response'`, u.TenantID)
		return err
	}))
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	q := responseapi.CatalogQuery{Start: base.Add(-time.Second), End: base.Add(time.Second), Limit: 20}
	seen := map[string]bool{}
	previous := "task_catalog_999"
	pages := 0
	for {
		var page store.ResponseActionPage
		client.request("GET", catalogPath(q), "", nil, &page, 200)
		pages++
		if len(page.Items) == 0 || len(page.Items) > 20 || page.ObservedAt.IsZero() {
			t.Fatal("分页内容不完整", page)
		}
		for _, row := range page.Items {
			if seen[row.ID] || row.ID >= previous || row.ResponseAction == nil {
				t.Fatal("同时间任务重复、乱序或来源缺失", row.ID)
			}
			seen[row.ID] = true
			previous = row.ID
		}
		if page.NextCursor == "" {
			break
		}
		q.Cursor = page.NextCursor
	}
	if len(seen) != 205 || pages != 11 {
		t.Fatal("超过最近 200 项的历史未完整读取", len(seen), pages)
	}
	q.Cursor = ""
	q.SensorID = "sensor_response"
	q.DeviceID = "device_protocol"
	q.TargetIP = input.TargetIP
	q.Kind = "response.block"
	q.State = "expired"
	var filtered store.ResponseActionPage
	client.request("GET", catalogPath(q), "", nil, &filtered, 200)
	if len(filtered.Items) != 1 || filtered.Items[0].ID != "task_catalog_204" || filtered.Items[0].State != "expired" {
		t.Fatal("筛选或待投递到期显示错误", filtered)
	}
	var state string
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT state FROM sensor_tasks WHERE tenant_id=$1 AND id='task_catalog_204'`, u.TenantID).Scan(&state)
	}))
	if state != "queued" {
		t.Fatal("只读目录改写了任务")
	}
	q.TargetIP = "198.51.100.99"
	client.request("GET", catalogPath(q), "", nil, &filtered, 200)
	if len(filtered.Items) != 0 || filtered.NextCursor != "" {
		t.Fatal("无结果未保持空页")
	}
	var detail store.SensorTask
	client.request("GET", "/response-actions/task_catalog_204", "", nil, &detail, 200)
	if detail.State != "expired" || detail.ResponseAction == nil || detail.ResponseAction.LeaseID != "task_catalog_204" {
		t.Fatal("详情不使用独立原租约")
	}
	// 有效的普通任务不属于响应目录，不能通过详情链接混入。
	newSensor := store.RandomID("sensor_")
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id) VALUES($1,$2,'普通任务','registration_other')`, u.TenantID, newSensor)
		return err
	}))
	diagnostic, err := f.Runtime.CreateTask(ctx, u, newSensor, "diagnostics", "catalog_diagnostic", json.RawMessage(`{}`), signer)
	require(t, err)
	client.request("GET", "/response-actions/"+diagnostic, "", nil, nil, 404)
	client.request("GET", "/response-actions/task_missing", "", nil, nil, 404)
	client.request("GET", "/response-actions/task_catalog_204?extra=x", "", nil, nil, 400)
}

func TestResponseCatalogPermissionCorruptionAndDependencyFailures(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	f, u, signer, input, password := responseTaskFixture(t, ctx)
	id, err := f.Runtime.CreateResponseTask(ctx, u, "sensor_response", "catalog_permissions", input, signer)
	require(t, err)
	q := responseapi.CatalogQuery{Start: time.Now().UTC().Add(-time.Hour), End: time.Now().UTC().Add(time.Second), Limit: 20}
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	client.request("GET", catalogPath(q), "", nil, nil, 200)
	viewerPassword := store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, u.TenantID, "本租户", "catalog_viewer", viewerPassword, "viewer"))
	viewer := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, "catalog_viewer", viewerPassword)
	viewer.request("GET", catalogPath(q), "", nil, nil, 403)
	viewer.request("GET", "/response-actions/"+id, "", nil, nil, 403)
	other, otherPassword := store.RandomID("it_catalog_other_"), store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, other, "隔离目录", other, otherPassword, "admin"))
	otherClient := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, other, otherPassword)
	var empty store.ResponseActionPage
	otherClient.request("GET", catalogPath(q), "", nil, &empty, 200)
	if len(empty.Items) != 0 {
		t.Fatal("其他租户获得响应动作")
	}
	otherClient.request("GET", "/response-actions/"+id, "", nil, nil, 404)
	for _, cut := range []string{"SET LOCAL lock_timeout", "SELECT pg_advisory_xact_lock_shared", "SELECT u.active,u.role", "SET LOCAL statement_timeout", "SELECT transaction_timestamp()", "SELECT id,sensor_id,kind"} {
		broken, _ := disconnectedStore(t, ctx, f.RuntimeDSN, cut)
		_, err := broken.ResponseActions(ctx, u, q)
		broken.Close()
		if err == nil {
			t.Fatal("依赖中断伪装正常目录", cut)
		}
	}
	broken, _ := disconnectedStore(t, ctx, f.RuntimeDSN, "SELECT id,sensor_id,kind")
	_, err = broken.ResponseAction(ctx, u, id)
	broken.Close()
	if err == nil {
		t.Fatal("详情依赖中断未传播")
	}
	bad := q
	bad.Limit = 0
	if _, err = (&store.Postgres{}).ResponseActions(ctx, u, bad); !errors.Is(err, responseapi.ErrInput) {
		t.Fatal("无效查询未在存储前拒绝")
	}
	if _, err = (&store.Postgres{}).ResponseAction(ctx, u, "UPPER"); !errors.Is(err, responseapi.ErrInput) {
		t.Fatal("无效任务身份未在存储前拒绝")
	}
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sensor_tasks SET command_sha256=$3 WHERE tenant_id=$1 AND id=$2`, u.TenantID, id, control.Digest([]byte("different")))
		return err
	}))
	client.request("GET", catalogPath(q), "", nil, nil, 503)
	client.request("GET", "/response-actions/"+id, "", nil, nil, 503)
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET active=false,revision=revision+1 WHERE tenant_id=$1 AND id=$2`, u.TenantID, u.ID)
		return err
	}))
	if _, err = f.Runtime.ResponseActions(ctx, u, q); !errors.Is(err, responseapi.ErrPermission) {
		t.Fatal("账号撤回仍可读取目录", err)
	}
	if _, err = f.Runtime.ResponseAction(ctx, u, id); !errors.Is(err, responseapi.ErrPermission) {
		t.Fatal("账号撤回仍可读取详情", err)
	}
}
