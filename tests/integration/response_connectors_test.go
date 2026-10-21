//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/store"
)

func connectorPath(q responseapi.ConnectorQuery) string {
	return "/response-connectors?" + url.Values{"sensor_id": {q.SensorID}, "device_id": {q.DeviceID}, "status": {q.Status}, "cursor": {q.Cursor}, "limit": {fmt.Sprint(q.Limit)}}.Encode()
}
func connectorHealth() model.HostHealth {
	return model.HostHealth{ObservedAt: time.Now().UTC(), TaskCapabilities: []string{"response.block", "response.read", "response.revoke"}, ResponseConnectors: []responseapi.Health{{ConnectorID: "connector_a", DeviceID: "device_a", Version: "fixture/1", Status: "ready", ConfigSHA256: strings.Repeat("a", 64), ObservedAt: time.Now().UTC(), MaxTTLSeconds: 3600}}}
}

func TestResponseConnectorsBoundedPagingAndFilters(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, _, _, password := responseTaskFixture(t, ctx)
	const sensors = 53
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		for i := 0; i < sensors; i++ {
			h := connectorHealth()
			h.ResponseConnectors = nil
			for n := 0; n < 4; n++ {
				row := connectorHealth().ResponseConnectors[0]
				row.ConnectorID = fmt.Sprintf("connector_%d", n)
				row.DeviceID = fmt.Sprintf("device_%d", n)
				h.ResponseConnectors = append(h.ResponseConnectors, row)
			}
			raw, _ := json.Marshal(h)
			id := fmt.Sprintf("sensor_connector_%03d", i)
			if _, err := tx.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id,last_seen,health) VALUES($1,$2,'目录分页探针',$3,now(),$4)`, u.TenantID, id, "registration_"+id, raw); err != nil {
				return err
			}
		}
		return nil
	}))
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	q := responseapi.ConnectorQuery{Limit: 20}
	seen := map[string]bool{}
	previous := ""
	pages := 0
	for {
		var page store.ResponseConnectorPage
		client.request("GET", connectorPath(q), "", nil, &page, 200)
		pages++
		if len(page.Items) < 1 || len(page.Items) > 20 || page.Query != q || page.ObservedAt.IsZero() {
			t.Fatal("目录分页或回显无效", page)
		}
		for _, row := range page.Items {
			key := row.SensorID + "/" + row.ConnectorID
			if seen[key] || key <= previous || row.SensorStatus != "online" || row.Observation != "fresh" || !row.TaskSupported {
				t.Fatal("分页乱序、重复或状态不完整", row)
			}
			seen[key] = true
			previous = key
		}
		if page.NextCursor == "" {
			break
		}
		q.Cursor = page.NextCursor
	}
	if len(seen) != sensors*4+1 || pages != 11 {
		t.Fatal("目录在最近两百项处被截断", len(seen), pages)
	}
	q.Cursor = ""
	q.SensorID = "sensor_connector_001"
	q.DeviceID = "device_2"
	q.Status = "ready"
	q.Limit = 1
	var page store.ResponseConnectorPage
	client.request("GET", connectorPath(q), "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].ConnectorID != "connector_2" || page.NextCursor != "" {
		t.Fatal(page)
	}
	q.DeviceID = "device_absent"
	client.request("GET", connectorPath(q), "", nil, &page, 200)
	if len(page.Items) != 0 {
		t.Fatal("设备筛选未生效")
	}
	q = responseapi.ConnectorQuery{Limit: 1}
	client.request("GET", connectorPath(q), "", nil, &page, 200)
	q.Cursor = page.NextCursor
	q.Limit = 2
	client.request("GET", connectorPath(q), "", nil, nil, 400)
}

func TestResponseConnectorsSourceFreshnessIsolationAndRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, _, _, password := responseTaskFixture(t, ctx)
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	q := responseapi.ConnectorQuery{Limit: 20, SensorID: "sensor_response"}
	write := func(raw []byte, active bool, last time.Time) {
		t.Helper()
		require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE sensors SET health=$2,active=$3,last_seen=$4 WHERE tenant_id=$1 AND id='sensor_response'`, u.TenantID, raw, active, last)
			return err
		}))
	}
	for _, test := range []struct {
		status  string
		active  bool
		age     time.Duration
		hostOld bool
	}{{"online", true, 0, false}, {"offline", true, time.Minute, false}, {"offline", true, 0, true}, {"disabled", false, 0, false}} {
		h := connectorHealth()
		if test.hostOld {
			h.ObservedAt = time.Now().Add(-time.Minute)
		}
		raw, _ := json.Marshal(h)
		write(raw, test.active, time.Now().Add(-test.age))
		var page store.ResponseConnectorPage
		client.request("GET", connectorPath(q), "", nil, &page, 200)
		if len(page.Items) != 1 || page.Items[0].SensorStatus != test.status {
			t.Fatal(test, page)
		}
	}
	h := connectorHealth()
	h.ResponseConnectors[0].ObservedAt = time.Now().Add(-time.Minute)
	raw, _ := json.Marshal(h)
	write(raw, true, time.Now())
	var page store.ResponseConnectorPage
	client.request("GET", connectorPath(q), "", nil, &page, 200)
	if page.Items[0].Observation != "stale" {
		t.Fatal("旧设备核验未标记过期")
	}
	h.ResponseConnectors[0].ObservedAt = time.Time{}
	h.ResponseConnectors[0].Status = "unverified"
	raw, _ = json.Marshal(h)
	write(raw, true, time.Now())
	client.request("GET", connectorPath(q), "", nil, &page, 200)
	if page.Items[0].Observation != "pending" {
		t.Fatal("待核验状态不正确")
	}
	for _, bad := range []string{`{"response_connectors":null}`, `{"response_connectors":{}}`, `{"response_connectors":[null]}`} {
		write([]byte(bad), true, time.Now())
		client.request("GET", connectorPath(q), "", nil, nil, 503)
	}
	for _, change := range []func(*model.HostHealth){func(h *model.HostHealth) {
		h.ResponseConnectors = append(h.ResponseConnectors, h.ResponseConnectors[0])
	}, func(h *model.HostHealth) {
		for i := 0; i < 8; i++ {
			h.ResponseConnectors = append(h.ResponseConnectors, h.ResponseConnectors[0])
		}
	}, func(h *model.HostHealth) { h.ResponseConnectors[0].Status = "unknown" }, func(h *model.HostHealth) { h.ResponseConnectors[0].ConfigSHA256 = "bad" }} {
		h := connectorHealth()
		change(&h)
		raw, _ := json.Marshal(h)
		write(raw, true, time.Now())
		client.request("GET", connectorPath(q), "", nil, nil, 503)
	}
	h = connectorHealth()
	raw, _ = json.Marshal(h)
	write(raw, true, time.Now())
	other, otherPassword := store.RandomID("it_devices_other_"), store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, other, "隔离设备目录", other, otherPassword, "admin"))
	otherClient := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, other, otherPassword)
	otherClient.request("GET", connectorPath(q), "", nil, &page, 200)
	if len(page.Items) != 0 {
		t.Fatal("设备目录跨租户泄漏")
	}
	viewerPassword := store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, u.TenantID, "设备目录", "devices_viewer", viewerPassword, "viewer"))
	viewer := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, "devices_viewer", viewerPassword)
	viewer.request("GET", connectorPath(q), "", nil, nil, 403)
	for _, cut := range []string{"SELECT pg_advisory_xact_lock_shared", "SELECT u.active,u.role", "SELECT transaction_timestamp()", "WITH source AS"} {
		broken, _ := disconnectedStore(t, ctx, f.RuntimeDSN, cut)
		_, err := broken.ResponseConnectors(ctx, u, q)
		broken.Close()
		if err == nil {
			t.Fatal("依赖中断伪装正常目录", cut)
		}
	}
	q.Limit = 0
	if _, err := (&store.Postgres{}).ResponseConnectors(ctx, u, q); !errors.Is(err, responseapi.ErrInput) {
		t.Fatal(err)
	}
	q.Limit = 20
	u.CredentialRevision = 9999
	if _, err := f.Runtime.ResponseConnectors(ctx, u, q); !errors.Is(err, responseapi.ErrPermission) {
		t.Fatal("旧账号修订仍可读取", err)
	}
	// 用户与租户状态均在事务内复核，未绕过目录的共享授权锁。
	u.CredentialRevision = 0
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET active=false,revision=revision+1 WHERE tenant_id=$1 AND id=$2`, u.TenantID, u.ID)
		return err
	}))
	if _, err := f.Runtime.ResponseConnectors(ctx, u, q); !errors.Is(err, responseapi.ErrPermission) {
		t.Fatal(err)
	}
}
