//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/agent"
	"github.com/kkx600/StarBeacon/internal/application"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestApplicationDeploymentImmutableSnapshotPermissionsCASAndProvenance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	f, u, foreign, password := accountFixture(t, ctx)
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	dir := t.TempDir()
	ca := filepath.Join(dir, "pki")
	require(t, admin.DevPKI(ca))
	identity, err := admin.Provision(ctx, f.Owner, u.TenantID, "application_probe", "应用识别探针", ca, filepath.Join(dir, "agent"))
	require(t, err)
	w, err := agent.OpenWAL(filepath.Join(dir, "wal.db"), identity.TenantID, identity.SensorID, identity.RegistrationID, 4*1024*1024)
	require(t, err)
	defer w.Close()
	service, err := agent.NewApplicationService(w)
	require(t, err)
	heartbeat := func(observed time.Time, capability bool) {
		rawState, _ := json.Marshal(service.Snapshot())
		h := model.HostHealth{ObservedAt: observed, CommandSignerSHA256: control.Digest(pub), ApplicationRules: rawState, TaskCapabilities: []string{}}
		if capability {
			h.TaskCapabilities = append(h.TaskCapabilities, "applications.apply")
		}
		raw, _ := json.Marshal(h)
		require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE sensors SET health=$3,last_seen=now() WHERE tenant_id=$1 AND id=$2`, u.TenantID, identity.SensorID, raw)
			return err
		}))
	}
	heartbeat(time.Now().UTC(), true)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Signer: signer}, u.Username, password)
	b := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Signer: signer}, foreign.Username, password)
	active := true
	viewUser, err := f.Runtime.CreateUser(ctx, u, "application_viewer_create", accounts.Create{Username: "application_viewer", Password: password, Role: "viewer", Active: &active})
	require(t, err)
	v := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Signer: signer}, viewUser.Username, password)
	change := applicationRuleInput("app_live")
	var first application.Record
	a.request("POST", "/application-rules", "application_first", change, &first, 200)
	var snapshot application.Snapshot
	a.request("GET", "/application-rules/snapshot", "", nil, &snapshot, 200)
	v.request("GET", "/application-rules/snapshot", "", nil, &snapshot, 200)
	if len(snapshot.Versions) != 1 || snapshot.RulesSHA256 != application.Digest(snapshot.Versions) {
		t.Fatal("快照遗漏或不完整")
	}
	input := application.DeploymentInput{ExpectedRegistrationID: identity.RegistrationID, ExpectedStateSHA256: service.Snapshot().StateSHA256, RulesSHA256: snapshot.RulesSHA256}
	path := "/sensors/" + identity.SensorID + "/application-rules"
	v.request("POST", path, "viewer_deploy", input, nil, 403)
	b.request("POST", path, "foreign_deploy", input, nil, 404)
	bad := input
	bad.ExpectedRegistrationID = "foreign_registration"
	a.request("POST", path, "registration_deploy", bad, nil, 409)
	bad = input
	bad.RulesSHA256 = application.EmptyState().RulesSHA256
	a.request("POST", path, "stale_directory_deploy", bad, nil, 409)
	heartbeat(time.Now().Add(-time.Minute), true)
	a.request("POST", path, "offline_deploy", input, nil, 409)
	heartbeat(time.Now().UTC(), false)
	a.request("POST", path, "unsupported_deploy", input, nil, 409)
	heartbeat(time.Now().UTC(), true)
	var accepted struct {
		ID string `json:"id"`
	}
	a.request("POST", path, "application_deploy", input, &accepted, 202)
	if _, err := f.Runtime.ApplicationDeployment(ctx, u.TenantID, identity.SensorID, identity.RegistrationID, accepted.ID); !errors.Is(err, store.ErrApplicationProvenance) {
		t.Fatal("尚未投递的任务提供了分类依据", err)
	}
	delivery, err := f.Runtime.NextTask(ctx, identity)
	require(t, err)
	if delivery == nil || delivery.ID != accepted.ID {
		t.Fatal("没有签名部署任务")
	}
	c, err := control.Decode(delivery.Command, delivery.Signature, pub, identity.TenantID, identity.SensorID, identity.RegistrationID, time.Now().UTC())
	require(t, err)
	started := time.Now().UTC()
	raw, code, err := service.Apply(ctx, c)
	require(t, err)
	if code != "" {
		t.Fatal("应用安装错误", code)
	}
	finished := time.Now().UTC()
	receipt := control.Receipt{CommandID: c.ID, CommandSHA256: control.Digest(delivery.Command), State: "succeeded", Result: raw, StartedAt: started, FinishedAt: &finished}
	wrong := receipt
	var fake application.State
	require(t, json.Unmarshal(raw, &fake))
	fake.RuleCount = 0
	wrong.Result, _ = json.Marshal(fake)
	if err := f.Runtime.SaveReceipt(ctx, identity, wrong); !errors.Is(err, application.ErrInput) {
		t.Fatal("伪造生效状态被接受", err)
	}
	require(t, f.Runtime.SaveReceipt(ctx, identity, receipt))
	require(t, f.Runtime.SaveReceipt(ctx, identity, receipt))
	matcher, err := f.Runtime.ApplicationDeployment(ctx, u.TenantID, identity.SensorID, identity.RegistrationID, accepted.ID)
	require(t, err)
	material := []byte(`{"event_type":"http","http":{"hostname":"files.example","http_method":"GET","url":"/documents"}}`)
	observed := time.Now().UTC()
	metadata, err := service.Attribute(material, observed)
	require(t, err)
	attribution, err := application.ReadAttribution(metadata)
	require(t, err)
	require(t, matcher.Verify(attribution, material, accepted.ID, observed))
	if _, err := f.Runtime.ApplicationDeployment(ctx, foreign.TenantID, identity.SensorID, identity.RegistrationID, accepted.ID); !errors.Is(err, store.ErrApplicationProvenance) {
		t.Fatal("跨租户依据被读取", err)
	}
	if _, err := f.Runtime.ApplicationDeployment(ctx, u.TenantID, identity.SensorID, "foreign_registration", accepted.ID); !errors.Is(err, store.ErrApplicationProvenance) {
		t.Fatal("跨注册依据被读取", err)
	}
	edit := applicationRuleEdit(first)
	edit.Definition.Any[0].Value = "other.example"
	var updated application.Record
	a.request("POST", "/application-rules", "application_edit", edit, &updated, 200)
	var repeated struct {
		ID string `json:"id"`
	}
	a.request("POST", path, "application_deploy", input, &repeated, 202)
	if repeated.ID != accepted.ID {
		t.Fatal("目录变化后原提交不再可确认")
	}
	matcher, err = f.Runtime.ApplicationDeployment(ctx, u.TenantID, identity.SensorID, identity.RegistrationID, accepted.ID)
	require(t, err)
	require(t, matcher.Verify(attribution, material, accepted.ID, observed))
	heartbeat(time.Now().UTC(), true)
	a.request("POST", path, "old_state_deploy", input, nil, 409)
	// 默认期限只回收历史档案，当前应用配置仍保留不可变复算依据。
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sensor_tasks SET retain_until=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, u.TenantID, accepted.ID)
		return err
	}))
	_, err = f.Runtime.SweepHistory(ctx)
	require(t, err)
	matcher, err = f.Runtime.ApplicationDeployment(ctx, u.TenantID, identity.SensorID, identity.RegistrationID, accepted.ID)
	require(t, err)
	require(t, matcher.Verify(attribution, material, accepted.ID, observed))
	verifyApplicationIndexingSupplementIsolation(t, ctx, f.Runtime, identity, matcher, accepted.ID)
}
