//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/platform"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
)

func TestResponsePluginDraftCatalogImmutableVersionsAndTenantScope(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, owner, other, password := accountFixture(t, ctx)
	require(t, admin.Bootstrap(ctx, f.Owner, owner.TenantID, "模板目录验收", "plugin_observer", password, "viewer"))
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, owner.Username, password)
	foreign := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, other.Username, password)
	viewer := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, "plugin_observer", password)
	raw, err := os.ReadFile("../../internal/response/testdata/owned_acl_template.json")
	require(t, err)
	var definition responseapi.Template
	require(t, json.Unmarshal(raw, &definition))
	draft := responseapi.PluginDraft{ID: "acl_owned", Name: "受控 ACL", Device: "HTTPS 设备夹具", Template: definition}
	const path = "/response-plugins"
	var v1, retry, v2, history responseapi.PluginVersion
	client.request("POST", path, "plugin_submit_v1", draft, &v1, 201)
	if v1.Validate() != nil || v1.Version != 1 || v1.State != "draft" || v1.TemplateSHA256 != definition.SHA256() {
		t.Fatal("草稿与版本摘要未在真实数据库中绑定")
	}
	client.request("POST", path, "plugin_submit_v1", draft, &retry, 201)
	if retry.Version != v1.Version || !retry.CreatedAt.Equal(v1.CreatedAt) {
		t.Fatal("相同提交产生了重复版本")
	}
	updated := draft
	updated.Name = "受控 ACL 修订"
	client.request("POST", path, "plugin_submit_v1", updated, nil, 409)
	client.request("POST", path, "plugin_submit_stale", updated, nil, 409)
	updated.ExpectedVersion = 1
	updated.Template.Block.Path = "/v2/acl"
	client.request("POST", path, "plugin_submit_v2", updated, &v2, 201)
	client.request("GET", path+"/acl_owned/versions/1", "", nil, &history, 200)
	if v2.Version != 2 || v2.State != "draft" || v1.TemplateSHA256 == v2.TemplateSHA256 || history.TemplateSHA256 != v1.TemplateSHA256 || history.State != "superseded" || history.Name != draft.Name {
		t.Fatal("新草稿改写了历史内容或没有切换当前版本")
	}
	foreign.request("GET", path+"/acl_owned/versions/1", "", nil, nil, 404)
	viewer.request("GET", path, "", nil, nil, 403)
	viewer.request("POST", path, "plugin_blocked_viewer", draft, nil, 403)
	var page responseapi.PluginPage
	foreign.request("GET", path, "", nil, &page, 200)
	if len(page.Items) != 0 || page.NextAfter != "" {
		t.Fatal("目录泄漏其他租户")
	}
	client.request("GET", path, "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].Version != 2 {
		t.Fatal("目录列出了旧版而非当前草稿")
	}
	stale := owner
	stale.CredentialRevision++
	if _, err := f.Runtime.ResponsePlugins(ctx, stale, "", 20); !errors.Is(err, responseapi.ErrPermission) {
		t.Fatal("旧账号修订仍可读取模板", err)
	}
	if _, err := f.Runtime.ResponsePluginVersion(ctx, stale, draft.ID, 1); !errors.Is(err, responseapi.ErrPermission) {
		t.Fatal("旧账号修订仍可读取模板历史", err)
	}
	if _, err := f.Runtime.SaveResponsePluginDraft(ctx, stale, "stale_account", draft); !errors.Is(err, responseapi.ErrPermission) {
		t.Fatal("旧账号修订仍可写入模板", err)
	}
	var auditCount int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action='response.plugin.draft.save' AND object_id=$2`, owner.TenantID, draft.ID).Scan(&auditCount))
	if auditCount != 2 {
		t.Fatal("审计与不可变版本数不一致", auditCount)
	}
	err = f.Runtime.TenantTx(ctx, owner.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE response_plugin_versions SET name='旧版被改写' WHERE plugin_id=$1`, draft.ID)
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatal("应用角色可改写现有草稿", err)
	}
	// 只向当前验收租户补足目录及历史容量，验证原有分页和额度。
	require(t, f.Owner.TenantTx(ctx, owner.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO response_plugin_versions(tenant_id,plugin_id,version,name,device,template,template_sha256,created_by,request_key_sha256,request_sha256)
		 SELECT tenant_id,'limit_'||lpad(n::text,2,'0'),1,name,device,template,template_sha256,created_by,lpad(to_hex(n+300),64,'0'),repeat('0',64)
		 FROM response_plugin_versions CROSS JOIN generate_series(1,63) AS n WHERE tenant_id=$1 AND plugin_id=$2 AND version=1`, owner.TenantID, draft.ID)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO response_plugin_versions(tenant_id,plugin_id,version,name,device,template,template_sha256,created_by,request_key_sha256,request_sha256)
		 SELECT tenant_id,plugin_id,n,name,device,template,template_sha256,created_by,lpad(to_hex(n+500),64,'0'),repeat('0',64)
		 FROM response_plugin_versions CROSS JOIN generate_series(3,32) AS n WHERE tenant_id=$1 AND plugin_id=$2 AND version=1`, owner.TenantID, draft.ID)
		return err
	}))
	client.request("GET", path+"?limit=10", "", nil, &page, 200)
	if len(page.Items) != 10 || page.NextAfter != "limit_09" || page.Items[0].Version != 32 {
		t.Fatal("分页未绑定当前版本和目录边界")
	}
	client.request("GET", path+"?after="+page.NextAfter+"&limit=10", "", nil, &page, 200)
	if len(page.Items) != 10 || page.Items[0].ID != "limit_10" {
		t.Fatal("续页重复或丢失模板")
	}
	updated.ExpectedVersion = responseapi.MaxPluginVersions
	client.request("POST", path, "plugin_version_quota", updated, nil, 429)
	draft.ID = "overflow"
	client.request("POST", path, "plugin_catalog_quota", draft, nil, 429)
	// 数据损坏时历史查询不能当成正常草稿返回。
	require(t, f.Owner.TenantTx(ctx, owner.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE response_plugin_versions SET template_sha256=repeat('0',64) WHERE tenant_id=$1 AND plugin_id=$2 AND version=1`, owner.TenantID, "acl_owned")
		return err
	}))
	client.request("GET", path+"/acl_owned/versions/1", "", nil, nil, 503)
}
