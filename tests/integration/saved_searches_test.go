//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/savedsearch"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/traffic"
)

func savedSearchInput(id string) savedsearch.Change {
	active := true
	return savedsearch.Change{ID: id, Name: "业务入口查询", Description: "检查指定业务入口", Visibility: "personal", Active: &active, Definition: savedsearch.Definition{SchemaVersion: savedsearch.Schema, ParserVersion: "1.0", Dataset: "alerts", Mode: "visual", Window: savedsearch.Window{Mode: "relative", Hours: 24}, Terms: savedsearch.Terms{SourceIP: "192.0.2.55", Protocol: "http", Method: "GET", Path: "/api/", Severity: "high"}}}
}

func savedSearchEdit(record savedsearch.Record) savedsearch.Change {
	active := record.Active
	return savedsearch.Change{ID: record.ID, ExpectedRevision: record.Revision, ExpectedGenerationID: record.GenerationID, Name: record.Name, Description: record.Description, Visibility: record.Visibility, Active: &active, Definition: record.Definition}
}

func savedSearchResolveInput(record savedsearch.Record) map[string]any {
	return map[string]any{"expected_revision": record.Revision, "expected_generation_id": record.GenerationID, "dataset": record.Definition.Dataset, "parser_version": record.Definition.ParserVersion}
}

func TestSavedSearchHTTPActualElasticsearchPrivateSharingAndVersionBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	f, u, foreign, password := accountFixture(t, ctx)
	active := true
	viewerAccount, err := f.Runtime.CreateUser(ctx, u, "query_create_viewer", accounts.Create{Username: "saved_query_viewer", Password: password, Role: "viewer", Active: &active})
	require(t, err)
	otherAccount, err := f.Runtime.CreateUser(ctx, u, "query_create_other", accounts.Create{Username: "saved_query_other", Password: password, Role: "admin", Active: &active})
	require(t, err)
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, err)
	now := time.Now().UTC()
	indices := []string{}
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 8*time.Second)
		defer stop()
		for _, index := range indices {
			res, err := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(clean))
			require(t, err)
			_ = res.Body.Close()
			if res.IsError() {
				t.Error("专属查询索引未能清理", res.StatusCode)
			}
		}
	})
	for _, tenant := range []string{u.TenantID, foreign.TenantID} {
		for _, dataset := range []string{"alerts", "context"} {
			index, err := contract.IndexName(tenant, dataset, now.Format("2006-01-02"))
			require(t, err)
			require(t, es.EnsureIndex(ctx, index, now.Format("2006-01-02")))
			indices = append(indices, index)
			doc := model.Alert{EventID: "event_saved_query", TenantID: tenant, SensorID: "sensor_saved_query", RegistrationID: "reg_saved_query", SourceGenerationID: "gen_saved_query", Timestamp: now.Add(-time.Minute), ObservedAt: now, ReceivedAt: now, Severity: "high"}
			doc.Source.IP, doc.Destination.IP = "192.0.2.55", "198.51.100.55"
			doc.Network.Protocol, doc.Network.Transport, doc.HTTP.Method, doc.HTTP.Path = "http", "tcp", "GET", "/api/status"
			doc.Rule.ID, doc.Rule.Name, doc.Suricata.FlowID = "100001", "保存查询验收事件", "18446744073709551615"
			doc.Event.Kind, doc.Event.Original = "alert", `{"event_type":"alert"}`
			if dataset == "context" {
				doc.Event.Kind, doc.Event.Original = "flow", `{"event_type":"flow","flow":{"bytes_toserver":8,"bytes_toclient":0,"pkts_toserver":1,"pkts_toclient":0}}`
			}
			for _, err := range es.Bulk(ctx, index, []model.Alert{doc}) {
				require(t, err)
			}
			res, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
			require(t, err)
			_ = res.Body.Close()
			if res.IsError() {
				t.Fatal("专属查询索引未能刷新", res.StatusCode)
			}
		}
	}
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, u.Username, password)
	other := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, otherAccount.Username, password)
	viewer := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, viewerAccount.Username, password)
	b := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, foreign.Username, password)
	input := savedSearchInput("query_personal")
	var owned, replay savedsearch.Record
	a.request("POST", "/saved-searches", "query_personal_create", input, &owned, 200)
	a.request("POST", "/saved-searches", "query_personal_create", input, &replay, 200)
	if owned.Validate() != nil || owned.OwnerID != u.ID || owned.GenerationID != replay.GenerationID || owned.Revision != 1 || !owned.CreatedAt.Equal(replay.CreatedAt) || owned.ExpiresAt != nil {
		t.Fatal("创建回执或原请求重复不稳定")
	}
	other.request("GET", "/saved-searches/"+owned.ID, "", nil, nil, 404)
	viewer.request("GET", "/saved-searches/"+owned.ID, "", nil, nil, 404)
	b.request("GET", "/saved-searches/"+owned.ID, "", nil, nil, 404)
	var listing savedsearch.Page
	other.request("GET", "/saved-searches", "", nil, &listing, 200)
	if len(listing.Items) != 0 {
		t.Fatal("私有查询出现在他人目录")
	}
	changed := input
	changed.Name = "不同输入"
	a.request("POST", "/saved-searches", "query_personal_create", changed, nil, 409)
	a.request("POST", "/saved-searches", "", input, nil, 400)
	noCSRF := *a
	noCSRF.csrf = ""
	noCSRF.request("POST", "/saved-searches", "query_csrf_denied", input, nil, 403)
	viewerInput := savedSearchInput("query_viewer_personal")
	var viewerRecord savedsearch.Record
	viewer.request("POST", "/saved-searches", "query_viewer_personal_create", viewerInput, &viewerRecord, 200)
	viewerInput.ID, viewerInput.Visibility = "query_viewer_team", "team"
	viewer.request("POST", "/saved-searches", "query_viewer_team_denied", viewerInput, nil, 403)
	sharedInput := savedSearchInput("query_team")
	sharedInput.Visibility = "team"
	var shared savedsearch.Record
	a.request("POST", "/saved-searches", "query_team_create", sharedInput, &shared, 200)
	for _, reader := range []*liveHTTP{other, viewer} {
		reader.request("GET", "/saved-searches/"+shared.ID, "", nil, &replay, 200)
		var resolved savedsearch.Resolution
		reader.request("POST", "/saved-searches/"+shared.ID+"/resolve", "", savedSearchResolveInput(shared), &resolved, 200)
		var query model.SearchRequest
		require(t, json.Unmarshal(resolved.Query, &query))
		var result model.SearchResult
		reader.request("POST", "/alerts/search", "", query, &result, 200)
		if result.Total != 1 || len(result.Items) != 1 || result.Items[0].TenantID != u.TenantID || query.End.Sub(query.Start) != 24*time.Hour || resolved.GenerationID != shared.GenerationID {
			t.Fatal("共享查询扩大权限、污染时间窗口或没有检索实际 ES")
		}
	}
	other.request("POST", "/saved-searches", "query_shared_edit_other", savedSearchEdit(shared), nil, 403)
	viewer.request("POST", "/saved-searches", "query_private_edit_other", savedSearchEdit(owned), nil, 404)
	b.request("POST", "/saved-searches/"+shared.ID+"/resolve", "", savedSearchResolveInput(shared), nil, 404)
	a.request("POST", "/saved-searches", "query_no_change", savedSearchEdit(shared), nil, 400)
	edit := savedSearchEdit(shared)
	edit.Name = "团队入口查询"
	var updated savedsearch.Record
	a.request("POST", "/saved-searches", "query_team_edit", edit, &updated, 200)
	a.request("POST", "/saved-searches", "query_team_create", sharedInput, &replay, 200)
	if replay.Revision != 1 || updated.Revision != 2 || updated.GenerationID != shared.GenerationID {
		t.Fatal("原提交被改成最新记录或实例代次发生漂移")
	}
	a.request("POST", "/saved-searches/"+shared.ID+"/resolve", "", savedSearchResolveInput(shared), nil, 409)
	for _, mutate := range []func(map[string]any){func(v map[string]any) { v["expected_generation_id"] = "old_generation" }, func(v map[string]any) { v["dataset"] = "context" }, func(v map[string]any) { v["parser_version"] = "2.0" }} {
		bad := savedSearchResolveInput(updated)
		mutate(bad)
		a.request("POST", "/saved-searches/"+shared.ID+"/resolve", "", bad, nil, 409)
	}
	for _, bad := range []map[string]any{{"expected_revision": 0, "expected_generation_id": "gen_1", "dataset": "alerts", "parser_version": "1.0"}, {"expected_revision": 1, "expected_generation_id": "", "dataset": "alerts", "parser_version": "1.0"}} {
		a.request("POST", "/saved-searches/"+shared.ID+"/resolve", "", bad, nil, 400)
	}
	advanced := savedSearchInput("query_advanced")
	advanced.Definition.Mode, advanced.Definition.Terms = "advanced", savedsearch.Terms{Filter: "ip.src == 192.0.2.55"}
	var advancedRecord savedsearch.Record
	a.request("POST", "/saved-searches", "query_advanced_create", advanced, &advancedRecord, 200)
	var resolved savedsearch.Resolution
	a.request("POST", "/saved-searches/"+advancedRecord.ID+"/resolve", "", savedSearchResolveInput(advancedRecord), &resolved, 200)
	var alertQuery model.SearchRequest
	require(t, json.Unmarshal(resolved.Query, &alertQuery))
	var alertResult model.SearchResult
	a.request("POST", "/alerts/search", "", alertQuery, &alertResult, 200)
	if alertResult.Total != 1 {
		t.Fatal("已保存显示过滤表达式没有进入真实 ES 查询")
	}
	contextInput := savedSearchInput("query_context")
	start, end := now.Add(-time.Hour), now.Add(time.Hour)
	contextInput.Definition.Dataset, contextInput.Definition.Window, contextInput.Definition.Terms = "context", savedsearch.Window{Mode: "absolute", Start: &start, End: &end}, savedsearch.Terms{EventKind: "flow", SensorID: "sensor_saved_query", RegistrationID: "reg_saved_query", GenerationID: "gen_saved_query", FlowID: "18446744073709551615"}
	var contextRecord savedsearch.Record
	a.request("POST", "/saved-searches", "query_context_create", contextInput, &contextRecord, 200)
	a.request("POST", "/saved-searches/"+contextRecord.ID+"/resolve", "", savedSearchResolveInput(contextRecord), &resolved, 200)
	var contextQuery model.TrafficSearchRequest
	require(t, json.Unmarshal(resolved.Query, &contextQuery))
	var contextResult traffic.Result
	a.request("POST", "/traffic/search", "", contextQuery, &contextResult, 200)
	if contextResult.Total != 1 || !contextQuery.Start.Equal(start) || !contextQuery.End.Equal(end) || contextQuery.FlowID != "18446744073709551615" {
		t.Fatal("协议查询、固定窗口或 uint64 流身份不一致")
	}
	edit = savedSearchEdit(updated)
	edit.Visibility = "personal"
	a.request("POST", "/saved-searches", "query_unshare", edit, &updated, 200)
	other.request("GET", "/saved-searches/"+updated.ID, "", nil, nil, 404)
	other.request("POST", "/saved-searches/"+updated.ID+"/resolve", "", savedSearchResolveInput(updated), nil, 404)
	edit = savedSearchEdit(updated)
	disabled := false
	edit.Active = &disabled
	a.request("POST", "/saved-searches", "query_archive", edit, &updated, 200)
	if updated.Active || updated.ExpiresAt == nil || updated.ExpiresAt.Sub(updated.UpdatedAt) < 179*24*time.Hour {
		t.Fatal("停用查询没有固化默认 180 天期限")
	}
	a.request("POST", "/saved-searches/"+updated.ID+"/resolve", "", savedSearchResolveInput(updated), nil, 409)
	a.request("GET", "/saved-searches?dataset=alerts&visibility=personal&active=false&keyword=%E5%9B%A2%E9%98%9F&limit=100", "", nil, &listing, 200)
	if len(listing.Items) != 1 || listing.Items[0].ID != updated.ID {
		t.Fatal("数据集、可见范围、名称或状态筛选不一致")
	}
	a.request("GET", "/saved-searches?keyword=%25", "", nil, &listing, 200)
	if len(listing.Items) != 0 {
		t.Fatal("名称关键字被解释成 SQL 通配符")
	}
	for _, suffix := range []string{"limit=0", "limit=101", "dataset=packets", "visibility=public", "active=yes", "cursor=a%2Fb", "keyword=a&keyword=b", "unknown=x"} {
		a.request("GET", "/saved-searches?"+suffix, "", nil, nil, 400)
	}
	a.request("GET", "/saved-searches/bad!id", "", nil, nil, 404)
	b.request("GET", "/saved-searches", "", nil, &listing, 200)
	if len(listing.Items) != 0 {
		t.Fatal("其他租户取得了查询目录")
	}
	var count int
	require(t, f.Runtime.Pool.QueryRow(ctx, `SELECT count(*) FROM saved_searches`).Scan(&count))
	if count != 0 {
		t.Fatal("无租户作用域可读取查询")
	}
	require(t, f.Runtime.Pool.QueryRow(ctx, `SELECT count(*) FROM saved_search_changes`).Scan(&count))
	if count != 0 {
		t.Fatal("无租户作用域可读取回执")
	}
	var receiptUpdate bool
	require(t, f.Runtime.Pool.QueryRow(ctx, `SELECT has_table_privilege(current_user,'saved_search_changes','UPDATE')`).Scan(&receiptUpdate))
	if receiptUpdate {
		t.Fatal("运行角色能够改写原提交依据")
	}
}

func TestSavedSearchTransactionsConcurrencyQuotasRetentionAndPermissionRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 130*time.Second)
	defer cancel()
	f, u, _, _ := accountFixture(t, ctx)
	seed, err := f.Runtime.SaveSavedSearch(ctx, u, "query_seed", savedSearchInput("query_seed"))
	require(t, err)
	var results [2]savedsearch.Record
	var failures [2]error
	var work sync.WaitGroup
	for i := range results {
		work.Add(1)
		go func(i int) {
			defer work.Done()
			edit := savedSearchEdit(seed)
			edit.Description = fmt.Sprint("并发版本 ", i)
			results[i], failures[i] = f.Runtime.SaveSavedSearch(ctx, u, fmt.Sprint("query_race_", i), edit)
		}(i)
	}
	work.Wait()
	successes, conflicts := 0, 0
	for i, err := range failures {
		if err == nil {
			successes++
			if results[i].Revision != 2 {
				t.Fatal("并发修订不连续")
			}
		} else if errors.Is(err, store.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatal("同一修订没有唯一写入者")
	}
	for i, prefix := range []string{"SELECT pg_advisory_xact_lock(hashtextextended", "SELECT pg_advisory_xact_lock_shared", "SELECT u.active", "SELECT input_hash", "SELECT tenant_id,id,generation_id", "SELECT count(*) FILTER", "SELECT count(*) FROM saved_search_changes", "INSERT INTO saved_searches", "INSERT INTO operation_audits", "INSERT INTO saved_search_changes"} {
		t.Run(fmt.Sprint("disconnect_", i), func(t *testing.T) {
			before := ownedBusinessSnapshot(t, ctx, f.Runtime, u.TenantID)
			broken, hook := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
			_, err := broken.SaveSavedSearch(ctx, u, fmt.Sprint("query_fault_key_", i), savedSearchInput(fmt.Sprint("query_fault_", i)))
			if err == nil || !hook.fired.Load() {
				t.Fatal("连接中断没有发生在指定真实语句")
			}
			if after := ownedBusinessSnapshot(t, ctx, f.Runtime, u.TenantID); before != after {
				t.Fatal("中断遗留了对象、版本、回执或审计")
			}
		})
	}
	for i, prefix := range []string{"SELECT pg_advisory_xact_lock_shared", "SELECT u.active", "SELECT tenant_id,id,generation_id"} {
		broken, hook := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
		_, err := broken.SavedSearches(ctx, u, savedsearch.ListQuery{Limit: 20})
		if err == nil || !hook.fired.Load() {
			t.Fatal("读取错误被当作空目录", i)
		}
	}
	var raw json.RawMessage
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT record FROM saved_search_changes WHERE tenant_id=$1 AND created_by=$2 AND key_hash=$3`, u.TenantID, u.ID, store.Hash("query_seed")).Scan(&raw))
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE saved_search_changes SET record='{}' WHERE tenant_id=$1 AND created_by=$2 AND key_hash=$3`, u.TenantID, u.ID, store.Hash("query_seed"))
	require(t, err)
	if _, err := f.Runtime.SaveSavedSearch(ctx, u, "query_seed", savedSearchInput(seed.ID)); err == nil {
		t.Fatal("损坏原提交回执被当成成功")
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE saved_search_changes SET record=$4 WHERE tenant_id=$1 AND created_by=$2 AND key_hash=$3`, u.TenantID, u.ID, store.Hash("query_seed"), raw)
	require(t, err)
	if _, err := f.Runtime.SaveSavedSearch(ctx, u, "query_seed", savedSearchInput(seed.ID)); err != nil {
		t.Fatal("恢复原回执后无法核对")
	}
	stored, err := f.Runtime.SavedSearch(ctx, u, seed.ID)
	require(t, err)
	badGeneration := savedSearchEdit(stored)
	badGeneration.ExpectedGenerationID = "generation_stale"
	badGeneration.Description = "过期实例"
	if _, err := f.Runtime.SaveSavedSearch(ctx, u, "query_stale_generation", badGeneration); !errors.Is(err, store.ErrConflict) {
		t.Fatal("变更实例身份未绑定")
	}
	malformedUser := u
	malformedUser.Role = "owner"
	if _, err := f.Runtime.SavedSearches(ctx, malformedUser, savedsearch.ListQuery{Limit: 20}); !errors.Is(err, savedsearch.ErrPermission) {
		t.Fatal("伪造角色能够读取保存查询")
	}
	malformedUser = u
	malformedUser.Role = "viewer"
	if _, err := f.Runtime.SaveSavedSearch(ctx, malformedUser, "query_stale_role", savedSearchInput("query_stale_role")); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("未重验实际账号角色")
	}
	malformedUser = u
	malformedUser.CredentialRevision++
	if _, err := f.Runtime.SavedSearch(ctx, malformedUser, seed.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("旧验证修订能够使用查询配置")
	}
	// 数据库存储损坏与解析器不兼容分别核对，未知版本可展示但不能应用。
	definition, err := json.Marshal(stored.Definition)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE saved_searches SET definition='{}' WHERE tenant_id=$1 AND id=$2`, u.TenantID, seed.ID)
	require(t, err)
	if _, err := f.Runtime.SavedSearch(ctx, u, seed.ID); err == nil {
		t.Fatal("损坏查询记录未被拒绝")
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE saved_searches SET definition=$3::jsonb||'{"parser_version":"2.0"}'::jsonb WHERE tenant_id=$1 AND id=$2`, u.TenantID, seed.ID, definition)
	require(t, err)
	if _, err := f.Runtime.SavedSearch(ctx, u, seed.ID); err != nil {
		t.Fatal("不兼容记录无法查看", err)
	}
	if _, err := f.Runtime.ResolveSavedSearch(ctx, u, seed.ID, stored.GenerationID, "alerts", stored.Revision); !errors.Is(err, savedsearch.ErrVersion) {
		t.Fatal("不兼容查询仍被执行")
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE saved_searches SET definition=$3 WHERE tenant_id=$1 AND id=$2`, u.TenantID, seed.ID, definition)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO saved_searches(tenant_id,id,generation_id,owner_id,revision,name,description,visibility,dataset,active,definition) SELECT $1,'query_limit_'||lpad(i::text,4,'0'),'gen_limit_'||i,$2,1,'限额夹具 '||i,'','personal','alerts',true,$3 FROM generate_series(1,200) i`, u.TenantID, u.ID, definition)
	require(t, err)
	if _, err := f.Runtime.SaveSavedSearch(ctx, u, "query_limit_denied", savedSearchInput("query_over_limit")); !errors.Is(err, savedsearch.ErrQuota) {
		t.Fatal("单账号目录超过配额")
	}
	seen := map[string]bool{}
	cursor := ""
	for round := 0; round < 3; round++ {
		page, err := f.Runtime.SavedSearches(ctx, u, savedsearch.ListQuery{Limit: 100, Cursor: cursor})
		require(t, err)
		for _, item := range page.Items {
			if seen[item.ID] {
				t.Fatal("目录分页重复")
			}
			seen[item.ID] = true
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	if len(seen) != 201 || cursor != "" {
		t.Fatal("目录分页遗漏查询", len(seen))
	}
	_, err = f.Owner.Pool.Exec(ctx, `DELETE FROM saved_searches WHERE tenant_id=$1 AND id LIKE 'query_limit_%'`, u.TenantID)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO saved_search_changes(tenant_id,created_by,key_hash,query_id,generation_id,revision,input_hash,record,expires_at) SELECT $1,$2,md5(i::text)||md5('query-budget-'||i),'query_budget_'||i,'gen_budget_'||i,1,repeat('0',64),'{}'::jsonb,now()+interval '1 day' FROM generate_series(1,10000) i`, u.TenantID, u.ID)
	require(t, err)
	if _, err := f.Runtime.SaveSavedSearch(ctx, u, "query_daily_denied", savedSearchInput("query_daily_denied")); !errors.Is(err, savedsearch.ErrQuota) {
		t.Fatal("共享日变更预算失效")
	}
	_, err = f.Owner.Pool.Exec(ctx, `DELETE FROM saved_search_changes WHERE tenant_id=$1 AND query_id LIKE 'query_budget_%'`, u.TenantID)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO retention_policies(tenant_id,category,days,revision) VALUES($1,'operations',7,1) ON CONFLICT(tenant_id,category) DO UPDATE SET days=7`, u.TenantID)
	require(t, err)
	disabled := false
	edit := savedSearchEdit(stored)
	edit.Active = &disabled
	retired, err := f.Runtime.SaveSavedSearch(ctx, u, "query_retire", edit)
	require(t, err)
	if retired.ExpiresAt == nil || retired.ExpiresAt.Sub(retired.UpdatedAt) != 7*24*time.Hour {
		t.Fatal("自定义留存没有固化")
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE saved_search_changes SET expires_at=now()-interval '1 day' WHERE tenant_id=$1`, u.TenantID)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE saved_searches SET active=false,created_at='2000-01-01',updated_at='2000-01-01',expires_at='2000-07-01' WHERE tenant_id=$1`, u.TenantID)
	require(t, err)
	sweep, err := f.Runtime.SweepHistory(ctx)
	require(t, err)
	if sweep.ByTable["saved_searches"] != 1 || sweep.ByTable["saved_search_changes"] < 1 {
		t.Fatal("过期查询和回执没有按依赖顺序回收", sweep.ByTable)
	}
	if _, err := f.Runtime.SavedSearch(ctx, u, seed.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("到期查询仍可访问")
	}
	newInstance, err := f.Runtime.SaveSavedSearch(ctx, u, "query_recreate", savedSearchInput(seed.ID))
	require(t, err)
	if newInstance.GenerationID == seed.GenerationID {
		t.Fatal("回收后创建沿用旧实例身份")
	}
	if _, err := f.Runtime.ResolveSavedSearch(ctx, u, seed.ID, seed.GenerationID, "alerts", 1); !errors.Is(err, store.ErrConflict) {
		t.Fatal("旧引用被用于另一次创建")
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE users SET active=false WHERE tenant_id=$1 AND id=$2`, u.TenantID, u.ID)
	require(t, err)
	if _, err := f.Runtime.SavedSearches(ctx, u, savedsearch.ListQuery{Limit: 20}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("停用账号还能读取保存查询")
	}
	if _, err := f.Runtime.SaveSavedSearch(ctx, u, "query_disabled_write", savedSearchInput("query_disabled_write")); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("停用账号还能写入保存查询")
	}
}
