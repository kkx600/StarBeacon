//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	accounts "github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/correlation"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
)

func correlationInput(id string) correlation.Change {
	active := true
	return correlation.Change{ID: id, Name: "同源多目标活动", Description: "已有告警的正向窗口回测", Active: &active, Definition: correlation.Definition{SchemaVersion: correlation.Schema, Dataset: "alerts", GroupBy: "source.ip", Metric: "count", WindowSeconds: 60, Threshold: 2}}
}

func TestCorrelationHTTPVersionsIsolationSnapshotEvidenceAndAudit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, foreign, password := accountFixture(t, ctx)
	active := true
	viewer, err := f.Runtime.CreateUser(ctx, u, "correlation_viewer_create", accounts.Create{Username: "correlation_viewer", Password: password, Role: "viewer", Active: &active})
	require(t, err)
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, err)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, u.Username, password)
	b := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, foreign.Username, password)
	v := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, viewer.Username, password)
	change := correlationInput("correlation_source")
	var first, again correlation.Record
	a.request("POST", "/correlation-rules", "correlation_create", change, &first, 200)
	a.request("POST", "/correlation-rules", "correlation_create", change, &again, 200)
	if first.Validate() != nil || first.TenantID != u.TenantID || first.CreatedBy != u.ID || first.Revision != 1 || first.CreatedAt != again.CreatedAt || first.ExpiresAt.Sub(first.CreatedAt) != 180*24*time.Hour {
		t.Fatal("修订、默认留存或原提交回执不一致", first)
	}
	changed := change
	changed.Name = "不同输入"
	a.request("POST", "/correlation-rules", "correlation_create", changed, nil, 409)
	a.request("POST", "/correlation-rules", "", change, nil, 400)
	v.request("POST", "/correlation-rules", "correlation_viewer_denied", change, nil, 403)
	noCSRF := *a
	noCSRF.csrf = ""
	noCSRF.request("POST", "/correlation-rules", "correlation_csrf_denied", change, nil, 403)
	b.request("GET", "/correlation-rules/correlation_source/revisions/1", "", nil, nil, 404)
	v.request("GET", "/correlation-rules/correlation_source/revisions/1", "", nil, &again, 200)
	var page correlation.Page
	b.request("GET", "/correlation-rules", "", nil, &page, 200)
	if len(page.Items) != 0 {
		t.Fatal("目录跨租户")
	}
	end := time.Now().UTC().Truncate(time.Minute)
	start := end.Add(-2 * time.Minute)
	query := correlation.Request{ExpectedRevision: 1, Start: start, End: end}
	v.request("POST", "/correlation-rules/correlation_source/backtest", "", query, nil, 403)
	for _, tenant := range []string{u.TenantID, foreign.TenantID} {
		partition := time.Now().UTC().Format("2006-01-02")
		index, err := contract.IndexName(tenant, "alerts", partition)
		require(t, err)
		require(t, es.EnsureIndex(ctx, index, partition))
		t.Cleanup(func() {
			clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			response, err := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(clean))
			require(t, err)
			defer response.Body.Close()
			if response.IsError() {
				t.Error("关联验收索引清理失败", response.StatusCode)
			}
		})
		docs := []model.Alert{}
		for n := range 4 {
			at := start.Add(time.Duration(n/2)*time.Minute + time.Duration(n%2+1)*time.Second)
			raw := fmt.Sprintf(`{"event_type":"alert","src_ip":"192.0.2.1","dest_ip":"198.51.100.%d","alert":{"signature_id":1000001,"signature":"fixture"}}`, n+1)
			digest := sha256.Sum256([]byte(raw))
			doc := model.Alert{SchemaVersion: "1.0", TenantID: tenant, EventID: fmt.Sprintf("correlation_event_%02d", n), SensorID: "correlation_probe", RegistrationID: "correlation_registration", Timestamp: at, ObservedAt: at, ReceivedAt: at, RawSHA256: hex.EncodeToString(digest[:])}
			doc.Event.Kind, doc.Event.Original, doc.Source.IP, doc.Destination.IP, doc.Destination.Port, doc.Rule.ID = "alert", raw, "192.0.2.1", fmt.Sprintf("198.51.100.%d", n+1), 443, "1000001"
			docs = append(docs, doc)
		}
		for _, err := range es.Bulk(ctx, index, docs) {
			require(t, err)
		}
		response, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
		require(t, err)
		if response.IsError() {
			t.Fatal("关联验收索引未刷新", response.StatusCode)
		}
		response.Body.Close()
	}
	var result, repeated correlation.Result
	a.request("POST", "/correlation-rules/correlation_source/backtest", "", query, &result, 200)
	a.request("POST", "/correlation-rules/correlation_source/backtest", "", query, &repeated, 200)
	if result.UniqueEvents != 4 || result.ThresholdWindows != 2 || len(result.Windows) != 2 || result.SourceCoverage != "not_attested" || result.ExecutionAuthorized || result.SnapshotSHA256 != repeated.SnapshotSHA256 || result.RuleRevision != 1 || result.DefinitionSHA256 != first.DefinitionSHA256 {
		t.Fatal("快照计数、稳定身份或范围不一致", result)
	}
	for i, w := range result.Windows {
		if w.Count != 2 || len(w.Evidence) != 2 || w.EvidenceTruncated || w.DetectionID != repeated.Windows[i].DetectionID || w.EvidenceSHA256 != repeated.Windows[i].EvidenceSHA256 || w.Status != "threshold_observed" {
			t.Fatal("窗口证据或重跑身份不一致", w)
		}
	}
	var reads, changes int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE action='correlation.backtest.read'),count(*) FILTER(WHERE action='correlation.rule.save') FROM operation_audits WHERE tenant_id=$1`, u.TenantID).Scan(&reads, &changes))
	if reads != 2 || changes != 1 {
		t.Fatal("回测审计或幂等写入不一致", reads, changes)
	}
	query.ExpectedRevision = 2
	a.request("POST", "/correlation-rules/correlation_source/backtest", "", query, nil, 409)
	query.ExpectedRevision = 1
	query.Start = start.Add(time.Second)
	a.request("POST", "/correlation-rules/correlation_source/backtest", "", query, &repeated, 200)
	if repeated.PartialWindows != 1 || repeated.ThresholdWindows != 1 {
		t.Fatal("边界窗口被计入完整阈值结果", repeated)
	}
	query.Start = start
	changed = change
	changed.ExpectedRevision = 1
	changed.Definition.Metric = "distinct"
	changed.Definition.DistinctField = "destination.ip"
	a.request("POST", "/correlation-rules", "correlation_edit", changed, &again, 200)
	a.request("POST", "/correlation-rules/correlation_source/backtest", "", query, nil, 409)
	query.ExpectedRevision = 2
	a.request("POST", "/correlation-rules/correlation_source/backtest", "", query, &result, 200)
	if result.ThresholdWindows != 2 || result.RuleRevision != 2 {
		t.Fatal("不同值回测不一致", result)
	}
	changed.ExpectedRevision = 2
	changed.Definition.Filter = "ip.src == 203.0.113.1"
	a.request("POST", "/correlation-rules", "correlation_filter", changed, &again, 200)
	query.ExpectedRevision = 3
	a.request("POST", "/correlation-rules/correlation_source/backtest", "", query, &result, 200)
	if result.UniqueEvents != 0 || len(result.Windows) != 0 || result.SourceCoverage != "not_attested" {
		t.Fatal("空快照被解释为覆盖证明", result)
	}
	changed.ExpectedRevision = 3
	inactive := false
	changed.Active = &inactive
	a.request("POST", "/correlation-rules", "correlation_disable", changed, &again, 200)
	query.ExpectedRevision = 4
	a.request("POST", "/correlation-rules/correlation_source/backtest", "", query, nil, 409)
	a.request("GET", "/correlation-rules/correlation_source/revisions/1", "", nil, &again, 200)
	stale := u
	stale.CredentialRevision = 999
	if _, err := f.Runtime.CurrentCorrelationRule(ctx, stale, change.ID, 4); !errors.Is(err, correlation.ErrPermission) {
		t.Fatal("过期身份未拒绝", err)
	}
	if err := f.Runtime.RecordCorrelationBacktest(ctx, u, change.ID, 3, "correlation_stale_audit"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("修订变化仍写入交付审计", err)
	}
}

func TestCorrelationDirectoryPaginationQuotasExpiryAndRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, foreign, password := accountFixture(t, ctx)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	var record correlation.Record
	for n := range correlation.MaxRules {
		change := correlationInput(fmt.Sprintf("correlation_%03d", n))
		a.request("POST", "/correlation-rules", fmt.Sprintf("correlation_create_%03d", n), change, &record, 200)
	}
	a.request("POST", "/correlation-rules", "correlation_over_quota", correlationInput("correlation_overflow"), nil, 429)
	seen := map[string]bool{}
	cursor := ""
	for {
		var page correlation.Page
		a.request("GET", "/correlation-rules?limit=17&keyword=同源&cursor="+cursor, "", nil, &page, 200)
		for _, item := range page.Items {
			if seen[item.ID] || item.Validate() != nil {
				t.Fatal("分页重复或损坏", item.ID)
			}
			seen[item.ID] = true
		}
		if page.NextCursor == "" {
			break
		}
		if cursor == page.NextCursor {
			t.Fatal("游标没有推进")
		}
		cursor = page.NextCursor
		a.request("GET", "/correlation-rules?limit=18&keyword=同源&cursor="+cursor, "", nil, nil, 400)
		if _, err := f.Runtime.CorrelationRules(ctx, foreign, correlation.Query{Limit: 17, Keyword: "同源", Cursor: cursor}); !errors.Is(err, correlation.ErrInput) {
			t.Fatal("游标未绑定租户", err)
		}
	}
	if len(seen) != correlation.MaxRules {
		t.Fatal("目录分页不完整", len(seen))
	}
	first := correlationInput("correlation_000")
	first.ExpectedRevision = 1
	first.Description = "受控修订"
	a.request("POST", "/correlation-rules", "correlation_revision_two", first, &record, 200)
	_, err := f.Owner.Pool.Exec(ctx, `UPDATE correlation_rule_revisions SET created_at=now()-interval '181 days',expires_at=now()-interval '1 day' WHERE tenant_id=$1 AND rule_id=$2 AND revision=1`, u.TenantID, first.ID)
	require(t, err)
	a.request("GET", "/correlation-rules/correlation_000/revisions/1", "", nil, nil, 404)
	a.request("POST", "/correlation-rules", "correlation_create_000", correlationInput(first.ID), nil, 409)
	_, err = f.Runtime.SweepHistory(ctx)
	require(t, err)
	var count int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM correlation_rule_revisions WHERE tenant_id=$1 AND rule_id=$2 AND revision=1`, u.TenantID, first.ID).Scan(&count))
	if count != 0 {
		t.Fatal("到期的未引用历史没有清理")
	}
	a.request("GET", "/correlation-rules/correlation_000/revisions/2", "", nil, &record, 200)
	for _, invalid := range []string{"/?bad=1", "/?limit=0", "/?limit=020", "/?active=yes", "/?keyword=x&keyword=y"} {
		a.request("GET", "/correlation-rules"+invalid[1:], "", nil, nil, 400)
	}
	if _, err := f.Runtime.CorrelationRule(ctx, u, first.ID, 0); !errors.Is(err, correlation.ErrInput) {
		t.Fatal(err)
	}
	if _, err := f.Runtime.CurrentCorrelationRule(ctx, u, first.ID, 0); !errors.Is(err, correlation.ErrInput) {
		t.Fatal(err)
	}
	if err := f.Runtime.RecordCorrelationBacktest(ctx, u, "/", 1, "request_owned"); !errors.Is(err, correlation.ErrInput) {
		t.Fatal(err)
	}
	if _, err := f.Runtime.CorrelationRules(ctx, u, correlation.Query{Limit: 0}); !errors.Is(err, correlation.ErrInput) {
		t.Fatal(err)
	}
	if _, err := f.Runtime.SaveCorrelationRule(ctx, u, "", first); !errors.Is(err, correlation.ErrInput) {
		t.Fatal(err)
	}

	// 头记录与不可变修订不一致时不能交付目录或使用该配置。
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE correlation_rules SET name='不一致的头记录' WHERE tenant_id=$1 AND id=$2`, u.TenantID, first.ID)
	require(t, err)
	a.request("GET", "/correlation-rules", "", nil, nil, 503)
	if _, err := f.Runtime.CurrentCorrelationRule(ctx, u, first.ID, 2); err == nil {
		t.Fatal("不一致配置仍允许回测")
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE correlation_rules SET name=$3 WHERE tenant_id=$1 AND id=$2`, u.TenantID, first.ID, first.Name)
	require(t, err)
	a.request("POST", "/correlation-rules", "correlation_no_change", first, nil, 409)
	first.ExpectedRevision = 2
	a.request("POST", "/correlation-rules", "correlation_no_change_two", first, nil, 400)
	// 在专属测试租户注入变更预算，检查超额请求没有生成下一修订。
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO correlation_rule_revisions(tenant_id,rule_id,revision,name,description,active,definition,definition_sha256,created_by,key_hash,input_hash,expires_at) SELECT v.tenant_id,v.rule_id,10000+n,v.name,v.description,v.active,v.definition,v.definition_sha256,v.created_by,'quota_'||n,v.input_hash,now()+interval '180 days' FROM correlation_rule_revisions v CROSS JOIN generate_series(1,2048) n WHERE v.tenant_id=$1 AND v.rule_id=$2 AND v.revision=2`, u.TenantID, first.ID)
	require(t, err)
	first.Description = "超过每日变更预算"
	a.request("POST", "/correlation-rules", "correlation_daily_quota", first, nil, 429)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE users SET active=false,revision=revision+1 WHERE tenant_id=$1 AND id=$2`, u.TenantID, u.ID)
	require(t, err)
	a.request("GET", "/correlation-rules", "", nil, nil, 401)
	if _, err := f.Runtime.CorrelationRule(ctx, u, first.ID, 2); !errors.Is(err, correlation.ErrPermission) {
		t.Fatal("被停用账号仍读取规则", err)
	}
	if _, err := f.Runtime.CurrentCorrelationRule(ctx, u, "missing_rule", 1); !errors.Is(err, correlation.ErrPermission) && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}
}
