//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/watchlist"
)

func watchlistInput(id string) watchlist.Change {
	active := true
	start := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	return watchlist.Change{ID: id, Name: "业务管理地址保护", Description: "保护限定探针的业务管理链路", Active: &active, Definition: watchlist.Definition{SchemaVersion: watchlist.Schema, Kind: "protect", MatchType: "ip", Values: []string{"192.0.2.1"}, Sensors: []watchlist.Sensor{{SensorID: "watchlist_probe", RegistrationID: "watchlist_registration"}}, ValidFrom: start, ValidUntil: start.Add(180 * 24 * time.Hour)}}
}
func watchlistProbe(t *testing.T, ctx context.Context, f *isolatedDatabase, u model.Principal) {
	t.Helper()
	_, e := f.Owner.Pool.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id,active) VALUES($1,'watchlist_probe','名单范围探针','watchlist_registration',true)`, u.TenantID)
	require(t, e)
}

func TestWatchlistsHTTPVersionsScopeMaterialPreviewAndAudit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	f, u, other, password := accountFixture(t, ctx)
	watchlistProbe(t, ctx, f, u)
	active := true
	viewer, e := f.Runtime.CreateUser(ctx, u, "watchlist_viewer_create", accounts.Create{Username: "watchlist_viewer", Password: password, Role: "viewer", Active: &active})
	require(t, e)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	b := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, other.Username, password)
	v := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, viewer.Username, password)
	c := watchlistInput("watchlist_owned")
	var first, repeated watchlist.Record
	a.request("POST", "/watchlists", "watchlist_create", c, &first, 200)
	a.request("POST", "/watchlists", "watchlist_create", c, &repeated, 200)
	if first.Validate() != nil || first.TenantID != u.TenantID || first.CreatedBy != u.ID || first.Revision != 1 || !first.CreatedAt.Equal(repeated.CreatedAt) || first.ExpiresAt.Sub(first.CreatedAt) != 180*24*time.Hour {
		t.Fatal("名单修订、来源或留存无效", first)
	}
	altered := c
	altered.Description = "另一依据"
	a.request("POST", "/watchlists", "watchlist_create", altered, nil, 409)
	a.request("POST", "/watchlists", "", c, nil, 400)
	v.request("POST", "/watchlists", "watchlist_viewer_denied", c, nil, 403)
	noCSRF := *a
	noCSRF.csrf = ""
	noCSRF.request("POST", "/watchlists", "watchlist_csrf_denied", c, nil, 403)
	b.request("GET", "/watchlists/watchlist_owned/revisions/1", "", nil, nil, 404)
	v.request("GET", "/watchlists/watchlist_owned/revisions/1", "", nil, &repeated, 200)
	var page watchlist.Page
	b.request("GET", "/watchlists", "", nil, &page, 200)
	if len(page.Items) != 0 {
		t.Fatal("目录跨租户")
	}
	preview := watchlist.PreviewRequest{Definition: c.Definition, Active: c.Active, Targets: []watchlist.Target{{SensorID: "watchlist_probe", RegistrationID: "watchlist_registration", Type: "ip", Value: "192.0.2.1"}, {SensorID: "watchlist_probe", RegistrationID: "other_registration", Type: "ip", Value: "192.0.2.1"}}}
	var result watchlist.Preview
	a.request("POST", "/watchlists/preview", "", preview, &result, 200)
	if result.SchemaVersion != watchlist.PreviewSchema || result.DefinitionSHA256 != first.DefinitionSHA256 || !result.Admissible || !result.Effective || len(result.Matches) != 2 || !result.Matches[0].Matched || result.Matches[1].Matched || result.ExecutionAuthorized || result.FactDeletionAllowed {
		t.Fatal("匹配、范围或权限错误", result)
	}
	v.request("POST", "/watchlists/preview", "", preview, nil, 403)
	b.request("POST", "/watchlists/preview", "", preview, nil, 409)
	inactive := false
	changed := c
	changed.ExpectedRevision = 1
	changed.Active = &inactive
	a.request("POST", "/watchlists", "watchlist_disable", changed, &repeated, 200)
	a.request("GET", "/watchlists/watchlist_owned/revisions/1", "", nil, &repeated, 200)
	a.request("POST", "/watchlists", "watchlist_stale", changed, nil, 409)
	changed.ExpectedRevision = 2
	a.request("POST", "/watchlists", "watchlist_nochange", changed, nil, 400)
	var writes, previews int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE action='watchlist.save'),count(*) FILTER(WHERE action='watchlist.preview') FROM operation_audits WHERE tenant_id=$1`, u.TenantID).Scan(&writes, &previews))
	if writes != 2 || previews != 1 {
		t.Fatal("名单审计不是原子或幂等", writes, previews)
	}
	_, e = f.Owner.Pool.Exec(ctx, `UPDATE sensors SET registration_id='watchlist_re_registered' WHERE tenant_id=$1 AND id='watchlist_probe'`, u.TenantID)
	require(t, e)
	preview.Definition = c.Definition
	a.request("POST", "/watchlists/preview", "", preview, nil, 409)
	changed.Description = "旧注册不得继承"
	changed.Active = &active
	a.request("POST", "/watchlists", "watchlist_old_registration", changed, nil, 409)
	changed.Active = &inactive
	a.request("POST", "/watchlists", "watchlist_disable_old_registration", changed, &repeated, 200)
	if repeated.Revision != 3 || repeated.Active {
		t.Fatal("旧范围失效后无法停用", repeated)
	}
	changed.ExpectedRevision = 3
	changed.Definition.Values = []string{"192.0.2.2"}
	a.request("POST", "/watchlists", "watchlist_change_old_registration", changed, nil, 409)
	if _, e = f.Runtime.Watchlist(ctx, u, "/", 1); !errors.Is(e, watchlist.ErrInput) {
		t.Fatal(e)
	}
	if _, e = f.Runtime.Watchlists(ctx, u, watchlist.Query{Limit: 0}); !errors.Is(e, watchlist.ErrInput) {
		t.Fatal("存储层接受无效目录", e)
	}
	if _, e = f.Runtime.SaveWatchlist(ctx, u, "", c); !errors.Is(e, watchlist.ErrInput) {
		t.Fatal("存储层接受缺失请求键", e)
	}
	if _, e = f.Runtime.PreviewWatchlist(ctx, u, watchlist.PreviewRequest{}); !errors.Is(e, watchlist.ErrInput) {
		t.Fatal("存储层接受无效预览", e)
	}
	stale := u
	stale.CredentialRevision = 999
	if _, e = f.Runtime.Watchlists(ctx, stale, watchlist.Query{Limit: 20}); !errors.Is(e, watchlist.ErrPermission) {
		t.Fatal("权限过期仍读取", e)
	}
	rollback := watchlistInput("watchlist_atomic_rollback")
	rollback.Definition.Sensors[0].RegistrationID = "watchlist_re_registered"
	_, e = f.Owner.Pool.Exec(ctx, `CREATE FUNCTION reject_watchlist_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='watchlist.save' THEN RAISE EXCEPTION 'isolated audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_watchlist_audit BEFORE INSERT ON operation_audits FOR EACH ROW EXECUTE FUNCTION reject_watchlist_audit()`)
	require(t, e)
	a.request("POST", "/watchlists", "watchlist_atomic_rollback", rollback, nil, 503)
	var heads, revisions int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM watchlists WHERE tenant_id=$1 AND id=$2),(SELECT count(*) FROM watchlist_revisions WHERE tenant_id=$1 AND list_id=$2)`, u.TenantID, rollback.ID).Scan(&heads, &revisions))
	if heads != 0 || revisions != 0 {
		t.Fatal("审计失败留下部分名单", heads, revisions)
	}
}

func TestWatchlistsResponseProtectionExpiryAndLinearizedDisable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	f, u, _, _ := accountFixture(t, ctx)
	watchlistProbe(t, ctx, f, u)
	c := watchlistInput("watchlist_guard")
	record, e := f.Runtime.SaveWatchlist(ctx, u, "watchlist_guard_create", c)
	require(t, e)
	check := func(sensor, registration, address string, now time.Time) (watchlist.ResponseCheck, error) {
		var out watchlist.ResponseCheck
		e := f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
			var inner error
			out, inner = store.CheckWatchlistResponseTx(ctx, tx, u.TenantID, sensor, registration, address, now)
			return inner
		})
		return out, e
	}
	now := time.Now().UTC()
	out, e := check("watchlist_probe", "watchlist_registration", "192.0.2.1", now)
	if !errors.Is(e, watchlist.ErrProtected) || out.StateSHA256 == "" || len(out.Matches) != 1 || out.Matches[0].ID != record.ID || out.Matches[0].Revision != 1 || out.Matches[0].DefinitionSHA256 != record.DefinitionSHA256 {
		t.Fatal("新授权未受保护", out, e)
	}
	protectedHash := out.StateSHA256
	for _, target := range []watchlist.Target{{SensorID: "other_probe", RegistrationID: "watchlist_registration", Type: "ip", Value: "192.0.2.1"}, {SensorID: "watchlist_probe", RegistrationID: "new_registration", Type: "ip", Value: "192.0.2.1"}, {SensorID: "watchlist_probe", RegistrationID: "watchlist_registration", Type: "ip", Value: "192.0.2.2"}} {
		out, e = check(target.SensorID, target.RegistrationID, target.Value, now)
		require(t, e)
		if len(out.Matches) != 0 || out.StateSHA256 != protectedHash {
			t.Fatal("范围外目标被保护", out)
		}
	}
	inactive := false
	c.ExpectedRevision = 1
	c.Active = &inactive
	_, e = f.Runtime.SaveWatchlist(ctx, u, "watchlist_guard_disable", c)
	require(t, e)
	out, e = check("watchlist_probe", "watchlist_registration", "192.0.2.1", now)
	require(t, e)
	if len(out.Matches) != 0 || out.StateSHA256 == protectedHash {
		t.Fatal("停用后新授权仍匹配旧修订", out)
	}
	observe := watchlistInput("watchlist_observe")
	observe.Definition.Kind = "observe"
	_, e = f.Runtime.SaveWatchlist(ctx, u, "watchlist_observe_create", observe)
	require(t, e)
	domain := watchlistInput("watchlist_domain")
	domain.Definition.MatchType = "domain"
	domain.Definition.Values = []string{"example.com"}
	_, e = f.Runtime.SaveWatchlist(ctx, u, "watchlist_domain_create", domain)
	require(t, e)
	out, e = check("watchlist_probe", "watchlist_registration", "192.0.2.1", now)
	require(t, e)
	if len(out.Matches) != 0 {
		t.Fatal("观察或域名被当成IP保护", out)
	}
	wide := watchlistInput("watchlist_wide")
	wide.Definition.MatchType = "cidr"
	wide.Definition.Values = []string{"0.0.0.0/0"}
	if _, e = f.Runtime.SaveWatchlist(ctx, u, "watchlist_wide_active", wide); !errors.Is(e, watchlist.ErrInput) {
		t.Fatal("过宽范围启用", e)
	}
	wide.Active = &inactive
	_, e = f.Runtime.SaveWatchlist(ctx, u, "watchlist_wide_draft", wide)
	require(t, e)
	expired := watchlistInput("watchlist_expired")
	expired.Definition.ValidFrom = now.Truncate(time.Second).Add(-2 * time.Hour)
	expired.Definition.ValidUntil = expired.Definition.ValidFrom.Add(time.Hour)
	if _, e = f.Runtime.SaveWatchlist(ctx, u, "watchlist_expired_create", expired); !errors.Is(e, watchlist.ErrInput) {
		t.Fatal("到期名单启用", e)
	}
	// 独立数据库保留一条先前启用、现已到期的配置，核对实际数据库时间而非调用前时刻。
	expired.Active = &inactive
	expired.Definition.Values = []string{"192.0.2.100"}
	_, e = f.Runtime.SaveWatchlist(ctx, u, "watchlist_expired_draft", expired)
	require(t, e)
	_, e = f.Owner.Pool.Exec(ctx, `UPDATE watchlist_revisions SET active=true WHERE tenant_id=$1 AND list_id=$2`, u.TenantID, expired.ID)
	require(t, e)
	_, e = f.Owner.Pool.Exec(ctx, `UPDATE watchlists SET active=true WHERE tenant_id=$1 AND id=$2`, u.TenantID, expired.ID)
	require(t, e)
	out, e = check("watchlist_probe", "watchlist_registration", "192.0.2.100", expired.Definition.ValidFrom)
	require(t, e)
	if len(out.Matches) != 0 || !out.CheckedAt.After(expired.Definition.ValidUntil) {
		t.Fatal("到期后仍按旧调用时刻命中", out)
	}
	var databaseNow time.Time
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&databaseNow))
	future := watchlistInput("watchlist_scheduled")
	future.Definition.Values = []string{"192.0.2.101"}
	future.Definition.ValidFrom = databaseNow.UTC().Truncate(time.Second).Add(time.Hour)
	future.Definition.ValidUntil = future.Definition.ValidFrom.Add(180 * 24 * time.Hour)
	_, e = f.Runtime.SaveWatchlist(ctx, u, "watchlist_scheduled_create", future)
	require(t, e)
	out, e = check("watchlist_probe", "watchlist_registration", "192.0.2.101", future.Definition.ValidUntil)
	require(t, e)
	if len(out.Matches) != 0 || !out.CheckedAt.Before(future.Definition.ValidFrom) {
		t.Fatal("未生效范围受调用方虚拟时刻影响", out)
	}
	for _, invalid := range []struct {
		tenant, sensor, registration, address string
		at                                    time.Time
	}{{"/", "watchlist_probe", "watchlist_registration", "192.0.2.1", now}, {u.TenantID, "/", "watchlist_registration", "192.0.2.1", now}, {u.TenantID, "watchlist_probe", "/", "192.0.2.1", now}, {u.TenantID, "watchlist_probe", "watchlist_registration", "::ffff:192.0.2.1", now}, {u.TenantID, "watchlist_probe", "watchlist_registration", "192.0.2.1", time.Time{}}} {
		err := f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
			_, inner := store.CheckWatchlistResponseTx(ctx, tx, invalid.tenant, invalid.sensor, invalid.registration, invalid.address, invalid.at)
			return inner
		})
		if !errors.Is(err, watchlist.ErrInput) {
			t.Fatal("无效保护输入没有拒绝", err)
		}
	}
	if e = f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		cancelled, stop := context.WithCancel(ctx)
		stop()
		_, inner := store.CheckWatchlistResponseTx(cancelled, tx, u.TenantID, "watchlist_probe", "watchlist_registration", "192.0.2.1", now)
		return inner
	}); !errors.Is(e, context.Canceled) {
		t.Fatal("取消的核对继续读取或授权", e)
	}
	_, e = f.Owner.Pool.Exec(ctx, `UPDATE watchlists SET name='损坏的当前头' WHERE tenant_id=$1 AND id='watchlist_guard'`, u.TenantID)
	require(t, e)
	if _, e = check("watchlist_probe", "watchlist_registration", "192.0.2.1", now); !errors.Is(e, watchlist.ErrSource) {
		t.Fatal("配置损坏仍授权", e)
	}
}

func TestWatchlistsDirectoryQuotaHistoryRetentionAndCorruption(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, foreign, password := accountFixture(t, ctx)
	watchlistProbe(t, ctx, f, u)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	var record watchlist.Record
	first := watchlistInput("watchlist_000")
	for n := range watchlist.MaxLists {
		c := first
		c.ID = fmt.Sprintf("watchlist_%03d", n)
		a.request("POST", "/watchlists", fmt.Sprintf("watchlist_create_%03d", n), c, &record, 200)
	}
	over := watchlistInput("watchlist_over")
	a.request("POST", "/watchlists", "watchlist_over_quota", over, nil, 429)
	seen := map[string]bool{}
	cursor := ""
	for {
		var page watchlist.Page
		a.request("GET", "/watchlists?limit=17&kind=protect&cursor="+cursor, "", nil, &page, 200)
		for _, item := range page.Items {
			if seen[item.ID] || item.Validate() != nil {
				t.Fatal("目录重复或损坏")
			}
			seen[item.ID] = true
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
		a.request("GET", "/watchlists?limit=18&kind=protect&cursor="+cursor, "", nil, nil, 400)
		if _, e := f.Runtime.Watchlists(ctx, foreign, watchlist.Query{Limit: 17, Kind: "protect", Cursor: cursor}); !errors.Is(e, watchlist.ErrInput) {
			t.Fatal("目录游标跨租户", e)
		}
	}
	if len(seen) != watchlist.MaxLists {
		t.Fatal("目录丢项", len(seen))
	}
	first.ExpectedRevision = 1
	first.Description = "独立修订"
	a.request("POST", "/watchlists", "watchlist_second_revision", first, &record, 200)
	_, e := f.Owner.Pool.Exec(ctx, `UPDATE watchlist_revisions SET created_at=now()-interval '181 days',expires_at=now()-interval '1 day' WHERE tenant_id=$1 AND list_id='watchlist_000' AND revision=1`, u.TenantID)
	require(t, e)
	a.request("GET", "/watchlists/watchlist_000/revisions/1", "", nil, nil, 404)
	original := first
	original.ExpectedRevision = 0
	original.Description = "保护限定探针的业务管理链路"
	a.request("POST", "/watchlists", "watchlist_create_000", original, nil, 409)
	// 清理仅允许已到期且非当前的不可变历史；运行角色不得更新历史。
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `DELETE FROM watchlist_revisions v WHERE v.tenant_id=$1 AND v.expires_at<=now() AND NOT EXISTS(SELECT 1 FROM watchlists h WHERE h.tenant_id=v.tenant_id AND h.id=v.list_id AND h.revision=v.revision)`, u.TenantID)
		return e
	}))
	var remaining int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM watchlist_revisions WHERE tenant_id=$1 AND list_id='watchlist_000' AND revision=1`, u.TenantID).Scan(&remaining))
	if remaining != 0 {
		t.Fatal("到期历史未回收")
	}
	a.request("GET", "/watchlists/watchlist_000/revisions/2", "", nil, &record, 200)
	_, e = f.Owner.Pool.Exec(ctx, `UPDATE watchlist_revisions SET created_at=now()-interval '181 days',expires_at=now()-interval '1 day' WHERE tenant_id=$1 AND list_id='watchlist_000' AND revision=2`, u.TenantID)
	require(t, e)
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		deleted, err := tx.Exec(ctx, `DELETE FROM watchlist_revisions WHERE tenant_id=$1 AND list_id='watchlist_000' AND expires_at<=now()`, u.TenantID)
		if err == nil && deleted.RowsAffected() != 0 {
			return errors.New("当前配置因历史期限被回收")
		}
		return err
	}))
	a.request("GET", "/watchlists/watchlist_000/revisions/2", "", nil, &record, 200)
	if e = f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE watchlist_revisions SET description='不可改写' WHERE tenant_id=$1`, u.TenantID)
		return e
	}); e == nil {
		t.Fatal("运行角色可改写历史")
	}
	_, e = f.Owner.Pool.Exec(ctx, `INSERT INTO watchlist_revisions(tenant_id,list_id,revision,name,description,active,definition,definition_sha256,created_by,key_hash,input_hash,expires_at) SELECT v.tenant_id,v.list_id,10000+n,v.name,v.description,v.active,v.definition,v.definition_sha256,v.created_by,'watchlist_quota_'||n,v.input_hash,now()+interval '180 days' FROM watchlist_revisions v CROSS JOIN generate_series(1,2048)n WHERE v.tenant_id=$1 AND v.list_id='watchlist_000' AND v.revision=2`, u.TenantID)
	require(t, e)
	first.ExpectedRevision = 2
	first.Description = "超过变更预算"
	a.request("POST", "/watchlists", "watchlist_change_over_quota", first, nil, 429)
	_, e = f.Owner.Pool.Exec(ctx, `UPDATE watchlists SET kind='observe' WHERE tenant_id=$1 AND id='watchlist_000'`, u.TenantID)
	require(t, e)
	a.request("GET", "/watchlists", "", nil, nil, 503)
}

func TestWatchlistsProtectionReadPrecedesConcurrentConfigurationChange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	f, u, other, _ := accountFixture(t, ctx)
	watchlistProbe(t, ctx, f, u)
	c := watchlistInput("watchlist_ordered")
	_, e := f.Runtime.SaveWatchlist(ctx, u, "watchlist_ordered_create", c)
	require(t, e)
	if e = f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, inner := store.CheckWatchlistResponseTx(ctx, tx, other.TenantID, "watchlist_probe", "watchlist_registration", "192.0.2.2", time.Now())
		return inner
	}); !errors.Is(e, watchlist.ErrPermission) {
		t.Fatal("调用租户与事务不同仍返回空保护范围", e)
	}
	held, release := make(chan struct{}), make(chan struct{})
	readDone, writeDone := make(chan error, 1), make(chan error, 1)
	released := false
	stop := func() {
		if !released {
			close(release)
			released = true
		}
	}
	defer stop()
	go func() {
		readDone <- f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
			if _, err := store.CheckWatchlistResponseTx(ctx, tx, u.TenantID, "watchlist_probe", "watchlist_registration", "192.0.2.2", time.Now()); err != nil {
				return err
			}
			close(held)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-held:
	case err := <-readDone:
		t.Fatal("保护核对未取得锁", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	inactive := false
	c.Active = &inactive
	c.ExpectedRevision = 1
	go func() { _, err := f.Runtime.SaveWatchlist(ctx, u, "watchlist_ordered_disable", c); writeDone <- err }()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	waiting := false
	for !waiting {
		select {
		case err := <-writeDone:
			t.Fatal("配置未等待在途授权事务", err)
		case <-deadline.C:
			t.Fatal("未观察到配置等待授权事务锁")
		case <-ticker.C:
			require(t, f.Owner.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.locktype='advisory' AND l.mode='ExclusiveLock' AND NOT l.granted AND a.datname=current_database())`).Scan(&waiting))
		}
	}
	stop()
	require(t, <-readDone)
	require(t, <-writeDone)
	var out watchlist.ResponseCheck
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var inner error
		out, inner = store.CheckWatchlistResponseTx(ctx, tx, u.TenantID, "watchlist_probe", "watchlist_registration", "192.0.2.1", time.Now())
		return inner
	}))
	if len(out.Matches) != 0 {
		t.Fatal("停用提交后新授权仍使用旧名单", out)
	}
}
