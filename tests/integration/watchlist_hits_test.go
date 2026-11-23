//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/watchlist"
)

// observeWatchlist 保存一份启用的观察名单；命中只关联修订保存之后接收的告警，调用方据返回的 CreatedAt 构造材料。
func observeWatchlist(t *testing.T, ctx context.Context, f *isolatedDatabase, u model.Principal, id, registrationID string, values ...string) watchlist.Record {
	t.Helper()
	c := watchlistInput(id)
	c.Definition.Kind = "observe"
	c.Definition.Sensors[0].RegistrationID = registrationID
	c.Definition.Values = values
	record, e := f.Runtime.SaveWatchlist(ctx, u, id+"_create", c)
	require(t, e)
	if record.Revision != 1 || !record.Active || record.Definition.Kind != "observe" {
		t.Fatal("观察名单初始修订无效", record)
	}
	return record
}

// hitAlert 构造符合索引映射与登记前置条件的告警；原始 EVE 只用于域名字段解析，不携带运行环境数据。
func hitAlert(tenant, event string, observed, received time.Time, source, destination string) model.Alert {
	raw := fmt.Sprintf(`{"event_type":"alert","src_ip":%q,"dest_ip":%q,"alert":{"signature_id":1000777,"signature":"观察名单命中验收"}}`, source, destination)
	a := model.Alert{SchemaVersion: "1.0", TenantID: tenant, EventID: event, SensorID: "watchlist_probe", RegistrationID: watchlistRegistrationID, SourceGenerationID: "generation_watchlist_hits", RawSHA256: store.Hash(event + "/" + raw), Timestamp: observed, ObservedAt: observed, ReceivedAt: received, Severity: "high"}
	a.Event.Kind, a.Event.Original = "alert", raw
	a.Source.IP, a.Destination.IP = source, destination
	a.Rule.ID, a.Rule.Name = "1000777", "观察名单命中验收规则"
	return a
}

func hitCount(t *testing.T, ctx context.Context, f *isolatedDatabase, tenant, list string) int {
	t.Helper()
	var count int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM watchlist_hits WHERE tenant_id=$1 AND list_id=$2`, tenant, list).Scan(&count))
	return count
}

func hitWindow(start, end time.Time, extra string) string {
	return "?start=" + url.QueryEscape(start.Format(time.RFC3339Nano)) + "&end=" + url.QueryEscape(end.Format(time.RFC3339Nano)) + extra
}

// 在实际 PostgreSQL 上核对命中登记的去重、日上限截断和跨租户隔离；不以返回值代替权威表的核对。
func TestWatchlistHitsRecordDeduplicationDailyCapAndTenantIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, other, password := accountFixture(t, ctx)
	const otherRegistrationID = "watchlist_other_registration"
	watchlistProbe(t, ctx, f, u, watchlistRegistrationID)
	watchlistProbe(t, ctx, f, other, otherRegistrationID)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	b := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, other.Username, password)
	record := observeWatchlist(t, ctx, f, u, "whits_dedup", watchlistRegistrationID, "198.18.0.1", "198.18.0.2")
	// 两个租户使用相同名单标识，跨租户读取只能被行级安全隔离，而不是靠名单不存在。
	observeWatchlist(t, ctx, f, other, "whits_dedup", otherRegistrationID, "198.18.0.1", "198.18.0.2")
	base := record.CreatedAt.UTC()
	received := base.Add(time.Second)
	alerts := []model.Alert{
		hitAlert(u.TenantID, "event_whits_source", base.Add(-30*time.Second), received, "198.18.0.1", "203.0.113.60"),
		hitAlert(u.TenantID, "event_whits_destination", base.Add(-20*time.Second), received, "203.0.113.61", "198.18.0.2"),
		hitAlert(u.TenantID, "event_whits_both", base.Add(-10*time.Second), received, "198.18.0.1", "198.18.0.2"),
		hitAlert(u.TenantID, "event_whits_unrelated", base.Add(-5*time.Second), received, "203.0.113.62", "203.0.113.63"),
	}
	// 修订保存前接收的告警不追溯登记；历史数据只能通过影响预览核对。
	historic := hitAlert(u.TenantID, "event_whits_historic", base.Add(-40*time.Second), base.Add(-time.Minute), "198.18.0.1", "203.0.113.64")
	require(t, f.Runtime.RecordWatchlistHits(ctx, u.TenantID, []model.Alert{historic}))
	if n := hitCount(t, ctx, f, u.TenantID, record.ID); n != 0 {
		t.Fatal("修订保存前接收的告警被登记", n)
	}
	// 同一批告警重复投递按稳定命中标识去重，命中数不变。
	require(t, f.Runtime.RecordWatchlistHits(ctx, u.TenantID, alerts))
	first := hitCount(t, ctx, f, u.TenantID, record.ID)
	require(t, f.Runtime.RecordWatchlistHits(ctx, u.TenantID, alerts))
	if second := hitCount(t, ctx, f, u.TenantID, record.ID); first != 3 || second != first {
		t.Fatal("命中登记未按稳定标识去重", first, second)
	}
	var recorded int
	var capped *time.Time
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT recorded,capped_at FROM watchlist_hit_days WHERE tenant_id=$1 AND list_id=$2`, u.TenantID, record.ID).Scan(&recorded, &capped))
	if recorded != 3 || capped != nil {
		t.Fatal("处理日计数重投后放大或误标截断", recorded, capped)
	}
	start, end := base.Add(-time.Hour), time.Now().UTC()
	var page watchlist.HitPage
	a.request("GET", "/watchlists/"+record.ID+"/hits"+hitWindow(start, end, ""), "", nil, &page, 200)
	if len(page.Items) != 3 || page.NextCursor != "" || len(page.CappedDays) != 0 || page.ObservedAt.IsZero() {
		t.Fatal("命中读取数量、游标或截断提示不一致", page)
	}
	// 按告警观测时间倒序；每条命中绑定当时的修订与定义摘要。
	for i, want := range []string{"event_whits_both", "event_whits_destination", "event_whits_source"} {
		hit := page.Items[i]
		if hit.EventID != want || hit.ListID != record.ID || hit.ListRevision != 1 || hit.DefinitionSHA256 != record.DefinitionSHA256 || hit.Validate(u.TenantID) != nil || hit.Severity != "high" || hit.RuleID != "1000777" {
			t.Fatal("命中顺序或固化材料不一致", i, hit)
		}
		if i > 0 && !page.Items[i-1].ObservedAt.After(hit.ObservedAt) {
			t.Fatal("命中未按观测时间倒序", page.Items)
		}
	}
	if len(page.Items[0].Matches) != 2 || page.Items[0].Matches[0].Field != watchlist.FieldSourceIP || page.Items[0].Matches[1].Field != watchlist.FieldDestinationIP {
		t.Fatal("多项匹配未按固定字段顺序登记", page.Items[0].Matches)
	}
	// 游标绑定租户、名单、窗口与页大小；翻页不重复也不丢项。
	seen := map[string]bool{}
	cursor := ""
	for {
		var single watchlist.HitPage
		a.request("GET", "/watchlists/"+record.ID+"/hits"+hitWindow(start, end, "&limit=1&cursor="+url.QueryEscape(cursor)), "", nil, &single, 200)
		if len(single.Items) != 1 || seen[single.Items[0].ID] {
			t.Fatal("命中翻页重复或空页", single)
		}
		seen[single.Items[0].ID] = true
		if single.NextCursor == "" {
			break
		}
		cursor = single.NextCursor
		// 同一游标换页大小或换窗口都必须拒绝，并且不得被当作服务不可用。
		a.request("GET", "/watchlists/"+record.ID+"/hits"+hitWindow(start, end, "&limit=2&cursor="+url.QueryEscape(cursor)), "", nil, nil, 400)
		a.request("GET", "/watchlists/"+record.ID+"/hits"+hitWindow(start.Add(-time.Minute), end, "&limit=1&cursor="+url.QueryEscape(cursor)), "", nil, nil, 400)
		a.request("GET", "/watchlists/"+record.ID+"/hits"+hitWindow(start, end, "&limit=1&cursor="+url.QueryEscape(cursor+"x")), "", nil, nil, 400)
	}
	if len(seen) != 3 {
		t.Fatal("命中翻页丢项", len(seen))
	}
	// 跨租户游标复用必须拒绝；行级安全同时保证异租户读不到命中。
	var foreign watchlist.HitPage
	b.request("GET", "/watchlists/"+record.ID+"/hits"+hitWindow(start, end, ""), "", nil, &foreign, 200)
	if len(foreign.Items) != 0 {
		t.Fatal("命中跨租户可见", foreign)
	}
	var leaked int
	require(t, f.Runtime.TenantTx(ctx, other.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM watchlist_hits`).Scan(&leaked)
	}))
	if leaked != 0 {
		t.Fatal("行级安全未隔离命中", leaked)
	}
	// 告警侧读取按事件身份与原始摘要配对；摘要不一致不得借用其他告警的关联。
	var alertHits watchlist.AlertHits
	a.request("GET", "/alerts/event_whits_both/watchlist-hits?sha256="+alerts[2].RawSHA256, "", nil, &alertHits, 200)
	if len(alertHits.Items) != 1 || alertHits.Items[0].EventID != "event_whits_both" || alertHits.Items[0].ListID != record.ID {
		t.Fatal("告警命中读取不一致", alertHits)
	}
	a.request("GET", "/alerts/event_whits_both/watchlist-hits?sha256="+alerts[0].RawSHA256, "", nil, &alertHits, 200)
	if len(alertHits.Items) != 0 {
		t.Fatal("摘要不一致的告警借用了其他命中", alertHits)
	}
	b.request("GET", "/alerts/event_whits_both/watchlist-hits?sha256="+alerts[2].RawSHA256, "", nil, &alertHits, 200)
	if len(alertHits.Items) != 0 {
		t.Fatal("告警命中跨租户可见", alertHits)
	}
	// 日上限只截断逐条登记并记录截断时刻，不中断告警流。
	capRecord := observeWatchlist(t, ctx, f, u, "whits_capped", watchlistRegistrationID, "198.18.0.3")
	capBase := capRecord.CreatedAt.UTC()
	require(t, f.Runtime.RecordWatchlistHits(ctx, u.TenantID, []model.Alert{hitAlert(u.TenantID, "event_whits_cap_seed", capBase.Add(-30*time.Second), capBase.Add(time.Second), "198.18.0.3", "203.0.113.70")}))
	if n := hitCount(t, ctx, f, u.TenantID, capRecord.ID); n != 1 {
		t.Fatal("截断前的首条命中未登记", n)
	}
	_, e := f.Owner.Pool.Exec(ctx, `UPDATE watchlist_hit_days SET recorded=$3 WHERE tenant_id=$1 AND list_id=$2`, u.TenantID, capRecord.ID, watchlist.MaxDailyHits-1)
	require(t, e)
	require(t, f.Runtime.RecordWatchlistHits(ctx, u.TenantID, []model.Alert{
		hitAlert(u.TenantID, "event_whits_cap_one", capBase.Add(-20*time.Second), capBase.Add(time.Second), "198.18.0.3", "203.0.113.71"),
		hitAlert(u.TenantID, "event_whits_cap_two", capBase.Add(-10*time.Second), capBase.Add(time.Second), "198.18.0.3", "203.0.113.72"),
	}))
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT recorded,capped_at FROM watchlist_hit_days WHERE tenant_id=$1 AND list_id=$2`, u.TenantID, capRecord.ID).Scan(&recorded, &capped))
	if n := hitCount(t, ctx, f, u.TenantID, capRecord.ID); n != 2 || recorded != watchlist.MaxDailyHits || capped == nil {
		t.Fatal("日上限未截断逐条登记或未记录截断时刻", n, recorded, capped)
	}
	var cappedPage watchlist.HitPage
	a.request("GET", "/watchlists/"+capRecord.ID+"/hits"+hitWindow(capBase.Add(-time.Hour), time.Now().UTC(), ""), "", nil, &cappedPage, 200)
	if len(cappedPage.CappedDays) != 1 || cappedPage.CappedDays[0].CappedAt == nil || cappedPage.CappedDays[0].Recorded != watchlist.MaxDailyHits {
		t.Fatal("截断处理日未在读取结果中标出", cappedPage.CappedDays)
	}
	// 名单停用不删除既有命中，也不再登记新告警。
	inactive := false
	change := watchlistInput(capRecord.ID)
	change.Definition.Kind = "observe"
	change.Definition.Values = []string{"198.18.0.3"}
	change.ExpectedRevision = 1
	change.Active = &inactive
	_, e = f.Runtime.SaveWatchlist(ctx, u, "whits_capped_disable", change)
	require(t, e)
	require(t, f.Runtime.RecordWatchlistHits(ctx, u.TenantID, []model.Alert{hitAlert(u.TenantID, "event_whits_after_disable", capBase.Add(-5*time.Second), time.Now().UTC(), "198.18.0.3", "203.0.113.73")}))
	if n := hitCount(t, ctx, f, u.TenantID, capRecord.ID); n != 2 {
		t.Fatal("停用后仍登记新命中或删除了既有命中", n)
	}
	// 异租户材料与超量批次都属确定性错误，由索引器分类处理，存储层必须明确拒绝。
	foreignAlert := hitAlert(other.TenantID, "event_whits_foreign", base.Add(-10*time.Second), received, "198.18.0.1", "203.0.113.80")
	foreignAlert.RegistrationID = otherRegistrationID
	if e = f.Runtime.RecordWatchlistHits(ctx, u.TenantID, []model.Alert{foreignAlert}); e == nil {
		t.Fatal("跨租户告警材料被登记")
	}
	if e = f.Runtime.RecordWatchlistHits(ctx, "/", alerts); e == nil {
		t.Fatal("无效租户标识被接受")
	}
}

// 命中表只授予读取、登记和到期回收；被未到期命中引用的历史修订不会被回收。
func TestWatchlistHitsRuntimeRoleAndReferencedRevisionRetention(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, _, _ := accountFixture(t, ctx)
	watchlistProbe(t, ctx, f, u, watchlistRegistrationID)
	record := observeWatchlist(t, ctx, f, u, "whits_retention", watchlistRegistrationID, "198.18.0.4")
	base := record.CreatedAt.UTC()
	require(t, f.Runtime.RecordWatchlistHits(ctx, u.TenantID, []model.Alert{hitAlert(u.TenantID, "event_whits_retained", base.Add(-30*time.Second), base.Add(time.Second), "198.18.0.4", "203.0.113.90")}))
	if n := hitCount(t, ctx, f, u.TenantID, record.ID); n != 1 {
		t.Fatal("留存验收命中未登记", n)
	}
	// 运行角色只有 SELECT／INSERT／DELETE，改写既有命中必须失败。
	if e := f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, inner := tx.Exec(ctx, `UPDATE watchlist_hits SET severity='low' WHERE tenant_id=$1`, u.TenantID)
		return inner
	}); e == nil {
		t.Fatal("运行角色可改写命中")
	}
	var severity string
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT severity FROM watchlist_hits WHERE tenant_id=$1 AND list_id=$2`, u.TenantID, record.ID).Scan(&severity))
	if severity != "high" {
		t.Fatal("命中严重级别被改写", severity)
	}
	// 未到期命中不得被删除；到期删除策略是限制性的，不靠调用方自觉。
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		tag, inner := tx.Exec(ctx, `DELETE FROM watchlist_hits WHERE tenant_id=$1`, u.TenantID)
		if inner == nil && tag.RowsAffected() != 0 {
			return fmt.Errorf("未到期命中被回收 %d 条", tag.RowsAffected())
		}
		return inner
	}))
	// 把当前修订推进到 2 并让修订 1 到期，被命中引用期间不得回收。
	change := watchlistInput(record.ID)
	change.Definition.Kind = "observe"
	change.Definition.Values = []string{"198.18.0.4", "198.18.0.5"}
	change.ExpectedRevision = 1
	second, e := f.Runtime.SaveWatchlist(ctx, u, "whits_retention_change", change)
	require(t, e)
	if second.Revision != 2 {
		t.Fatal("名单修订未推进", second)
	}
	_, e = f.Owner.Pool.Exec(ctx, `UPDATE watchlist_revisions SET created_at=now()-interval '181 days',expires_at=now()-interval '1 day' WHERE tenant_id=$1 AND list_id=$2 AND revision=1`, u.TenantID, record.ID)
	require(t, e)
	cleanupRevisions := func() int64 {
		t.Helper()
		var affected int64
		require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
			tag, inner := tx.Exec(ctx, `DELETE FROM watchlist_revisions WHERE tenant_id=$1 AND list_id=$2 AND expires_at<=now()`, u.TenantID, record.ID)
			if inner != nil {
				return inner
			}
			affected = tag.RowsAffected()
			return nil
		}))
		return affected
	}
	if affected := cleanupRevisions(); affected != 0 {
		t.Fatal("被命中引用的到期修订被回收", affected)
	}
	var remaining int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM watchlist_revisions WHERE tenant_id=$1 AND list_id=$2 AND revision=1`, u.TenantID, record.ID).Scan(&remaining))
	if remaining != 1 {
		t.Fatal("引用保护未保留历史修订", remaining)
	}
	// 命中仍能回读当时的定义，修订变化不改写既有命中。
	var hitRevision int64
	var hitDefinition string
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT x.list_revision,v.definition_sha256 FROM watchlist_hits x JOIN watchlist_revisions v ON v.tenant_id=x.tenant_id AND v.list_id=x.list_id AND v.revision=x.list_revision WHERE x.tenant_id=$1 AND x.list_id=$2`, u.TenantID, record.ID).Scan(&hitRevision, &hitDefinition))
	if hitRevision != 1 || hitDefinition != record.DefinitionSHA256 {
		t.Fatal("命中未固化在当时的修订上", hitRevision, hitDefinition)
	}
	// 命中到期后由运行角色回收，随后历史修订恢复可回收。
	_, e = f.Owner.Pool.Exec(ctx, `UPDATE watchlist_hits SET created_at=now()-interval '181 days',expires_at=now()-interval '1 day' WHERE tenant_id=$1 AND list_id=$2`, u.TenantID, record.ID)
	require(t, e)
	var page watchlist.HitPage
	page, e = f.Runtime.WatchlistHits(ctx, u, watchlist.HitQuery{ListID: record.ID, Start: base.Add(-time.Hour), End: time.Now().UTC(), Limit: 20})
	require(t, e)
	if len(page.Items) != 0 {
		t.Fatal("到期命中仍被读取", page)
	}
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		tag, inner := tx.Exec(ctx, `DELETE FROM watchlist_hits WHERE tenant_id=$1 AND expires_at<=now()`, u.TenantID)
		if inner == nil && tag.RowsAffected() != 1 {
			return fmt.Errorf("到期命中回收数量不符 %d", tag.RowsAffected())
		}
		return inner
	}))
	if affected := cleanupRevisions(); affected != 1 {
		t.Fatal("命中回收后历史修订仍不可回收", affected)
	}
	// 处理日计数同样到期即删，且不会连带删除仍在使用的名单。
	_, e = f.Owner.Pool.Exec(ctx, `UPDATE watchlist_hit_days SET created_at=now()-interval '181 days',expires_at=now()-interval '1 day' WHERE tenant_id=$1 AND list_id=$2`, u.TenantID, record.ID)
	require(t, e)
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		tag, inner := tx.Exec(ctx, `DELETE FROM watchlist_hit_days WHERE tenant_id=$1 AND expires_at<=now()`, u.TenantID)
		if inner == nil && tag.RowsAffected() != 1 {
			return fmt.Errorf("到期处理日回收数量不符 %d", tag.RowsAffected())
		}
		return inner
	}))
	var heads int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM watchlists WHERE tenant_id=$1 AND id=$2`, u.TenantID, record.ID).Scan(&heads))
	if heads != 1 {
		t.Fatal("命中回收影响了名单本体", heads)
	}
}

// 对共享索引中的真实告警执行历史影响预览；预览不登记命中、不回填历史，也不授予任何设备动作。
func TestWatchlistImpactHistoricalPreviewOverIndexedAlerts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, other, password := accountFixture(t, ctx)
	watchlistProbe(t, ctx, f, u, watchlistRegistrationID)
	active := true
	viewer, e := f.Runtime.CreateUser(ctx, u, "whits_impact_viewer_create", accounts.Create{Username: "watchlist_impact_viewer", Password: password, Role: "viewer", Active: &active})
	require(t, e)
	es, e := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, e)
	// 每个客户端使用独立的接口实例；共享实例会让后一次登录覆盖前一个客户端的来源校验。
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, u.Username, password)
	v := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, viewer.Username, password)
	record := observeWatchlist(t, ctx, f, u, "whits_impact", watchlistRegistrationID, "198.18.0.1", "198.18.0.2")
	// 预览早于名单保存的告警，正是实时关联覆盖不到的历史数据。
	observed := record.CreatedAt.UTC().Add(-10 * time.Minute)
	partition := observed.Format("2006-01-02")
	index := sharedEventIndex(t, "alerts", partition)
	require(t, es.EnsureIndex(ctx, index, partition))
	// 共享索引同时承载其他租户，只回收本验收租户的文档。
	t.Cleanup(func() { deleteTenantEvents(t, es, u.TenantID) })
	t.Cleanup(func() { deleteTenantEvents(t, es, other.TenantID) })
	docs := []model.Alert{
		hitAlert(u.TenantID, "event_whits_impact_one", observed.Add(-time.Second), observed, "198.18.0.1", "203.0.113.60"),
		hitAlert(u.TenantID, "event_whits_impact_two", observed.Add(-2*time.Second), observed, "203.0.113.61", "198.18.0.2"),
		hitAlert(u.TenantID, "event_whits_impact_three", observed.Add(-3*time.Second), observed, "203.0.113.62", "198.18.0.1"),
		hitAlert(u.TenantID, "event_whits_impact_outside", observed.Add(-time.Hour), observed, "198.18.0.1", "203.0.113.63"),
		hitAlert(u.TenantID, "event_whits_impact_unrelated", observed.Add(-4*time.Second), observed, "203.0.113.64", "203.0.113.65"),
		// 另一租户的同值告警写入同一共享索引，预览只能计入本租户文档。
		hitAlert(other.TenantID, "event_whits_impact_foreign", observed.Add(-time.Second), observed, "198.18.0.1", "203.0.113.66"),
	}
	// 探针范围外的告警不计入；名单只覆盖注册在范围内的探针。
	outOfScope := hitAlert(u.TenantID, "event_whits_impact_other_probe", observed.Add(-5*time.Second), observed, "198.18.0.1", "203.0.113.67")
	outOfScope.SensorID = "watchlist_other_probe"
	docs = append(docs, outOfScope)
	for _, err := range es.Bulk(ctx, index, docs) {
		require(t, err)
	}
	refresh, e := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
	require(t, e)
	if refresh.IsError() {
		t.Fatal("影响预览验收材料未刷新", refresh.StatusCode)
	}
	refresh.Body.Close()
	request := watchlist.ImpactRequest{Revision: 1, Start: observed.Add(-time.Minute), End: observed.Add(time.Minute)}
	v.request("POST", "/watchlists/"+record.ID+"/impact", "", request, nil, 403)
	noCSRF := *a
	noCSRF.csrf = ""
	noCSRF.request("POST", "/watchlists/"+record.ID+"/impact", "", request, nil, 403)
	var result, repeated watchlist.Impact
	a.request("POST", "/watchlists/"+record.ID+"/impact", "", request, &result, 200)
	a.request("POST", "/watchlists/"+record.ID+"/impact", "", request, &repeated, 200)
	if result.SchemaVersion != watchlist.ImpactSchema || result.ListID != record.ID || result.ListRevision != 1 || result.DefinitionSHA256 != record.DefinitionSHA256 || result.Kind != "observe" || result.MatchType != "ip" || !result.Current || !result.Active {
		t.Fatal("预览回执身份或修订不一致", result)
	}
	if result.HitsRecorded || result.ExecutionAuthorized {
		t.Fatal("预览宣称登记命中或授予执行许可", result)
	}
	if len(result.Fields) != 2 || result.Fields[0] != watchlist.FieldSourceIP || result.Fields[1] != watchlist.FieldDestinationIP {
		t.Fatal("预览参与字段与已索引字段不符", result.Fields)
	}
	if result.Total != 3 || repeated.Total != result.Total {
		t.Fatal("预览总数包含异租户、范围外或窗口外告警", result.Total, repeated.Total)
	}
	if len(result.Values) != 2 || result.Values[0].Value != "198.18.0.1" || result.Values[0].Count != 2 || result.Values[1].Value != "198.18.0.2" || result.Values[1].Count != 1 {
		t.Fatal("逐值命中数与名单值不一一对应", result.Values)
	}
	if len(result.Samples) != 3 {
		t.Fatal("样本数量与总数不一致", len(result.Samples))
	}
	for i, sample := range result.Samples {
		if sample.SensorID != "watchlist_probe" || sample.RegistrationID != watchlistRegistrationID || len(sample.Matches) == 0 || sample.Timestamp.Before(request.Start) || !sample.Timestamp.Before(request.End) {
			t.Fatal("样本范围、时间或匹配值不一致", i, sample)
		}
		if i > 0 && !result.Samples[i-1].Timestamp.After(sample.Timestamp) {
			t.Fatal("样本未按时间倒序", result.Samples)
		}
	}
	// 预览是只读核对，不得在权威表留下任何命中或处理日计数。
	if n := hitCount(t, ctx, f, u.TenantID, record.ID); n != 0 {
		t.Fatal("预览登记了命中", n)
	}
	var days int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM watchlist_hit_days WHERE tenant_id=$1 AND list_id=$2`, u.TenantID, record.ID).Scan(&days))
	if days != 0 {
		t.Fatal("预览写入了处理日计数", days)
	}
	// 每次预览都留下操作审计，额度按滚动窗口计数。
	var previews int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action='watchlist.impact'`, u.TenantID).Scan(&previews))
	if previews != 2 {
		t.Fatal("预览审计不是每次一条", previews)
	}
	// 不存在或已到期且非当前的修订不交付计数。
	missing := request
	missing.Revision = 2
	a.request("POST", "/watchlists/"+record.ID+"/impact", "", missing, nil, 404)
	a.request("POST", "/watchlists/whits_impact_absent/impact", "", request, nil, 404)
	// 窗口超过上限、顺序颠倒或字段未知都在进入存储前拒绝。
	tooWide := request
	tooWide.Start = request.End.Add(-32 * 24 * time.Hour)
	a.request("POST", "/watchlists/"+record.ID+"/impact", "", tooWide, nil, 400)
	reversed := request
	reversed.Start, reversed.End = request.End, request.Start
	a.request("POST", "/watchlists/"+record.ID+"/impact", "", reversed, nil, 400)
	// 没有告警索引时不能给出部分计数，缺失索引按不完整处理。
	withoutES := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	withoutES.request("POST", "/watchlists/"+record.ID+"/impact", "", request, nil, 503)
	// 预览不限名单类型；保护名单管理员同样需要只读核对历史告警，且同样不授予动作。
	protect := watchlistInput("whits_impact_protect")
	protect.Definition.Values = []string{"198.18.0.1"}
	protectRecord, e := f.Runtime.SaveWatchlist(ctx, u, "whits_impact_protect_create", protect)
	require(t, e)
	var protectResult watchlist.Impact
	a.request("POST", "/watchlists/"+protectRecord.ID+"/impact", "", request, &protectResult, 200)
	if protectResult.Kind != "protect" || protectResult.Total != 2 || protectResult.HitsRecorded || protectResult.ExecutionAuthorized {
		t.Fatal("保护名单预览口径或授权边界不一致", protectResult)
	}
	if n := hitCount(t, ctx, f, u.TenantID, protectRecord.ID); n != 0 {
		t.Fatal("保护名单预览登记了命中", n)
	}
}
