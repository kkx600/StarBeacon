package store

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/analytics"
)

func (p *Postgres) OverviewInventory(ctx context.Context, tenant string) (analytics.Inventory, error) {
	var out analytics.Inventory
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var assets, groups, networks, sensors, online, offline, disabled int64
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE kind='assets'),count(*) FILTER(WHERE kind='groups'),count(*) FILTER(WHERE kind='networks') FROM inventory_objects WHERE tenant_id=$1`, tenant).Scan(&assets, &groups, &networks); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE active AND last_seen>=now()-interval '35 seconds'),count(*) FILTER(WHERE active AND (last_seen IS NULL OR last_seen<now()-interval '35 seconds')),count(*) FILTER(WHERE NOT active) FROM sensors WHERE tenant_id=$1`, tenant).Scan(&sensors, &online, &offline, &disabled); err != nil {
			return err
		}
		out = analytics.Inventory{Assets: strconv.FormatInt(assets, 10), Groups: strconv.FormatInt(groups, 10), Networks: strconv.FormatInt(networks, 10), Sensors: strconv.FormatInt(sensors, 10), Online: strconv.FormatInt(online, 10), Offline: strconv.FormatInt(offline, 10), Disabled: strconv.FormatInt(disabled, 10)}
		return nil
	})
	return out, err
}

func (s *Elasticsearch) OverviewEvents(ctx context.Context, tenant string, w analytics.Window) (analytics.Events, error) {
	body, err := analytics.Query(tenant, w)
	if err != nil {
		return analytics.Events{}, err
	}
	res, err := s.API.Search(s.API.Search.WithIndex("sb-alerts-"+tenant+"-*"), s.API.Search.WithBody(bytes.NewReader(body)), s.API.Search.WithIgnoreUnavailable(true), s.API.Search.WithAllowNoIndices(true), s.API.Search.WithAllowPartialSearchResults(false), s.API.Search.WithContext(ctx))
	var raw json.RawMessage
	if err = response(res, err, &raw); err != nil {
		return analytics.Events{}, err
	}
	return analytics.Decode(raw, w)
}
