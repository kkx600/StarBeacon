package store

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/discovery"
	"github.com/kkx600/StarBeacon/internal/inventory"
	"github.com/kkx600/StarBeacon/internal/model"
)

// DiscoveryScope 在查询前后核对同一网段修订和探针注册；不会把地址观测写成资产身份。
func (p *Postgres) DiscoveryScope(ctx context.Context, u model.Principal, q discovery.Query, expected *discovery.Scope, requestID string) (discovery.Scope, error) {
	var scope discovery.Scope
	if q.Validate() != nil || u.Role != "admin" {
		return scope, discovery.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := sensorManager(ctx, tx, u); err != nil {
			return err
		}
		var raw json.RawMessage
		var revision int64
		var active bool
		if err := tx.QueryRow(ctx, `SELECT revision,active,data FROM inventory_objects WHERE tenant_id=$1 AND kind='networks' AND id=$2 FOR SHARE`, u.TenantID, q.NetworkID).Scan(&revision, &active, &raw); err != nil {
			return err
		}
		normalized, err := inventory.Validate("networks", raw)
		var network inventory.Network
		if err != nil || json.Unmarshal(normalized.Data, &network) != nil || normalized.Active != active {
			return discovery.ErrIncomplete
		}
		if revision != q.NetworkRevision || !active {
			return ErrConflict
		}
		var name, registration string
		if err := tx.QueryRow(ctx, `SELECT name,registration_id FROM sensors WHERE tenant_id=$1 AND id=$2 FOR SHARE`, u.TenantID, q.SensorID).Scan(&name, &registration); err != nil {
			return err
		}
		if registration != q.RegistrationID {
			return ErrConflict
		}
		scope = discovery.Scope{NetworkID: q.NetworkID, NetworkRevision: revision, NetworkName: network.Name, NetworkDomain: network.NetworkDomain, NetworkPrefix: network.Prefix, SensorID: q.SensorID, SensorName: name, RegistrationID: registration}
		if err := scope.Validate(q); err != nil {
			return err
		}
		if expected != nil {
			if scope != *expected {
				return ErrConflict
			}
			return insertOperationAudit(ctx, tx, u, "inventory.assets.discover", q.NetworkID, requestID)
		}
		return nil
	})
	return scope, err
}

// DiscoverAddresses 按租户索引族查询实际事件时间，兼容跨日积压和离线事件。
// 每次请求同时完成两个方向的有界聚合；超限、分片失败和超时不交付截断目录。
func (s *Elasticsearch) DiscoverAddresses(ctx context.Context, tenant string, q discovery.Query) (discovery.Result, error) {
	body, err := discovery.DSL(tenant, q)
	if err != nil {
		return discovery.Result{}, err
	}
	// 日期后缀不含连字符；排除后缀含连字符的匹配，避免纳入同前缀的其他租户。
	// 分区日期来自上传路由，不能用事件时间推算应读取的分区。
	prefix := "sb-context-" + tenant + "-"
	indices := []string{prefix + "*", "-" + prefix + "*-*"}
	res, err := s.API.Search(s.API.Search.WithIndex(indices...), s.API.Search.WithBody(bytes.NewReader(body)), s.API.Search.WithIgnoreUnavailable(false), s.API.Search.WithAllowNoIndices(true), s.API.Search.WithAllowPartialSearchResults(false), s.API.Search.WithMaxConcurrentShardRequests(2), s.API.Search.WithPreFilterShardSize(1), s.API.Search.WithExpandWildcards("open", "closed"), s.API.Search.WithContext(ctx))
	if err != nil {
		if res != nil && res.Body != nil {
			res.Body.Close()
		}
		return discovery.Result{}, err
	}
	defer res.Body.Close()
	if res.IsError() {
		return discovery.Result{}, discovery.ErrIncomplete
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 8*1024*1024+1))
	if err != nil {
		return discovery.Result{}, err
	}
	result, err := discovery.Decode(raw, tenant, q)
	if err != nil {
		return discovery.Result{}, err
	}
	return result, nil
}
