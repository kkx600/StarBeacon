package platform

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/discovery"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
)

var errDiscoveryBusy = errors.New("当前资产发现查询正在执行或已达到分钟预算")

func (a *API) registerDiscovery(m *http.ServeMux) {
	m.HandleFunc("POST /api/v1/inventory/discovery", a.Auth.Require(true, a.discoverAssets))
}

func (a *API) discoverAssets(w http.ResponseWriter, r *http.Request) {
	var raw json.RawMessage
	var q discovery.Query
	if r.URL.RawQuery != "" || httpapi.Decode(w, r, &raw) != nil || contract.JSONFields(string(raw), []string{"network_id", "network_revision", "sensor_id", "registration_id", "prefix", "start", "end"}, 8192) != nil || json.Unmarshal(raw, &q) != nil || q.Validate() != nil {
		httpapi.Fail(w, r, 400, "invalid_discovery", "请选择有效探针、网段修订及不超过 24 小时的时间窗口；地址前缀必须为标准 CIDR")
		return
	}
	if a.DB == nil || a.ES == nil || a.Redis == nil {
		httpapi.Fail(w, r, 503, "discovery_unavailable", "资产发现所需的存储或额度服务尚未就绪")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	u := httpapi.Principal(r)
	q.Start, q.End = q.Start.UTC(), q.End.UTC()
	scope, err := a.DB.DiscoveryScope(ctx, u, q, nil, "")
	if err != nil {
		discoveryFailure(w, r, err)
		return
	}
	release, err := a.discoverySlot(ctx, u.TenantID)
	if err != nil {
		discoveryFailure(w, r, err)
		return
	}
	defer release()
	cookie, err := r.Cookie(a.Auth.CookieName)
	if err != nil {
		discoveryFailure(w, r, model.ErrUnauthenticated)
		return
	}
	authorize := func() error {
		current, err := a.Auth.Store.Session(ctx, cookie.Value)
		if err != nil {
			return err
		}
		if current.ID != u.ID || current.TenantID != u.TenantID || current.Role != u.Role || current.CSRF != u.CSRF || current.CredentialRevision != u.CredentialRevision {
			return model.ErrUnauthenticated
		}
		return nil
	}
	if err := authorize(); err != nil {
		discoveryFailure(w, r, err)
		return
	}
	result, err := a.ES.DiscoverAddresses(ctx, u.TenantID, q)
	if err != nil {
		discoveryFailure(w, r, err)
		return
	}
	result.QueriedAt = time.Now().UTC()
	if err := authorize(); err != nil {
		discoveryFailure(w, r, err)
		return
	}
	current, err := a.DB.DiscoveryScope(ctx, u, q, &scope, httpapi.RequestID(r))
	if err != nil {
		discoveryFailure(w, r, err)
		return
	}
	if current != scope {
		discoveryFailure(w, r, store.ErrConflict)
		return
	}
	if err := authorize(); err != nil {
		discoveryFailure(w, r, err)
		return
	}
	result.Scope = scope
	w.Header().Set("Cache-Control", "no-store")
	httpapi.JSON(w, 200, result)
}

func discoveryFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, discovery.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_discovery", "发现范围与当前网段不一致，请核对地址前缀")
	case errors.Is(err, model.ErrUnauthenticated):
		httpapi.Fail(w, r, 401, "session_expired", "会话或权限已变化，观测结果未交付，请重新登录")
	case errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "探针或网段不存在或不可访问")
	case errors.Is(err, store.ErrConflict):
		httpapi.Fail(w, r, 409, "discovery_scope_changed", "网段或探针注册已变化，请刷新目录后重新查询")
	case errors.Is(err, discovery.ErrLimit):
		httpapi.Fail(w, r, 413, "discovery_limit", discovery.ErrLimit.Error())
	case errors.Is(err, errDiscoveryBusy):
		w.Header().Set("Retry-After", "60")
		httpapi.Fail(w, r, 429, "discovery_busy", "当前租户存在进行中的发现查询，或已达到每分钟 6 次的预算，请稍后重试")
	default:
		httpapi.Fail(w, r, 503, "discovery_unavailable", "未能完整核对流量观测，本次不提供部分结果；请稍后重试")
	}
}

func (a *API) discoverySlot(ctx context.Context, tenant string) (func(), error) {
	if a.Redis == nil || !contract.ValidID(tenant) {
		return nil, discovery.ErrIncomplete
	}
	lock, token := "sb:discovery:{"+tenant+"}:lock", store.Token()
	quota := "sb:discovery:{" + tenant + "}:quota:" + time.Now().UTC().Format("200601021504")
	accepted, err := a.Redis.Eval(ctx, `if redis.call('EXISTS',KEYS[1])==1 then return 0 end;local n=redis.call('INCR',KEYS[2]);if n==1 then redis.call('EXPIRE',KEYS[2],120) end;if n>6 then return 0 end;redis.call('SET',KEYS[1],ARGV[1],'EX',12);return 1`, []string{lock, quota}, token).Int()
	if err != nil {
		return nil, err
	}
	if accepted != 1 {
		return nil, errDiscoveryBusy
	}
	return func() {
		clean, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = a.Redis.Eval(clean, `if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) end;return 0`, []string{lock}, token).Err()
	}, nil
}
