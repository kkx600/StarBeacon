package platform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/searchsnapshot"
	"github.com/kkx600/StarBeacon/internal/store"
)

var errExportBusy = errors.New("当前导出配额已用满")

func (a *API) registerSearchExports(m *http.ServeMux) {
	m.HandleFunc("POST /api/v1/alerts/export", a.Auth.Require(false, a.exportAlerts))
	m.HandleFunc("POST /api/v1/traffic/export", a.Auth.Require(false, a.exportTraffic))
}

func (a *API) exportAlerts(w http.ResponseWriter, r *http.Request) {
	var q model.SearchRequest
	if httpapi.Decode(w, r, &q) != nil {
		httpapi.Fail(w, r, 400, "invalid_request", "告警导出参数无效")
		return
	}
	if err := store.ValidateSearch(&q); err != nil {
		httpapi.Fail(w, r, 400, "invalid_search", err.Error())
		return
	}
	a.exportEvents(w, r, "alerts", model.TrafficSearchRequest{SearchRequest: q})
}

func (a *API) exportTraffic(w http.ResponseWriter, r *http.Request) {
	var q model.TrafficSearchRequest
	if httpapi.Decode(w, r, &q) != nil {
		httpapi.Fail(w, r, 400, "invalid_request", "协议记录导出参数无效")
		return
	}
	if err := store.ValidateTrafficSearch(&q); err != nil {
		httpapi.Fail(w, r, 400, "invalid_search", err.Error())
		return
	}
	a.exportEvents(w, r, "context", q)
}

func (a *API) exportEvents(w http.ResponseWriter, r *http.Request, dataset string, q model.TrafficSearchRequest) {
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if a.ES == nil || a.DB == nil {
		httpapi.Fail(w, r, 503, "export_unavailable", "检索导出服务暂时不可用")
		return
	}
	u := httpapi.Principal(r)
	release, err := a.exportSlot(r.Context(), u.TenantID)
	if err != nil {
		if errors.Is(err, errExportBusy) {
			w.Header().Set("Retry-After", "5")
			httpapi.Fail(w, r, 429, "export_busy", "当前有导出任务执行中，请稍后重试")
		} else {
			httpapi.Fail(w, r, 503, "export_unavailable", "暂时无法核对导出额度")
		}
		return
	}
	defer release()
	cookie, _ := r.Cookie(a.Auth.CookieName)
	authorize := func(ctx context.Context) error {
		current, err := a.Auth.Store.Session(ctx, cookie.Value)
		if err != nil {
			return err
		}
		if current.ID != u.ID || current.TenantID != u.TenantID || current.Role != u.Role || current.CredentialRevision != u.CredentialRevision || current.CSRF != u.CSRF {
			return model.ErrUnauthenticated
		}
		return nil
	}
	raw, rows, err := a.ES.ExportEvents(r.Context(), u.TenantID, dataset, q, authorize)
	if err == nil {
		err = authorize(r.Context())
	}
	if err == nil {
		err = a.DB.RecordSearchExport(r.Context(), u, dataset, httpapi.RequestID(r))
	}
	if err == nil {
		err = authorize(r.Context())
	}
	if err != nil {
		switch {
		case errors.Is(err, model.ErrUnauthenticated):
			httpapi.Fail(w, r, 401, "session_expired", "会话或权限已变化，导出未交付，请重新登录")
		case errors.Is(err, searchsnapshot.ErrLimit):
			httpapi.Fail(w, r, 413, "export_limit", searchsnapshot.ErrLimit.Error())
		default:
			httpapi.Fail(w, r, 503, "export_unavailable", "导出未完成，未生成部分文件；请稍后重试")
		}
		return
	}
	digest := sha256.Sum256(raw)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="starbeacon-`+dataset+`-`+time.Now().UTC().Format("20060102T150405Z")+`.csv"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.Header().Set("X-Content-SHA256", hex.EncodeToString(digest[:]))
	w.Header().Set("X-Export-Rows", strconv.Itoa(rows))
	w.Header().Set("X-Export-Dataset", dataset)
	w.Header().Set("X-Export-Start", q.Start.UTC().Format(time.RFC3339Nano))
	w.Header().Set("X-Export-End", q.End.UTC().Format(time.RFC3339Nano))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}

func (a *API) exportSlot(ctx context.Context, tenant string) (func(), error) {
	a.exportMu.Lock()
	if len(a.exportActive) >= 2 || a.exportActive[tenant] {
		a.exportMu.Unlock()
		return nil, errExportBusy
	}
	if a.exportActive == nil {
		a.exportActive = make(map[string]bool)
	}
	a.exportActive[tenant] = true
	a.exportMu.Unlock()
	localRelease := func() { a.exportMu.Lock(); delete(a.exportActive, tenant); a.exportMu.Unlock() }
	if a.Redis == nil {
		return localRelease, nil
	}
	key, token := "sb:search-export:"+tenant, store.Token()
	budget, cancel := context.WithTimeout(ctx, 2*time.Second)
	accepted, err := a.Redis.SetNX(budget, key, token, 60*time.Second).Result()
	cancel()
	if err != nil || !accepted {
		localRelease()
		if err != nil {
			return nil, err
		}
		return nil, errExportBusy
	}
	return func() {
		defer localRelease()
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer stop()
		// 只释放自己的租约；网络失败由技术租约期限回收，不删除其它执行者。
		_ = a.Redis.Eval(cleanup, `if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) end;return 0`, []string{key}, token).Err()
	}, nil
}
