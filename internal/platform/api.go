// Package platform 编排平台 HTTP 功能，领域数据通过持久存储读取。
package platform

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/hosthealth"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/mcpserver"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/probepki"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/searchfilter"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/redis/go-redis/v9"
	"github.com/riverqueue/river"
	"golang.org/x/sync/singleflight"
)

type API struct {
	DB             *store.Postgres
	ES             *store.Elasticsearch
	Redis          *redis.Client
	Auth           *httpapi.Auth
	Signer         ed25519.PrivateKey
	Wakeup         *control.Wakeup
	Samples        replay.Storage
	Packets        packetarchive.ObjectStorage
	PacketStaging  string
	SampleQuota    int64
	Vault          *secrets.Vault
	Outbound       outbound.Policy
	Jobs           *river.Client[pgx.Tx]
	JobsReady      func() bool
	MCP            *mcpserver.Server
	Authority      probepki.Authority
	overviewFlight singleflight.Group
	exportMu       sync.Mutex
	exportActive   map[string]bool
}

func (a *API) Handler() http.Handler {
	m := http.NewServeMux()
	a.Auth.Register(m, "/api/v1")
	httpapi.Health(m, a.Ready)
	m.HandleFunc("GET /api/v1/sensors", a.Auth.Require(false, a.sensors))
	m.HandleFunc("PATCH /api/v1/sensors/{id}", a.Auth.Require(true, a.setSensor))
	m.HandleFunc("GET /api/v1/response-connectors", a.Auth.Require(true, a.responseConnectors))
	a.registerSyslog(m)
	a.registerSensorManagement(m)
	a.registerQualityEvents(m)
	a.registerProbeCertificates(m)
	m.HandleFunc("POST /api/v1/alerts/search", a.Auth.Require(false, a.alerts))
	a.registerSearchExports(m)
	m.HandleFunc("POST /api/v1/overview", a.Auth.Require(false, a.overview))
	m.HandleFunc("GET /api/v1/search/fields", a.Auth.Require(false, a.searchFields))
	m.HandleFunc("POST /api/v1/search/validate", a.Auth.Require(false, a.validateFilter))
	m.HandleFunc("GET /api/v1/platform/health", a.Auth.Require(true, a.health))
	m.HandleFunc("GET /api/v1/audits/operations", a.Auth.Require(true, a.audits))
	m.HandleFunc("GET /api/v1/audits/logins", a.Auth.Require(true, a.loginAudits))
	a.registerTasks(m)
	a.registerRuleSync(m)
	a.registerRuleRollouts(m)
	a.registerAlertAssessments(m)
	a.registerAlertTriage(m)
	a.registerIncidents(m)
	a.registerUsers(m)
	a.registerTraffic(m)
	a.registerApplicationRules(m)
	a.registerCorrelation(m)
	a.registerDecisionPolicies(m)
	a.registerSavedSearches(m)
	a.registerReplay(m)
	a.registerPacketArchives(m)
	a.registerInventory(m)
	a.registerDiscovery(m)
	a.registerNotifications(m)
	a.registerModels(m)
	a.registerAnalysis(m)
	a.registerRuleGeneration(m)
	a.registerRetention(m)
	a.registerMCP(m)
	return m
}
func (a *API) searchFields(w http.ResponseWriter, r *http.Request) {
	httpapi.JSON(w, 200, map[string]any{"version": searchfilter.Version, "dataset": "alerts", "fields": searchfilter.Catalog()})
}
func (a *API) validateFilter(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Filter string `json:"filter"`
	}
	if e := httpapi.Decode(w, r, &input); e != nil {
		httpapi.Fail(w, r, 400, "invalid_request", "过滤表达式参数无效")
		return
	}
	_, e := searchfilter.Compile(input.Filter)
	if e != nil {
		var detail *searchfilter.Error
		if errors.As(e, &detail) {
			httpapi.JSON(w, 400, map[string]any{"code": "invalid_filter", "message": detail.Error(), "line": detail.Line, "column": detail.Column, "request_id": httpapi.RequestID(r)})
			return
		}
		httpapi.Fail(w, r, 400, "invalid_filter", e.Error())
		return
	}
	httpapi.JSON(w, 200, map[string]any{"valid": true, "version": searchfilter.Version, "dataset": "alerts"})
}
func (a *API) Ready(ctx context.Context) error {
	return errors.Join(checkDependencies(ctx, a.dependencyChecks())...)
}
func (a *API) sensors(w http.ResponseWriter, r *http.Request) {
	q, e := sensorQuery(r, false)
	if e != nil {
		sensorManagementFailure(w, r, e)
		return
	}
	if !a.sensorManagementReady(w, r) {
		return
	}
	result, e := a.DB.SensorDirectory(r.Context(), httpapi.Principal(r).TenantID, q)
	if e != nil {
		httpapi.Fail(w, r, 503, "storage_unavailable", "暂时无法读取探针")
		return
	}
	httpapi.JSON(w, 200, result)
}
func (a *API) setSensor(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Active *bool `json:"active"`
	}
	if e := httpapi.Decode(w, r, &input); e != nil || input.Active == nil {
		httpapi.Fail(w, r, 400, "invalid_request", "需要提供探针启用状态")
		return
	}
	e := a.DB.SetSensorActive(r.Context(), httpapi.Principal(r), r.PathValue("id"), *input.Active, httpapi.RequestID(r))
	if errors.Is(e, pgx.ErrNoRows) {
		httpapi.Fail(w, r, 404, "not_found", "探针不存在或不可访问")
		return
	}
	if e != nil {
		httpapi.Fail(w, r, 503, "storage_unavailable", "暂时无法保存探针状态")
		return
	}
	httpapi.JSON(w, 200, map[string]bool{"ok": true})
}
func (a *API) alerts(w http.ResponseWriter, r *http.Request) {
	var q model.SearchRequest
	if e := httpapi.Decode(w, r, &q); e != nil {
		httpapi.Fail(w, r, 400, "invalid_request", e.Error())
		return
	}
	if e := store.ValidateSearch(&q); e != nil {
		httpapi.Fail(w, r, 400, "invalid_search", e.Error())
		return
	}
	u := httpapi.Principal(r)
	v, e := a.SearchAlerts(r.Context(), u, q)
	if e != nil {
		httpapi.Fail(w, r, 503, "search_unavailable", "检索服务暂时不可用")
		return
	}
	httpapi.JSON(w, 200, v)
}

func (a *API) SearchAlerts(ctx context.Context, u model.Principal, q model.SearchRequest) (model.SearchResult, error) {
	if err := store.ValidateSearch(&q); err != nil {
		return model.SearchResult{}, err
	}
	if a.ES == nil {
		return model.SearchResult{}, errors.New("检索服务暂时不可用")
	}
	result, err := a.ES.Search(ctx, u.TenantID, q)
	if u.Role != "admin" {
		for i := range result.Items {
			result.Items[i].Event.Original = ""
		}
	}
	return result, err
}
func (a *API) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	// 资源读取和依赖探测共享观测窗口，单个存储超时不会使其他依赖误报。
	runtime := hosthealth.Read(ctx)
	results := checkDependencies(ctx, a.dependencyChecks())
	states := map[string]string{}
	for i, name := range []string{"postgresql", "redis", "elasticsearch"} {
		states[name] = "ready"
		if results[i] != nil {
			states[name] = "unavailable"
		}
	}
	httpapi.JSON(w, 200, map[string]any{"services": states, "observed_at": time.Now().UTC(), "runtime": runtime})
}
