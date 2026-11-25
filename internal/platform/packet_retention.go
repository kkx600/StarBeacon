package platform

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/packetpolicy"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerPacketRetention(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/packet-storage", a.Auth.Require(true, a.packetStorageSettings))
	m.HandleFunc("POST /api/v1/sensors/{id}/packet-retention", a.Auth.Require(true, a.applyPacketRetention))
}

func (a *API) packetStorageSettings(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		httpapi.Fail(w, r, 400, "invalid_request", "全流量存储读取不接受查询参数")
		return
	}
	if a.DB == nil {
		httpapi.Fail(w, r, 503, "storage_unavailable", "全流量存储目录无法读取")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	u := httpapi.Principal(r)
	sensors, err := a.DB.PacketStorageSensors(ctx, u, a.Signer)
	if err != nil {
		packetRetentionError(w, r, err)
		return
	}
	warmState := "not_configured"
	var warm *store.PacketStorageStatus
	if a.Packets != nil {
		warmState = "unavailable"
		if status, err := a.DB.PacketStorageStatus(ctx, u, a.PacketBackend, a.Packets, a.PacketPool); err == nil {
			warmState, warm = "ready", &status
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.JSON(w, 200, map[string]any{"sensors": sensors[:min(len(sensors), 500)], "sensors_limited": len(sensors) > 500, "warm": warm, "warm_state": warmState, "cold_state": "unmanaged"})
}

func (a *API) applyPacketRetention(w http.ResponseWriter, r *http.Request) {
	if len(a.Signer) != ed25519.PrivateKeySize || a.DB == nil {
		httpapi.Fail(w, r, 503, "signer_unavailable", "平台任务签名或存储服务未配置")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if len(r.Header.Values("Idempotency-Key")) != 1 || len(key) < 8 || len(key) > 128 || strings.TrimSpace(key) != key {
		httpapi.Fail(w, r, 400, "idempotency_key_required", "需要提供 8–128 字符的幂等键")
		return
	}
	sensor := r.PathValue("id")
	var input packetpolicy.Change
	if !contract.ValidID(sensor) || r.URL.RawQuery != "" || httpapi.Decode(w, r, &input) != nil {
		httpapi.Fail(w, r, 400, "invalid_packet_retention", "采集器标识、留存参数、修订或摘要无效")
		return
	}
	payload, err := json.Marshal(input)
	if err != nil {
		packetRetentionError(w, r, err)
		return
	}
	id, err := a.DB.CreateTask(r.Context(), httpapi.Principal(r), sensor, control.PacketRetentionConfigure, key, payload, a.Signer)
	if err != nil {
		packetRetentionError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.JSON(w, 202, map[string]string{"task_id": id})
}

func packetRetentionError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrPacketRetentionPermission):
		httpapi.Fail(w, r, 403, "forbidden", err.Error())
	case errors.Is(err, packetarchive.ErrRetentionConflict):
		httpapi.Fail(w, r, 409, "packet_retention_changed", "采集器配置已变化、离线或签名能力未就绪，请刷新后核对")
	default:
		operationError(w, r, err)
	}
}
