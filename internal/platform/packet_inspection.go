package platform

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
)

func (a *API) inspectPacketArchive(w http.ResponseWriter, r *http.Request) {
	number, err := packetarchive.InspectionNumber(r.PathValue("number"), r.URL.Query())
	if err != nil || !contract.ValidID(r.PathValue("id")) {
		httpapi.Fail(w, r, 400, "invalid_packet_number", "请选择有效归档和 1–1,048,576 范围内的整数包序号")
		return
	}
	if a.DB == nil || a.Packets == nil || a.PacketStaging == "" {
		httpapi.Fail(w, r, 503, "packet_storage_unavailable", "原包对象存储或私有暂存未配置")
		return
	}
	select {
	case packetDownloads <- struct{}{}:
		defer func() { <-packetDownloads }()
	default:
		httpapi.Fail(w, r, 429, "packet_download_busy", "原包读取额度已满，请稍后重试")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	u := httpapi.Principal(r)
	row, err := a.DB.PacketArchive(ctx, u, r.PathValue("id"))
	if err != nil {
		operationError(w, r, err)
		return
	}
	source := func(ctx context.Context, start, length int64) (io.ReadCloser, error) {
		return a.Packets.Range(ctx, row.ObjectKey, row.ObjectVersion, start, length)
	}
	result, err := packetarchive.InspectPacket(ctx, source, row.Manifest, a.PacketStaging, number)
	if err != nil {
		if errors.Is(err, packetarchive.ErrPacketNotFound) {
			httpapi.Fail(w, r, 404, "packet_not_found", "所选归档中不存在该包序号")
		} else {
			httpapi.Fail(w, r, 503, "packet_object_unconfirmed", "指定原包对象版本无法完整核验，请稍后重试")
		}
		return
	}
	// 原字节发送前再次核对当前管理员、目录和留存期限；审计失败不返回通信内容。
	current, err := a.DB.PacketArchive(ctx, u, row.ID)
	if err != nil {
		operationError(w, r, err)
		return
	}
	if current.ManifestSHA256 != row.ManifestSHA256 || current.ObjectVersion != row.ObjectVersion || result.ManifestSHA256 != row.ManifestSHA256 {
		httpapi.Fail(w, r, 409, "packet_directory_changed", "原包目录状态已变化，请重新读取")
		return
	}
	a.Auth.Require(true, func(w http.ResponseWriter, latest *http.Request) {
		principal := httpapi.Principal(latest)
		if principal.ID != u.ID || principal.TenantID != u.TenantID {
			httpapi.Fail(w, latest, 403, "permission_changed", "登录身份已变化，请重新读取原包")
			return
		}
		if err = a.DB.AuditPacketInspection(ctx, principal, row.ID, httpapi.RequestID(latest)); err != nil {
			operationError(w, latest, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		httpapi.JSON(w, 200, result)
	})(w, r.WithContext(ctx))
}
