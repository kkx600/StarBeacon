package platform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/store"
)

var packetDownloads = make(chan struct{}, 4)
var sessionExports = make(chan struct{}, 2)

func (a *API) registerPacketArchives(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/packet-archives", a.Auth.Require(true, a.packetArchives))
	m.HandleFunc("GET /api/v1/packet-archives/{id}", a.Auth.Require(true, a.packetArchive))
	m.HandleFunc("GET /api/v1/packet-archives/{id}/download", a.Auth.Require(true, a.downloadPacketArchive))
	m.HandleFunc("GET /api/v1/packet-archives/{id}/packets/{number}", a.Auth.Require(true, a.inspectPacketArchive))
	m.HandleFunc("POST /api/v1/packet-archives/session-export", a.Auth.Require(true, a.exportPacketSession))
}

func (a *API) exportPacketSession(w http.ResponseWriter, r *http.Request) {
	var request packetarchive.SessionRequest
	if len(r.URL.RawQuery) != 0 || httpapi.Decode(w, r, &request) != nil || request.Validate() != nil {
		httpapi.Fail(w, r, 400, "invalid_session_export", "需要选择 1–16 个原包归档、导出模式及准确的双端 IP、端口和 MAC")
		return
	}
	if a.Packets == nil || a.PacketStaging == "" {
		httpapi.Fail(w, r, 503, "packet_storage_unavailable", "原包对象存储未配置")
		return
	}
	select {
	case sessionExports <- struct{}{}:
		defer func() { <-sessionExports }()
	default:
		httpapi.Fail(w, r, 429, "session_export_busy", "会话导出额度已满，请稍后重试")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	u := httpapi.Principal(r)
	if err := a.DB.AuditPacketSessionExport(ctx, u, request.ArchiveIDs, request.Mode, httpapi.RequestID(r)); err != nil {
		operationError(w, r, err)
		return
	}
	output, err := os.CreateTemp(a.PacketStaging, ".session-export-")
	if err != nil {
		httpapi.Fail(w, r, 503, "packet_staging_unavailable", "会话导出暂存不可用")
		return
	}
	defer output.Close()
	defer os.Remove(output.Name())
	var report packetarchive.SessionReport
	err = a.DB.WithPacketArchives(ctx, u, request.ArchiveIDs, func(rows []store.PacketArchive) error {
		inputs := make([]packetarchive.SessionInput, 0, len(rows))
		var total int64
		for _, row := range rows {
			total += row.Manifest.Encoding.RawBytes
			if total > packetarchive.MaxSessionInputBytes {
				return packetarchive.ErrLimit
			}
			file, e := os.CreateTemp(a.PacketStaging, ".session-source-")
			if e != nil {
				return e
			}
			defer file.Close()
			defer os.Remove(file.Name())
			source := func(ctx context.Context, start, length int64) (io.ReadCloser, error) {
				return a.Packets.Range(ctx, row.ObjectKey, row.ObjectVersion, start, length)
			}
			if e = packetarchive.ReadRange(ctx, file, source, row.Manifest.Encoding, 0, row.Manifest.Encoding.RawBytes); e != nil {
				return e
			}
			inputs = append(inputs, packetarchive.SessionInput{Manifest: row.Manifest, ObjectVersion: row.ObjectVersion, File: file})
		}
		var e error
		report, e = packetarchive.ExportSession(ctx, output, request, inputs)
		return e
	})
	if err != nil {
		switch {
		case errors.Is(err, packetarchive.ErrSessionIncomplete):
			message := "所选原包未满足完整会话条件。请查看缺口原因；需要快照时请选择快照模式重新提交"
			if request.Mode == "snapshot" {
				message = "所选原包没有可导出的匹配报文，请核对双端身份和切片范围"
			}
			httpapi.JSON(w, 422, map[string]any{"code": "session_incomplete", "message": message, "report": report, "request_id": httpapi.RequestID(r)})
		case errors.Is(err, packetarchive.ErrLimit):
			httpapi.Fail(w, r, 413, "session_export_budget", "会话导出超过处理预算：最多 16 个切片、256 MiB 输入、1 小时捕获窗口与 64 MiB 输出")
		case errors.Is(err, pgx.ErrNoRows):
			operationError(w, r, err)
		default:
			httpapi.Fail(w, r, 503, "session_source_unconfirmed", "原包身份、指定对象版本或通信内容无法完整核验，请重新读取目录")
		}
		return
	}
	if _, err = output.Seek(0, io.SeekStart); err != nil {
		httpapi.Fail(w, r, 503, "packet_staging_unavailable", "会话导出制品不可读取")
		return
	}
	hash := sha256.New()
	size, err := io.Copy(hash, output)
	if err != nil || ctx.Err() != nil {
		httpapi.Fail(w, r, 503, "session_export_unconfirmed", "会话导出未完成，请稍后重试")
		return
	}
	// 发送前再核对当前登录账号和每个源对象；准备完成不等于有权继续下载。
	for _, id := range request.ArchiveIDs {
		if _, err = a.DB.PacketArchive(ctx, u, id); err != nil {
			operationError(w, r, err)
			return
		}
	}
	if _, err = output.Seek(0, io.SeekStart); err != nil {
		httpapi.Fail(w, r, 503, "packet_staging_unavailable", "会话导出制品不可读取")
		return
	}
	w.Header().Set("Content-Type", "application/x-pcapng")
	w.Header().Set("Content-Disposition", `attachment; filename="session-`+request.ArchiveIDs[0]+`.pcapng"`)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-SHA256", hex.EncodeToString(hash.Sum(nil)))
	w.Header().Set("X-Session-Completeness", report.Completeness)
	if _, err = io.Copy(w, output); err != nil {
		panic(http.ErrAbortHandler)
	}
}
func (a *API) packetArchives(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Query()) > 2 || len(r.URL.Query()["sensor_id"]) > 1 || len(r.URL.Query()["cursor"]) > 1 {
		httpapi.Fail(w, r, 400, "invalid_request", "原包目录筛选参数无效")
		return
	}
	for name := range r.URL.Query() {
		if name != "sensor_id" && name != "cursor" {
			httpapi.Fail(w, r, 400, "invalid_request", "原包目录筛选参数无效")
			return
		}
	}
	items, next, err := a.DB.PacketArchives(r.Context(), httpapi.Principal(r), r.URL.Query().Get("sensor_id"), r.URL.Query().Get("cursor"))
	if err != nil {
		if errors.Is(err, packetarchive.ErrIntegrity) {
			httpapi.Fail(w, r, 400, "invalid_request", "原包目录筛选参数无效")
		} else {
			operationError(w, r, err)
		}
		return
	}
	httpapi.JSON(w, 200, map[string]any{"items": items, "next": next, "available": a.Packets != nil})
}
func (a *API) packetArchive(w http.ResponseWriter, r *http.Request) {
	if !contract.ValidID(r.PathValue("id")) {
		httpapi.Fail(w, r, 404, "not_found", "原包归档不存在或不可访问")
		return
	}
	row, err := a.DB.PacketArchive(r.Context(), httpapi.Principal(r), r.PathValue("id"))
	if err != nil {
		operationError(w, r, err)
		return
	}
	httpapi.JSON(w, 200, row)
}
func (a *API) downloadPacketArchive(w http.ResponseWriter, r *http.Request) {
	if a.Packets == nil || a.PacketStaging == "" {
		httpapi.Fail(w, r, 503, "packet_storage_unavailable", "原包对象存储未配置")
		return
	}
	select {
	case packetDownloads <- struct{}{}:
		defer func() { <-packetDownloads }()
	default:
		httpapi.Fail(w, r, 429, "packet_download_busy", "原包下载额度已满，请稍后重试")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	row, err := a.DB.PacketArchive(ctx, httpapi.Principal(r), r.PathValue("id"))
	if err != nil {
		operationError(w, r, err)
		return
	}
	file, err := os.CreateTemp(a.PacketStaging, ".packet-download-")
	if err != nil {
		httpapi.Fail(w, r, 503, "packet_staging_unavailable", "原包下载暂存不可用")
		return
	}
	defer file.Close()
	defer os.Remove(file.Name())
	source := func(ctx context.Context, start, length int64) (io.ReadCloser, error) {
		return a.Packets.Range(ctx, row.ObjectKey, row.ObjectVersion, start, length)
	}
	if err = packetarchive.ReadRange(ctx, file, source, row.Manifest.Encoding, 0, row.Manifest.Encoding.RawBytes); err == nil {
		err = packetarchive.ValidateRawFile(ctx, file, row.Manifest.Capture)
	}
	if err != nil {
		httpapi.Fail(w, r, 503, "packet_object_unconfirmed", "指定原包对象版本无法完整核验，请稍后重试")
		return
	}
	// 下载制品准备完成后再次核对当前账号、目录状态与留存窗口，再允许发送原始通信数据。
	current, err := a.DB.PacketArchive(ctx, httpapi.Principal(r), row.ID)
	if err != nil {
		operationError(w, r, err)
		return
	}
	if current.ManifestSHA256 != row.ManifestSHA256 || current.ObjectVersion != row.ObjectVersion {
		httpapi.Fail(w, r, 409, "packet_directory_changed", "原包目录状态已变化，请重新读取")
		return
	}
	if err = a.DB.AuditPacketDownload(ctx, httpapi.Principal(r), row.ID, httpapi.RequestID(r)); err != nil {
		operationError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-pcapng")
	w.Header().Set("Content-Disposition", `attachment; filename="`+row.ID+`.pcapng"`)
	w.Header().Set("Content-Length", strconv.FormatInt(row.Manifest.Encoding.RawBytes, 10))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-SHA256", row.Manifest.Encoding.RawSHA256)
	if _, err = io.Copy(w, file); err != nil {
		panic(http.ErrAbortHandler)
	}
}
