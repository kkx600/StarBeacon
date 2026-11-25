package platform

import (
	"context"
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
	m.HandleFunc("POST /api/v1/packet-archives/{id}/flow-packets/{number}", a.Auth.Require(true, a.packetFlow))
	m.HandleFunc("POST /api/v1/packet-archives/{id}/flow-snapshot", a.Auth.Require(true, a.packetFlow))
}

func (a *API) exportPacketSession(w http.ResponseWriter, r *http.Request) {
	request, valid := httpapi.ReadPacketSession(w, r)
	if !valid {
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
		httpapi.Fail(w, r, 503, "packet_staging_unavailable", "会话导出暂存服务异常，请稍后重试")
		return
	}
	defer output.Close()
	defer os.Remove(output.Name())
	var report packetarchive.SessionReport
	var incomplete error
	err = a.DB.WithPacketFlowIndexes(ctx, u, request.ArchiveIDs, func(rows []store.PacketArchive, save func(string, packetarchive.IndexRecord) error) error {
		var total int64
		for _, row := range rows {
			total += row.Manifest.Encoding.RawBytes
		}
		if total > packetarchive.MaxSessionInputBytes {
			return packetarchive.ErrLimit
		}
		inputs := make([]packetarchive.SessionInput, 0, len(rows))
		for _, row := range rows {
			source := func(ctx context.Context, start, length int64) (io.ReadCloser, error) {
				return a.Packets.Range(ctx, row.ObjectKey, row.ObjectVersion, start, length)
			}
			if row.Manifest.Encoding.Schema == packetarchive.PackedSchema {
				index, e := packetarchive.ResolveSegmentIndex(ctx, row.Index, row.Manifest, source, a.PacketStaging, func(rebuilt packetarchive.IndexRecord) error { return save(row.ID, rebuilt) })
				if e != nil {
					return e
				}
				inputs = append(inputs, packetarchive.SessionInput{Manifest: row.Manifest, ObjectVersion: row.ObjectVersion, Range: source, Index: &index})
				continue
			}
			file, e := packetarchive.StageSessionSource(ctx, a.PacketStaging, row.Manifest, source)
			if e != nil {
				return e
			}
			defer file.Close()
			defer os.Remove(file.Name())
			inputs = append(inputs, packetarchive.SessionInput{Manifest: row.Manifest, ObjectVersion: row.ObjectVersion, File: file})
		}
		var e error
		report, e = packetarchive.ExportSession(ctx, output, request, inputs)
		if errors.Is(e, packetarchive.ErrSessionIncomplete) {
			incomplete = e
			return nil
		}
		return e
	})
	if err == nil {
		err = incomplete
	}
	if err != nil {
		if httpapi.PacketSessionFailure(w, r, request, report, err) {
			return
		}
		if errors.Is(err, pgx.ErrNoRows) {
			operationError(w, r, err)
		} else {
			httpapi.Fail(w, r, 503, "session_source_unconfirmed", "原包身份、指定对象版本或通信内容无法完整核验，请重新读取目录")
		}
		return
	}
	// 发送前再核对当前登录账号和每个源对象；准备完成不等于有权继续下载。
	httpapi.SendPacketSession(ctx, w, r, output, request.ArchiveIDs[0], report.Completeness, func() bool {
		for _, id := range request.ArchiveIDs {
			if _, err := a.DB.PacketArchive(ctx, u, id); err != nil {
				operationError(w, r, err)
				return false
			}
		}
		return true
	})
}
func (a *API) packetArchives(w http.ResponseWriter, r *http.Request) {
	limit, ok := requestListLimit(w, r)
	if !ok {
		return
	}
	if !incidentQuery(r, "sensor_id", "cursor", "limit") {
		httpapi.Fail(w, r, 400, "invalid_request", "原包目录筛选参数无效")
		return
	}
	q := r.URL.Query()
	items, next, err := a.DB.PacketArchives(r.Context(), httpapi.Principal(r), q.Get("sensor_id"), q.Get("cursor"), limit)
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
		httpapi.Fail(w, r, 503, "packet_staging_unavailable", "原包下载暂存服务异常，请稍后重试")
		return
	}
	defer file.Close()
	defer os.Remove(file.Name())
	source := func(ctx context.Context, start, length int64) (io.ReadCloser, error) {
		return a.Packets.Range(ctx, row.ObjectKey, row.ObjectVersion, start, length)
	}
	if err = packetarchive.ReadRange(ctx, file, source, row.Manifest.Encoding, 0, row.Manifest.Encoding.RawBytes); err == nil {
		err = packetarchive.ValidateManifestRawFile(ctx, file, row.Manifest)
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
