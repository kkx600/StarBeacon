package agent

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
)

var localPacketDownloads = make(chan struct{}, 2)

func registerLocalPackets(m *http.ServeMux, wal *WAL, auth *httpapi.Auth) {
	m.HandleFunc("GET /api/local/v1/packet-archives/{id}/packets/{number}", auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		number, err := packetarchive.InspectionNumber(r.PathValue("number"), r.URL.Query())
		if err != nil || !contract.ValidID(r.PathValue("id")) {
			httpapi.Fail(w, r, 400, "invalid_packet_number", "请选择有效归档和 1–1,048,576 范围内的整数包序号")
			return
		}
		if wal.packetArchives == nil {
			httpapi.Fail(w, r, 503, "packet_capture_unavailable", "独立原包捕获未启用")
			return
		}
		select {
		case localPacketDownloads <- struct{}{}:
			defer func() { <-localPacketDownloads }()
		default:
			httpapi.Fail(w, r, 429, "packet_download_busy", "本机原包读取额度已满，请稍后重试")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		file, row, err := wal.packetArchives.Spool.OpenStored(r.PathValue("id"))
		if err != nil {
			httpapi.Fail(w, r, 409, "packet_not_available", "本机仅可查看尚待主平台确认的完整制品；已确认数据请在主平台查看")
			return
		}
		defer file.Close()
		result, err := packetarchive.InspectPacket(ctx, packetarchive.RangeFile(file), *row.Manifest, wal.packetArchives.Spool.Dir, number)
		if err != nil {
			if errors.Is(err, packetarchive.ErrPacketNotFound) {
				httpapi.Fail(w, r, 404, "packet_not_found", "所选归档中不存在该包序号")
			} else {
				httpapi.Fail(w, r, 503, "packet_unconfirmed", "原包制品尚未完整核验")
			}
			return
		}
		current, err := wal.packetArchives.Spool.Record(row.ID)
		if err != nil || current.State != "ready" || current.ManifestSHA256 != row.ManifestSHA256 || result.ManifestSHA256 != row.ManifestSHA256 {
			httpapi.Fail(w, r, 409, "packet_state_changed", "原包暂存状态已变化，请重新读取目录")
			return
		}
		original := httpapi.Principal(r)
		auth.Require(true, func(w http.ResponseWriter, latest *http.Request) {
			principal := httpapi.Principal(latest)
			if principal.ID != original.ID || principal.TenantID != original.TenantID {
				httpapi.Fail(w, latest, 403, "permission_changed", "登录身份已变化，请重新读取原包")
				return
			}
			if err = wal.RecordLocalOperation(ctx, principal.Username, "pcap.inspect.request", row.ID, httpapi.RequestID(latest)); err != nil {
				httpapi.Fail(w, latest, 503, "audit_unavailable", "无法保存原包访问记录")
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			httpapi.JSON(w, 200, result)
		})(w, r.WithContext(ctx))
	}))
	m.HandleFunc("GET /api/local/v1/packet-archives", auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		if wal.packetArchives == nil {
			httpapi.JSON(w, 200, map[string]any{"items": []packetarchive.LocalRecord{}, "available": false})
			return
		}
		rows, err := wal.packetArchives.Spool.List()
		if err != nil {
			httpapi.Fail(w, r, 503, "packet_spool_unavailable", "原包暂存目录无法读取")
			return
		}
		httpapi.JSON(w, 200, map[string]any{"items": rows, "available": true, "health": wal.packetArchives.Snapshot(), "limit": 200})
	}))
	m.HandleFunc("GET /api/local/v1/packet-archives/{id}", auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		if wal.packetArchives == nil {
			httpapi.Fail(w, r, 503, "packet_capture_unavailable", "独立原包捕获未启用")
			return
		}
		row, err := wal.packetArchives.Spool.Record(r.PathValue("id"))
		if err != nil {
			httpapi.Fail(w, r, 404, "not_found", "原包暂存记录不存在或不可访问")
			return
		}
		httpapi.JSON(w, 200, row)
	}))
	m.HandleFunc("GET /api/local/v1/packet-archives/{id}/download", auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		if wal.packetArchives == nil {
			httpapi.Fail(w, r, 503, "packet_capture_unavailable", "独立原包捕获未启用")
			return
		}
		select {
		case localPacketDownloads <- struct{}{}:
			defer func() { <-localPacketDownloads }()
		default:
			httpapi.Fail(w, r, 429, "packet_download_busy", "本机原包下载额度已满，请稍后重试")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		file, row, err := wal.packetArchives.Spool.OpenStored(r.PathValue("id"))
		if err != nil {
			httpapi.Fail(w, r, 409, "packet_not_available", "本机仅可下载尚待主平台确认的完整制品；已确认数据请在主平台查看")
			return
		}
		defer file.Close()
		decoded, err := os.CreateTemp(wal.packetArchives.Spool.Dir, ".packet-download-")
		if err != nil {
			httpapi.Fail(w, r, 503, "packet_staging_unavailable", "原包下载暂存不可用")
			return
		}
		defer decoded.Close()
		defer os.Remove(decoded.Name())
		if err = packetarchive.ReadRange(ctx, decoded, packetarchive.RangeFile(file), row.Manifest.Encoding, 0, row.Manifest.Encoding.RawBytes); err == nil {
			err = packetarchive.ValidateRawFile(ctx, decoded, row.Capture)
		}
		if err != nil {
			httpapi.Fail(w, r, 503, "packet_unconfirmed", "原包制品尚未完整核验")
			return
		}
		current, err := wal.packetArchives.Spool.Record(row.ID)
		if err != nil || current.State != "ready" || current.ManifestSHA256 != row.ManifestSHA256 {
			httpapi.Fail(w, r, 409, "packet_state_changed", "原包暂存状态已变化，请重新读取目录")
			return
		}
		if err = wal.RecordLocalOperation(ctx, httpapi.Principal(r).Username, "pcap.download.request", row.ID, httpapi.RequestID(r)); err != nil {
			httpapi.Fail(w, r, 503, "audit_unavailable", "无法保存原包访问记录")
			return
		}
		w.Header().Set("Content-Type", "application/x-pcapng")
		w.Header().Set("Content-Disposition", `attachment; filename="`+row.ID+`.pcapng"`)
		w.Header().Set("Content-Length", strconv.FormatInt(row.Manifest.Encoding.RawBytes, 10))
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-SHA256", row.Manifest.Encoding.RawSHA256)
		if _, err = io.Copy(w, decoded); err != nil {
			panic(http.ErrAbortHandler)
		}
	}))
}
