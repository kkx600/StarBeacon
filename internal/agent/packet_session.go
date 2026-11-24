package agent

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
)

func localPacketSession(wal *WAL, auth *httpapi.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, valid := httpapi.ReadPacketSession(w, r)
		if !valid {
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
			httpapi.Fail(w, r, 429, "session_export_busy", "会话导出额度已满，请稍后重试")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		principal := httpapi.Principal(r)
		spool := wal.packetArchives.Spool
		rows := make([]packetarchive.LocalRecord, 0, len(request.ArchiveIDs))
		files := make([]*os.File, 0, len(request.ArchiveIDs))
		var rawBytes int64
		for _, id := range request.ArchiveIDs {
			file, row, err := spool.OpenStored(id)
			if err != nil {
				httpapi.Fail(w, r, 409, "packet_not_available", "本机仅可导出尚待主平台确认的归档")
				return
			}
			defer file.Close()
			rows, files = append(rows, row), append(files, file)
			rawBytes += row.Manifest.Encoding.RawBytes
		}
		if rawBytes > packetarchive.MaxSessionInputBytes {
			httpapi.PacketSessionFailure(w, r, request, packetarchive.SessionReport{}, packetarchive.ErrLimit)
			return
		}
		if err := wal.RecordLocalOperation(ctx, principal.Username, "pcap.session.export."+request.Mode+".request", rows[0].ID, httpapi.RequestID(r)); err != nil {
			httpapi.Fail(w, r, 503, "audit_unavailable", "无法保存原包访问记录")
			return
		}
		inputs := make([]packetarchive.SessionInput, 0, len(rows))
		for i, row := range rows {
			manifest := *row.Manifest
			source := packetarchive.RangeFile(files[i])
			input := packetarchive.SessionInput{Manifest: manifest, ObjectVersion: "local_" + manifest.Encoding.StoredSHA256, Range: source}
			if manifest.Encoding.Schema == packetarchive.PackedSchema {
				index, err := spool.RebuildIndex(ctx, files[i], row)
				if err != nil {
					httpapi.Fail(w, r, 503, "session_source_unconfirmed", "本机会话索引或原包无法核验")
					return
				}
				input.Index = &index
			} else {
				file, err := packetarchive.StageSessionSource(ctx, spool.Dir, manifest, source)
				if err != nil {
					httpapi.Fail(w, r, 503, "session_source_unconfirmed", "本机原包尚未核验")
					return
				}
				defer file.Close()
				defer os.Remove(file.Name())
				input.File = file
			}
			inputs = append(inputs, input)
		}
		output, err := os.CreateTemp(spool.Dir, ".session-export-")
		if err != nil {
			httpapi.Fail(w, r, 503, "packet_staging_unavailable", "会话导出暂存服务异常，请稍后重试")
			return
		}
		defer output.Close()
		defer os.Remove(output.Name())
		report, err := packetarchive.ExportSession(ctx, output, request, inputs)
		if err != nil {
			if !httpapi.PacketSessionFailure(w, r, request, report, err) {
				httpapi.Fail(w, r, 503, "session_source_unconfirmed", "本机会话证据尚未核验")
			}
			return
		}
		httpapi.SendPacketSession(ctx, w, r, output, request.ArchiveIDs[0], report.Completeness, func() bool {
			for _, row := range rows {
				latest, err := spool.Record(row.ID)
				if err != nil || latest.State != "ready" || latest.ManifestSHA256 != row.ManifestSHA256 {
					httpapi.Fail(w, r, 409, "packet_state_changed", "原包暂存状态已变化，请重新读取目录")
					return false
				}
			}
			authorized := false
			auth.Require(true, func(w http.ResponseWriter, check *http.Request) {
				latest := httpapi.Principal(check)
				authorized = latest.ID == principal.ID && latest.TenantID == principal.TenantID
				if !authorized {
					httpapi.Fail(w, check, 403, "permission_changed", "登录身份已变化，请重新读取原包")
				}
			})(w, r.WithContext(ctx))
			return authorized
		})
	}
}
