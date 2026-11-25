package platform

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) packetFlow(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var request packetarchive.SegmentFlowRequest
	if !contract.ValidID(id) || r.URL.RawQuery != "" || httpapi.Decode(w, r, &request) != nil {
		httpapi.Fail(w, r, 400, "invalid_flow_segment", "请选择有效的归档和会话分段")
		return
	}
	number := 0
	slots := sessionExports
	if raw := r.PathValue("number"); raw != "" {
		var err error
		number, err = packetarchive.InspectionNumber(raw, nil)
		if err != nil {
			httpapi.Fail(w, r, 400, "invalid_packet_number", "请选择有效的分段包序号")
			return
		}
		slots = packetDownloads
	}
	if a.DB == nil || a.Packets == nil || a.PacketStaging == "" {
		httpapi.Fail(w, r, 503, "packet_storage_unavailable", "原包对象存储或私有暂存未配置")
		return
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		httpapi.Fail(w, r, 429, "packet_download_busy", "原包读取额度已满，请稍后重试")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	u := httpapi.Principal(r)
	var flow packetarchive.SegmentFlow
	var version string
	err := a.DB.WithPacketFlowIndexes(ctx, u, []string{id}, func(rows []store.PacketArchive, save func(string, packetarchive.IndexRecord) error) error {
		row := rows[0]
		if row.ManifestSHA256 != request.ManifestSHA256 || row.Manifest.Encoding.RawSHA256 != request.RawSHA256 {
			return errFlowDirectoryChanged
		}
		version = row.ObjectVersion
		source := func(ctx context.Context, start, length int64) (io.ReadCloser, error) {
			return a.Packets.Range(ctx, row.ObjectKey, version, start, length)
		}
		input := packetarchive.SessionInput{Manifest: row.Manifest, ObjectVersion: version, Range: source}
		if row.Manifest.Encoding.Schema == packetarchive.PackedSchema {
			index, err := packetarchive.ResolveSegmentIndex(ctx, row.Index, row.Manifest, source, a.PacketStaging, func(rebuilt packetarchive.IndexRecord) error { return save(id, rebuilt) })
			if err != nil {
				return err
			}
			input.Index = &index
		} else {
			file, err := packetarchive.StageSessionSource(ctx, a.PacketStaging, row.Manifest, source)
			if err != nil {
				return err
			}
			defer os.Remove(file.Name())
			defer file.Close()
			input.File = file
		}
		var err error
		flow, err = packetarchive.ReadSegmentFlow(ctx, request, input)
		return err
	})
	if err != nil {
		packetFlowError(w, r, err)
		return
	}
	authorize := func(inspection bool) bool {
		allowed := false
		a.Auth.Require(true, func(w http.ResponseWriter, latest *http.Request) {
			principal := httpapi.Principal(latest)
			if principal.ID != u.ID || principal.TenantID != u.TenantID {
				httpapi.Fail(w, latest, 403, "permission_changed", "登录身份已变化，请重新读取原包")
				return
			}
			row, err := a.DB.PacketArchive(ctx, principal, id)
			if err == nil && (row.ManifestSHA256 != request.ManifestSHA256 || row.ObjectVersion != version) {
				err = errFlowDirectoryChanged
			}
			if err == nil {
				if inspection {
					err = a.DB.AuditPacketInspection(ctx, principal, id, httpapi.RequestID(latest))
				} else {
					err = a.DB.AuditPacketSessionExport(ctx, principal, []string{id}, "snapshot", httpapi.RequestID(latest))
				}
			}
			if err != nil {
				packetFlowError(w, latest, err)
				return
			}
			allowed = true
		})(w, r.WithContext(ctx))
		return allowed
	}
	if number > 0 {
		packet, err := flow.Inspect(number)
		if err != nil {
			packetFlowError(w, r, err)
		} else if authorize(true) {
			w.Header().Set("Cache-Control", "no-store")
			httpapi.JSON(w, 200, packet)
		}
		return
	}
	output, err := os.CreateTemp(a.PacketStaging, ".flow-snapshot-")
	if err != nil {
		httpapi.Fail(w, r, 503, "packet_staging_unavailable", "会话分段暂存服务异常")
		return
	}
	defer os.Remove(output.Name())
	defer output.Close()
	if err := flow.WriteSnapshot(ctx, output); err != nil {
		packetFlowError(w, r, err)
		return
	}
	httpapi.SendPacketFlowSnapshot(ctx, w, r, output, id, flow.Retention, func() bool { return authorize(false) })
}

var errFlowDirectoryChanged = errors.New("会话分段对应的归档已变化")

func packetFlowError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errFlowDirectoryChanged):
		httpapi.Fail(w, r, 409, "packet_directory_changed", "会话分段对应的归档已变化，请重新查询")
	case errors.Is(err, packetarchive.ErrPacketNotFound), errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "flow_packet_not_found", "归档已到期、不可访问或没有所选的留存报文")
	case errors.Is(err, packetarchive.ErrLimit):
		httpapi.Fail(w, r, 413, "session_export_budget", "会话快照超过 64 MiB 处理预算")
	default:
		httpapi.Fail(w, r, 503, "packet_object_unconfirmed", "会话分段的原包或对象版本无法核验")
	}
}
