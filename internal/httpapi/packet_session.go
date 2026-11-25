package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/kkx600/StarBeacon/internal/packetarchive"
)

func ReadPacketSession(w http.ResponseWriter, r *http.Request) (request packetarchive.SessionRequest, valid bool) {
	if r.URL.RawQuery != "" || Decode(w, r, &request) != nil || request.Validate() != nil {
		Fail(w, r, 400, "invalid_session_export", "需要选择 1–16 个原包归档、导出模式及准确的双端 IP、端口和 MAC")
		return request, false
	}
	return request, true
}

func PacketSessionFailure(w http.ResponseWriter, r *http.Request, request packetarchive.SessionRequest, report packetarchive.SessionReport, err error) bool {
	switch {
	case errors.Is(err, packetarchive.ErrSessionIncomplete):
		message := "所选原包未满足完整会话条件。请查看缺口原因。需要快照时请选择快照模式重新提交"
		if request.Mode == "snapshot" {
			message = "所选原包没有可导出的匹配报文，请核对双端身份和切片范围"
		}
		JSON(w, 422, map[string]any{"code": "session_incomplete", "message": message, "report": report, "request_id": RequestID(r)})
	case errors.Is(err, packetarchive.ErrLimit):
		Fail(w, r, 413, "session_export_budget", "会话导出超过处理预算，最多允许 16 个切片、256 MiB 输入、1 小时捕获窗口和 64 MiB 输出")
	default:
		return false
	}
	return true
}

func SendPacketSession(ctx context.Context, w http.ResponseWriter, r *http.Request, output *os.File, id, completeness string, authorize func() bool) {
	sendPacketFile(ctx, w, r, output, "session-"+id+".pcapng", completeness, "", authorize)
}

func SendPacketFlowSnapshot(ctx context.Context, w http.ResponseWriter, r *http.Request, output *os.File, id, retention string, authorize func() bool) {
	name := "snapshot-" + id
	if retention == "policy_truncated" {
		name += "-partial"
	}
	sendPacketFile(ctx, w, r, output, name+".pcapng", "snapshot", retention, authorize)
}

func sendPacketFile(ctx context.Context, w http.ResponseWriter, r *http.Request, output *os.File, name, completeness, retention string, authorize func() bool) {
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		Fail(w, r, 503, "packet_staging_unavailable", "会话导出制品不可读取")
		return
	}
	hash := sha256.New()
	size, err := io.Copy(hash, output)
	if err != nil || ctx.Err() != nil {
		Fail(w, r, 503, "session_export_unconfirmed", "会话导出未完成，请稍后重试")
		return
	}
	if !authorize() {
		return
	}
	if _, err = output.Seek(0, io.SeekStart); err != nil {
		Fail(w, r, 503, "packet_staging_unavailable", "会话导出制品不可读取")
		return
	}
	w.Header().Set("Content-Type", "application/x-pcapng")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-SHA256", hex.EncodeToString(hash.Sum(nil)))
	w.Header().Set("X-Session-Completeness", completeness)
	if retention != "" {
		w.Header().Set("X-Packet-Retention", retention)
	}
	if _, err = io.Copy(w, output); err != nil {
		panic(http.ErrAbortHandler)
	}
}
