package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/packetpolicy"
	bolt "go.etcd.io/bbolt"
)

func (p *PacketArchiveController) retentionManaged() bool {
	return p != nil && p.Spool.RetentionFile != ""
}

func (p *PacketArchiveController) retentionStatus() packetpolicy.Status {
	status := packetpolicy.Status{State: "not_configured", ObservedAt: time.Now().UTC(), QuotaBytes: "0", SegmentBytes: "0"}
	if !p.retentionManaged() {
		return status
	}
	status.State = "unavailable"
	status.QuotaBytes = strconv.FormatInt(p.Spool.Quota, 10)
	status.SegmentBytes = strconv.FormatInt(p.Spool.SegmentBytes, 10)
	status.RotateSeconds = int(p.Config.PacketRotateInterval / time.Second)
	if reserved, err := p.Spool.Reserved(); err == nil {
		value := strconv.FormatInt(reserved, 10)
		status.ReservedBytes = &value
	}
	if observation, err := p.Spool.RetentionObservation(); err == nil {
		status.State = "ready"
		status.Configuration = &observation
	}
	return status
}

func (p *PacketArchiveController) updateRetention(ctx context.Context, input packetpolicy.Change, username, taskID, requestID string) (packetpolicy.Observation, error) {
	if !p.retentionManaged() {
		return packetpolicy.Observation{}, packetarchive.ErrRetentionUnavailable
	}
	origin := "local"
	if taskID != "" {
		origin = "platform"
	}
	return p.Spool.UpdateRetention(input, origin, taskID, func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		meta := model.RequestMetadataFrom(ctx)
		now := time.Now().UTC()
		return appendAudit(tx, LocalAudit{Username: username, Action: "packet.retention.configure", RequestID: requestID, SourceIP: meta.SourceIP, UserAgent: meta.UserAgent, CreatedAt: now, ExpiresAt: now.AddDate(0, 0, 180)})
	})
}

func (p *PacketArchiveController) executeRetention(ctx context.Context, c control.Command) (json.RawMessage, string, error) {
	var input packetpolicy.Change
	if err := json.Unmarshal(c.Payload, &input); err != nil {
		return nil, "invalid_packet_retention", err
	}
	result, err := p.updateRetention(ctx, input, "platform", c.ID, c.ID)
	if errors.Is(err, packetarchive.ErrRetentionUnavailable) || errors.Is(err, packetarchive.ErrRetentionConflict) {
		return nil, "packet_retention_changed", err
	}
	if err != nil {
		return nil, "packet_retention_write_failed", err
	}
	raw, err := json.Marshal(result)
	return raw, "", err
}

func (wal *WAL) localPacketRetention(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		httpapi.Fail(w, r, 400, "invalid_request", "留存配置读取不接受查询参数")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.JSON(w, 200, wal.packetArchives.retentionStatus())
}

func (wal *WAL) saveLocalPacketRetention(w http.ResponseWriter, r *http.Request) {
	var input packetpolicy.Change
	if r.URL.RawQuery != "" || httpapi.Decode(w, r, &input) != nil {
		httpapi.Fail(w, r, 400, "invalid_packet_retention", "留存策略参数、修订或摘要无效")
		return
	}
	u := httpapi.Principal(r)
	result, err := wal.packetArchives.updateRetention(r.Context(), input, u.Username, "", httpapi.RequestID(r))
	switch {
	case errors.Is(err, packetarchive.ErrRetentionConflict), errors.Is(err, packetarchive.ErrRetentionUnavailable):
		httpapi.Fail(w, r, 409, "packet_retention_changed", err.Error())
	case err != nil:
		httpapi.Fail(w, r, 503, "packet_retention_write_failed", "留存策略未保存，请检查采集器存储")
	default:
		w.Header().Set("Cache-Control", "no-store")
		httpapi.JSON(w, 200, result)
	}
}
