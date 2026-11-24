package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/traffic"
)

func packetSessionDocuments(row PacketArchive, observed PacketArchiveObservations, received time.Time) ([]model.Alert, error) {
	capture := row.Manifest.Capture
	documents := make([]model.Alert, 0, len(observed.Flows))
	for i, flow := range observed.Flows {
		segment := traffic.PacketSessionSegment{
			Schema: traffic.PacketSessionSchema, ArchiveID: capture.ID, ManifestSHA256: row.ManifestSHA256,
			ArchiveRawSHA: row.Manifest.Encoding.RawSHA256, RunID: capture.RunID, Interface: capture.Interface,
			WindowStart: capture.StartedAt, WindowEnd: capture.EndedAt, FirstObserved: flow.StartedAt, LastObserved: flow.EndedAt,
			VLAN: flow.VLAN, Retention: flow.State, OriginalBytes: flow.OriginalBytes, RetainedBytes: flow.RetainedBytes,
			RetainedPackets: flow.Packets, KernelDrops: capture.KernelDrops, Limited: observed.Limited,
		}
		if capture.Retention != nil {
			segment.NetworkDomain, segment.PolicyRevision = capture.Retention.NetworkDomain, capture.Retention.PolicyRevision
		}
		raw, err := json.Marshal(segment)
		if err != nil {
			return nil, err
		}
		position := uint64(i + 1)
		doc := model.Alert{
			SchemaVersion: "1.0", TenantID: capture.TenantID, SensorID: capture.SensorID, RegistrationID: capture.RegistrationID,
			SourceGenerationID: capture.ID, SourceOffset: strconv.FormatUint(position, 10), Sequence: strconv.FormatUint(position, 10),
			EventID:   contract.EventID(capture.TenantID, capture.RegistrationID, capture.ID, position, 0),
			RawSHA256: packetarchive.Digest(raw), Timestamp: flow.EndedAt, ObservedAt: capture.EndedAt, ReceivedAt: received,
			Source:      model.Endpoint{IP: flow.A.Addr().String(), Port: flow.A.Port()},
			Destination: model.Endpoint{IP: flow.B.Addr().String(), Port: flow.B.Port()},
			Severity:    "unknown", EvidenceStatus: "not_linked",
		}
		doc.Event.Kind, doc.Event.Dataset, doc.Event.Original = traffic.PacketSessionKind, traffic.PacketSessionDataset, string(raw)
		doc.Network.Transport = flow.Transport
		documents = append(documents, doc)
	}
	return documents, nil
}

func enqueuePacketSessions(ctx context.Context, tx pgx.Tx, row PacketArchive, period contract.IndexPeriod, observed PacketArchiveObservations) error {
	var now time.Time
	var days int
	tenant := row.Manifest.Capture.TenantID
	err := tx.QueryRow(ctx, `SELECT clock_timestamp(), COALESCE((SELECT days FROM retention_policies
		WHERE tenant_id=$1 AND category='network'),180)`, tenant).Scan(&now, &days)
	if err != nil {
		return err
	}
	partition := now.UTC().Format("2006-01-02")
	index, err := contract.EventIndexName("context", days, period, partition)
	if err != nil {
		return err
	}
	documents, err := packetSessionDocuments(row, observed, now.UTC())
	if err != nil {
		return err
	}
	raw, err := json.Marshal(documents)
	if err != nil {
		return err
	}
	// 与对象确认同一事务冻结来源、索引分区和内容。对象保留期不影响待办的独立恢复。
	_, err = tx.Exec(ctx, `INSERT INTO packet_session_outbox(tenant_id,archive_id,partition_day,index_name,documents,expires_at)
		VALUES($1,$2,$3::date,$4,$5,$6) ON CONFLICT DO NOTHING`, tenant, row.ID, partition, index, raw, now.AddDate(0, 0, days))
	return err
}

type PacketSessionBatch struct {
	Partition string
	Index     string
	Documents []model.Alert
}

// ProjectPacketSessions 领取一个已持久确认的定稿段，保持行锁直至不可变写入完成。
func (p *Postgres) ProjectPacketSessions(ctx context.Context, tenant string, project func(PacketSessionBatch) error) error {
	if !contract.ValidID(tenant) || project == nil {
		return packetarchive.ErrIntegrity
	}
	var workErr error
	dbErr := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var archiveID string
		var raw []byte
		var batch PacketSessionBatch
		err := tx.QueryRow(ctx, `SELECT archive_id,partition_day::text,index_name,documents FROM packet_session_outbox
			WHERE tenant_id=$1 AND expires_at>now() AND next_at<=now() ORDER BY next_at,archive_id LIMIT 1 FOR UPDATE SKIP LOCKED`,
			tenant).Scan(&archiveID, &batch.Partition, &batch.Index, &raw)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		workErr = decodePacketSessionBatch(tenant, archiveID, raw, &batch)
		if workErr == nil {
			workErr = project(batch)
		}
		if workErr != nil {
			_, err = tx.Exec(ctx, `UPDATE packet_session_outbox SET attempts=attempts+1,
				next_at=now()+make_interval(secs=>LEAST(300,power(2,LEAST(attempts+1,8)))::integer)
				WHERE tenant_id=$1 AND archive_id=$2`, tenant, archiveID)
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM packet_session_outbox WHERE tenant_id=$1 AND archive_id=$2`, tenant, archiveID)
		return err
	})
	return errors.Join(dbErr, workErr)
}

func decodePacketSessionBatch(tenant, archiveID string, raw []byte, batch *PacketSessionBatch) error {
	index, err := contract.ParseEventIndex(batch.Index)
	if err != nil || index.Stream != "context" || !index.LogsDB || !index.Covers(batch.Partition) || !contract.ValidID(archiveID) ||
		json.Unmarshal(raw, &batch.Documents) != nil || len(batch.Documents) == 0 || len(batch.Documents) > 1024 {
		return packetarchive.ErrIntegrity
	}
	for i, doc := range batch.Documents {
		position := uint64(i + 1)
		sequence := strconv.FormatUint(position, 10)
		if doc.TenantID != tenant || doc.SourceGenerationID != archiveID ||
			!contract.ValidID(doc.SensorID) || !contract.ValidID(doc.RegistrationID) ||
			doc.Sequence != sequence || doc.SourceOffset != sequence ||
			doc.EventID != contract.EventID(tenant, doc.RegistrationID, archiveID, position, 0) {
			return packetarchive.ErrIntegrity
		}
		if _, err = traffic.ParsePacketSession(doc); err != nil {
			return err
		}
	}
	return nil
}
