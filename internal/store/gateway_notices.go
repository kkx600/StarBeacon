package store

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/gatewayblock"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/secrets"
)

func (p *Postgres) EnqueueGatewayNotices(ctx context.Context, tenant string, vault *secrets.Vault) error {
	return p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id,sensor_id,gateway_result FROM gateway_block_requests
			WHERE tenant_id=$1 AND notice_pending AND expires_at>now() ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 4`, tenant)
		if err != nil {
			return err
		}
		notices, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (notify.GatewaySummary, error) {
			var item notify.GatewaySummary
			var raw []byte
			if err := row.Scan(&item.RequestID, &item.SensorID, &raw); err != nil {
				return item, err
			}
			var result gatewayblock.Result
			if json.Unmarshal(raw, &result) != nil || result.RequestID != item.RequestID ||
				result.Observation == nil || result.Observation.State != gatewayblock.FlowContinued {
				return item, gatewayblock.ErrUnknown
			}
			item.ObservedAt = result.Observation.FinishedAt
			item.Reconnected = result.Observation.Reconnect != nil
			if !item.Valid() {
				return item, gatewayblock.ErrUnknown
			}
			return item, nil
		})
		if err != nil {
			return err
		}
		for _, item := range notices {
			if err := enqueueMessageTx(ctx, tx, tenant, item.RequestID, nil, nil, &item, vault, ""); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE gateway_block_requests SET notice_pending=false WHERE tenant_id=$1 AND id=$2`,
				tenant, item.RequestID); err != nil {
				return err
			}
		}
		return nil
	})
}
