package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/watchlist"
)

// ResponseProtection 固定新封禁授权时的名单状态，不表示设备执行时又读取了当前名单。
type ResponseProtection struct {
	SchemaVersion string                  `json:"schema_version"`
	CommandSHA256 string                  `json:"command_sha256"`
	CheckSHA256   string                  `json:"check_sha256"`
	Check         watchlist.ResponseCheck `json:"check"`
}

func responseProtectionCheck(ctx context.Context, tx pgx.Tx, tenant, sensor, registration string, raw json.RawMessage, now time.Time) (*watchlist.ResponseCheck, error) {
	action, err := responseapi.ReadAction(raw)
	if err != nil {
		return nil, err
	}
	check, err := CheckWatchlistResponseTx(ctx, tx, tenant, sensor, registration, action.TargetIP, now)
	if errors.Is(err, watchlist.ErrProtected) {
		// 业务调度器识别为无法授权，不能把保护命中当作可反复重试的设备写入失败。
		return nil, errors.Join(responseapi.ErrInput, err)
	}
	if err != nil {
		return nil, errors.Join(responseapi.ErrUnavailable, err)
	}
	if !validResponseProtectionCheck(check, action) {
		return nil, errors.Join(responseapi.ErrUnavailable, watchlist.ErrSource)
	}
	return &check, nil
}

func validResponseProtectionCheck(check watchlist.ResponseCheck, action responseapi.Action) bool {
	if check.SchemaVersion != watchlist.ResponseSchema || check.CheckedAt.IsZero() || check.CheckedAt.Before(action.RequestedAt.Add(-30*time.Second)) || check.CheckedAt.After(action.RequestedAt.Add(30*time.Second)) || !check.CheckedAt.Before(action.ExpiresAt) || check.Matches == nil || len(check.Matches) != 0 || len(check.StateSHA256) != 64 {
		return false
	}
	state, err := hex.DecodeString(check.StateSHA256)
	return err == nil && hex.EncodeToString(state) == check.StateSHA256
}

func saveResponseProtection(ctx context.Context, tx pgx.Tx, tenant, task, commandSHA string, check *watchlist.ResponseCheck) error {
	if check == nil {
		return nil
	}
	raw, err := json.Marshal(check)
	if err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `INSERT INTO response_watchlist_checks(tenant_id,task_id,command_sha256,check_sha256,check_data,expires_at) SELECT $1,$2,$3,$4,$5,retain_until FROM sensor_tasks WHERE tenant_id=$1 AND id=$2`, tenant, task, commandSHA, control.Digest(raw), raw)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return watchlist.ErrSource
	}
	return nil
}

func readResponseProtection(raw []byte, commandSHA string, task SensorTask) (*ResponseProtection, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var proof ResponseProtection
	var envelope map[string]json.RawMessage
	fields := []string{"schema_version", "command_sha256", "check_sha256", "check", "checked_at", "state_sha256", "matches", "id", "revision", "definition_sha256"}
	if len(raw) > 32768 || contract.JSONFields(string(raw), fields, 32768) != nil || json.Unmarshal(raw, &proof) != nil || json.Unmarshal(raw, &envelope) != nil || len(envelope) != 4 || proof.SchemaVersion != "response.protection.v1" || proof.CommandSHA256 != commandSHA || task.Kind != "response.block" || task.ResponseAction == nil || !validResponseProtectionCheck(proof.Check, *task.ResponseAction) {
		return nil, watchlist.ErrSource
	}
	var checkFields map[string]json.RawMessage
	if json.Unmarshal(envelope["check"], &checkFields) != nil || len(checkFields) != 4 {
		return nil, watchlist.ErrSource
	}
	check, err := json.Marshal(proof.Check)
	if err != nil || proof.CheckSHA256 != control.Digest(check) {
		return nil, watchlist.ErrSource
	}
	return &proof, nil
}
