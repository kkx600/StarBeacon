//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/testpcap"
	"github.com/kkx600/StarBeacon/migrations"
)

func TestReplayLeaseMigrationPreservesSignedCommandsAndRejectsBrokenReferences(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	fixture := newIsolatedDatabase(t, ctx)
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	capture, err := testpcap.HTTP(false)
	require(t, err)
	payload, err := control.ReplayPayload(control.Replay{SampleID: "legacy_sample", SampleSize: int64(len(capture)), SampleSHA256: control.Digest(capture), RuleMode: "registered"})
	require(t, err)
	now := time.Now().UTC()
	command := control.Command{ID: "task_legacy", TenantID: "lease_tenant", SensorID: "lease_sensor", RegistrationID: "lease_registration", Kind: "rules.replay", IssuedAt: now, ExpiresAt: now.Add(30 * time.Minute), Payload: payload}
	raw, signature, err := control.Encode(command, signer)
	require(t, err)
	diagnostic := command
	diagnostic.Kind, diagnostic.Payload = "diagnostics", json.RawMessage(`{}`)
	diagnosticRaw, diagnosticSignature, err := control.Encode(diagnostic, signer)
	require(t, err)
	migration, err := migrations.FS.ReadFile("00014_replay_task_leases.sql")
	require(t, err)
	up := strings.Split(string(migration), "-- +goose Down")[0]
	legacy := func(t *testing.T) pgx.Tx {
		t.Helper()
		tx, err := fixture.Owner.Pool.Begin(ctx)
		require(t, err)
		t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
		schema := pgx.Identifier{store.RandomID("it_lease_")}.Sanitize()
		_, err = tx.Exec(ctx, "CREATE SCHEMA "+schema)
		require(t, err)
		_, err = tx.Exec(ctx, "SET LOCAL search_path TO "+schema+",public")
		require(t, err)
		_, err = tx.Exec(ctx, `CREATE TABLE sensor_tasks (
 id text PRIMARY KEY,tenant_id text NOT NULL,kind text NOT NULL,state text NOT NULL,
 command bytea NOT NULL,signature bytea NOT NULL,command_sha256 text NOT NULL,expires_at timestamptz NOT NULL)`)
		require(t, err)
		return tx
	}
	t.Run("valid_legacy_task", func(t *testing.T) {
		tx := legacy(t)
		_, err := tx.Exec(ctx, `INSERT INTO sensor_tasks VALUES('replay','lease_tenant','rules.replay','queued',$1,$2,$3,$4),
 ('diagnostic','lease_tenant','diagnostics','queued',$5,$6,$7,$4)`, raw, signature, control.Digest(raw), command.ExpiresAt, diagnosticRaw, diagnosticSignature, control.Digest(diagnosticRaw))
		require(t, err)
		_, err = tx.Exec(ctx, up)
		require(t, err)
		var sample string
		var actualRaw, actualSignature []byte
		var digest string
		require(t, tx.QueryRow(ctx, "SELECT replay_sample_id,command,signature,command_sha256 FROM sensor_tasks WHERE id='replay'").Scan(&sample, &actualRaw, &actualSignature, &digest))
		if sample != "legacy_sample" || !bytes.Equal(raw, actualRaw) || !bytes.Equal(signature, actualSignature) || digest != control.Digest(raw) {
			t.Fatal("历史任务样本引用错误或签名原文被改写")
		}
		_, err = control.Decode(actualRaw, actualSignature, signer.Public().(ed25519.PublicKey), command.TenantID, command.SensorID, command.RegistrationID, now)
		require(t, err)
		var diagnosticSample *string
		require(t, tx.QueryRow(ctx, "SELECT replay_sample_id FROM sensor_tasks WHERE id='diagnostic'").Scan(&diagnosticSample))
		if diagnosticSample != nil {
			t.Fatal("非重放任务被绑定到样本")
		}
	})
	for _, test := range []struct{ name, command string }{
		{"missing_reference", `{"payload":{}}`},
		{"invalid_reference", `{"payload":{"sample_id":"../other"}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx := legacy(t)
			_, err := tx.Exec(ctx, "INSERT INTO sensor_tasks VALUES('broken','lease_tenant','rules.replay','queued',$1,$2,$3,$4)", []byte(test.command), signature, control.Digest([]byte(test.command)), command.ExpiresAt)
			require(t, err)
			_, err = tx.Exec(ctx, up)
			var postgresError *pgconn.PgError
			if !errors.As(err, &postgresError) || postgresError.Code != "23514" {
				t.Fatal("缺失或非法引用没有使迁移停止", err)
			}
		})
	}
}
