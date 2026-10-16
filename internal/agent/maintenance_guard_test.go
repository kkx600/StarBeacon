package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	bolt "go.etcd.io/bbolt"
)

func TestMaintenanceGuardRequiresLinkedRuleReconciliation(t *testing.T) {
	for _, scenario := range []string{"valid", "missing_task", "bad_binding", "bad_result", "bad_kind", "corrupt_resolution"} {
		t.Run(scenario, func(t *testing.T) {
			_, m, command, input, original := reconciliationFixture(t)
			proof := control.RuleReconcileResult{Verified: true, UnknownTaskID: input.UnknownTaskID, UnknownCommandSHA256: input.UnknownCommandSHA256, ActiveSHA256: input.ExpectedSHA256, ConfigSHA256: input.ConfigSHA256, ProfileSHA256: input.ProfileSHA256, Stats: json.RawMessage(`[{"rules_loaded":1,"rules_failed":0}]`)}
			raw, _ := json.Marshal(proof)
			now := time.Now().UTC()
			digest := control.Digest([]byte("reconciliation fixture"))
			reconciled := LocalTask{Origin: "platform", Command: command, SHA256: digest, Acknowledged: true, Receipt: control.Receipt{CommandID: command.ID, CommandSHA256: digest, State: "succeeded", Result: raw, StartedAt: now, FinishedAt: &now}, RetainUntil: now.AddDate(0, 0, 180)}
			if err := m.WAL.DB.Update(func(tx *bolt.Tx) error {
				if err := m.putTask(tx, reconciled); err != nil {
					return err
				}
				if err := m.resolveRuleTask(tx, command, raw); err != nil {
					return err
				}
				bucket := tx.Bucket([]byte("sensor_tasks"))
				switch scenario {
				case "missing_task":
					return bucket.Delete([]byte(command.ID))
				case "bad_binding":
					reconciled.Command.SensorID = "another_sensor"
				case "bad_result":
					reconciled.Receipt.Result = json.RawMessage(`{}`)
				case "bad_kind":
					reconciled.Command.Kind = "diagnostics"
				case "corrupt_resolution":
					if err := json.Unmarshal(bucket.Get([]byte(original.Command.ID)), &original); err != nil {
						return err
					}
					original.RuleResolution = json.RawMessage(`{}`)
					return m.putTask(tx, original)
				}
				return m.putTask(tx, reconciled)
			}); err != nil {
				t.Fatal(err)
			}
			path := m.WAL.DB.Path()
			m.WAL.Close()
			if path != filepath.Join(filepath.Dir(path), "agent.db") {
				if err := os.Rename(path, filepath.Join(filepath.Dir(path), "agent.db")); err != nil {
					t.Fatal(err)
				}
			}
			err := InspectStoppedForUpdate(context.Background(), filepath.Dir(path))
			if (err == nil) != (scenario == "valid") {
				t.Fatal("维护准入没有核对独立规则核实记录", scenario, err)
			}
		})
	}
}

func TestMaintenanceGuardDataCorruptionDoesNotRewriteState(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent.db"), []byte("invalid bbolt"), 0600); err != nil {
		t.Fatal(err)
	}
	if InspectStoppedForUpdate(context.Background(), dir) == nil {
		t.Fatal("损坏 WAL 通过维护检查")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "agent.db"))
	if string(raw) != "invalid bbolt" {
		t.Fatal("维护检查改写了损坏状态")
	}
}
