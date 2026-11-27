package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/gatewayblock"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/playbook"
	"github.com/kkx600/StarBeacon/internal/triage"
)

// 原业务入口处理设备权限。编排步骤键额外限制本次输入与当前人工步骤的绑定。
func playbookStepForKey(ctx context.Context, tx pgx.Tx, u model.Principal, key, kind string) (playbook.Run, playbook.Step, error) {
	var run playbook.Run
	var step playbook.Step
	id, index, reserved, err := playbook.ParseStepKey(key)
	if err != nil {
		return run, step, ErrConflict
	}
	if !reserved {
		return run, step, nil
	}
	run, err = readPlaybookRun(tx.QueryRow(ctx, `SELECT `+playbookRunColumns+playbookRunOwner+` AND r.id=$3 FOR SHARE OF r`, u.TenantID, u.ID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return run, step, ErrConflict
	}
	if err != nil {
		return run, step, err
	}
	step, ok := run.Current()
	if !ok || len(run.Results) != index || step.Kind != kind {
		return run, step, ErrConflict
	}
	return run, step, nil
}

func checkPlaybookTriage(ctx context.Context, tx pgx.Tx, u model.Principal, key string, input triage.Request) error {
	run, step, err := playbookStepForKey(ctx, tx, u, key, "triage")
	if err != nil || run.ID == "" {
		return err
	}
	if !input.ManualOnly || input.ObservationOnly || run.Alert.EventID != input.EventID || run.Alert.RawSHA256 != input.RawSHA256 ||
		step.Model.ID != input.ProviderID || step.Model.Revision != input.ProviderRevision {
		return ErrConflict
	}
	return configurationActor(ctx, tx, u, true, ErrConflict)
}

func checkPlaybookPlugin(ctx context.Context, tx pgx.Tx, u model.Principal, key string, e decision.Evaluation, input decision.ResponseRequest, now time.Time) error {
	run, step, err := playbookStepForKey(ctx, tx, u, key, "plugin")
	if err != nil || run.ID == "" {
		return err
	}
	b := step.Plugin
	triaged := triageResult(run)
	if !run.ApprovalActive(now) || run.Alert.EventID != e.Result.EventID || run.Alert.RawSHA256 != e.Result.RawSHA256 ||
		triaged.Outcome != "triage_confirmed" || triaged.Reference != e.Result.TriageID || e.Policy.ID != b.Policy.ID || e.Policy.Revision != b.Policy.Revision ||
		input.SensorID != b.SensorID || input.RegistrationID != b.RegistrationID || input.ConnectorID != b.ConnectorID || input.ConfigSHA256 != b.ConfigSHA256 || input.TTLSeconds != b.TTLSeconds {
		return ErrConflict
	}
	return nil
}

func checkPlaybookGateway(ctx context.Context, tx pgx.Tx, u model.Principal, key string, e *gatewayEvidence, p gatewayblock.Policy, now time.Time) error {
	run, step, err := playbookStepForKey(ctx, tx, u, key, "gateway")
	if err != nil || run.ID == "" {
		return err
	}
	if !run.ApprovalActive(now) || run.Alert.EventID != e.EventID || run.Alert.RawSHA256 != e.RawSHA256 ||
		run.Alert.SensorID != e.SensorID || run.Alert.RegistrationID != e.RegistrationID ||
		step.Gateway.ID != p.ID || step.Gateway.Revision != p.Revision || p.Definition.FollowUp != nil {
		return ErrConflict
	}
	allowed, err := playbookGatewayAllowed(ctx, tx, u.TenantID)
	if err != nil {
		return err
	}
	if !allowed {
		return gatewayblock.ErrPermission
	}
	e.PlaybookRunID = run.ID
	e.Deadline = run.Results[len(run.Results)-1].At.Add(playbook.ApprovalWindow)
	return nil
}

func playbookGatewayAllowed(ctx context.Context, tx pgx.Tx, tenant string) (bool, error) {
	if err := lockDecisionAutomation(ctx, tx, tenant); err != nil {
		return false, err
	}
	settings, err := decisionAutomationSettings(ctx, tx, tenant)
	return err == nil && settings.Effective(decision.Approval) == decision.Approval, err
}
