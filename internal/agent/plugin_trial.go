package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/responsescript"
	bolt "go.etcd.io/bbolt"
)

func (s *PluginService) trial(ctx context.Context, command control.Command) (json.RawMessage, string, error) {
	t, err := response.ReadPluginTrial(command.Payload)
	if err != nil {
		return nil, "plugin_invalid", err
	}
	profile := s.profiles[t.Binding.PluginID]
	if profile.binding() != t.Binding || !profile.supports(t.Version) {
		return nil, "plugin_binding", response.ErrUnavailable
	}
	now := time.Now().UTC()
	task := command.ID
	if t.Stage == response.PluginSimulate {
		task = "fixture-lease"
	}
	lease := pluginLease{DeviceID: profile.Device.DeviceID, LeaseID: task,
		OwnerSHA256: response.Owner(command.TenantID, command.SensorID, command.RegistrationID, task),
		ExpiresAt:   now.Add(pluginTrialSeconds * time.Second)}
	var replay *response.PluginReplay
	if t.Stage == response.PluginSimulate {
		replay = response.NewPluginReplay(t.Version.Examples, map[string]string{
			"lease_id": task, "owner_sha256": lease.OwnerSHA256, "expires_at": lease.ExpiresAt.Format(time.RFC3339Nano),
			"observed_at": now.Format(time.RFC3339Nano), "target_ip": profile.TestAddress, "host_id": profile.TestHost,
			"device_id": profile.Device.DeviceID, "device_version": profile.Device.DeviceVersion,
		})
	}
	if t.Stage == response.PluginCapability && t.Version.Supports("block") {
		if err = s.protection.protectManagement(ctx, profile.TestAddress); err != nil {
			return nil, "plugin_test_address", err
		}
	}
	runtime, err := s.open(profile, t.Version, replay)
	if err != nil {
		return nil, "plugin_binding", err
	}
	defer runtime.close()
	writes := t.Stage == response.PluginCapability && t.Version.TrialMode() != "read_only"
	if writes {
		if err = s.reserveTrial(t.Version.ID, lease.ExpiresAt); err != nil {
			return nil, "plugin_test_reserved", err
		}
	}
	result := t.Result()
	check := func(entry string, fn func(context.Context) error) error {
		started := time.Now()
		var requests []response.PluginTrialRequest
		err := fn(response.WithPluginTrialRequests(ctx, &requests))
		code := "ok"
		if err != nil {
			code = pluginFailure(err)
		} else {
			result.Checks = append(result.Checks, entry)
		}
		result.Events = append(result.Events, response.PluginTrialEvent{Entry: entry, Code: code, DurationMS: time.Since(started).Milliseconds(), Requests: requests})
		return err
	}
	err = runtime.runTrial(ctx, t, lease, check)
	if err == nil && replay != nil && !replay.Complete() {
		err = response.ErrInput
	}
	if err == nil && writes {
		err = s.wal.DB.Update(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte("plugin_trial_reservations")).Delete([]byte(t.Version.ID))
		})
	}
	raw, _ := json.Marshal(result)
	if err != nil {
		return raw, pluginFailure(err), err
	}
	return raw, "", nil
}

func (s *PluginService) reserveTrial(id string, expires time.Time) error {
	return s.wal.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("plugin_trial_reservations"))
		now := time.Now()
		until := time.Unix(0, int64(uintValue(b.Get([]byte(id)))))
		if until.After(now) || !expires.After(now.Add(5*time.Second)) {
			return response.ErrUnavailable
		}
		return b.Put([]byte(id), key(uint64(expires.UnixNano())))
	})
}

func pluginFailure(err error) string {
	var code responsescript.Code
	if errors.As(err, &code) && code != "" {
		return "plugin_" + string(code)
	}
	switch {
	case errors.Is(err, response.ErrUnknown):
		return "result_unknown"
	case errors.Is(err, response.ErrUnavailable):
		return "plugin_unavailable"
	default:
		return "plugin_validation_failed"
	}
}

func (r *pluginRuntime) runTrial(ctx context.Context, t response.PluginTrial, lease pluginLease, check func(string, func(context.Context) error) error) error {
	if t.Stage != response.PluginCapability {
		if t.Version.Supports("health") {
			if err := check("health", r.health); err != nil {
				return err
			}
		}
		if t.Version.Supports("pull_alerts") {
			if err := check("pull_alerts", func(call context.Context) error { _, err := r.pull(call, ""); return err }); err != nil {
				return err
			}
		}
		if slices.Contains(t.Checks(), "verify") {
			if err := check("verify", func(call context.Context) error { return r.probe(call, lease) }); err != nil {
				return err
			}
		}
	}
	if t.Stage == response.PluginRead {
		return nil
	}
	if t.Version.Supports("block") {
		test := lease
		test.TargetIP = r.profile.TestAddress
		if err := r.testMutation(ctx, "block", "unblock", "verify_blocked", "verify_unblocked", test, check); err != nil {
			return err
		}
	}
	if t.Version.Supports("isolate") {
		test := lease
		test.HostID = r.profile.TestHost
		if err := r.testMutation(ctx, "isolate", "release", "verify_isolated", "verify_released", test, check); err != nil {
			return err
		}
	}
	if t.Stage == response.PluginCapability && t.Version.TrialMode() == "read_only" {
		return check("writes_denied", r.readOnly)
	}
	return nil
}

func (r *pluginRuntime) health(ctx context.Context) error {
	if r.template != nil {
		return r.template.CheckPlugin(ctx)
	}
	if r.profile.Script.DeviceHealth != nil {
		_, err := (&scriptConnector{runtime: r}).Describe(ctx)
		return err
	}
	res := r.script.Run(ctx, responsescript.Invocation{Entry: "health"})
	if res.Code != responsescript.OK {
		return res.Code
	}
	if !successfulRead(res.Events) || !acceptedScriptResult(res.Value) {
		return response.ErrUnavailable
	}
	return nil
}

func (r *pluginRuntime) pull(ctx context.Context, cursor string) (contract.DeviceAlertPage, error) {
	if r.template != nil {
		return r.template.PullAlerts(ctx, cursor)
	}
	raw, _ := json.Marshal(cursor)
	res := r.script.Run(ctx, responsescript.Invocation{Entry: "pull_alerts", Args: []json.RawMessage{raw}})
	if res.Code != responsescript.OK {
		return contract.DeviceAlertPage{}, res.Code
	}
	if !successfulRead(res.Events) {
		return contract.DeviceAlertPage{}, response.ErrUnavailable
	}
	return contract.ReadDeviceAlertPage(res.Value)
}

func successfulRead(events []responsescript.Event) bool {
	return slices.ContainsFunc(events, func(event responsescript.Event) bool {
		return event.Code == responsescript.OK && event.Method == http.MethodGet && event.Status >= 200 && event.Status < 300
	})
}

func acceptedScriptResult(raw []byte) bool {
	var yes bool
	var result struct {
		OK bool `json:"ok"`
	}
	return json.Unmarshal(raw, &yes) == nil && yes || json.Unmarshal(raw, &result) == nil && result.OK
}

func (r *pluginRuntime) probe(ctx context.Context, lease pluginLease) error {
	for _, mode := range []string{"block", "isolate"} {
		if !r.version.Supports(mode) {
			continue
		}
		if mode == "block" {
			lease.TargetIP, lease.HostID = r.profile.TestAddress, ""
		} else {
			lease.TargetIP, lease.HostID = "", r.profile.TestHost
		}
		v, err := r.observe(ctx, mode, lease)
		if err != nil || v.State != "missing" {
			return response.ErrUnknown
		}
	}
	if r.version.TrialMode() == "read_only" && r.script != nil {
		in := scriptInvocation("verify", lease)
		in.RuleID = lease.LeaseID
		in.Args = scriptArguments(map[string]string{"ip": "", "host_id": ""}, scriptLeaseArgs(lease, lease.LeaseID))
		res := r.script.Run(ctx, in)
		if res.Code != responsescript.OK {
			return res.Code
		}
		if !slices.ContainsFunc(res.Events, func(event responsescript.Event) bool {
			return event.Method == http.MethodGet && (event.Status == 200 || event.Status == 404)
		}) {
			return response.ErrUnavailable
		}
	}
	return nil
}

func (r *pluginRuntime) readOnly(ctx context.Context) error {
	if r.version.TrialMode() != "read_only" {
		return response.ErrInput
	}
	if r.template != nil {
		if _, err := r.template.ExecuteBound(ctx, "response.block", response.Action{}, ""); !errors.Is(err, response.ErrInput) {
			return response.ErrInput
		}
		return nil
	}
	entry := r.version.Entries()[0]
	// 最后一档验证只读入口拒绝写入授权，不连接设备。
	res := r.script.Run(ctx, responsescript.Invocation{Entry: entry, Write: &responsescript.ApprovedWrite{Method: http.MethodPut, Path: "/scope-check"}})
	if res.Code != responsescript.Scope {
		return response.ErrInput
	}
	return nil
}

func (r *pluginRuntime) testMutation(ctx context.Context, add, remove, verifyActive, verifyReleased string, lease pluginLease, check func(string, func(context.Context) error) error) (err error) {
	before, err := r.observe(ctx, add, lease)
	if err != nil || before.State != "missing" || !lease.ExpiresAt.After(time.Now().Add(5*time.Second)) {
		return response.ErrUnknown
	}
	removeAttempted := false
	defer func() {
		if err == nil || removeAttempted {
			return
		}
		// 写入失败或响应中断后，先核对同一所有者及原租约，再尝试解除一次。
		cleanup, stop := context.WithTimeout(context.Background(), 12*time.Second)
		defer stop()
		if actual, readErr := r.observe(cleanup, add, lease); readErr == nil && actual.State == "active" {
			_, _ = r.mutate(cleanup, remove, actual, pluginTrialSeconds)
		}
	}()
	if err = check(add, func(call context.Context) error {
		known, err := r.mutate(call, add, lease, pluginTrialSeconds)
		lease.RuleID = known
		return err
	}); err != nil {
		return err
	}
	if err = check(verifyActive, func(call context.Context) error {
		actual, err := r.observe(call, add, lease)
		if err != nil || actual.State != "active" {
			return response.ErrUnknown
		}
		lease.RuleID = actual.RuleID
		return nil
	}); err != nil {
		return err
	}
	removeAttempted = true
	if err = check(remove, func(call context.Context) error {
		_, err := r.mutate(call, remove, lease, pluginTrialSeconds)
		return err
	}); err != nil {
		// 确认未知结果属于原租约，保持失败回执，保留限时保护。
		_, _ = r.observe(ctx, add, lease)
		return err
	}
	return check(verifyReleased, func(call context.Context) error {
		actual, err := r.observe(call, add, lease)
		if err != nil || actual.State == "active" {
			return response.ErrUnknown
		}
		return nil
	})
}

func (r *pluginRuntime) action(lease pluginLease) response.Action {
	return response.Action{SchemaVersion: response.ActionSchema, ConnectorID: r.profile.Device.ID, ConfigSHA256: r.template.BindingSHA256(),
		DeviceID: lease.DeviceID, LeaseID: lease.LeaseID, OwnerSHA256: lease.OwnerSHA256, TargetIP: lease.TargetIP,
		RequestedAt: lease.ExpiresAt.Add(-pluginTrialSeconds * time.Second), ExpiresAt: lease.ExpiresAt, Reason: "联动插件保留地址试运行"}
}

func (r *pluginRuntime) mutate(ctx context.Context, entry string, lease pluginLease, duration int) (string, error) {
	remove := entry == "unblock" || entry == "release"
	if r.template != nil {
		kind := "response.block"
		if remove {
			kind = "response.revoke"
		}
		result, err := r.template.ExecuteBound(ctx, kind, r.action(lease), lease.RuleID)
		return result.Observation.DeviceRuleID, err
	}
	if !remove && !lease.ExpiresAt.After(time.Now().Add(5*time.Second)) {
		return "", response.ErrInput
	}
	in := scriptInvocation(entry, lease)
	in.DurationSeconds = duration
	var target any = map[string]string{"ip": lease.TargetIP}
	if entry == "isolate" || entry == "release" {
		target = lease.HostID
	}
	in.Write = r.profile.Script.Actions[entry].grant(lease, duration)
	if remove {
		in.Args = scriptArguments(target, scriptLeaseArgs(lease, lease.RuleID))
		in.RuleID = lease.RuleID
	} else {
		in.Args = scriptArguments(target, duration)
	}
	res := r.script.Run(ctx, in)
	if res.Code != responsescript.OK {
		return "", res.Code
	}
	onDevice := slices.ContainsFunc(res.Events, func(event responsescript.Event) bool {
		return event.Method == in.Write.Method && event.Code == responsescript.OK && event.Status >= 200 && event.Status < 300
	})
	if !onDevice || !acceptedScriptResult(res.Value) {
		return "", response.ErrUnknown
	}
	return "", nil
}

func (r *pluginRuntime) observe(ctx context.Context, mode string, lease pluginLease) (pluginLease, error) {
	if r.template != nil {
		state, missing, err := r.template.CheckPluginLease(ctx, r.action(lease))
		if err != nil {
			return pluginLease{}, err
		}
		if missing {
			return pluginLease{State: "missing"}, nil
		}
		if lease.RuleID != "" && state.DeviceRuleID != lease.RuleID {
			return pluginLease{}, response.ErrUnknown
		}
		return pluginLease{State: state.State, RuleID: state.DeviceRuleID}, nil
	}
	plan := r.profile.Script.Verify[mode]
	in := scriptInvocation("verify", lease)
	in.RuleID = lease.LeaseID
	in.ReadbackPath = strings.Replace(plan.Path, "{rule_id}", lease.LeaseID, 1)
	in.Args = scriptArguments(map[string]string{"ip": lease.TargetIP, "host_id": lease.HostID}, scriptLeaseArgs(lease, lease.LeaseID))
	res := r.script.Run(ctx, in)
	if res.Code != responsescript.OK {
		return pluginLease{}, res.Code
	}
	actual, err := plan.readback(res.Readback, lease)
	if err != nil || !reportedState(res.Value, actual.State) {
		return pluginLease{}, response.ErrUnknown
	}
	return actual, nil
}

func scriptInvocation(entry string, lease pluginLease) responsescript.Invocation {
	return responsescript.Invocation{Entry: entry, TaskID: lease.LeaseID, OwnerSHA256: lease.OwnerSHA256,
		ExpiresAt: lease.ExpiresAt.Format(time.RFC3339Nano), DurationSeconds: pluginTrialSeconds}
}

func scriptArguments(values ...any) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(values))
	for _, v := range values {
		raw, _ := json.Marshal(v)
		out = append(out, raw)
	}
	return out
}

func scriptLeaseArgs(lease pluginLease, pathID string) map[string]string {
	return map[string]string{"rule_id": pathID, "lease_id": lease.LeaseID, "device_rule_id": lease.RuleID,
		"owner_sha256": lease.OwnerSHA256, "expires_at": lease.ExpiresAt.Format(time.RFC3339Nano)}
}

func reportedState(raw []byte, want string) bool {
	if string(raw) == "true" || string(raw) == "false" {
		return (string(raw) == "true") == (want == "active")
	}
	var state string
	return json.Unmarshal(raw, &state) == nil && state == want
}
