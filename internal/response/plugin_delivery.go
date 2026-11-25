package response

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"slices"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/strictjson"
)

const PluginTrialCommand = "plugin.trial"
const PluginApplyCommand = "plugin.apply"

const (
	PluginSimulate   = "simulate"
	PluginRead       = "read"
	PluginCapability = "capability"
	PluginPublish    = "publish"
	PluginRollback   = "rollback"
	PluginDisable    = "disable"
)

var PluginStages = [3]string{PluginSimulate, PluginRead, PluginCapability}

type PluginOperation struct {
	SensorID           string `json:"sensor_id"`
	Version            int    `json:"version"`
	Action             string `json:"action"`
	ExpectedGeneration int64  `json:"expected_generation"`
}

func (op PluginOperation) Validate() error {
	if !contract.ValidID(op.SensorID) || op.Version < 1 || op.Version > MaxPluginVersions || op.ExpectedGeneration < 0 {
		return ErrInput
	}
	switch op.Action {
	case PluginSimulate, PluginRead, PluginCapability, PluginPublish, PluginRollback, PluginDisable:
		return nil
	default:
		return ErrInput
	}
}

func StageIndex(stage string) int { return slices.Index(PluginStages[:], stage) }

type PluginBinding struct {
	PluginID      string `json:"plugin_id"`
	DeviceID      string `json:"device_id"`
	BindingSHA256 string `json:"binding_sha256"`
}

func (b PluginBinding) Validate() error {
	if !contract.ValidID(b.PluginID) || !contract.ValidID(b.DeviceID) || !validHash(b.BindingSHA256) {
		return ErrInput
	}
	return nil
}

type PluginTrial struct {
	Version PluginVersion `json:"version"`
	Binding PluginBinding `json:"binding"`
	Stage   string        `json:"stage"`
}

func ReadPluginTrial(raw []byte) (PluginTrial, error) {
	var t PluginTrial
	if decodePlugin(raw, []string{"version", "binding", "stage"}, &t) != nil || t.Version.Validate() != nil ||
		t.Binding.Validate() != nil || t.Binding.PluginID != t.Version.ID || StageIndex(t.Stage) < 0 ||
		t.Stage == PluginSimulate && len(t.Version.Examples) == 0 {
		return t, ErrInput
	}
	return t, nil
}

type PluginTrialEvent struct {
	Entry      string               `json:"entry"`
	Code       string               `json:"code"`
	DurationMS int64                `json:"duration_ms"`
	Requests   []PluginTrialRequest `json:"requests,omitempty"`
}

type PluginTrialRequest struct {
	Method string `json:"method"`
	Status int    `json:"status"`
}

const maxPluginTrialRequests = 16

type trialRequestsKey struct{}

func WithPluginTrialRequests(ctx context.Context, requests *[]PluginTrialRequest) context.Context {
	return context.WithValue(ctx, trialRequestsKey{}, requests)
}

// RecordPluginTrialRequest 只记录方法与状态，避免把地址、凭据及厂商响应带入任务回执。
func RecordPluginTrialRequest(ctx context.Context, method string, res *http.Response) {
	requests, _ := ctx.Value(trialRequestsKey{}).(*[]PluginTrialRequest)
	if requests == nil || len(*requests) >= maxPluginTrialRequests {
		return
	}
	status := 0
	if res != nil {
		status = res.StatusCode
	}
	*requests = append(*requests, PluginTrialRequest{Method: method, Status: status})
}

type PluginTrialResult struct {
	PluginID         string             `json:"plugin_id"`
	Version          int                `json:"version"`
	DefinitionSHA256 string             `json:"definition_sha256"`
	Binding          PluginBinding      `json:"binding"`
	Stage            string             `json:"stage"`
	Mode             string             `json:"mode"`
	Checks           []string           `json:"checks"`
	Events           []PluginTrialEvent `json:"events"`
}

func (t PluginTrial) Result() PluginTrialResult {
	return PluginTrialResult{
		PluginID: t.Version.ID, Version: t.Version.Version, DefinitionSHA256: t.Version.DefinitionSHA256(),
		Binding: t.Binding, Stage: t.Stage, Mode: t.Version.TrialMode(), Checks: []string{}, Events: []PluginTrialEvent{},
	}
}

func (t PluginTrial) Checks() []string {
	var result []string
	if t.Stage != PluginCapability {
		for _, entry := range []string{"health", "pull_alerts"} {
			if t.Version.Supports(entry) {
				result = append(result, entry)
			}
		}
		if t.Version.Supports("verify") && (t.Stage == PluginRead || t.Version.TrialMode() == "read_only") {
			result = append(result, "verify")
		}
	}
	if t.Stage == PluginSimulate || t.Stage == PluginCapability {
		if t.Version.Supports("block") {
			result = append(result, "block", "verify_blocked", "unblock", "verify_unblocked")
		}
		if t.Version.Supports("isolate") {
			result = append(result, "isolate", "verify_isolated", "release", "verify_released")
		}
	}
	if t.Stage == PluginCapability && t.Version.TrialMode() == "read_only" {
		result = append(result, "writes_denied")
	}
	return result
}

func (r PluginTrialResult) SHA256() string { return digest(r) }

func ReadPluginTrialResult(raw []byte, t PluginTrial) (PluginTrialResult, error) {
	var r PluginTrialResult
	fields := []string{"plugin_id", "version", "definition_sha256", "binding", "stage", "mode", "checks", "events"}
	if decodePlugin(raw, fields, &r) != nil {
		return r, ErrInput
	}
	want := t.Result()
	if r.PluginID != want.PluginID || r.Version != want.Version || r.DefinitionSHA256 != want.DefinitionSHA256 ||
		r.Binding != want.Binding || r.Stage != want.Stage || r.Mode != want.Mode || !slices.Equal(r.Checks, t.Checks()) ||
		len(r.Events) != len(r.Checks) || len(r.Checks) == 0 {
		return r, ErrInput
	}
	for i, event := range r.Events {
		if event.Entry != r.Checks[i] || event.Code != "ok" || event.DurationMS < 0 || event.DurationMS > 120_000 || len(event.Requests) > maxPluginTrialRequests {
			return r, ErrInput
		}
		for _, request := range event.Requests {
			switch request.Method {
			case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete:
			default:
				return r, ErrInput
			}
			if request.Status != 0 && (request.Status < 100 || request.Status > 599) {
				return r, ErrInput
			}
		}
	}
	return r, nil
}

// PluginGrant 绑定内容、设备配置、采集器注册代次和三个相互独立的试运行回执。
type PluginGrant struct {
	TenantID         string        `json:"tenant_id"`
	SensorID         string        `json:"sensor_id"`
	RegistrationID   string        `json:"registration_id"`
	Binding          PluginBinding `json:"binding"`
	Version          int           `json:"version"`
	DefinitionSHA256 string        `json:"definition_sha256"`
	TrialSHA256      [3]string     `json:"trial_sha256"`
}

type SignedPlugin struct {
	Grant     PluginGrant `json:"grant"`
	Signature []byte      `json:"signature"`
}

func (g PluginGrant) Validate() error {
	if !contract.ValidID(g.TenantID) || !contract.ValidID(g.SensorID) || !contract.ValidID(g.RegistrationID) ||
		g.Binding.Validate() != nil || g.Version < 1 || g.Version > MaxPluginVersions || !validHash(g.DefinitionSHA256) {
		return ErrInput
	}
	for i, hash := range g.TrialSHA256 {
		if !validHash(hash) || slices.Contains(g.TrialSHA256[:i], hash) {
			return ErrInput
		}
	}
	return nil
}

func (g PluginGrant) signedBytes() []byte {
	raw, _ := json.Marshal(g)
	return append([]byte("StarBeacon/response-plugin.release.v1\x00"), raw...)
}

func SignPlugin(g PluginGrant, key ed25519.PrivateKey) (SignedPlugin, error) {
	if len(key) != ed25519.PrivateKeySize || g.Validate() != nil {
		return SignedPlugin{}, ErrInput
	}
	return SignedPlugin{Grant: g, Signature: ed25519.Sign(key, g.signedBytes())}, nil
}

func (s SignedPlugin) Verify(key ed25519.PublicKey, tenant, sensor, registration string) error {
	if s.Grant.Validate() != nil || len(key) != ed25519.PublicKeySize || s.Grant.TenantID != tenant ||
		s.Grant.SensorID != sensor || s.Grant.RegistrationID != registration ||
		!ed25519.Verify(key, s.Grant.signedBytes(), s.Signature) {
		return ErrInput
	}
	return nil
}

type PluginArtifact struct {
	Version PluginVersion `json:"version"`
	Release SignedPlugin  `json:"release"`
}

func (a PluginArtifact) Validate() error {
	g := a.Release.Grant
	if a.Version.Validate() != nil || g.Validate() != nil || len(a.Release.Signature) != ed25519.SignatureSize ||
		g.Binding.PluginID != a.Version.ID || g.Version != a.Version.Version || g.DefinitionSHA256 != a.Version.DefinitionSHA256() {
		return ErrInput
	}
	return nil
}

type PluginActivation struct {
	PluginID           string          `json:"plugin_id"`
	Action             string          `json:"action"`
	ExpectedGeneration int64           `json:"expected_generation"`
	Artifact           *PluginArtifact `json:"artifact,omitempty"`
}

func ReadPluginActivation(raw []byte) (PluginActivation, error) {
	var a PluginActivation
	if decodePlugin(raw, []string{"plugin_id", "action", "expected_generation", "artifact"}, &a) != nil ||
		!contract.ValidID(a.PluginID) || a.ExpectedGeneration < 0 || a.ExpectedGeneration == (1<<63)-1 {
		return a, ErrInput
	}
	switch a.Action {
	case PluginPublish, PluginRollback:
		if a.Artifact == nil || a.Artifact.Validate() != nil || a.Artifact.Version.ID != a.PluginID {
			return a, ErrInput
		}
	case PluginDisable:
		if a.Artifact != nil || a.ExpectedGeneration == 0 {
			return a, ErrInput
		}
	default:
		return a, ErrInput
	}
	return a, nil
}

type PluginAssignment struct {
	Generation int64           `json:"generation"`
	Current    *PluginArtifact `json:"current,omitempty"`
	Previous   *PluginArtifact `json:"previous,omitempty"`
}

func (a PluginActivation) Apply(old PluginAssignment) (PluginAssignment, error) {
	if old.Generation != a.ExpectedGeneration {
		return old, ErrInput
	}
	next := PluginAssignment{Generation: old.Generation + 1, Current: a.Artifact, Previous: old.Current}
	switch a.Action {
	case PluginRollback:
		if old.Previous == nil || a.Artifact == nil || old.Previous.Version.DefinitionSHA256() != a.Artifact.Version.DefinitionSHA256() ||
			!bytes.Equal(old.Previous.Release.Signature, a.Artifact.Release.Signature) {
			return old, ErrInput
		}
	case PluginPublish:
		if a.Artifact == nil || old.Current != nil && old.Current.Version.Version == a.Artifact.Version.Version {
			return old, ErrInput
		}
		// 从停用状态重启时继续保留上一个可回退版本。
		if old.Current == nil && old.Previous != nil && old.Previous.Version.Version != a.Artifact.Version.Version {
			next.Previous = old.Previous
		}
	case PluginDisable:
		if old.Current == nil {
			return old, ErrInput
		}
	default:
		return old, ErrInput
	}
	return next, nil
}

type PluginActivationResult struct {
	PluginID         string `json:"plugin_id"`
	Action           string `json:"action"`
	Generation       int64  `json:"generation"`
	Version          int    `json:"version"`
	DefinitionSHA256 string `json:"definition_sha256,omitempty"`
}

func (a PluginActivation) Result() PluginActivationResult {
	r := PluginActivationResult{PluginID: a.PluginID, Action: a.Action, Generation: a.ExpectedGeneration + 1}
	if a.Artifact != nil {
		r.Version, r.DefinitionSHA256 = a.Artifact.Version.Version, a.Artifact.Version.DefinitionSHA256()
	}
	return r
}

func ReadPluginActivationResult(raw []byte, a PluginActivation) error {
	var r PluginActivationResult
	if decodePlugin(raw, []string{"plugin_id", "action", "generation", "version", "definition_sha256"}, &r) != nil || r != a.Result() {
		return ErrInput
	}
	return nil
}

type PluginDeployment struct {
	PluginID        string    `json:"plugin_id"`
	SensorID        string    `json:"sensor_id"`
	SensorName      string    `json:"sensor_name"`
	Generation      int64     `json:"generation"`
	Version         int       `json:"version"`
	PreviousVersion int       `json:"previous_version"`
	UpdatedAt       time.Time `json:"updated_at"`
	Unavailable     bool      `json:"unavailable"`
}

type PluginExecution struct {
	PluginID  string    `json:"plugin_id"`
	UpdatedAt time.Time `json:"updated_at"`
}

type PluginOperationResult struct {
	TaskID    string             `json:"task_id"`
	Action    string             `json:"action"`
	Version   int                `json:"version"`
	State     string             `json:"state"`
	Code      string             `json:"code,omitempty"`
	UpdatedAt time.Time          `json:"updated_at"`
	Trial     *PluginTrialResult `json:"trial,omitempty"`
}

type PluginOperations struct {
	Deployment PluginDeployment        `json:"deployment"`
	Binding    *PluginBinding          `json:"binding,omitempty"`
	Operations []PluginOperationResult `json:"operations"`
}

func decodePlugin(raw []byte, fields []string, target any) error {
	if strictjson.TopFields(string(raw), fields, MaxPluginDraftBytes+8192) != nil {
		return ErrInput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(target)
}
