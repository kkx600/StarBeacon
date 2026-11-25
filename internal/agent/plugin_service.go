package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"log/slog"
	"net"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/responsescript"
	bolt "go.etcd.io/bbolt"
)

var pluginAssignments = []byte("plugin_assignments")

type PluginService struct {
	wal          *WAL
	key          ed25519.PublicKey
	workerBinary string
	profiles     map[string]pluginProfile
	bindings     []response.PluginBinding
	protection   ResponseService
	mu           sync.Mutex
	running      map[string]*pluginRuntime
	healthMu     sync.RWMutex
	connectors   map[string]response.Health
}

func NewPluginService(wal *WAL, filename, workerBinary string, key ed25519.PublicKey, management ...string) (*PluginService, error) {
	profiles, err := readPluginProfiles(filename)
	if err != nil || wal == nil || len(key) != ed25519.PublicKeySize {
		return nil, response.ErrInput
	}
	s := &PluginService{wal: wal, key: slices.Clone(key), workerBinary: workerBinary,
		profiles: make(map[string]pluginProfile), running: make(map[string]*pluginRuntime), connectors: make(map[string]response.Health),
		protection: ResponseService{management: management, addresses: net.InterfaceAddrs, resolve: net.DefaultResolver.LookupNetIP}}
	for _, profile := range profiles {
		s.profiles[profile.PluginID] = profile
		s.bindings = append(s.bindings, profile.binding())
	}
	sort.Slice(s.bindings, func(i, j int) bool { return s.bindings[i].PluginID < s.bindings[j].PluginID })
	err = wal.DB.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{pluginAssignments, []byte("plugin_trial_reservations"), []byte("device_alert_sources")} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	})
	return s, err
}

func (s *PluginService) Bindings() []response.PluginBinding { return slices.Clone(s.bindings) }

func (s *PluginService) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, current := range s.running {
		current.close()
	}
	clear(s.running)
}

func (s *PluginService) execute(ctx context.Context, command control.Command) (json.RawMessage, string, error) {
	if command.TenantID != s.wal.TenantID || command.SensorID != s.wal.SensorID ||
		command.RegistrationID != s.wal.RegistrationID || control.Validate(command) != nil {
		return nil, "plugin_scope", response.ErrInput
	}
	if command.Kind == response.PluginTrialCommand {
		return s.trial(ctx, command)
	}
	activation, err := response.ReadPluginActivation(command.Payload)
	if err != nil {
		return nil, "plugin_invalid", err
	}
	profile := s.profiles[activation.PluginID]
	if profile.PluginID == "" {
		return nil, "plugin_binding", response.ErrUnavailable
	}
	if artifact := activation.Artifact; artifact != nil {
		if artifact.Release.Verify(s.key, command.TenantID, command.SensorID, command.RegistrationID) != nil ||
			artifact.Release.Grant.Binding != profile.binding() {
			return nil, "plugin_signature", response.ErrInput
		}
		runtime, err := s.open(profile, artifact.Version, nil)
		if err != nil {
			return nil, "plugin_binding", err
		}
		runtime.close()
	}
	if err = s.wal.DB.View(func(tx *bolt.Tx) error {
		if s.hasOpenResponseLease(tx, profile.Device.ID) {
			return response.ErrUnavailable
		}
		old, err := localPluginAssignment(tx, activation.PluginID)
		if err != nil {
			return err
		}
		_, err = activation.Apply(old)
		return err
	}); err != nil {
		return nil, "plugin_deployment_changed", err
	}
	raw, err := json.Marshal(activation.Result())
	return raw, "", err
}

func localPluginAssignment(tx *bolt.Tx, id string) (response.PluginAssignment, error) {
	var old response.PluginAssignment
	b := tx.Bucket(pluginAssignments)
	if b == nil {
		return old, response.ErrUnavailable
	}
	if raw := b.Get([]byte(id)); raw != nil {
		if json.Unmarshal(raw, &old) != nil || old.Generation < 1 ||
			old.Current != nil && (old.Current.Validate() != nil || old.Current.Version.ID != id) ||
			old.Previous != nil && (old.Previous.Validate() != nil || old.Previous.Version.ID != id) {
			return old, response.ErrInput
		}
	}
	return old, nil
}

// commitActivation 与成功回执同事务落盘，断电只会保留已确认的一侧。
func (s *PluginService) commitActivation(tx *bolt.Tx, c control.Command, result []byte) error {
	a, err := response.ReadPluginActivation(c.Payload)
	if err != nil || response.ReadPluginActivationResult(result, a) != nil {
		return response.ErrInput
	}
	if a.Artifact != nil && (a.Artifact.Release.Verify(s.key, c.TenantID, c.SensorID, c.RegistrationID) != nil ||
		a.Artifact.Release.Grant.Binding != s.profiles[a.PluginID].binding()) {
		return response.ErrInput
	}
	if s.hasOpenResponseLease(tx, s.profiles[a.PluginID].Device.ID) {
		return response.ErrUnavailable
	}
	old, err := localPluginAssignment(tx, a.PluginID)
	if err != nil {
		return err
	}
	next, err := a.Apply(old)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	return tx.Bucket(pluginAssignments).Put([]byte(a.PluginID), raw)
}

type pluginRuntime struct {
	profile   pluginProfile
	version   response.PluginVersion
	template  *response.Client
	script    *responsescript.Runtime
	connector *response.Client
}

func (s *PluginService) open(profile pluginProfile, v response.PluginVersion, replay *response.PluginReplay) (*pluginRuntime, error) {
	if !profile.supports(v) || v.Validate() != nil {
		return nil, response.ErrInput
	}
	r := &pluginRuntime{profile: profile, version: v}
	var err error
	if v.Script == nil {
		if replay == nil {
			r.template, err = response.NewTemplateClient(profile.Device, v.Template)
		} else {
			r.template, err = response.NewTemplateSimulation(profile.Device, v.Template, replay)
		}
		return r, err
	}
	cfg := responsescript.Config{Source: v.Script.Source, Origin: profile.Device.Origin, Login: profile.Script.Login, Secrets: profile.Script.Secrets}
	for _, route := range profile.Script.Routes {
		if v.Supports(route.Entry) {
			cfg.Routes = append(cfg.Routes, route)
		}
	}
	if replay != nil {
		r.script, err = responsescript.NewSimulation(cfg, s.workerBinary, replay)
		return r, err
	}
	cfg.Roots, err = outbound.LoadRoots(profile.Device.CAFile)
	if err != nil || cfg.Roots == nil {
		return nil, response.ErrUnavailable
	}
	r.script, err = responsescript.New(cfg, s.workerBinary)
	return r, err
}

func (r *pluginRuntime) close() {
	if r.template != nil {
		r.template.Close()
	}
	if r.script != nil {
		r.script.Close()
	}
}

func (s *PluginService) current(id string) (*pluginRuntime, error) {
	var active response.PluginAssignment
	err := s.wal.DB.View(func(tx *bolt.Tx) error {
		var err error
		active, err = localPluginAssignment(tx, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	artifact := active.Current
	prior := s.running[id]
	if artifact == nil {
		if prior != nil {
			prior.close()
			delete(s.running, id)
		}
		return nil, nil
	}
	p := s.profiles[id]
	if artifact.Release.Verify(s.key, s.wal.TenantID, s.wal.SensorID, s.wal.RegistrationID) != nil ||
		artifact.Release.Grant.Binding != p.binding() {
		return nil, response.ErrInput
	}
	if prior != nil {
		if prior.version.DefinitionSHA256() == artifact.Version.DefinitionSHA256() {
			return prior, nil
		}
		prior.close()
		delete(s.running, id)
	}
	next, err := s.open(p, artifact.Version, nil)
	if err == nil {
		if err = next.bindConnector(); err != nil {
			next.close()
			return nil, err
		}
		s.running[id] = next
	}
	return next, err
}

func (s *PluginService) Run(ctx context.Context, route func(context.Context, string) (string, error)) error {
	next := make(map[string]time.Time, len(s.profiles))
	delay := make(map[string]time.Duration, len(s.profiles))
	for ctx.Err() == nil {
		for _, binding := range s.bindings {
			id := binding.PluginID
			if time.Now().Before(next[id]) {
				continue
			}
			err := s.poll(ctx, id, route)
			if ctx.Err() != nil {
				return nil
			}
			if err != nil {
				delay[id] = min(max(5*time.Second, 2*delay[id]), 2*time.Minute)
				next[id] = time.Now().Add(delay[id])
				slog.Warn("设备告警拉取待重试", "plugin_id", id)
			} else {
				delay[id] = 0
				next[id] = time.Now().Add(time.Minute)
			}
			s.wal.setFailure("plugin_"+id+"_unavailable", err != nil)
		}
		if !pause(ctx, time.Second) {
			break
		}
	}
	return nil
}

func (s *PluginService) poll(ctx context.Context, id string, route func(context.Context, string) (string, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.current(id)
	if err != nil || current == nil || !current.version.Supports("pull_alerts") {
		return err
	}
	cursor, err := s.wal.deviceAlertCursor(id, current.profile.Device.DeviceID)
	if err != nil {
		return err
	}
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	page, err := current.pull(call, cursor)
	if err != nil {
		return err
	}
	token := ""
	if len(page.Items) != 0 {
		token, err = route(call, "alerts")
		if err != nil {
			return err
		}
	}
	return s.wal.appendDeviceAlerts(id, current.version.Name, current.profile.Device.DeviceID, cursor, token, page)
}
