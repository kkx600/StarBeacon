//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/agent"
	"github.com/kkx600/StarBeacon/internal/assessment"
	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/gatewayblock"
	"github.com/kkx600/StarBeacon/internal/ingest"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/normalize"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
	"github.com/kkx600/StarBeacon/internal/watchlist"
	"github.com/kkx600/StarBeacon/internal/worker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const gatewayTestSensor = "gateway_probe"
const gatewayTestRegistration = "gateway_registration"
const testRulePolicy = "gateway_rule"
const testReviewPolicy = "gateway_review"

type gatewayFixture struct {
	t                    *testing.T
	ctx                  context.Context
	db                   *isolatedDatabase
	user                 model.Principal
	id                   transport.SensorIdentity
	es                   *store.Elasticsearch
	index                string
	client, peer, viewer *liveHTTP
	signer               ed25519.PrivateKey
	wake                 *control.Wakeup
	scope                gatewayblock.Scope
	currentSettings      gatewayblock.Settings
}

func newGatewayFixture(t *testing.T, ctx context.Context, scope gatewayblock.Scope) *gatewayFixture {
	t.Helper()
	db := newIsolatedDatabase(t, ctx)
	name, other, password := store.RandomID("it_gateway_"), store.RandomID("it_gateway_other_"), store.Token()
	require(t, admin.Bootstrap(ctx, db.Owner, name, "网关授权验收", name, password, "admin"))
	require(t, admin.Bootstrap(ctx, db.Owner, other, "其他网关租户", other, password, "admin"))
	require(t, admin.Bootstrap(ctx, db.Owner, name, "网关授权验收", name+"_viewer", password, "viewer"))
	user, _, err := db.Runtime.Password(ctx, name)
	require(t, err)
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, err)
	partition := time.Now().UTC().Format("2006-01-02")
	index := sharedEventIndex(t, "alerts", partition)
	require(t, es.EnsureIndex(ctx, index, partition))
	t.Cleanup(func() { deleteTenantEvents(t, es, name) })
	wake := &control.Wakeup{}
	config := func() *platform.API { return &platform.API{DB: db.Runtime, ES: es, Signer: signer, Wakeup: wake} }
	client := authenticatedFaultHTTP(t, ctx, db.Runtime, config(), name, password)
	peer := authenticatedFaultHTTP(t, ctx, db.Runtime, config(), other, password)
	viewer := authenticatedFaultHTTP(t, ctx, db.Runtime, config(), name+"_viewer", password)
	id := transport.SensorIdentity{TenantID: name, SensorID: gatewayTestSensor, RegistrationID: gatewayTestRegistration}
	_, err = db.Owner.Pool.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id,active) VALUES($1,$2,'受控网关',$3,true)`,
		id.TenantID, id.SensorID, id.RegistrationID)
	require(t, err)
	return &gatewayFixture{t: t, ctx: ctx, db: db, user: user, id: id, es: es, index: index, client: client,
		peer: peer, viewer: viewer, signer: signer, wake: wake, scope: scope}
}

type gatewayControlFixture struct{ address, root, cert, key string }

func startGatewayControl(t *testing.T, f *gatewayFixture, dir string) gatewayControlFixture {
	t.Helper()
	pki, probe := filepath.Join(dir, "pki"), filepath.Join(dir, "probe")
	require(t, admin.DevPKI(pki, nil))
	id, err := admin.Provision(f.ctx, f.db.Owner, f.user.TenantID, "gateway_authenticated", "双向认证验收网关", pki, probe)
	require(t, err)
	f.id = id
	root := filepath.Join(pki, "ca.crt")
	tls, err := transport.TLS(root, filepath.Join(pki, "server.crt"), filepath.Join(pki, "server.key"), true)
	require(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require(t, err)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tls)))
	sensorv1.RegisterSensorServiceServer(server, &ingest.Server{DB: f.db.Runtime, ControlOnly: true,
		TasksEnabled: true, GatewaySigner: f.signer, Wakeup: f.wake})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return gatewayControlFixture{listener.Addr().String(), root, filepath.Join(probe, "agent.crt"), filepath.Join(probe, "agent.key")}
}

func (f *gatewayFixture) startAgent(dir string, link gatewayControlFixture, local gatewayblock.LocalConfig) {
	f.t.Helper()
	raw, err := x509.MarshalPKIXPublicKey(f.signer.Public().(ed25519.PublicKey))
	require(f.t, err)
	pub, eve, gatewayPath := filepath.Join(dir, "signer.pub"), filepath.Join(dir, "eve.json"), filepath.Join(dir, "gateway.json")
	require(f.t, os.WriteFile(pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: raw}), 0600))
	require(f.t, os.WriteFile(eve, nil, 0600))
	raw, err = json.Marshal(local)
	require(f.t, err)
	require(f.t, os.WriteFile(gatewayPath, raw, 0600))
	cfg := config.Config{Mode: "development", HTTPAddr: "127.0.0.1:0", AllowedOrigin: "http://127.0.0.1",
		TenantID: f.id.TenantID, SensorID: f.id.SensorID, RegistrationID: f.id.RegistrationID, TLSCA: link.root,
		TLSCert: link.cert, TLSKey: link.key, CommandPublicKey: pub,
		LocalPassword: store.Token(), CookieName: "gateway_local_session", StatePath: filepath.Join(dir, "agent.db"), EVEPath: eve,
		IngestAddr: link.address, PlatformAddr: link.address, WALBytes: 8 << 20,
		HeartbeatInterval: time.Second, ReplayDir: filepath.Join(dir, "replay"), ReplayBytes: 100 << 20,
		ReplayRetentionDays: 180, TaskRetentionDays: 180, GatewayBlockFile: gatewayPath}
	runCtx, stop := context.WithCancel(f.ctx)
	done := make(chan error, 1)
	go func() { done <- agent.Run(runCtx, cfg) }()
	f.t.Cleanup(func() { stop(); require(f.t, <-done) })
}

func (f *gatewayFixture) settings(enabled bool, perMinute int) gatewayblock.SettingsChange {
	f.t.Helper()
	input := gatewayblock.SettingsChange{ExpectedRevision: f.currentSettings.Revision, Enabled: enabled, PerMinute: perMinute}
	f.client.request("PUT", "/gateway-block/settings", "", input, &f.currentSettings, 200)
	return input
}

func (f *gatewayFixture) policies(seconds int) (gatewayblock.PolicyChange, gatewayblock.PolicyChange) {
	f.t.Helper()
	d := gatewayblock.Definition{Name: "实验网关授权", Enabled: true, Trigger: gatewayblock.Rule,
		SensorID: f.id.SensorID, RegistrationID: f.id.RegistrationID, RuleID: "1003340", RuleRevision: "1",
		Scope: f.scope, LeaseSeconds: seconds, ValidUntil: time.Now().UTC().Add(time.Hour)}
	rule := gatewayblock.PolicyChange{Definition: d}
	var saved gatewayblock.Policy
	f.client.request("PUT", "/gateway-block/policies/"+testRulePolicy, "", rule, &saved, 200)
	if saved.Revision != 1 || saved.AuthorID != f.user.ID {
		f.t.Fatal("策略缺少授权人与修订", saved)
	}
	d.Trigger, d.RuleID = gatewayblock.Review, "1003341"
	review := gatewayblock.PolicyChange{Definition: d}
	f.client.request("PUT", "/gateway-block/policies/"+testReviewPolicy, "", review, nil, 200)
	return rule, review
}

func (f *gatewayFixture) heartbeat(health *gatewayblock.Health) {
	f.t.Helper()
	require(f.t, f.db.Runtime.Heartbeat(f.ctx, f.id, model.HostHealth{ObservedAt: time.Now().UTC(),
		CommandSignerSHA256: control.Digest(f.signer.Public().(ed25519.PublicKey)), GatewayBlock: health}))
}

func (f *gatewayFixture) observe(rule, source, dest string, port uint16) model.Alert {
	now := time.Now().UTC()
	a := model.Alert{SchemaVersion: "1.0", TenantID: f.id.TenantID, SensorID: f.id.SensorID, RegistrationID: f.id.RegistrationID,
		EventID: store.Hash(store.Token()), RawSHA256: store.Hash(store.Token()), Timestamp: now, ObservedAt: now, ReceivedAt: now,
		Source: model.Endpoint{IP: source, Port: port}, Destination: model.Endpoint{IP: dest, Port: 8080}, Severity: "high"}
	a.Event.Kind, a.Event.Dataset = "alert", "suricata.eve"
	a.Rule.ID, a.Rule.Revision, a.Suricata.FlowID = rule, "1", "420033"
	a.Network.Transport = "tcp"
	return a
}

func (f *gatewayFixture) indexAlerts(items ...model.Alert) {
	f.t.Helper()
	for _, err := range f.es.Bulk(f.ctx, f.index, items) {
		require(f.t, err)
	}
	f.refreshAlerts()
}

func (f *gatewayFixture) refreshAlerts() {
	f.t.Helper()
	resp, err := f.es.API.Indices.Refresh(f.es.API.Indices.Refresh.WithIndex(f.index), f.es.API.Indices.Refresh.WithContext(f.ctx))
	require(f.t, err)
	defer resp.Body.Close()
	if resp.IsError() {
		f.t.Fatal("实际告警索引刷新失败", resp.Status())
	}
}

func (f *gatewayFixture) indexer() *worker.Indexer {
	f.t.Helper()
	queue, err := bus.OpenNamespace(f.ctx, os.Getenv("SB_NATS_URL"), store.RandomID("it_gateway_"))
	require(f.t, err)
	f.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		defer queue.Close()
		for _, stream := range []string{bus.Alerts, bus.Context, bus.Logs, bus.Quarantine, bus.Indexed} {
			require(f.t, queue.JS.DeleteStream(ctx, queue.StreamName(stream)))
		}
	})
	require(f.t, queue.Ensure(f.ctx, 1, 16<<20))
	return &worker.Indexer{DB: f.db.Runtime, ES: f.es, Bus: queue}
}

// 编码流量夹具的指定观测，使用实际索引器的原生告警契约。
func (f *gatewayFixture) envelope(a model.Alert) (model.Alert, []byte) {
	f.t.Helper()
	raw, err := json.Marshal(map[string]any{
		"timestamp": a.Timestamp, "event_type": "alert", "flow_id": json.Number(a.Suricata.FlowID),
		"src_ip": a.Source.IP, "src_port": a.Source.Port, "dest_ip": a.Destination.IP, "dest_port": a.Destination.Port,
		"proto": a.Network.Transport, "alert": map[string]any{"signature_id": json.Number(a.Rule.ID), "rev": json.Number(a.Rule.Revision), "severity": 1},
	})
	require(f.t, err)
	digest := sha256.Sum256(raw)
	generation := store.RandomID("gateway_generation_")
	record := &sensorv1.EventRecord{EventId: contract.EventID(a.TenantID, a.RegistrationID, generation, 0, 0),
		SourceGenerationId: generation, Sequence: 1, Payload: raw, PayloadSha256: digest[:], RawSha256: digest[:],
		PayloadSchema: "suricata.eve.v1", ContentType: "application/json", EventType: "alert",
		EventTime: timestamppb.New(a.Timestamp), ObservedAt: timestamppb.New(a.ObservedAt)}
	batch := &sensorv1.EventBatch{SensorId: a.SensorID, SensorRegistrationId: a.RegistrationID, StreamId: "alerts",
		ProducerEpoch: "epoch_gateway", SchemaVersion: "1.0", RouteToken: "owned-route", Records: []*sensorv1.EventRecord{record}}
	contract.Seal(batch)
	encoded, err := proto.Marshal(batch)
	require(f.t, err)
	envelope, err := json.Marshal(bus.Envelope{TenantID: a.TenantID, Batch: encoded, Partition: a.ReceivedAt.Format("2006-01-02"),
		Index: f.index, ReceivedAt: a.ReceivedAt})
	require(f.t, err)
	alert, err := normalize.Normalize(a.TenantID, a.SensorID, a.RegistrationID, record, a.ReceivedAt)
	require(f.t, err)
	return alert, envelope
}

func (f *gatewayFixture) gatewayRecord(event string) gatewayblock.Request {
	f.t.Helper()
	id := "gateway_" + store.Hash(f.id.TenantID + "/" + event)[:40]
	var result gatewayblock.Request
	f.client.request("GET", "/gateway-block/requests/"+id, "", nil, &result, 200)
	return result
}

func (f *gatewayFixture) assessment(a model.Alert, revision int64, verdict string) gatewayblock.ReviewRequest {
	f.t.Helper()
	review := assessment.Change{ExpectedRevision: revision, Spec: assessment.Spec{Status: "investigating",
		Verdict: verdict, Outcome: "unknown", Note: "验收确认业务连接", Evidence: []string{}}}
	f.client.request("POST", "/alerts/"+a.EventID+"/assessment?sha256="+a.RawSHA256, store.RandomID("gateway_assessment_"), review, nil, 200)
	return gatewayblock.ReviewRequest{PolicyID: testReviewPolicy, PolicyRevision: 1, AssessmentRevision: revision + 1, RawSHA256: a.RawSHA256}
}

func (f *gatewayFixture) next() *store.TaskDelivery {
	f.t.Helper()
	delivery, err := f.db.Runtime.NextGatewayBlock(f.ctx, f.id, f.signer)
	require(f.t, err)
	return delivery
}

func (f *gatewayFixture) blocked(event, code string) {
	f.t.Helper()
	if d := f.next(); d != nil {
		f.t.Fatal("拒绝场景签发了阻断任务", code, d.ID)
	}
	if result := f.gatewayRecord(event); result.State != "denied" || result.Code != code || result.TaskID != "" {
		f.t.Fatal("拒绝原因未落盘", result)
	}
}

func (f *gatewayFixture) command(d *store.TaskDelivery, trigger string) (control.Command, gatewayblock.Action) {
	f.t.Helper()
	if d == nil {
		f.t.Fatal("没有签发网关任务")
	}
	command, err := control.Decode(d.Command, d.Signature, f.signer.Public().(ed25519.PublicKey),
		f.id.TenantID, f.id.SensorID, f.id.RegistrationID, time.Now().UTC())
	require(f.t, err)
	action, err := gatewayblock.ReadAction(command.Payload, command.IssuedAt, command.ExpiresAt)
	require(f.t, err)
	if command.Kind != gatewayblock.CommandKind || action.Trigger != trigger {
		f.t.Fatal("签发命令或触发方式不对应", command.Kind, action)
	}
	return command, action
}

func (f *gatewayFixture) receipt(d *store.TaskDelivery, result gatewayblock.Result, verifyFailure bool) {
	f.t.Helper()
	raw, err := json.Marshal(result)
	require(f.t, err)
	finish := time.Now().UTC()
	r := control.Receipt{CommandID: d.ID, CommandSHA256: control.Digest(d.Command), State: "succeeded",
		StartedAt: result.VerifiedAt, FinishedAt: &finish, Result: raw}
	if verifyFailure {
		badCode := r
		badCode.Code = "unknown_result"
		if err := f.db.Runtime.SaveReceipt(f.ctx, f.id, badCode); !errors.Is(err, gatewayblock.ErrUnknown) {
			f.t.Fatal("接受含失败状态码的成功回执", err)
		}
		wrong := result
		wrong.Flow.DestinationPort++
		r.Result, err = json.Marshal(wrong)
		require(f.t, err)
		if err := f.db.Runtime.SaveReceipt(f.ctx, f.id, r); !errors.Is(err, gatewayblock.ErrUnknown) {
			f.t.Fatal("接受不同连接的回执", err)
		}
		r.Result = raw
	}
	require(f.t, f.db.Runtime.SaveReceipt(f.ctx, f.id, r))
	task, err := f.db.Runtime.Task(f.ctx, f.id.TenantID, d.ID)
	require(f.t, err)
	if task.State != "succeeded" {
		f.t.Fatal("回执未登记", task)
	}
}

func TestGatewayBlockHTTPPolicyAndSharedBudgetProtectBothEndpoints(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	scope := gatewayblock.Scope{Sources: []netip.Prefix{netip.MustParsePrefix("10.203.35.0/24")},
		Destinations: []netip.Prefix{netip.MustParsePrefix("10.203.36.0/24")}}
	f := newGatewayFixture(t, ctx, scope)
	var disabled gatewayblock.Settings
	f.client.request("GET", "/gateway-block/settings", "", nil, &disabled, 200)
	if disabled.Enabled || disabled.Revision != 0 || disabled.PerMinute != gatewayblock.DefaultPerMinute {
		t.Fatal("租户默认启用了阻断", disabled)
	}
	rule, _ := f.policies(20)
	change := f.settings(true, 2)
	f.client.request("PUT", "/gateway-block/settings", "", change, nil, 200)
	change.PerMinute++
	f.client.request("PUT", "/gateway-block/settings", "", change, nil, 409)
	f.client.request("PUT", "/gateway-block/policies/"+testRulePolicy, "", rule, nil, 200)
	edit := rule
	edit.Definition.LeaseSeconds++
	f.client.request("PUT", "/gateway-block/policies/"+testRulePolicy, "", edit, nil, 409)
	var policies gatewayblock.PolicyPage
	f.client.request("GET", "/gateway-block/policies?limit=10", "", nil, &policies, 200)
	if len(policies.Items) != 2 || policies.NextCursor != "" {
		t.Fatal("策略目录与保存内容不一致", policies)
	}
	f.peer.request("GET", "/gateway-block/policies", "", nil, &policies, 200)
	if len(policies.Items) != 0 {
		t.Fatal("其他租户读取网关策略")
	}
	inactive := rule
	inactive.Definition.Enabled = false
	for i := range 9 {
		f.client.request("PUT", "/gateway-block/policies/catalog_extra_"+strconv.Itoa(i), "", inactive, nil, 200)
	}
	var firstPage, secondPage gatewayblock.PolicyPage
	f.client.request("GET", "/gateway-block/policies?limit=10", "", nil, &firstPage, 200)
	if len(firstPage.Items) != 10 || firstPage.NextCursor != firstPage.Items[9].ID {
		t.Fatal("策略目录缺少下一页游标", firstPage)
	}
	f.client.request("GET", "/gateway-block/policies?limit=10&cursor="+firstPage.NextCursor, "", nil, &secondPage, 200)
	if len(secondPage.Items) != 1 || secondPage.Items[0].ID == firstPage.NextCursor || secondPage.NextCursor != "" {
		t.Fatal("策略目录分页重叠或遗漏", firstPage, secondPage)
	}
	for _, path := range []string{"/gateway-block/settings", "/gateway-block/policies"} {
		f.viewer.request("GET", path, "", nil, nil, 403)
	}
	f.viewer.request("PUT", "/gateway-block/settings", "", gatewayblock.SettingsChange{ExpectedRevision: f.currentSettings.Revision, Enabled: false, PerMinute: 2}, nil, 403)
	const source, destination = "10.203.35.3", "10.203.36.3"
	const protectedSource, protectedDestination = "10.203.35.7", "10.203.36.7"
	for i, value := range []string{protectedSource, protectedDestination} {
		list := watchlistInput([]string{"gateway_source_protect", "gateway_destination_protect"}[i])
		list.Definition.Sensors = []watchlist.Sensor{{SensorID: f.id.SensorID, RegistrationID: f.id.RegistrationID}}
		list.Definition.Values = []string{value}
		f.client.request("POST", "/watchlists", list.ID, list, nil, 200)
	}
	health := (gatewayblock.LocalConfig{Enabled: true, Scope: scope}).Binding()
	f.heartbeat(&health)
	for _, pair := range [][2]string{{protectedSource, destination}, {source, protectedDestination}} {
		a := f.observe("1003340", pair[0], pair[1], 41005)
		require(t, f.db.Runtime.RecordGatewayBlockMatches(ctx, f.id.TenantID, []model.Alert{a}))
		f.blocked(a.EventID, "protected_endpoint")
	}
	a := f.observe("1003340", source, destination, 42100)
	require(t, f.db.Runtime.RecordGatewayBlockMatches(ctx, f.id.TenantID, []model.Alert{a, a}))
	require(t, f.db.Runtime.RecordGatewayBlockMatches(ctx, f.id.TenantID, []model.Alert{a}))
	f.heartbeat(nil)
	if f.next() != nil || f.gatewayRecord(a.EventID).State != "pending" {
		t.Fatal("本地未就绪仍获签发")
	}
	f.heartbeat(&health)
	var parallel sync.WaitGroup
	writes := make(chan *store.TaskDelivery, 2)
	for range 2 {
		parallel.Go(func() {
			d, err := f.db.Runtime.NextGatewayBlock(ctx, f.id, f.signer)
			if err != nil {
				t.Error(err)
			}
			if d != nil {
				writes <- d
			}
		})
	}
	parallel.Wait()
	close(writes)
	d := <-writes
	if <-writes != nil {
		t.Fatal("同一连接重复签发")
	}
	_, action := f.command(d, gatewayblock.Rule)
	f.receipt(d, gatewayblock.Result{RequestID: action.RequestID, ConfigSHA256: action.ConfigSHA256,
		Flow: action.Flow, LeaseUntil: action.LeaseUntil, VerifiedAt: time.Now().UTC()}, true)
	repeated := f.observe("1003340", source, destination, 42100)
	require(t, f.db.Runtime.RecordGatewayBlockMatches(ctx, f.id.TenantID, []model.Alert{repeated}))
	f.blocked(repeated.EventID, "active_flow_lease")

	b := f.observe("1003341", source, destination, 42101)
	f.indexAlerts(b)
	path := "/alerts/" + b.EventID + "/gateway-blocks"
	request := gatewayblock.ReviewRequest{PolicyID: testReviewPolicy, PolicyRevision: 1, AssessmentRevision: 1, RawSHA256: b.RawSHA256}
	f.client.request("POST", path, "missing_assessment", request, nil, 409)
	request = f.assessment(b, 0, "confirmed")
	wrongPolicy := request
	wrongPolicy.PolicyID = "unknown_gateway_policy"
	f.client.request("POST", path, "no_such_policy", wrongPolicy, nil, 404)
	wrongPolicy.PolicyID = testRulePolicy
	f.client.request("POST", path, "incorrect_trigger", wrongPolicy, nil, 409)
	wrongPolicy = request
	wrongPolicy.RawSHA256 = store.Hash(store.Token())
	f.client.request("POST", path, "different_raw_observation", wrongPolicy, nil, 409)
	var first, replayed gatewayblock.Request
	f.client.request("POST", path, "approved_gateway_observation", request, &first, 202)
	f.client.request("POST", path, "approved_gateway_observation", request, &replayed, 202)
	if first.State != "pending" || first.ID != replayed.ID || first.EventID != b.EventID {
		t.Fatal("研判后的签发缺少原请求绑定", first, replayed)
	}
	wrong := request
	wrong.AssessmentRevision++
	f.client.request("POST", path, "approved_gateway_observation", wrong, nil, 409)
	f.client.request("POST", path, "another_review_key", request, nil, 409)
	f.viewer.request("POST", path, "viewer_gateway_observation", request, nil, 403)
	f.peer.request("POST", path, "peer_gateway_observation", request, nil, 404)
	f.peer.request("GET", "/gateway-block/requests/"+first.ID, "", nil, nil, 404)
	_, err := f.db.Owner.Pool.Exec(ctx, `REVOKE SELECT ON alert_assessments FROM starbeacon_app`)
	require(t, err)
	if d, err := f.db.Runtime.NextGatewayBlock(ctx, f.id, f.signer); err == nil || d != nil {
		t.Fatal("缺少研判复核时仍签发命令", d, err)
	}
	_, err = f.db.Owner.Pool.Exec(ctx, `GRANT SELECT ON alert_assessments TO starbeacon_app`)
	require(t, err)
	d = f.next()
	_, action = f.command(d, gatewayblock.Review)
	f.receipt(d, gatewayblock.Result{RequestID: action.RequestID, ConfigSHA256: action.ConfigSHA256,
		Flow: action.Flow, LeaseUntil: action.LeaseUntil, VerifiedAt: time.Now().UTC()}, false)
	c := f.observe("1003340", source, destination, 42102)
	require(t, f.db.Runtime.RecordGatewayBlockMatches(ctx, f.id.TenantID, []model.Alert{c}))
	f.blocked(c.EventID, "rate_limited")
}

func TestGatewayBlockDispatchRechecksFreshnessPolicyAndReview(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	scope := gatewayblock.Scope{Sources: []netip.Prefix{netip.MustParsePrefix("10.203.35.0/24")},
		Destinations: []netip.Prefix{netip.MustParsePrefix("10.203.36.0/24")}}
	f := newGatewayFixture(t, ctx, scope)
	rule, _ := f.policies(20)
	makeRuleAlert := func() model.Alert { return f.observe("1003340", "10.203.35.3", "10.203.36.3", 41015) }
	a := makeRuleAlert()
	require(t, f.db.Runtime.RecordGatewayBlockMatches(ctx, f.id.TenantID, []model.Alert{a}))
	f.client.request("GET", "/gateway-block/requests/gateway_"+store.Hash(f.id.TenantID + "/" + a.EventID)[:40], "", nil, nil, 404)
	f.settings(true, 10)
	health := (gatewayblock.LocalConfig{Enabled: true, Scope: scope}).Binding()
	f.heartbeat(&health)
	invalid := makeRuleAlert()
	invalid.Suricata.FlowID = ""
	stale := makeRuleAlert()
	stale.Timestamp = stale.Timestamp.Add(-time.Hour)
	require(t, f.db.Runtime.RecordGatewayBlockMatches(ctx, f.id.TenantID, []model.Alert{a, stale, invalid}))
	if f.next() != nil {
		t.Fatal("历史或非原生连接获签发")
	}
	b := makeRuleAlert()
	require(t, f.db.Runtime.RecordGatewayBlockMatches(ctx, f.id.TenantID, []model.Alert{b}))
	f.settings(false, 10)
	f.blocked(b.EventID, "gateway_block_disabled")
	f.settings(true, 10)
	c := makeRuleAlert()
	require(t, f.db.Runtime.RecordGatewayBlockMatches(ctx, f.id.TenantID, []model.Alert{c}))
	rule.ExpectedRevision, rule.Definition.LeaseSeconds = 1, 19
	f.client.request("PUT", "/gateway-block/policies/"+testRulePolicy, "", rule, nil, 200)
	f.blocked(c.EventID, "policy_changed")
	d := f.observe("1003341", "10.203.35.3", "10.203.36.3", 41018)
	f.indexAlerts(d)
	request := f.assessment(d, 0, "confirmed")
	f.client.request("POST", "/alerts/"+d.EventID+"/gateway-blocks", "review_changed_key", request, nil, 202)
	f.assessment(d, 1, "false_positive")
	f.blocked(d.EventID, "assessment_changed")
	e := makeRuleAlert()
	require(t, f.db.Runtime.RecordGatewayBlockMatches(ctx, f.id.TenantID, []model.Alert{e}))
	if _, err := f.db.Runtime.CreateTask(ctx, f.user, f.id.SensorID, gatewayblock.CommandKind, "bypass_authorization", json.RawMessage("{}"), f.signer); !errors.Is(err, gatewayblock.ErrPermission) {
		t.Fatal("通用任务入口能绕开网关授权", err)
	}
	require(t, f.db.Owner.TenantTx(ctx, f.id.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE gateway_block_requests SET deadline=now()-interval '1 second' WHERE tenant_id=$1 AND event_id=$2`, f.id.TenantID, e.EventID)
		return err
	}))
	f.blocked(e.EventID, "observation_expired")
}

func TestGatewayBlockControlRequiresLiveBindingAndAtomicAudit(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	scope := gatewayblock.Scope{Sources: []netip.Prefix{netip.MustParsePrefix("10.203.35.0/24")},
		Destinations: []netip.Prefix{netip.MustParsePrefix("10.203.36.0/24")}}
	f := newGatewayFixture(t, ctx, scope)
	link := startGatewayControl(t, f, t.TempDir())
	rule, _ := f.policies(20)
	f.settings(true, 2)
	health := (gatewayblock.LocalConfig{Enabled: true, Scope: scope}).Binding()
	f.heartbeat(&health)
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := f.db.Owner.Pool.Exec(ctx, sql, args...)
		require(t, err)
	}
	observe := func(port uint16) model.Alert {
		t.Helper()
		a := f.observe("1003340", "10.203.35.3", "10.203.36.3", port)
		require(t, f.db.Runtime.RecordGatewayBlockMatches(ctx, f.id.TenantID, []model.Alert{a}))
		return a
	}
	// 活动账号和原始授权必须在签发时仍然有效。
	a := observe(42400)
	exec(`UPDATE users SET active=false WHERE tenant_id=$1 AND id=$2`, f.id.TenantID, f.user.ID)
	if f.next() != nil {
		t.Fatal("已撤销账号的策略仍可签发")
	}
	exec(`UPDATE users SET active=true WHERE tenant_id=$1 AND id=$2`, f.id.TenantID, f.user.ID)
	if row := f.gatewayRecord(a.EventID); row.State != "denied" || row.Code != "authorization_revoked" {
		t.Fatal("撤销后的拒绝原因未保存", row)
	}
	// 模拟仅限验收库的写入故障。审计、预算和待交付任务应一起回滚。
	b := observe(42401)
	exec(`REVOKE INSERT ON operation_audits FROM starbeacon_app`)
	if d, err := f.db.Runtime.NextGatewayBlock(ctx, f.id, f.signer); err == nil || d != nil {
		t.Fatal("审计不可写仍签发任务", d, err)
	}
	var issued int
	require(t, f.db.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM sensor_tasks WHERE tenant_id=$1`, f.id.TenantID).Scan(&issued))
	if row := f.gatewayRecord(b.EventID); issued != 0 || row.State != "pending" || row.TaskID != "" || row.AuthorizedAt != nil {
		t.Fatal("审计失败留下交付任务或消费预算", issued, row)
	}
	last := f.currentSettings
	f.client.request("PUT", "/gateway-block/settings", "", gatewayblock.SettingsChange{ExpectedRevision: last.Revision, Enabled: false, PerMinute: 2}, nil, 503)
	f.client.request("GET", "/gateway-block/settings", "", nil, &f.currentSettings, 200)
	if f.currentSettings.Revision != last.Revision || f.currentSettings.Enabled != last.Enabled {
		t.Fatal("配置修改绕过不可用的操作审计")
	}
	rule.ExpectedRevision, rule.Definition.LeaseSeconds = 1, 21
	f.client.request("PUT", "/gateway-block/policies/"+testRulePolicy, "", rule, nil, 503)
	exec(`GRANT INSERT ON operation_audits TO starbeacon_app`)
	_, wrongSigner, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	if d, err := f.db.Runtime.NextGatewayBlock(ctx, f.id, wrongSigner); err != nil || d != nil {
		t.Fatal("非采集器绑定的签名密钥获准签发", d, err)
	}
	_, err = f.db.Runtime.NextGatewayBlock(ctx, f.id, nil)
	if !errors.Is(err, gatewayblock.ErrInput) {
		t.Fatal("缺少签名密钥未被拒绝", err)
	}
	// 读取策略失败时保留同一待处理请求，恢复后重新核对授权。
	exec(`REVOKE SELECT ON gateway_block_policies FROM starbeacon_app`)
	if d, err := f.db.Runtime.NextGatewayBlock(ctx, f.id, f.signer); err == nil || d != nil {
		t.Fatal("策略无法读取仍可签发", d, err)
	}
	f.client.request("GET", "/gateway-block/policies", "", nil, nil, 503)
	f.client.request("PUT", "/gateway-block/policies/"+testRulePolicy, "", rule, nil, 503)
	exec(`GRANT SELECT ON gateway_block_policies TO starbeacon_app`)
	removed := rule
	removed.ExpectedRevision, removed.Definition.RegistrationID = 0, "gateway_not_installed"
	f.client.request("PUT", "/gateway-block/policies/nonexistent_registration", "", removed, nil, 409)
	exec(`REVOKE SELECT ON watchlists FROM starbeacon_app`)
	if d, err := f.db.Runtime.NextGatewayBlock(ctx, f.id, f.signer); err == nil || d != nil {
		t.Fatal("保护名单不可读时仍签发命令", d, err)
	}
	exec(`GRANT SELECT ON watchlists TO starbeacon_app`)
	exec(`REVOKE SELECT ON gateway_block_settings FROM starbeacon_app`)
	if d, err := f.db.Runtime.NextGatewayBlock(ctx, f.id, f.signer); err == nil || d != nil {
		t.Fatal("无法核对租户开关时仍签发命令", d, err)
	}
	f.client.request("GET", "/gateway-block/settings", "", nil, nil, 503)
	f.client.request("PUT", "/gateway-block/settings", "", gatewayblock.SettingsChange{ExpectedRevision: last.Revision, Enabled: false, PerMinute: 2}, nil, 503)
	exec(`GRANT SELECT ON gateway_block_settings TO starbeacon_app`)

	tls, err := transport.TLS(link.root, link.cert, link.key, false)
	require(t, err)
	conn, err := grpc.NewClient(link.address, grpc.WithTransportCredentials(credentials.NewTLS(tls)))
	require(t, err)
	defer conn.Close()
	client := sensorv1.NewSensorServiceClient(conn)
	message := func(binding *gatewayblock.Health) *sensorv1.AgentMessage {
		t.Helper()
		raw, err := json.Marshal(model.HostHealth{ObservedAt: time.Now().UTC(), GatewayBlock: binding,
			CommandSignerSHA256: control.Digest(f.signer.Public().(ed25519.PublicKey))})
		require(t, err)
		return &sensorv1.AgentMessage{SensorId: f.id.SensorID, SensorRegistrationId: f.id.RegistrationID,
			Kind: sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_HEARTBEAT, MessageId: store.RandomID("hb_gateway_"),
			PayloadSchema: "host.health.v1", PayloadJson: raw}
	}
	call, stop := context.WithTimeout(ctx, 12*time.Second)
	defer stop()
	invalid, err := client.Control(call)
	require(t, err)
	require(t, invalid.Send(message(&gatewayblock.Health{ConfigSHA256: "not-a-digest"})))
	if _, err = invalid.Recv(); status.Code(err) != codes.InvalidArgument {
		t.Fatal("控制流接受不合法的网关绑定", err)
	}
	stream, err := client.Control(call)
	require(t, err)
	ack := func(binding *gatewayblock.Health) {
		t.Helper()
		m := message(binding)
		require(t, stream.Send(m))
		r, err := stream.Recv()
		require(t, err)
		if r.GetKind() != sensorv1.CommandKind_COMMAND_KIND_HEARTBEAT_ACK || r.GetCommandId() != m.MessageId {
			t.Fatal("双向认证健康消息没有确认", r.GetKind())
		}
	}
	ack(&health)
	f.wake.Notify(f.id.TenantID, f.id.SensorID)
	native, err := stream.Recv()
	require(t, err)
	if native.GetKind() != sensorv1.CommandKind_COMMAND_KIND_TASK || native.GetPayloadSchema() != control.Schema {
		t.Fatal("待处理请求没有通过实际双向认证控制流签发", native.GetKind())
	}
	d := &store.TaskDelivery{ID: native.GetCommandId(), Command: native.GetPayloadJson(), Signature: native.GetSignature()}
	_, action := f.command(d, gatewayblock.Rule)
	if action.EventID != b.EventID || action.ConfigSHA256 != health.ConfigSHA256 {
		t.Fatal("重试任务未沿用原有观测和本地授权绑定", action.EventID)
	}
	f.receipt(d, gatewayblock.Result{RequestID: action.RequestID, ConfigSHA256: action.ConfigSHA256,
		Flow: action.Flow, LeaseUntil: action.LeaseUntil, VerifiedAt: time.Now().UTC()}, false)
	ack(nil)
	c := observe(42402)
	stop()
	started := time.Now()
	f.startAgent(t.TempDir(), link, gatewayblock.LocalConfig{Scope: scope})
	eventually(t, ctx, "实采进程汇报本地开关关闭", func() bool {
		sensors, err := f.db.Runtime.Sensors(ctx, f.id.TenantID)
		require(t, err)
		for _, sensor := range sensors {
			var h model.HostHealth
			if sensor.ID == f.id.SensorID && json.Unmarshal(sensor.Health, &h) == nil && h.ObservedAt.After(started) && h.GatewayBlock == nil {
				return true
			}
		}
		return false
	})
	if f.next() != nil || f.gatewayRecord(c.EventID).State != "pending" {
		t.Fatal("网关撤销本地能力后平台仍可签发")
	}
}

func TestGatewayBlockBoundsCandidateQueueAndConfigurationCatalog(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	scope := gatewayblock.Scope{Sources: []netip.Prefix{netip.MustParsePrefix("10.203.35.0/24")},
		Destinations: []netip.Prefix{netip.MustParsePrefix("10.203.36.0/24")}}
	f := newGatewayFixture(t, ctx, scope)
	rule, _ := f.policies(20)
	f.settings(true, 2)
	indexer := f.indexer()
	first, encoded := f.envelope(f.observe("1003340", "10.203.35.3", "10.203.36.3", 42999))
	exec := func(sql string) {
		t.Helper()
		_, err := f.db.Owner.Pool.Exec(ctx, sql)
		require(t, err)
	}
	exec(`REVOKE INSERT ON gateway_block_requests FROM starbeacon_app`)
	if err := indexer.Process(ctx, encoded); err == nil {
		t.Fatal("网关候选请求未持久化时索引器确认了告警")
	}
	exec(`GRANT INSERT ON gateway_block_requests TO starbeacon_app`)
	require(t, indexer.Process(ctx, encoded))
	require(t, indexer.Process(ctx, encoded))
	if row := f.gatewayRecord(first.EventID); row.State != "pending" || row.RawSHA256 != first.RawSHA256 {
		t.Fatal("索引重投未登记原始观测与摘要", row)
	}
	// 已损坏的策略不会触发阻断，也不会丢掉正常索引链路的告警通知。
	_, err := f.db.Owner.Pool.Exec(ctx, `UPDATE gateway_block_policies SET definition=definition-'sensor_id' WHERE tenant_id=$1 AND id=$2`, f.id.TenantID, testRulePolicy)
	require(t, err)
	corrupt, encoded := f.envelope(f.observe("1003340", "10.203.35.3", "10.203.36.3", 42998))
	require(t, indexer.Process(ctx, encoded))
	f.client.request("GET", "/gateway-block/requests/gateway_"+store.Hash(f.id.TenantID + "/" + corrupt.EventID)[:40], "", nil, nil, 404)
	_, err = f.db.Owner.Pool.Exec(ctx, `UPDATE gateway_block_policies SET definition=jsonb_set(definition,'{sensor_id}',to_jsonb($3::text)) WHERE tenant_id=$1 AND id=$2`,
		f.id.TenantID, testRulePolicy, f.id.SensorID)
	require(t, err)
	// 两套独立限制保护待核对连接和目录容量。数据库操作限定在当前验收库。
	alerts := make([]model.Alert, 130)
	for i := range alerts {
		alerts[i] = f.observe("1003340", "10.203.35.3", "10.203.36.3", uint16(43000+i))
	}
	require(t, f.db.Runtime.RecordGatewayBlockMatches(ctx, f.id.TenantID, alerts))
	var count int
	require(t, f.db.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM gateway_block_requests WHERE tenant_id=$1 AND state='pending'`, f.id.TenantID).Scan(&count))
	if count != 128 {
		t.Fatal("即时触发队列没有遵守有限容量", count)
	}
	reviewAlert := f.observe("1003341", "10.203.35.3", "10.203.36.3", 43200)
	f.indexAlerts(reviewAlert)
	review := f.assessment(reviewAlert, 0, "confirmed")
	f.client.request("POST", "/alerts/"+reviewAlert.EventID+"/gateway-blocks", "queue_full_review", review, nil, 429)
	// 批量装载同等权限的停用策略，核对上限两侧都能正确处理。
	rule.Definition.Enabled = false
	definition, err := json.Marshal(rule.Definition)
	require(t, err)
	_, err = f.db.Owner.Pool.Exec(ctx, `INSERT INTO gateway_block_policies(tenant_id,id,revision,definition,author_id)
		SELECT $1,'disabled_policy_'||n,1,$2,$3 FROM generate_series(1,$4::int) AS n`,
		f.id.TenantID, definition, f.user.ID, gatewayblock.MaxPolicies-3)
	require(t, err)
	f.client.request("PUT", "/gateway-block/policies/catalog_last", "", rule, nil, 200)
	f.client.request("PUT", "/gateway-block/policies/catalog_overflow", "", rule, nil, 429)
	rule.ExpectedRevision, rule.Definition.Name = 1, "最后一项保留可编辑"
	f.client.request("PUT", "/gateway-block/policies/catalog_last", "", rule, nil, 200)
}
