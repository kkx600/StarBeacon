//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/application"
	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
	"github.com/kkx600/StarBeacon/internal/worker"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func verifyApplicationIndexingSupplementIsolation(t *testing.T, ctx context.Context, db *store.Postgres, identity transport.SensorIdentity, matcher *application.Matcher, deployment string) {
	t.Helper()
	queue, err := bus.OpenNamespace(ctx, os.Getenv("SB_NATS_URL"), store.RandomID("it_app_"))
	require(t, err)
	defer queue.Close()
	require(t, queue.Ensure(ctx, 1, 16<<20))
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, stream := range []string{bus.Alerts, bus.Context, bus.Logs, bus.Quarantine, bus.Indexed} {
			require(t, queue.JS.DeleteStream(cleanup, queue.StreamName(stream)))
		}
	}()
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), "")
	require(t, err)
	index, err := contract.IndexName(identity.TenantID, "alerts", time.Now().UTC().Format("2006-01-02"))
	require(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		response, err := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(cleanup))
		require(t, err)
		response.Body.Close()
	}()
	indexer := &worker.Indexer{DB: db, ES: es, Bus: queue}
	for i, mode := range []string{"valid", "changed_product", "missing_deployment", "invalid_schema"} {
		observed := time.Now().UTC()
		raw := []byte(fmt.Sprintf(`{"timestamp":%q,"event_type":"alert","app_proto":"http","proto":"TCP","src_ip":"192.0.2.10","dest_ip":"198.51.100.20","http":{"hostname":"files.example","http_method":"GET","url":"/documents"},"alert":{"signature_id":1000123,"severity":1}}`, observed.Format(time.RFC3339Nano)))
		attribution, supported, err := matcher.Attribute(raw, deployment, observed)
		require(t, err)
		if !supported || attribution.Result.Status != "candidate" {
			t.Fatal("受控 HTTP 材料没有命中原规则")
		}
		switch mode {
		case "changed_product":
			attribution.ProductName = "其他产品"
		case "missing_deployment":
			attribution.DeploymentID = "missing_application_deployment"
			attribution.StateSHA256 = application.StateDigest(attribution.DeploymentID, attribution.Result.RulesSHA256)
		case "invalid_schema":
			attribution.SchemaVersion = "unsupported.v1"
		}
		metadata, err := json.Marshal(attribution)
		require(t, err)
		rawDigest, attributionDigest := sha256.Sum256(raw), sha256.Sum256(metadata)
		generation := fmt.Sprintf("generation_app_%d", i)
		record := &sensorv1.EventRecord{EventId: contract.EventID(identity.TenantID, identity.RegistrationID, generation, 0, 0), SourceGenerationId: generation, Sequence: 1, Payload: raw, RawSha256: rawDigest[:], PayloadSha256: rawDigest[:], PayloadSchema: "suricata.eve.v1", ContentType: "application/json", EventType: "alert", EventTime: timestamppb.New(observed), ObservedAt: timestamppb.New(observed), ApplicationJson: metadata, ApplicationSha256: attributionDigest[:]}
		batch := &sensorv1.EventBatch{SensorId: identity.SensorID, SensorRegistrationId: identity.RegistrationID, StreamId: "alerts", ProducerEpoch: "epoch_app", SchemaVersion: "1.0", RouteToken: "owned-route", Records: []*sensorv1.EventRecord{record}}
		contract.Seal(batch)
		encoded, err := proto.Marshal(batch)
		require(t, err)
		envelope, err := json.Marshal(bus.Envelope{TenantID: identity.TenantID, Batch: encoded, Partition: observed.Format("2006-01-02"), ReceivedAt: observed})
		require(t, err)
		for range 2 {
			require(t, indexer.Process(ctx, envelope))
		}
		stream, err := queue.JS.Stream(ctx, queue.StreamName(bus.Indexed))
		require(t, err)
		message, err := stream.GetLastMsgForSubject(ctx, queue.Subject("sb.indexed"))
		require(t, err)
		var indexed struct {
			EventIDs    []string         `json:"event_ids"`
			Alerts      []notify.Summary `json:"alerts"`
			Quarantined int              `json:"quarantined"`
		}
		require(t, json.Unmarshal(message.Data, &indexed))
		expectedQuarantined := 1
		if mode == "valid" {
			expectedQuarantined = 0
		}
		if len(indexed.EventIDs) != 1 || indexed.EventIDs[0] != record.EventId || len(indexed.Alerts) != 1 || indexed.Alerts[0].ID != record.EventId || indexed.Quarantined != expectedQuarantined {
			t.Fatal("附加分类丢失原告警通知或隔离计数", mode, indexed)
		}
		if mode != "valid" {
			stream, err := queue.JS.Stream(ctx, queue.StreamName(bus.Quarantine))
			require(t, err)
			message, err := stream.GetLastMsgForSubject(ctx, queue.Subject("sb.quarantine"))
			require(t, err)
			var quarantined struct {
				Reason  string `json:"reason"`
				EventID string `json:"event_id"`
			}
			require(t, json.Unmarshal(message.Data, &quarantined))
			if quarantined.Reason != "application_attribution_rejected" || quarantined.EventID != record.EventId {
				t.Fatal("附加分类隔离失去原事件身份", mode)
			}
		}
		response, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
		require(t, err)
		response.Body.Close()
		result, err := es.Search(ctx, identity.TenantID, model.SearchRequest{Start: observed.Add(-time.Minute), End: observed.Add(time.Minute), Filter: `event_id == "` + record.EventId + `"`})
		require(t, err)
		if result.Total != 1 || result.Items[0].Event.Original != string(raw) || result.Items[0].RawSHA256 != hex.EncodeToString(rawDigest[:]) || (result.Items[0].Application != nil) != (mode == "valid") {
			t.Fatal("附加分类拒绝改变了原告警或重投身份", mode, result.Total)
		}
	}
}
