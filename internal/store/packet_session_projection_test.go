package store

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
)

func TestPacketSessionProjectionRejectsUnboundPersistedDocuments(t *testing.T) {
	begin := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	row := PacketArchive{ID: "archive_a", ManifestSHA256: strings.Repeat("a", 64),
		Manifest: packetarchive.Manifest{
			Capture: packetarchive.Capture{ID: "archive_a", TenantID: "tenant_a", SensorID: "sensor_a", RegistrationID: "reg_a",
				RunID: "run_a", Interface: "eth0", StartedAt: begin, EndedAt: begin.Add(time.Minute)},
			Encoding: packetarchive.Encoding{RawSHA256: strings.Repeat("b", 64)},
		}}
	flow := packetarchive.IndexedFlow{StartedAt: begin, EndedAt: begin.Add(time.Second), Packets: 1,
		OriginalBytes: 64, RetainedBytes: 64, State: "retained"}
	flow.A, flow.B = netip.MustParseAddrPort("192.0.2.1:53000"), netip.MustParseAddrPort("198.51.100.1:443")
	flow.Transport = "tcp"
	documents, err := packetSessionDocuments(row, PacketArchiveObservations{Flows: []packetarchive.IndexedFlow{flow}}, begin)
	if err != nil || len(documents) != 1 {
		t.Fatal("构造会话分段失败", err)
	}
	batch := PacketSessionBatch{Index: "sb-v2-context-logsdb-r180-d2026.11.25", Partition: "2026-11-25"}
	decode := func(doc model.Alert, batch PacketSessionBatch) error {
		t.Helper()
		data, err := json.Marshal([]model.Alert{doc})
		if err != nil {
			t.Fatal(err)
		}
		return decodePacketSessionBatch("tenant_a", "archive_a", data, &batch)
	}
	if err = decode(documents[0], batch); err != nil {
		t.Fatal("冻结分段无法回读", err)
	}
	for name, change := range map[string]func(*model.Alert){
		"异租户":  func(doc *model.Alert) { doc.TenantID = "tenant_b" },
		"异归档":  func(doc *model.Alert) { doc.SourceGenerationID = "archive_b" },
		"来源序号": func(doc *model.Alert) { doc.SourceOffset = "2" },
		"事件标识": func(doc *model.Alert) { doc.EventID = "different" },
		"来源内容": func(doc *model.Alert) { doc.Event.Original += " " },
	} {
		t.Run(name, func(t *testing.T) {
			doc := documents[0]
			change(&doc)
			if err := decode(doc, batch); err == nil {
				t.Fatal("来源身份漂移被接纳")
			}
		})
	}
	batch.Index = "sb-v2-context-r180-d2026.11.25"
	if err = decode(documents[0], batch); err == nil {
		t.Fatal("分段被写入非冻结的索引模式")
	}
}
