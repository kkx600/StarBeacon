package contract

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDeviceAlertVendorPageValidation(t *testing.T) {
	const vendor = `{"id":"alert-1","time":"2026-11-24T12:00:00+08:00","severity":"严重","name":"测试告警","source_ip":"192.0.2.10","destination_ip":"2001:db8::2","host":"fixture-1","raw":{"vendor":{"value":17}}}`
	page := func(alert string) string { return `{"cursor":"next","items":[` + alert + `]}` }
	got, err := ReadDeviceAlertPage([]byte(page(vendor)))
	if err != nil || got.Cursor != "next" || len(got.Items) != 1 || got.Items[0].Severity != "critical" ||
		got.Items[0].Time.Format(time.RFC3339) != "2026-11-24T04:00:00Z" || string(got.Items[0].Raw) != `{"vendor":{"value":17}}` {
		t.Fatal("设备告警未保留统一时间、级别和厂商原文", got, err)
	}
	for _, tc := range []struct{ wire, value string }{{"高危", "high"}, {"中危", "medium"}, {"低危", "low"}} {
		got, err := ReadDeviceAlertPage([]byte(page(strings.Replace(vendor, "严重", tc.wire, 1))))
		if err != nil || got.Items[0].Severity != tc.value {
			t.Fatal("设备级别转换错误", tc, err)
		}
	}
	for _, field := range []struct{ old, new string }{
		{`"id":"alert-1"`, `"id":""`}, {`"name":"测试告警"`, `"name":" 前方空格"`},
		{`"severity":"严重"`, `"severity":"fatal"`}, {`"source_ip":"192.0.2.10"`, `"source_ip":"::ffff:192.0.2.10"`},
		{`"destination_ip":"2001:db8::2"`, `"destination_ip":"fe80::1%eth0"`},
		{`"destination_ip":"2001:db8::2"`, `"destination_ip":"2001:0DB8::2"`},
		{`"host":"fixture-1"`, `"host":"a\nb"`}, {`"raw":`, `"raw_again":`},
		{`"name":`, `"id":"repeated","name":`},
		{"2026-11-24T12:00:00+08:00", "1960-01-01T00:00:00Z"},
		{"2026-11-24T12:00:00+08:00", "2263-01-01T00:00:00Z"},
	} {
		if _, err := ReadDeviceAlertPage([]byte(page(strings.Replace(vendor, field.old, field.new, 1)))); err == nil {
			t.Fatal("无效的厂商告警通过校验", field)
		}
	}
	for _, bad := range []string{
		`{}`, `{"cursor":null,"items":[]}`, `{"cursor":"ok","items":null}`,
		`{"cursor":"ok","cursor":"skip","items":[]}`, `{"cursor":"\u0000","items":[]}`,
		fmt.Sprintf(`{"cursor":"%s","items":[]}`, strings.Repeat("x", MaxDeviceAlertBytes)),
	} {
		if _, err := ReadDeviceAlertPage([]byte(bad)); err == nil {
			t.Fatal("无效分页通过校验")
		}
	}
}

func TestDeviceAlertRecordAndBatchRejectMismatchedProvenance(t *testing.T) {
	at := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	record := DeviceAlertRecord{PluginID: "plugin", PluginName: "夹具", DeviceID: "device",
		Alert: DeviceAlert{ID: "alert", Time: at, Severity: "critical", Name: "受控历程",
			Raw: json.RawMessage(`{"vendor":"原始数据"}`)}}
	wide := record
	wide.Alert.Raw = json.RawMessage(fmt.Sprintf(`"%s"`, strings.Repeat("x", MaxDeviceAlertBytes-300)))
	wide.PluginName = strings.Repeat("x", 500)
	rawWide, _ := json.Marshal(wide)
	if len(rawWide) <= MaxDeviceAlertBytes {
		t.Fatal("测试记录没有覆盖外层元数据空间")
	}
	if _, err := ReadDeviceAlertRecord(rawWide); err != nil {
		t.Fatal("合法告警加封后的元数据超限", err)
	}
	raw, _ := json.Marshal(record)
	hash, original := sha256.Sum256(raw), sha256.Sum256(record.Alert.Raw)
	tenant, sensor, registration := "tenant", "sensor", "registration"
	id := DeviceAlertID(tenant, registration, record.PluginID, record.DeviceID, record.Alert.ID)
	b := &sensorv1.EventBatch{SensorId: sensor, SensorRegistrationId: registration, StreamId: "alerts",
		ProducerEpoch: "epoch", SchemaVersion: "1.0", RouteToken: "route",
		Records: []*sensorv1.EventRecord{{EventId: id, Sequence: 1, SourceGenerationId: record.PluginID,
			EventTime: timestamppb.New(at), ObservedAt: timestamppb.New(at), EventType: "device_alert",
			PayloadSchema: DeviceAlertSchema, ContentType: "application/json", Payload: raw, PayloadSha256: hash[:], RawSha256: original[:]}}}
	Seal(b)
	if err := Validate(tenant, sensor, registration, b); err != nil {
		t.Fatal("合法设备来源无法通过事件契约", err)
	}
	for _, edit := range []func(*sensorv1.EventBatch){
		func(x *sensorv1.EventBatch) { x.StreamId = "context" },
		func(x *sensorv1.EventBatch) { x.Records[0].SourceGenerationId = "other" },
		func(x *sensorv1.EventBatch) {
			x.Records[0].EventId = DeviceAlertID(tenant, registration, "plugin", "other", "alert")
		},
		func(x *sensorv1.EventBatch) { x.Records[0].RawSha256 = hash[:] },
		func(x *sensorv1.EventBatch) { x.Records[0].EventTime = timestamppb.New(at.Add(time.Second)) },
		func(x *sensorv1.EventBatch) { x.Records[0].SourceOffset++ },
	} {
		bad := proto.CloneOf(b)
		edit(bad)
		Seal(bad)
		if err := Validate(tenant, sensor, registration, bad); err != ErrDeviceAlert {
			t.Fatal("不一致的设备告警来源未拒绝", err)
		}
	}
}
