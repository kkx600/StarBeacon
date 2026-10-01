package normalize

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestEVEKeepsNumbersBytesAndObservationBoundaries(t *testing.T) {
	raw := `{"timestamp":"2026-10-01T08:01:02.123456789+08:00","event_type":"alert","flow_id":18446744073709551000,"src_ip":"::ffff:192.0.2.1","dest_ip":"10.0.0.1","proto":"TCP","app_proto":"http","ether":{"src_mac":"AA:BB:CC:DD:EE:FF"},"alert":{"signature_id":1000001,"rev":2,"severity":2,"signature":"中文规则","action":"allowed"},"http":{"http_method":"POST","url":"/api/test"}}`
	v, e := Normalize("tenant_test", "sensor_test", "sr_test", &sensorv1.EventRecord{Payload: []byte(raw), ObservedAt: timestamppb.New(time.Now())}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if v.Suricata.FlowID != "18446744073709551000" || v.Event.Original != raw || v.Source.MAC != "aa:bb:cc:dd:ee:ff" || v.Source.IP != "192.0.2.1" || v.Timestamp.Nanosecond() != 123456789 || v.Severity != "medium" {
		t.Fatalf("映射错误: %+v", v)
	}
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "outcome") || strings.Contains(string(b), "decrypted") {
		t.Fatal("检测结果被扩展为未经证实的结论")
	}
	if v.EvidenceStatus != "not_linked" {
		t.Fatal("未捕获 PCAP 不能声称有原包证据")
	}
}
func TestInvalidEVEIsNotSilentlyNormalized(t *testing.T) {
	for _, raw := range []string{`{"timestamp":"bad","event_type":"alert"}`, `{"event_type":"alert"} {}`, `{"timestamp":"2026-10-01T00:00:00Z","event_type":"alert","src_ip":"bad"}`, "<html>invalid</html>", "{\"timestamp\":\"2026-10-01T00:00:00Z\",\"event_type\":\"alert\",\"alert\":{\"signature\":\"\xff\"}}"} {
		if _, e := Normalize("tenant_test", "sensor_test", "sr_test", &sensorv1.EventRecord{Payload: []byte(raw), ObservedAt: timestamppb.Now()}, time.Now()); e == nil {
			t.Fatalf("错误原文被接受: %s", raw)
		}
	}
}
