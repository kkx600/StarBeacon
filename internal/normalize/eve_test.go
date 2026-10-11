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

func TestEthernetAddressesUseTheSameContractAsSearchAndInventory(t *testing.T) {
	for _, fields := range []string{`"ether":{"src_mac":"00:11:22:33:44:55:66:77"}`, `"ether":{"dest_mac":"00:11:22:33:44:55:66:77"}`, `"src_ip":"fe80::1%eth0"`, `"dest_ip":"fe80::1%eth0"`} {
		raw := `{"timestamp":"2026-10-02T00:00:00Z","event_type":"alert",` + fields + `}`
		if _, err := Normalize("tenant_test", "sensor_test", "sr_test", &sensorv1.EventRecord{Payload: []byte(raw), ObservedAt: timestamppb.Now()}, time.Now()); err == nil {
			t.Fatalf("不符合地址契约的字段被接受：%s", fields)
		}
	}
	// 无 Ethernet 头或源记录未采集 L2 字段时保留缺失，不能补成全零地址。
	raw := `{"timestamp":"2026-10-02T00:00:00Z","event_type":"flow","src_ip":"2001:db8::1"}`
	value, err := Normalize("tenant_test", "sensor_test", "sr_test", &sensorv1.EventRecord{Payload: []byte(raw), ObservedAt: timestamppb.Now()}, time.Now())
	if err != nil || value.Source.MAC != "" || value.Destination.MAC != "" {
		t.Fatal("缺失的链路层地址被补造")
	}
}

func TestProtocolTransactionsKeepAnExplicitProtocolWithoutAppProto(t *testing.T) {
	for _, kind := range []string{"http", "http2", "dns", "tls", "quic", "ssh", "smtp", "ftp", "smb", "nfs", "dhcp", "rdp", "alert", "flow", "anomaly", "fileinfo", "stats", "http_unknown"} {
		t.Run(kind, func(t *testing.T) {
			raw := `{"timestamp":"2026-10-02T00:00:00Z","event_type":"` + kind + `","proto":"TCP","http":{"http_method":"GET","url":"/starbeacon/validation"}}`
			value, err := Normalize("tenant_test", "sensor_test", "sr_test", &sensorv1.EventRecord{Payload: []byte(raw), ObservedAt: timestamppb.Now()}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			want := kind
			switch kind {
			case "alert", "flow", "anomaly", "fileinfo", "stats", "http_unknown":
				want = ""
			}
			if value.Network.Protocol != want || value.Network.Transport != "tcp" || value.Event.Original != raw || value.HTTP.Method != "GET" {
				t.Fatal("协议事件未保持正确检索语义或改写了原文", kind, value.Network)
			}
		})
	}
	raw := `{"timestamp":"2026-10-02T00:00:00Z","event_type":"flow","app_proto":"HTTP2"}`
	value, err := Normalize("tenant_test", "sensor_test", "sr_test", &sensorv1.EventRecord{Payload: []byte(raw), ObservedAt: timestamppb.Now()}, time.Now())
	if err != nil || value.Network.Protocol != "http2" || value.Event.Original != raw {
		t.Fatal("显式源协议未被保留", err)
	}
}
