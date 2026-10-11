package normalize

import (
	"strings"
	"testing"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNativeEVETimePreservesOffsetAndPrecision(t *testing.T) {
	for _, sample := range []struct{ native, standard string }{
		{"2026-10-02T00:00:00.003000+0000", "2026-10-02T00:00:00.003Z"},
		{"2026-10-02T08:01:02.123456789+0800", "2026-10-02T08:01:02.123456789+08:00"},
		{"2026-10-02T03:30:00.654321-0130", "2026-10-02T03:30:00.654321-01:30"},
		{"2026-10-02T00:00:00+0530", "2026-10-02T00:00:00+05:30"},
	} {
		t.Run(sample.native, func(t *testing.T) {
			actual, err := ParseTimestamp(sample.native)
			expected, parseError := time.Parse(time.RFC3339Nano, sample.standard)
			if err != nil || parseError != nil || !actual.Equal(expected) {
				t.Fatal("原生时间偏移或精度丢失", actual, expected, err)
			}
			raw := `{"timestamp":"` + sample.native + `","event_type":"alert","alert":{"signature_id":1000999,"signature":"原生时间告警","severity":1}}`
			alert, err := Normalize("tenant_owned", "sensor_owned", "sr_owned", &sensorv1.EventRecord{Payload: []byte(raw), ObservedAt: timestamppb.Now()}, time.Now())
			if err != nil || !alert.Timestamp.Equal(expected) || alert.Timestamp.Location() != time.UTC || alert.Event.Original != raw {
				t.Fatal("合法原生 EVE 被隔离或原文被改写", err)
			}
		})
	}
	for _, raw := range []string{"", strings.Repeat("x", 41), "2026-10-02T00:00:00", "2026-10-02T00:00:00.001+2400", "2026-10-02T00:00:00+0060", "2026-10-02T00:00:00+aa00", "2026-10-02T00:00:00+24:00", "2026-10-02T00:00:00+00:60", "2026-02-30T00:00:00+0000", "2026-10-02T00:00:00+0000 trailing"} {
		if _, err := ParseTimestamp(raw); err == nil {
			t.Fatal("接受无效原生时间", raw)
		}
	}
}
