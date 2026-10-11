package store

import (
	"errors"
	"testing"

	"github.com/kkx600/StarBeacon/internal/savedsearch"
)

func TestSavedDefinitionsUseTheActualDatasetValidators(t *testing.T) {
	d := savedsearch.Definition{SchemaVersion: savedsearch.Schema, ParserVersion: "1.0", Dataset: "alerts", Mode: "visual", Window: savedsearch.Window{Mode: "relative", Hours: 24}, Terms: savedsearch.Terms{SourceIP: "::ffff:192.0.2.1"}}
	if ValidateSavedDefinition(d) != nil {
		t.Fatal("合法告警查询没有使用实际校验器")
	}
	bad := d
	bad.Terms.SourceIP = "unknown"
	if !errors.Is(ValidateSavedDefinition(bad), savedsearch.ErrInput) {
		t.Fatal("非法 IP 被保存")
	}
	bad = d
	bad.ParserVersion = "2.0"
	if !errors.Is(ValidateSavedDefinition(bad), savedsearch.ErrVersion) {
		t.Fatal("未知版本静默编译")
	}
	d.Dataset = "context"
	d.Terms.EventKind = "tls"
	d.Terms.SensorID = "sensor_1"
	d.Terms.RegistrationID = "registration_1"
	d.Terms.GenerationID = "generation_1"
	d.Terms.FlowID = "18446744073709551615"
	if ValidateSavedDefinition(d) != nil {
		t.Fatal("合法协议和来源身份没有通过实际校验")
	}
	for _, mutate := range []func(*savedsearch.Definition){func(d *savedsearch.Definition) { d.Terms.EventKind = "alert" }, func(d *savedsearch.Definition) { d.Terms.SensorID = "" }, func(d *savedsearch.Definition) { d.Terms.FlowID = "01" }, func(d *savedsearch.Definition) { d.Mode = "advanced"; d.Terms.Filter = "ip.addr ===" }} {
		bad := d
		mutate(&bad)
		if ValidateSavedDefinition(bad) == nil {
			t.Fatal("非法协议、来源、流标识或表达式进入保存配置")
		}
	}
}
