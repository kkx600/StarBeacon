package mcpserver

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSensorSummaryKeepsExistingFieldsAndBoundedOutput(t *testing.T) {
	for _, raw := range []string{"", "null", `{}`, `{"cpu_percent":25}`, `{"rx_bytes":"18446744073709551615"}`} {
		value, err := sensorSummaryHealth(json.RawMessage(raw))
		if err != nil || string(value) != raw {
			t.Fatal("已有摘要不应改变", raw, err)
		}
	}
	original := json.RawMessage(`{"cpu_percent":25,"rx_bytes":"18446744073709551615","protocol_capabilities":{"records":"` + strings.Repeat("a", 60*1024) + `"}}`)
	value, err := sensorSummaryHealth(original)
	if err != nil || !strings.Contains(string(value), `"cpu_percent":25`) || !strings.Contains(string(value), `"18446744073709551615"`) || strings.Contains(string(value), "protocol_capabilities") || !strings.Contains(string(original), "protocol_capabilities") {
		t.Fatal("目录裁剪不应改写原健康观测或资源精度", err)
	}
	for _, raw := range []string{`{`, `[]`, `"secret"`, strings.Repeat(" ", 72*1024+1)} {
		if _, err = sensorSummaryHealth(json.RawMessage(raw)); err == nil {
			t.Fatal("畸形或超额摘要未拒绝")
		}
	}
}
