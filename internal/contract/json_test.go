package contract

import (
	"strings"
	"testing"
)

func TestJSONFieldsRejectsAmbiguousAndUnboundedInputs(t *testing.T) {
	fields := []string{"value", "items"}
	for _, input := range []string{`{}`, `{"value":0}`, `{"value":null,"items":[true,false,1,"字段",{}]}`, `{"value":{"items":[]}}`} {
		if err := JSONFields(input, fields, 256); err != nil {
			t.Fatalf("合法唯一字段被拒绝 %q: %v", input, err)
		}
	}
	for _, input := range []string{
		"", `null`, `true`, `1`, `[]`, `"value"`, `{"Value":1}`, `{"other":1}`, `{"value":1,"value":2}`,
		`{"value":{"items":[],"items":[1]}}`, `{"value":1} {}`, `{"value":`, `{"value":[}`, `{"value":{"items":}`, `{"value":"` + string([]byte{255}) + `"}`, "{\x00}",
		`{"items":` + strings.Repeat("[", 9) + `1` + strings.Repeat("]", 9) + `}`,
	} {
		if err := JSONFields(input, fields, 256); err == nil {
			t.Fatalf("歧义或不完整 JSON 被接受 %q", input)
		}
	}
	if JSONFields(`{"value":1}`, fields, 0) == nil || JSONFields(`{"value":1}`, fields, 5) == nil {
		t.Fatal("长度预算没有生效")
	}
}
