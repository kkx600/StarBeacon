package searchsnapshot

import (
	"encoding/csv"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/model"
)

func TestCSVPreservesMetadataAndRejectsFormulaExecution(t *testing.T) {
	v := model.Alert{EventID: "event_owned", Timestamp: time.Date(2026, 10, 9, 3, 0, 0, 7, time.FixedZone("scope", 28800)), Sequence: "18446744073709551615", RawSHA256: "digest"}
	v.Rule.Name, v.HTTP.Path, v.Event.Original = " \t=HYPERLINK(\"https://example.test\")", "/a,\"b\"\r\npath", "never_export_raw_eve"
	v.Source.Port, v.Suricata.FlowID = 65535, "18446744073709551615"
	c := NewCSV()
	if err := c.Append(v); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(c.Bytes()), "\ufeff"))).ReadAll()
	if err != nil || len(rows) != 2 || len(rows[0]) != 28 || len(rows[1]) != 28 || c.Rows() != 1 {
		t.Fatal("CSV 字段或记录不完整", rows, err)
	}
	if rows[1][1] != "2026-10-08T19:00:00.000000007Z" || rows[1][2] != "" || rows[1][8] != "'18446744073709551615" || rows[1][10] != "65535" || !strings.HasPrefix(rows[1][21], "'") || rows[1][24] != "/a,\"b\"\npath" || rows[1][25] != "'18446744073709551615" || strings.Contains(string(c.Bytes()), v.Event.Original) {
		t.Fatal("CSV 时区、长整数、公式防护或载荷范围错误", rows[1])
	}
	for _, value := range []string{"=1+1", "+cmd", "-cmd", "@SUM(1)", "\ufeff=1", "\r\n\t+cmd", "  @A1"} {
		if safeCell(value) != "'"+value {
			t.Fatal("表格公式前缀未转成文本", value)
		}
	}
	for _, value := range []string{"", "path", "192.0.2.1", "1+1", "184467440737095", "123456789012345a", "中文"} {
		if safeCell(value) != value {
			t.Fatal("普通字段被改变", value)
		}
	}
}

func TestCSVLimitsNeverAppendPartialRows(t *testing.T) {
	for _, v := range []model.Alert{{EventID: "\xff"}, {}} {
		c := NewCSV()
		before := string(c.Bytes())
		if v.EventID == "" {
			v.Rule.Name = strings.Repeat("x", MaxBytes)
		}
		if c.Append(v) == nil || c.Rows() != 0 || string(c.Bytes()) != before {
			t.Fatal("失败字段留下部分记录")
		}
	}
	c := NewCSV()
	for range MaxRows {
		if err := c.Append(model.Alert{}); err != nil {
			t.Fatal(err)
		}
	}
	before := len(c.Bytes())
	if !errors.Is(c.Append(model.Alert{}), ErrLimit) || c.Rows() != MaxRows || len(c.Bytes()) != before {
		t.Fatal("记录上限没有生效")
	}
}
