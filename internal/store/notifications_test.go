package store

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDeliveryCursorIsChronologicalAndStrict(t *testing.T) {
	created := time.Date(2026, 10, 2, 1, 2, 3, 456789000, time.FixedZone("offset", 8*3600))
	cursor := deliveryCursor(Delivery{ID: "delivery_owned", CreatedAt: created})
	at, id, err := parseDeliveryCursor(cursor)
	if err != nil || id != "delivery_owned" || !at.Equal(created) {
		t.Fatal("日志时间和标识在游标中丢失")
	}
	if at, id, err := parseDeliveryCursor(""); err != nil || at != nil || id != "" {
		t.Fatal("首屏游标无效")
	}
	for _, value := range []string{"invalid+padding", strings.Repeat("a", 257), base64.RawURLEncoding.EncodeToString([]byte("2026-10-02T01:02:03Z\n../other")), base64.RawURLEncoding.EncodeToString([]byte("bad\ndelivery_owned")), base64.RawURLEncoding.EncodeToString([]byte("0001-01-01T00:00:00Z\ndelivery_owned")), base64.RawURLEncoding.EncodeToString([]byte("2026-10-02T01:02:03Z\ndelivery_owned\nextra"))} {
		if _, _, err := parseDeliveryCursor(value); !errors.Is(err, ErrNotificationQuery) {
			t.Fatal("非法游标被接受")
		}
	}
}
