package response

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func catalogExample() CatalogQuery {
	end := time.Now().UTC().Truncate(time.Microsecond)
	return CatalogQuery{Start: end.Add(-24 * time.Hour), End: end, Limit: 20}
}

func TestResponseCatalogCursorBindsFiltersAndStableTie(t *testing.T) {
	q := catalogExample()
	q.SensorID = "sensor_example"
	q.TargetIP = "10.20.2.10"
	q.DeviceID = "device_example"
	q.Kind = "response.block"
	q.State = "succeeded"
	if q.Validate() != nil {
		t.Fatal("合法筛选被拒绝")
	}
	position := q.End.Add(-time.Hour)
	q.Cursor = q.Next(position, "task_example")
	got, id, err := q.Position()
	if err != nil || !got.Equal(position) || id != "task_example" || q.Validate() != nil {
		t.Fatal("续页游标无法复用", got, id, err)
	}
	for _, change := range []func(*CatalogQuery){func(v *CatalogQuery) { v.SensorID = "other" }, func(v *CatalogQuery) { v.TargetIP = "10.20.2.11" }, func(v *CatalogQuery) { v.DeviceID = "other" }, func(v *CatalogQuery) { v.Start = v.Start.Add(-time.Minute) }, func(v *CatalogQuery) { v.End = v.End.Add(-time.Minute) }, func(v *CatalogQuery) { v.Limit++ }, func(v *CatalogQuery) { v.Kind = "response.read" }, func(v *CatalogQuery) { v.State = "failed" }} {
		copy := q
		change(&copy)
		if copy.Validate() == nil {
			t.Fatal("其他筛选沿用了游标", copy)
		}
	}
	q.Cursor = ""
	copy := q
	copy.Start = q.Start.In(time.FixedZone("offset", 3600))
	copy.End = q.End.In(time.FixedZone("offset", 3600))
	copy.Cursor = q.Next(position, "task_example")
	if copy.Validate() != nil {
		t.Fatal("同一绝对窗口被时区表示影响")
	}
}

func TestResponseCatalogRejectsMalformedFiltersAndCursors(t *testing.T) {
	for _, change := range []func(*CatalogQuery){func(q *CatalogQuery) { q.Start = time.Time{} }, func(q *CatalogQuery) { q.End = time.Time{} }, func(q *CatalogQuery) { q.Start = q.End }, func(q *CatalogQuery) { q.Start = q.End.Add(-32 * 24 * time.Hour) }, func(q *CatalogQuery) { q.End = time.Now().Add(time.Hour) }, func(q *CatalogQuery) { q.Limit = 0 }, func(q *CatalogQuery) { q.Limit = 101 }, func(q *CatalogQuery) { q.SensorID = "UPPER" }, func(q *CatalogQuery) { q.DeviceID = "device/bad" }, func(q *CatalogQuery) { q.TargetIP = "10.20.0.0/16" }, func(q *CatalogQuery) { q.Kind = "diagnostics" }, func(q *CatalogQuery) { q.State = "queued|delivered" }, func(q *CatalogQuery) { q.State = "UPPER" }, func(q *CatalogQuery) { q.Cursor = strings.Repeat("x", 513) }, func(q *CatalogQuery) { q.Cursor = "%%%" }, func(q *CatalogQuery) {
		q.Cursor = base64.RawURLEncoding.EncodeToString([]byte(`{"id":"bad","id":"bad"}`))
	}} {
		q := catalogExample()
		change(&q)
		if q.Validate() == nil {
			t.Fatal("无效筛选被接受", q)
		}
	}
	q := catalogExample()
	for _, c := range []catalogCursor{{Time: q.Start.Add(-time.Second), ID: "task_ok", Query: q.fingerprint()}, {Time: q.End, ID: "task_ok", Query: q.fingerprint()}, {Time: q.Start, ID: "UPPER", Query: q.fingerprint()}, {Time: q.Start, ID: "task_ok", Query: "wrong"}} {
		raw, _ := json.Marshal(c)
		q.Cursor = base64.RawURLEncoding.EncodeToString(raw)
		if q.Validate() == nil {
			t.Fatal("游标边界失效")
		}
	}
}
