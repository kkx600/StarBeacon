//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/traffic"
)

func TestDisplayFilterRealFamilyPresenceOrderingAndRawString(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant, foreign, password := store.RandomID("it_filter_"), store.RandomID("it_filter_other_"), store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "高级检索验收", tenant, password, "admin"))
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), "")
	require(t, err)
	now := time.Now().UTC()
	for _, target := range []string{tenant, foreign} {
		for _, dataset := range []string{"alerts", "context"} {
			index, err := contract.IndexName(target, dataset, now.Format("2006-01-02"))
			require(t, err)
			require(t, es.EnsureIndex(ctx, index, now.Format("2006-01-02")))
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				res, err := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(cleanup))
				require(t, err)
				defer res.Body.Close()
				if res.IsError() {
					t.Error("无法清理高级检索验收索引", res.StatusCode)
				}
			})
			var docs []model.Alert
			for _, ip := range []string{"192.0.2.10", "2001:db8::10", ""} {
				doc := model.Alert{EventID: store.RandomID("event_"), TenantID: target, SensorID: "sensor_owned", Timestamp: now, ReceivedAt: now, ObservedAt: now}
				doc.Event.Kind, doc.Event.Original, doc.Severity = "alert", `{"fixture":"display_filter"}`, "medium"
				if dataset == "context" {
					doc.Event.Kind = "http"
				}
				doc.Source.IP, doc.Network.Protocol, doc.Network.Transport = ip, "http", "tcp"
				doc.HTTP.Path = `\private\files`
				if ip == "192.0.2.10" {
					doc.Source.MAC = "02:00:00:00:00:01"
				}
				docs = append(docs, doc)
			}
			for _, err := range es.Bulk(ctx, index, docs) {
				require(t, err)
			}
			res, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
			require(t, err)
			if res.IsError() {
				t.Fatal("高级检索验收索引未刷新", res.StatusCode)
			}
			res.Body.Close()
		}
	}
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, tenant, password)
	for _, tc := range []struct {
		filter string
		count  int64
	}{
		{`ip`, 1}, {`ipv6`, 1}, {`eth`, 1}, {`not ip and not ipv6`, 1},
		{`ip and ipv6`, 0}, {`not ipv6`, 2}, {`ipv6.addr`, 1},
		{`ipv6.src < 2001:db8::11`, 1}, {`ipv6.src != 2001:db8::11`, 1},
		{`ip.src > 192.0.2.5`, 1}, {`ipv6.src >= 2001:db8::11`, 0},
		{`source.ip < 192.0.2.10`, 0}, {`ip or ipv6`, 2},
		{`http.path contains r"\private\files"`, 3},
		{`ip and eth and http.path contains r"\private"`, 1},
	} {
		t.Run(tc.filter, func(t *testing.T) {
			query := model.SearchRequest{Start: now.Add(-time.Hour), End: now.Add(time.Minute), Filter: tc.filter}
			var alerts model.SearchResult
			client.request("POST", "/alerts/search", "", query, &alerts, 200)
			if alerts.Total != tc.count {
				t.Fatalf("告警检索 %q 返回 %d，预期 %d", tc.filter, alerts.Total, tc.count)
			}
			var records traffic.Result
			client.request("POST", "/traffic/search", "", model.TrafficSearchRequest{SearchRequest: query}, &records, 200)
			if records.Total != tc.count {
				t.Fatalf("协议检索 %q 返回 %d，预期 %d", tc.filter, records.Total, tc.count)
			}
		})
	}
}
