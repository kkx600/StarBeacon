package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/searchsnapshot"
)

func TestSnapshotFactsProjectionBoundsAndCleanup(t *testing.T) {
	for _, mode := range []string{"complete", "row_limit", "byte_limit", "close_failed", "revoked", "invalid_bound"} {
		t.Run(mode, func(t *testing.T) {
			closed, reads := false, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "DELETE" {
					closed = true
					if mode == "close_failed" {
						w.WriteHeader(503)
					} else {
						_, _ = w.Write([]byte(`{"succeeded":true,"num_freed":1}`))
					}
					return
				}
				if strings.HasSuffix(r.URL.Path, "/_pit") {
					_, _ = w.Write([]byte(`{"id":"pit_first","_shards":{"total":1,"successful":1,"skipped":0,"failed":0}}`))
					return
				}
				reads++
				h := snapshotHit(1)
				source := h["_source"].(map[string]any)
				source["sensor_id"] = "probe_owned"
				source["sensor_registration_id"] = "reg_owned"
				source["raw_sha256"] = strings.Repeat("a", 64)
				source["source"] = map[string]any{"ip": "192.0.2.1", "port": 42000}
				source["destination"] = map[string]any{"ip": "198.51.100.2", "port": 443}
				source["rule"] = map[string]any{"id": "1000001"}
				if mode == "byte_limit" {
					source["http"] = map[string]any{"path": strings.Repeat("x", searchsnapshot.MaxBytes)}
				}
				total := 1
				if mode == "row_limit" {
					total = 2
				}
				_ = json.NewEncoder(w).Encode(snapshotBody(total, h))
			}))
			defer server.Close()
			es, err := OpenES(server.URL, "")
			if err != nil {
				t.Fatal(err)
			}
			checked := 0
			maximum := 1
			if mode == "invalid_bound" {
				maximum = 0
			}
			facts, err := es.SnapshotEvents(context.Background(), "tenant_owned", "alerts", snapshotQuery(), maximum, func(context.Context) error {
				checked++
				if mode == "revoked" && checked > 1 {
					return errors.New("已撤权")
				}
				return nil
			})
			if mode == "complete" {
				if err != nil || len(facts) != 1 || facts[0].SensorID != "probe_owned" || facts[0].RegistrationID != "reg_owned" || facts[0].Source.Port != 42000 || facts[0].Destination.IP != "198.51.100.2" || facts[0].Rule.ID != "1000001" || facts[0].Event.Original != "" || !closed {
					t.Fatal("事实白名单或快照清理不一致", facts, err)
				}
				return
			}
			if err == nil || facts != nil {
				t.Fatal("失败仍返回部分事实", facts, err)
			}
			if mode == "row_limit" || mode == "byte_limit" {
				if !errors.Is(err, searchsnapshot.ErrLimit) {
					t.Fatal("资源上限未明确拒绝", err)
				}
			}
			if mode == "invalid_bound" {
				if reads != 0 || closed {
					t.Fatal("无效上限仍访问来源")
				}
			} else if !closed {
				t.Fatal("失败未释放快照")
			}
		})
	}
}
