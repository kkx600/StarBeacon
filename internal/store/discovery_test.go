package store

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elastic/go-elasticsearch/v9/esapi"
	"github.com/kkx600/StarBeacon/internal/discovery"
	"github.com/kkx600/StarBeacon/internal/model"
)

func discoveryQuery() discovery.Query {
	start := time.Date(2026, 10, 18, 23, 30, 0, 0, time.UTC)
	return discovery.Query{NetworkID: "network_owned", NetworkRevision: 1, SensorID: "sensor_owned", RegistrationID: "registration_owned", Prefix: "192.0.2.0/24", Start: start, End: start.Add(time.Hour)}
}

const emptyDiscovery = `{"timed_out":false,"_shards":{"total":1,"successful":1,"skipped":0,"failed":0},"aggregations":{"source":{"doc_count":0,"eligible":{"doc_count":0,"addresses":{"buckets":[]}}},"destination":{"doc_count":0,"eligible":{"doc_count":0,"addresses":{"buckets":[]}}}}}`

func TestDiscoveryOwnedIndexFamilyAndStorageFailures(t *testing.T) {
	for _, mode := range []string{"available", "absent", "forbidden", "deleted", "invalid", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			searches := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				searches++
				if r.Method == "HEAD" || r.URL.Path != "/sb-context-tenant_owned-*,-sb-context-tenant_owned-*-*/_search" || r.URL.Query().Get("pre_filter_shard_size") != "1" || r.URL.Query().Get("expand_wildcards") != "open,closed" || r.URL.Query().Get("ignore_unavailable") != "false" || r.URL.Query().Get("allow_no_indices") != "true" || r.URL.Query().Get("allow_partial_search_results") != "false" || r.URL.Query().Get("max_concurrent_shard_requests") != "2" {
					t.Error("缺少租户隔离、预过滤或完整性约束")
				}
				switch mode {
				case "forbidden":
					w.WriteHeader(403)
				case "deleted":
					w.WriteHeader(404)
				case "invalid":
					_, _ = io.WriteString(w, `{}`)
				case "oversize":
					_, _ = io.WriteString(w, strings.Repeat(" ", 8*1024*1024+1))
				case "absent":
					_, _ = io.WriteString(w, `{"timed_out":false,"_shards":{"total":0,"successful":0,"skipped":0,"failed":0},"hits":{"hits":[]}}`)
				default:
					_, _ = io.WriteString(w, emptyDiscovery)
				}
			}))
			defer server.Close()
			es, _ := OpenES(server.URL, "")
			result, err := es.DiscoverAddresses(context.Background(), "tenant_owned", discoveryQuery())
			if searches != 1 {
				t.Fatal("发现应使用一次原子搜索")
			}
			if mode == "available" || mode == "absent" {
				if err != nil || result.PartitionStatus != mode || result.Addresses == nil {
					t.Fatal("空目标与完整聚合未正确区分", result, err)
				}
			} else if err == nil || result.SchemaVersion != "" {
				t.Fatal("失败返回了可交付结果")
			}
		})
	}
}

type discoveryTransport func(*http.Request) (*http.Response, error)

func (f discoveryTransport) Perform(r *http.Request) (*http.Response, error) { return f(r) }

type discoveryReadFailure struct{}

func (discoveryReadFailure) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (discoveryReadFailure) Close() error             { return nil }

func TestDiscoveryTransportCancellationReadFailureAndInvalidInputs(t *testing.T) {
	for _, mode := range []string{"transport", "read"} {
		es := &Elasticsearch{API: esapi.New(discoveryTransport(func(r *http.Request) (*http.Response, error) {
			if mode == "transport" {
				return nil, errors.New("transport failed")
			}
			var body io.ReadCloser = io.NopCloser(strings.NewReader(""))
			if r.Method != "HEAD" {
				body = discoveryReadFailure{}
			}
			return &http.Response{StatusCode: 200, Body: body, Header: http.Header{}}, nil
		}))}
		if _, err := es.DiscoverAddresses(context.Background(), "tenant_owned", discoveryQuery()); err == nil {
			t.Fatal("传输或读取错误被忽略", mode)
		}
	}
	es := &Elasticsearch{}
	if _, err := es.DiscoverAddresses(context.Background(), "../other", discoveryQuery()); !errors.Is(err, discovery.ErrInput) {
		t.Fatal(err)
	}
	if _, err := (&Postgres{}).DiscoveryScope(context.Background(), model.Principal{Role: "viewer"}, discoveryQuery(), nil, ""); !errors.Is(err, discovery.ErrInput) {
		t.Fatal(err)
	}
}
