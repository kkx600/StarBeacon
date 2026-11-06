//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/store"
)

// sharedEventIndex 返回默认布局与默认 180 天保留期下，路由日写入的共享索引。
func sharedEventIndex(t *testing.T, stream, day string) string {
	t.Helper()
	index, err := contract.EventIndexName(stream, 180, contract.DefaultIndexLayout().For(stream).Period, day)
	require(t, err)
	return index
}

// deleteTenantEvents 只删除测试租户在共享索引中的文档；共享索引同时承载其他租户，不能整体删除。
func deleteTenantEvents(t *testing.T, es *store.Elasticsearch, tenant string) {
	t.Helper()
	clean, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	response, err := es.API.DeleteByQuery([]string{contract.SharedIndexPrefix + "*"}, strings.NewReader(`{"query":{"term":{"tenant_id":"`+tenant+`"}}}`), es.API.DeleteByQuery.WithConflicts("proceed"), es.API.DeleteByQuery.WithRefresh(true), es.API.DeleteByQuery.WithContext(clean))
	if err == nil {
		response.Body.Close()
	}
}
