//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/syslogdata"
	"github.com/kkx600/StarBeacon/internal/transport"
)

type nativeSyslogProbe struct {
	configuration string
	source        syslogdata.Source
	clientTLS     *tls.Config
}

func prepareNativeSyslog(t *testing.T, directory string, c config.Config) *nativeSyslogProbe {
	t.Helper()
	dir := filepath.Join(directory, "syslog")
	require(t, os.Mkdir(dir, 0700))
	paths := map[string]string{"server.crt": filepath.Join(filepath.Dir(c.TLSCA), "server.crt"), "server.key": filepath.Join(filepath.Dir(c.TLSCA), "server.key"), "ca.crt": c.TLSCA}
	for name, path := range paths {
		raw, err := os.ReadFile(path)
		require(t, err)
		require(t, os.WriteFile(filepath.Join(dir, name), raw, 0600))
	}
	clientPEM, err := os.ReadFile(c.TLSCert)
	require(t, err)
	leaf, _ := pem.Decode(clientPEM)
	if leaf == nil {
		t.Fatal("原生 Syslog 客户端证书缺失")
	}
	source := syslogdata.Source{ID: "native_syslog", Name: "原生角色设备日志", NetworkDomain: "isolated", Listen: availableAddress(t), Transport: "tls", Format: "rfc5424", AllowedPeers: []string{"127.0.0.1/32"}, MaxMessageBytes: 4096, MaxConnections: 4, MaxEventsPerSecond: 100, TLS: syslogdata.TLSFiles{CertificateFile: filepath.Join(dir, "server.crt"), PrivateKeyFile: filepath.Join(dir, "server.key"), ClientCAFile: filepath.Join(dir, "ca.crt"), ClientFingerprints: []string{syslogdata.Hash(leaf.Bytes)}}}
	require(t, source.Validate())
	raw, err := json.Marshal(syslogdata.File{SchemaVersion: "syslog.sources.v1", Sources: []syslogdata.Source{source}})
	require(t, err)
	configuration := filepath.Join(dir, "sources.json")
	require(t, os.WriteFile(configuration, raw, 0600))
	clientTLS, err := transport.TLS(c.TLSCA, c.TLSCert, c.TLSKey, false)
	require(t, err)
	return &nativeSyslogProbe{configuration: configuration, source: source, clientTLS: clientTLS}
}

// 配置通过真实角色环境进入 Agent；验证后台接收、独立上传与索引，不能用库调用替代入口接线。
func (p *nativeSyslogProbe) verify(t *testing.T, ctx context.Context, platform, collector *liveHTTP, es *store.Elasticsearch, tenant string) {
	t.Helper()
	var health struct {
		Items []syslogdata.Health `json:"items"`
	}
	eventually(t, ctx, "原生 Syslog 来源监听", func() bool {
		collector.request("GET", "/syslog/sources", "", nil, &health, 200)
		return len(health.Items) == 1 && health.Items[0].Valid() && health.Items[0].State == "listening"
	})
	if health.Items[0].ConfigSHA256 != p.source.SHA256() {
		t.Fatal("原生采集器未读取指定来源修订")
	}
	collector.request("GET", "/syslog/sources?limit=1", "", nil, nil, 400)
	started := time.Now().UTC()
	stamp := started.Format("2006-01-02T15:04:05.000000Z")
	raw := []byte("<13>1 " + stamp + " edge-device policy 138 DENY - 原生角色日志：策略命中\n原文换行保持")
	malformed := []byte("<13>1 2026-10-21T00:00:00.123456789Z edge-device policy - BAD - invalid-time")
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", p.source.Listen, p.clientTLS.Clone())
	require(t, err)
	require(t, connection.SetDeadline(time.Now().Add(5*time.Second)))
	for _, message := range [][]byte{raw, raw, malformed} {
		_, err = fmt.Fprintf(connection, "%d ", len(message))
		require(t, err)
		_, err = connection.Write(message)
		require(t, err)
	}
	require(t, connection.Close())
	// 监听就绪只证明可以接收；索引分片建立与首次刷新仍是异步阶段。
	// 先观察真实入库数量，再以平台 API 核对内容，避免把初始化中的分片当作检索契约失败。
	unavailable := 0
	eventually(t, ctx, "原生 Syslog 索引实际可读", func() bool {
		response, err := es.API.Count(es.API.Count.WithIndex("sb-logs-"+tenant+"-*"), es.API.Count.WithContext(ctx))
		if err != nil {
			unavailable++
			return false
		}
		defer response.Body.Close()
		if response.StatusCode == 404 || response.StatusCode == 503 {
			unavailable++
			return false
		}
		if response.IsError() {
			t.Fatalf("原生日志索引计数失败：%d", response.StatusCode)
		}
		var count struct {
			Count int `json:"count"`
		}
		require(t, json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&count))
		if count.Count > 3 {
			t.Fatal("原生日志被重复索引", count.Count)
		}
		return count.Count == 3
	})
	t.Logf("原生 Syslog 分片与刷新就绪，3 条消息实际可读；启动阶段未就绪观测 %d 次", unavailable)
	q := syslogdata.SearchQuery{Start: started.Add(-time.Minute), End: started.Add(time.Minute), SensorID: "sensor_live", SourceID: p.source.ID, Limit: 20}
	var result struct {
		Items []syslogdata.Document `json:"items"`
	}
	eventually(t, ctx, "真实角色 Syslog 上报和索引", func() bool {
		platform.request("POST", "/logs/search", "", q, &result, 200)
		return len(result.Items) == 3
	})
	ids := map[string]bool{}
	states := map[string]int{}
	for _, row := range result.Items {
		if ids[row.EventID] || row.Record.RawBase64 != "" || row.Record.Binding.ConfigSHA256 != p.source.SHA256() {
			t.Fatal("同文日志身份、列表投影或来源绑定错误")
		}
		ids[row.EventID] = true
		states[row.Parsed.State]++
		var detail syslogdata.Document
		platform.request("GET", "/logs/"+row.EventID+"?partition="+row.Partition, "", nil, &detail, 200)
		decoded, err := base64.StdEncoding.Strict().DecodeString(detail.Record.RawBase64)
		require(t, err)
		if syslogdata.Hash(decoded) != detail.Record.RawSHA256 || !bytes.Equal(decoded, raw) && !bytes.Equal(decoded, malformed) || detail.Record.Peer.CertificateSHA256 != p.source.TLS.ClientFingerprints[0] {
			t.Fatal("原生链路原文或客户端身份发生变化")
		}
	}
	if states["parsed"] != 2 || states["quarantined"] != 1 {
		t.Fatal("原生索引没有保留严格解析隔离", states)
	}
	q.Keyword = "策略命中"
	platform.request("POST", "/logs/search", "", q, &result, 200)
	if len(result.Items) != 2 {
		t.Fatal("原生链路中文检索未返回两条独立同文消息")
	}
	var audits store.AuditResult
	platform.request("GET", "/audits/operations?action=syslog.raw.read&limit=20", "", nil, &audits, 200)
	for _, audit := range audits.Items {
		delete(ids, audit.ObjectID)
	}
	if len(ids) != 0 {
		t.Fatal("原文返回后缺少对应审计")
	}
	eventually(t, ctx, "原生来源持久计数", func() bool {
		collector.request("GET", "/syslog/sources", "", nil, &health, 200)
		return len(health.Items) == 1 && health.Items[0].Persisted == "3" && health.Items[0].Received == "3" && health.Items[0].Dropped == "0"
	})
	t.Logf("原生 Syslog 完成三条消息、两条中文命中、三次原文审计；耗时 %.3f 秒", time.Since(started).Seconds())
}
