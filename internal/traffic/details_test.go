package traffic

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestFlowUsesActualTimesCountersAndMACCollections(t *testing.T) {
	view := Parse(`{"flow":{"start":"2026-10-03T01:02:03.123456+0800","end":"2026-10-03T01:02:04.123456+0800","pkts_toserver":0,"pkts_toclient":4,"bytes_toserver":18446744073709551615,"state":"closed","reason":"shutdown"},"ether":{"src_macs":["AA-BB-CC-DD-EE-FF"],"dest_macs":["02:00:00:00:00:01"]},"community_id":"1:owned","pkt_src":"wire/pcap","direction":"to_client"}`)
	if view.State != "available" || view.Truncated || view.Flow == nil || view.Flow.Start.Format("2006-01-02T15:04:05.999999Z07:00") != "2026-10-02T17:02:03.123456Z" || view.Flow.BytesToServer != "18446744073709551615" || view.Flow.BytesToClient != "" || view.Flow.PacketsToServer != "0" || len(view.SourceMACs) != 1 || view.SourceMACs[0] != "aa:bb:cc:dd:ee:ff" {
		t.Fatal("实际观测被替换、精度丢失或缺测补零", view)
	}
	if view.PacketSource != "wire/pcap" || view.Direction != "to_client" || view.CommunityID != "1:owned" {
		t.Fatal(view)
	}
	view = Parse(`{"flow":{"pkts_toserver":1}}`)
	if view.Flow == nil || view.Flow.Start != nil || view.Flow.End != nil || view.Flow.PacketsToServer != "1" {
		t.Fatal("缺少的会话时间被构造", view)
	}
}

func TestProtocolViewsPreserveMissingFieldsAndBoundUntrustedData(t *testing.T) {
	view := Parse(`{"tls":{"sni":"service.example.com","version":"TLS 1.3","subject":"CN=example.com","issuerdn":"CN=issuer","fingerprint":"00:11"},"dns":{"version":3,"type":"answer","rcode":"NOERROR","queries":[{"rrname":"service.example.com","rrtype":"A"}]}}`)
	if view.State != "available" || view.TLS == nil || view.TLS.SNI != "service.example.com" || view.TLS.Issuer != "CN=issuer" || view.DNS == nil || len(view.DNS.Queries) != 1 || view.DNS.Queries[0].Type != "A" {
		t.Fatal(view)
	}
	view = Parse(`{"tls":{"session_resumed":true},"dns":{"version":2,"rrname":"legacy.example.com"}}`)
	if view.TLS == nil || view.TLS.SNI != "" || view.DNS == nil || len(view.DNS.Queries) != 0 {
		t.Fatal("会话恢复或旧 DNS 被猜测成完整观测", view)
	}
	queries := []map[string]string{}
	macs := []string{}
	for i := 0; i < 33; i++ {
		queries = append(queries, map[string]string{"rrname": fmt.Sprintf("q%d.example.com", i), "rrtype": "A"})
		macs = append(macs, "02:00:00:00:00:01")
	}
	raw, err := json.Marshal(map[string]any{"dns": map[string]any{"version": 3, "queries": queries}, "tls": map[string]any{"sni": strings.Repeat("长", 1025), "issuerdn": "issuer\nprivate"}, "ether": map[string]any{"src_macs": macs, "dest_macs": []string{"invalid", "02:00:00:00:00:00:00:01"}}})
	if err != nil {
		t.Fatal(err)
	}
	view = Parse(string(raw))
	if !view.Truncated || len(view.DNS.Queries) != 32 || len(view.SourceMACs) != 16 || len(view.DestinationMACs) != 0 || len([]rune(view.TLS.SNI)) != 1024 || view.TLS.Issuer != "" {
		t.Fatal("长度、数量、控制字符或 MAC 边界没有标识", view)
	}
	view = Parse(`{"dns":{"version":4}}`)
	if !view.Truncated || view.DNS.Version != "" {
		t.Fatal("未知 DNS 版本被当作已支持", view)
	}
}

func TestMalformedFlowMetadataDoesNotBecomeZeroTraffic(t *testing.T) {
	for _, raw := range []string{"", "\xff", "{", strings.Repeat(" ", 131073), `{"flow":{"start":"invalid"}}`, `{"flow":{"start":"2026-10-03T00:00:01Z","end":"2026-10-03T00:00:00Z"}}`, `{"flow":{"pkts_toserver":-1}}`, `{"flow":{"pkts_toserver":1.5}}`, `{"flow":{"bytes_toclient":18446744073709551616}}`, `{"flow":{"bytes_toclient":"01"}}`, `{"dns":{"version":"wrong"}}`, `{"tls":{"sni":[]}}`, `null`} {
		view := Parse(raw)
		if view.State != "unavailable" || view.Flow != nil || view.TLS != nil || view.DNS != nil || view.SourceMACs == nil || view.DestinationMACs == nil {
			t.Fatal("损坏元数据伪装为零流量", raw, view)
		}
	}
	view := Parse(`{}`)
	if view.State != "available" || view.Flow != nil || view.TLS != nil || view.DNS != nil {
		t.Fatal("合法缺测对象被补造协议", view)
	}
}
