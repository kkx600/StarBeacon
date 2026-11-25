package store

import (
	"errors"
	"net/netip"

	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/traffic"
)

func validatePacketSessionSearch(q *model.TrafficSearchRequest) error {
	if q.EndpointA == "" && q.EndpointB == "" && q.Retention == "" {
		return nil
	}
	if q.EventKind != traffic.PacketSessionKind {
		return errors.New("端点和留存条件仅用于会话分段检索")
	}
	switch q.Retention {
	case "", "retained", "policy_truncated", "metadata_only":
	default:
		return errors.New("会话分段的留存状态无效")
	}
	for _, value := range []string{q.EndpointA, q.EndpointB} {
		if value != "" {
			if ip, _ := packetEndpoint(value); ip == "" {
				return errors.New("端点需为 IP、网段或 IP:端口，IPv6 端口写为 [IP]:端口")
			}
		}
	}
	return nil
}

func packetEndpoint(value string) (string, *uint16) {
	if len(value) > 80 {
		return "", nil
	}
	if ip, err := netip.ParseAddr(value); err == nil && ip.Zone() == "" {
		return ip.Unmap().String(), nil
	}
	if prefix, err := netip.ParsePrefix(value); err == nil && !prefix.Addr().Is4In6() {
		return prefix.Masked().String(), nil
	}
	if pair, err := netip.ParseAddrPort(value); err == nil && pair.Addr().Zone() == "" {
		port := pair.Port()
		return pair.Addr().Unmap().String(), &port
	}
	return "", nil
}

const sessionRetentionField = "packet_session_retention"

// T27 的不可变会话分段将留存状态冻结在 event.original 中。查询时为生成格式提取该键，
// 既能筛选旧分段，也无需修改已冻结的共享 LogsDB 索引。
func packetSessionRetentionMapping() map[string]any {
	const source = `
def event = params._source['event'];
if (event == null || event['dataset'] != 'starbeacon.packet_flow') return;
def raw = event['original'];
if (raw == null) return;
String key = ',"retention":"';
int start = raw.indexOf(key);
if (start < 0) return;
start += key.length();
int end = raw.indexOf('"', start);
if (end > start) emit(raw.substring(start, end));`
	return map[string]any{sessionRetentionField: map[string]any{"type": "keyword", "script": map[string]string{"source": source}}}
}

func packetSessionSearchFilters(q model.TrafficSearchRequest, filters []any) []any {
	for _, endpoint := range []struct{ field, value string }{{"source", q.EndpointA}, {"destination", q.EndpointB}} {
		ip, port := packetEndpoint(endpoint.value)
		if ip != "" {
			filters = append(filters, map[string]any{"term": map[string]string{endpoint.field + ".ip": ip}})
		}
		if port != nil {
			filters = append(filters, map[string]any{"term": map[string]uint16{endpoint.field + ".port": *port}})
		}
	}
	if q.Retention != "" {
		filters = append(filters, map[string]any{"term": map[string]string{sessionRetentionField: q.Retention}})
	}
	return filters
}
