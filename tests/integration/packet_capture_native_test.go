//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/kkx600/StarBeacon/internal/agent"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/packetpolicy"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/traffic"
	"github.com/kkx600/StarBeacon/internal/transport"
)

func verifyNativePacketArchive(t *testing.T, ctx context.Context, platformHTTP *liveHTTP, id transport.SensorIdentity, nic agent.NetworkInterface, started time.Time) {
	t.Helper()
	var confirmed store.PacketArchive
	var original []byte
	eventually(t, ctx, "实际旁路原包经压缩、mTLS 上传和平台下载读回", func() bool {
		var page struct {
			Items []store.PacketArchiveSummary `json:"items"`
		}
		platformHTTP.request("GET", "/packet-archives?sensor_id="+id.SensorID, "", nil, &page, 200)
		for _, item := range page.Items {
			if item.State != "ready" || item.Capture.Packets == 0 {
				continue
			}
			response, err := platformHTTP.client.Get(platformHTTP.origin + platformHTTP.prefix + "/packet-archives/" + item.ID + "/download")
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(io.LimitReader(response.Body, packetarchive.MaxSegmentBytes+1))
			response.Body.Close()
			require(t, err)
			if response.StatusCode != 200 {
				t.Fatal("实际原包对象未能下载", response.StatusCode)
			}
			if !bytes.Contains(data, []byte("/starbeacon/validation")) {
				continue
			}
			platformHTTP.request("GET", "/packet-archives/"+item.ID, "", nil, &confirmed, 200)
			if response.Header.Get("X-Content-SHA256") != confirmed.Manifest.Encoding.RawSHA256 || packetarchive.Digest(data) != confirmed.Manifest.Encoding.RawSHA256 {
				t.Fatal("实际原始通信数据摘要不一致")
			}
			original = data
			return true
		}
		return false
	})
	capture := confirmed.Manifest.Capture
	if capture.TenantID != id.TenantID || capture.SensorID != id.SensorID || capture.RegistrationID != id.RegistrationID || capture.Interface != nic.Name || capture.InterfaceMAC != nic.MAC || capture.BPFFilter != "tcp port 8088" || capture.Source != "AF_PACKET" || capture.TruncatedPackets != 0 || capture.FirstPacketAt == nil || capture.LastPacketAt == nil || confirmed.ExpiresAt.Sub(confirmed.CreatedAt) < 179*24*time.Hour || confirmed.Manifest.Encoding.Codec != "zstd" || confirmed.ObjectVersion == "" {
		t.Fatal("真实捕获来源、版本、压缩或留存不一致")
	}
	path := filepath.Join(t.TempDir(), "captured-original.pcapng")
	require(t, os.WriteFile(path, original, 0600))
	input, err := os.Open(path)
	require(t, err)
	validateErr := packetarchive.ValidateManifestRawFile(ctx, input, confirmed.Manifest)
	input.Close()
	require(t, validateErr)
	metadata, err := replay.Inspect(ctx, path)
	require(t, err)
	if metadata.TCPHandshake.CompleteHandshakes < 1 || metadata.TruncatedPackets != 0 {
		t.Fatal("实际 HTTP 连接握手未被原包捕获保存", metadata.TCPHandshake)
	}
	reader, err := pcapgo.NewNgReader(bytes.NewReader(original), pcapgo.DefaultNgReaderOptions)
	require(t, err)
	requestObserved := false
	for number := 1; ; number++ {
		frame, ci, e := reader.ReadPacketData()
		if e == io.EOF {
			break
		}
		require(t, e)
		isRequest := bytes.Contains(frame, []byte("/starbeacon/validation"))
		if number != 1 && !isRequest {
			continue
		}
		var inspection packetarchive.PacketInspection
		platformHTTP.request("GET", "/packet-archives/"+confirmed.ID+"/packets/"+strconv.Itoa(number), "", nil, &inspection, 200)
		decoded, e := base64.StdEncoding.DecodeString(inspection.Packet)
		require(t, e)
		if !bytes.Equal(decoded, frame) || inspection.PacketSHA256 != packetarchive.Digest(frame) || !inspection.CapturedAt.Equal(ci.Timestamp) || inspection.Interface != nic.Name || inspection.ManifestSHA256 != confirmed.ManifestSHA256 || inspection.DecodeStatus != "parsed" {
			t.Fatal("真实网卡原包协议查看与实际帧、来源或捕获时间不一致", number)
		}
		if isRequest {
			requestObserved = true
			break
		}
	}
	if !requestObserved {
		t.Fatal("逐包查看没有核实实际发出的 HTTP 请求")
	}
	t.Logf("真实原包链路：%d 包，原始 %d 字节，压缩 %d 字节；可见完整 TCP 握手 %d；请求至原包下载核验耗时 %s", capture.Packets, confirmed.Manifest.Encoding.RawBytes, confirmed.Manifest.Encoding.StoredBytes, metadata.TCPHandshake.CompleteHandshakes, time.Since(started).Round(time.Millisecond))
}

func nativeRetentionPolicy(t *testing.T, path string, revision uint64, mode string) {
	t.Helper()
	disabled := 0
	raw, err := json.Marshal(packetarchive.RetentionPolicy{NetworkDomain: "docker_capture_pilot", Revision: revision, Mode: mode, PlainBytes: 64 << 10, DedupMillis: &disabled})
	require(t, err)
	require(t, os.WriteFile(path+".new", raw, 0600))
	require(t, os.Rename(path+".new", path))
}

func verifyNativeIndexedSnapshot(t *testing.T, ctx context.Context, platformHTTP *liveHTTP, archive store.PacketArchive, flow packetarchive.RetentionSession, port uint16) {
	t.Helper()
	var inspection packetarchive.PacketInspection
	platformHTTP.request("GET", "/packet-archives/"+archive.ID+"/packets/"+strconv.FormatUint(flow.FirstPacket, 10), "", nil, &inspection, 200)
	raw, err := base64.StdEncoding.DecodeString(inspection.Packet)
	require(t, err)
	packet := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
	ethernet, etherOK := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	tcp, tcpOK := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !etherOK || !tcpOK || uint16(tcp.SrcPort) != port || flow.VLAN != "" {
		t.Fatal("未从隔离网络捕获该会话的 Ethernet/TCP 首包")
	}
	client, server := flow.A, flow.B
	if client.Port() != port {
		client, server = server, client
	}
	query := packetarchive.SessionRequest{ArchiveIDs: []string{archive.ID}, Mode: "snapshot", ClientIP: client.Addr().String(), ClientPort: client.Port(), ServerIP: server.Addr().String(), ServerPort: server.Port(), ClientMAC: ethernet.SrcMAC.String(), ServerMAC: ethernet.DstMAC.String(), VLANs: []uint16{}}
	body, err := json.Marshal(query)
	require(t, err)
	request, err := http.NewRequestWithContext(ctx, "POST", platformHTTP.origin+platformHTTP.prefix+"/packet-archives/session-export", bytes.NewReader(body))
	require(t, err)
	request.Header.Set("Origin", platformHTTP.origin)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", platformHTTP.csrf)
	response, err := platformHTTP.client.Do(request)
	require(t, err)
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, packetarchive.MaxSegmentBytes+1))
	require(t, err)
	if response.StatusCode != 200 || response.Header.Get("X-Session-Completeness") != "snapshot" ||
		response.Header.Get("X-Content-SHA256") != packetarchive.Digest(data) || !bytes.Contains(data, []byte("/starbeacon/retention")) {
		t.Fatalf("隔离网络会话取回缺少真实 HTTP 报文或校验证据，响应 %d", response.StatusCode)
	}
	reader, err := pcapgo.NewNgReader(bytes.NewReader(data), pcapgo.DefaultNgReaderOptions)
	require(t, err)
	var report packetarchive.SessionReport
	require(t, json.Unmarshal([]byte(reader.SectionInfo().Comment), &report))
	if report.PacketBytes != flow.RetainedBytes || len(report.Sources) != 1 || report.Sources[0].ObjectVersion != archive.ObjectVersion {
		t.Fatalf("隔离网络会话与保存的捕获内容不一致，导出 %d／留存 %d 字节", report.PacketBytes, flow.RetainedBytes)
	}
	t.Logf("分段取回实测 隔离 Docker 网络的实际 HTTP 会话 %d 包、%d 字节，PCAPNG 摘要与对象版本已核验", report.Packets, report.PacketBytes)
	source := archive.Manifest.Capture
	querySegment := model.TrafficSearchRequest{
		SearchRequest: model.SearchRequest{Start: flow.StartedAt.Add(-time.Second), End: flow.EndedAt.Add(time.Second), SourceIP: flow.A.Addr().String(), DestinationIP: flow.B.Addr().String()},
		EventKind:     traffic.PacketSessionKind, SensorID: source.SensorID, RegistrationID: source.RegistrationID, GenerationID: archive.ID,
	}
	eventually(t, ctx, "真实 HTTP 采集窗口由索引工作进程追加", func() bool {
		var list traffic.Result
		platformHTTP.request("POST", "/traffic/search", "", querySegment, &list, 200)
		for _, hit := range list.Items {
			if hit.Source.Port != flow.A.Port() || hit.Destination.Port != flow.B.Port() {
				continue
			}
			detail := hit.Details.Segment
			if detail == nil || detail.ArchiveID != archive.ID || detail.OriginalBytes != flow.OriginalBytes || detail.RetainedBytes != flow.RetainedBytes ||
				detail.ManifestSHA256 != archive.ManifestSHA256 || !detail.WindowStart.Equal(source.StartedAt) || !detail.WindowEnd.Equal(source.EndedAt) {
				t.Fatal("真实会话索引未保留原包窗口和实际字节")
			}
			t.Logf("会话分段实测 隔离 Docker 网络的实际 HTTP 连接已追加到 LogsDB，窗口 %s，观测 %d 字节",
				detail.WindowEnd.Sub(detail.WindowStart).Round(time.Millisecond), detail.OriginalBytes)
			return true
		}
		return false
	})
}

func verifyNativeRetention(t *testing.T, ctx context.Context, collectorHTTP, platformHTTP *liveHTTP, sensor, policy string) {
	t.Helper()
	const bodyBytes = 2 * 1024 * 1024
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	current := func() string {
		var page struct {
			Health agent.PacketArchiveState `json:"health"`
		}
		collectorHTTP.request("GET", "/packet-archives", "", nil, &page, 200)
		for _, capture := range page.Health.Interfaces {
			if capture.State == "capturing" {
				return capture.ID
			}
		}
		return ""
	}
	traffic := func(path string) uint16 {
		ports := make(chan uint16, 1)
		trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
			ports <- uint16(info.Conn.LocalAddr().(*net.TCPAddr).Port)
		}}
		request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, os.Getenv("SB_TEST_CAPTURE_ENDPOINT")+path, nil)
		require(t, err)
		response, err := client.Do(request)
		require(t, err)
		bytes, err := io.Copy(io.Discard, io.LimitReader(response.Body, bodyBytes+1))
		require(t, response.Body.Close())
		require(t, err)
		if response.StatusCode != 200 || bytes != bodyBytes {
			t.Fatalf("隔离网络响应不完整 %d／%d", response.StatusCode, bytes)
		}
		return <-ports
	}
	for index, mode := range []string{packetarchive.RetentionSmart, packetarchive.RetentionFull, packetarchive.RetentionAlertOnly} {
		revision := uint64(index + 2)
		var status packetpolicy.Status
		collectorHTTP.request("GET", "/packet-retention", "", nil, &status, 200)
		if status.Configuration == nil || status.Configuration.Policy.Revision != revision-1 || !status.Valid() {
			t.Fatalf("采集器当前留存观测无效 %+v", status)
		}
		next := status.Configuration.Policy
		next.Revision, next.Mode = revision, mode
		change := packetpolicy.Change{ExpectedRevision: revision - 1, ExpectedSHA256: status.Configuration.SHA256, Policy: next}
		var taskID string
		origin := "file"
		switch index {
		case 0:
			// 本机修改一个实际参数，下一次心跳同步到平台。
			bytes := 32 << 10
			change.Policy.EncryptedBytes = &bytes
			var saved packetpolicy.Observation
			collectorHTTP.request("PUT", "/packet-retention", "", change, &saved, 200)
			if !saved.Valid() || !saved.Policy.Equal(change.Policy) || saved.Origin != "local" {
				t.Fatal("本机配置没有返回已持久保存的修订")
			}
			collectorHTTP.request("PUT", "/packet-retention", "", change, nil, 409)
			origin = "local"
		case 1:
			var submitted struct {
				TaskID string `json:"task_id"`
			}
			platformHTTP.request("POST", "/sensors/"+sensor+"/packet-retention", "native-packet-retention-v3", change, &submitted, 202)
			taskID, origin = submitted.TaskID, "platform"
			if taskID == "" {
				t.Fatal("平台没有创建签名任务")
			}
			eventually(t, ctx, "平台收到已核验的留存配置任务回执", func() bool {
				var task store.SensorTask
				platformHTTP.request("GET", "/tasks/"+taskID, "", nil, &task, 200)
				if task.State == "failed" || task.State == "unknown" || task.State == "expired" {
					t.Fatalf("留存签名任务未成功：%s %s", task.State, task.Receipt)
				}
				return task.State == "succeeded"
			})
			// 同一个提交在已经生效后重试仍得到原任务。
			var retry map[string]string
			platformHTTP.request("POST", "/sensors/"+sensor+"/packet-retention", "native-packet-retention-v3", change, &retry, 202)
			if retry["task_id"] != taskID {
				t.Fatal("留存下发重试产生了新任务")
			}
		case 2:
			nativeRetentionPolicy(t, policy, revision, mode)
		}
		eventually(t, ctx, "平台读取采集器实际当前修订与来源", func() bool {
			var storage struct {
				Sensors []store.PacketStorageSensor `json:"sensors"`
				Warm    *store.PacketStorageStatus  `json:"warm"`
			}
			platformHTTP.request("GET", "/packet-storage", "", nil, &storage, 200)
			for _, row := range storage.Sensors {
				if row.ID == sensor && row.Fresh && row.CanApply && row.Status != nil && row.Status.Configuration != nil &&
					row.Status.Configuration.Policy.Revision == revision {
					if row.Status.Configuration.Origin != origin || row.Status.Configuration.TaskID != taskID ||
						row.Status.Configuration.Policy.Mode != mode || row.Status.ReservedBytes == nil || storage.Warm == nil {
						t.Fatalf("配置来源或热温用量失真 %+v", row.Status)
					}
					if index < 2 && !row.Status.Configuration.Policy.Equal(change.Policy) {
						t.Fatal("平台显示的实际配置不同于已提交参数")
					}
					t.Logf("留存策略同步实测 修订 %d，来源 %s，模式 %s", revision, origin, mode)
					return true
				}
			}
			return false
		})
		if index == 1 {
			var conflict struct{ Code string }
			platformHTTP.request("POST", "/sensors/"+sensor+"/packet-retention", "native-packet-retention-stale", change, &conflict, 409)
			if conflict.Code != "packet_retention_changed" {
				t.Fatal("平台旧修订未按回读基线拒绝", conflict.Code)
			}
		}
		old := current()
		var captureID string
		eventually(t, ctx, "等待专属采集器打开后继热写段", func() bool {
			captureID = current()
			return captureID != "" && captureID != old
		})
		port := traffic("/starbeacon/retention")
		var alertPort uint16
		if mode == packetarchive.RetentionAlertOnly {
			alertPort = traffic("/starbeacon/validation?retention=1")
		}
		var archive store.PacketArchive
		eventually(t, ctx, "平台持久确认隔离网络捕获与留存目录", func() bool {
			var page struct {
				Items []store.PacketArchiveSummary `json:"items"`
			}
			platformHTTP.request("GET", "/packet-archives?sensor_id="+sensor, "", nil, &page, 200)
			for _, row := range page.Items {
				if row.ID == captureID && row.State == "ready" {
					platformHTTP.request("GET", "/packet-archives/"+row.ID, "", nil, &archive, 200)
					return true
				}
			}
			return false
		})
		capture := archive.Manifest.Capture
		summary := capture.Retention
		if archive.Manifest.Encoding.Schema != packetarchive.PackedSchema || summary == nil || summary.PolicyRevision != revision || summary.Mode != mode || summary.NetworkDomain != "docker_capture_pilot" ||
			summary.Degradation != "" || capture.KernelDrops == nil || *capture.KernelDrops != 0 {
			t.Fatalf("实际归档的模式、修订或捕获计数有误 %+v／%+v", summary, capture)
		}
		var normal, alerted packetarchive.RetentionSession
		for _, session := range archive.Manifest.Sessions {
			switch {
			case session.A.Port() == port || session.B.Port() == port:
				normal = session
			case alertPort != 0 && (session.A.Port() == alertPort || session.B.Port() == alertPort):
				alerted = session
			}
		}
		if normal.OriginalBytes < bodyBytes || normal.PolicyRevision != revision {
			t.Fatalf("实际普通 HTTP 流量未完整进入热段 %+v", normal)
		}
		verifyNativeFlowPage(t, ctx, platformHTTP, archive, normal)
		switch mode {
		case packetarchive.RetentionSmart:
			if normal.Protocol != "http" || normal.State != "policy_truncated" || normal.RetainedBytes == 0 || normal.RetainedBytes >= normal.OriginalBytes {
				t.Fatalf("实际明文大传输未按策略裁剪 %+v", normal)
			}
		case packetarchive.RetentionFull:
			if normal.State != "retained" || normal.RetainedBytes != normal.OriginalBytes {
				t.Fatalf("完整保存遗漏了实际报文 %+v", normal)
			}
			verifyNativeIndexedSnapshot(t, ctx, platformHTTP, archive, normal, port)
		case packetarchive.RetentionAlertOnly:
			if normal.State != "metadata_only" || normal.RetainedBytes != 0 || alerted.State != "retained" ||
				alerted.OriginalBytes < bodyBytes || alerted.RetainedBytes != alerted.OriginalBytes {
				t.Fatalf("实际告警与普通连接的留存不符 %+v／%+v", normal, alerted)
			}
			t.Logf("留存实测 告警关联会话 %d/%d 字节", alerted.RetainedBytes, alerted.OriginalBytes)
		}
		elapsed := capture.EndedAt.Sub(capture.StartedAt).Seconds()
		active := normal.EndedAt.Sub(normal.StartedAt).Seconds()
		if elapsed <= 0 || active <= 0 {
			t.Fatal("实际写入计量窗口无效")
		}
		t.Logf("留存实测 %s 修订 %d，普通会话 %d/%d 字节（%.2f%%），热段 %d 字节/%.3f 秒（%.3f MiB/s），活跃普通会话 %.3f MiB/s，内核丢包 %d",
			mode, revision, normal.RetainedBytes, normal.OriginalBytes, 100*float64(normal.RetainedBytes)/float64(normal.OriginalBytes),
			summary.OriginalBytes, elapsed, float64(summary.OriginalBytes)/elapsed/(1<<20), float64(normal.OriginalBytes)/active/(1<<20), *capture.KernelDrops)
	}
}

func verifyNativeFlowPage(t *testing.T, ctx context.Context, platformHTTP *liveHTTP, archive store.PacketArchive, flow packetarchive.RetentionSession) {
	t.Helper()
	query := model.TrafficSearchRequest{
		SearchRequest: model.SearchRequest{Start: flow.StartedAt.Add(-time.Second), End: flow.EndedAt.Add(time.Second)},
		EventKind:     traffic.PacketSessionKind, SensorID: archive.Manifest.Capture.SensorID,
		RegistrationID: archive.Manifest.Capture.RegistrationID, GenerationID: archive.ID,
		EndpointA: flow.A.String(), EndpointB: flow.B.String(), Retention: flow.State,
	}
	var selected traffic.Record
	eventually(t, ctx, "全流量回溯按端点与留存状态命中实际 HTTP 会话", func() bool {
		var result traffic.Result
		platformHTTP.request("POST", "/traffic/search", "", query, &result, 200)
		for _, row := range result.Items {
			if row.Details.Segment != nil && row.Details.Segment.ArchiveID == archive.ID {
				selected = row
				return true
			}
		}
		return false
	})
	segment := selected.Details.Segment
	if segment.Retention != flow.State || segment.RetainedBytes != flow.RetainedBytes || segment.OriginalBytes != flow.OriginalBytes {
		t.Fatal("全流量检索与实际归档策略计数不一致")
	}
	query.Retention = "metadata_only"
	if flow.State == query.Retention {
		query.Retention = "retained"
	}
	var excluded traffic.Result
	platformHTTP.request("POST", "/traffic/search", "", query, &excluded, 200)
	if excluded.Total != 0 {
		t.Fatal("留存筛选包含不同状态的会话")
	}
	input := map[string]string{"endpoint_a": flow.A.String(), "endpoint_b": flow.B.String(), "transport": flow.Transport, "vlan": flow.VLAN,
		"manifest_sha256": archive.ManifestSHA256, "archive_raw_sha256": archive.Manifest.Encoding.RawSHA256}
	base := "/packet-archives/" + archive.ID
	if flow.State == "metadata_only" {
		platformHTTP.request("POST", base+"/flow-packets/1", "", input, nil, 404)
		platformHTTP.request("POST", base+"/flow-snapshot", "", input, nil, 404)
		return
	}
	var view packetarchive.SegmentFlowInspection
	platformHTTP.request("POST", base+"/flow-packets/1", "", input, &view, 200)
	raw, err := json.Marshal(input)
	require(t, err)
	request, err := http.NewRequestWithContext(ctx, "POST", platformHTTP.origin+platformHTTP.prefix+base+"/flow-snapshot", bytes.NewReader(raw))
	require(t, err)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", platformHTTP.origin)
	request.Header.Set("X-CSRF-Token", platformHTTP.csrf)
	response, err := platformHTTP.client.Do(request)
	require(t, err)
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, packetarchive.MaxSegmentBytes+1))
	require(t, err)
	if response.StatusCode != 200 || response.Header.Get("X-Session-Completeness") != "snapshot" || response.Header.Get("X-Packet-Retention") != flow.State ||
		response.Header.Get("X-Content-SHA256") != packetarchive.Digest(data) || (flow.State == "policy_truncated") != strings.Contains(response.Header.Get("Content-Disposition"), "-partial.pcapng") {
		t.Fatalf("会话快照完整性、留存标签或摘要不正确：%d", response.StatusCode)
	}
	reader, err := pcapgo.NewNgReader(bytes.NewReader(data), pcapgo.DefaultNgReaderOptions)
	require(t, err)
	var reference map[string]any
	require(t, json.Unmarshal([]byte(reader.SectionInfo().Comment), &reference))
	if reference["retention"] != flow.State || reference["completeness"] != "snapshot" {
		t.Fatal("导出文件没有保存实际留存标记")
	}
	var count, stored uint64
	for {
		frame, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		require(t, err)
		if count == 0 && (view.PacketSHA256 != packetarchive.Digest(frame) || view.Packet != base64.StdEncoding.EncodeToString(frame) || !view.CapturedAt.Equal(ci.Timestamp)) {
			t.Fatal("逐包查看与快照首包字节、捕获时间不一致")
		}
		count++
		stored += uint64(len(frame))
	}
	if view.Retention != flow.State || view.Total != count || count != segment.RetainedPackets || stored != segment.RetainedBytes {
		t.Fatal("会话逐包和快照数量与原包观测不一致")
	}
	t.Logf("全流量回溯实测 %s，逐包校验和快照 %d 包、%d 字节", flow.State, count, stored)
}
