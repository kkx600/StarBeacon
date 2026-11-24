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
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/kkx600/StarBeacon/internal/agent"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/store"
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
		nativeRetentionPolicy(t, policy, revision, mode)
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
