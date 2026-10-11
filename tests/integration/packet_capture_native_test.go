//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

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
	validateErr := packetarchive.ValidateRawFile(ctx, input, capture)
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
